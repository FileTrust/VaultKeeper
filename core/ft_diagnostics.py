"""FileTrust diagnostics: safe local drafts; network only after explicit approval.

Standard library only. Never parse raw logs, exception messages, locals, config,
environment dumps, user files or blockchain identifiers into a report.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

ENDPOINT = "https://reports.filetrust.io/v1/reports"
MAX_BYTES = 32768
MAX_DRAFTS = 20
KEEP_SECONDS = 7 * 86400
_ID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z")
_client = None
_install_lock = threading.Lock()


class DiagnosticError(Exception):
    """Deliberately generic, safe for the reporting UI/CLI to display."""


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _read(path, limit=MAX_BYTES):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise DiagnosticError("Invalid diagnostic file.")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DiagnosticError("Diagnostic file is too large.")
    return data


def _private_directory(path):
    if path.is_symlink():
        raise DiagnosticError("Diagnostic directory must not be a symbolic link.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    if path.stat().st_mode & 0o077:
        raise DiagnosticError("Diagnostic storage does not support private permissions.")


def _atomic(path, data):
    # Do not chmod a user's existing export folder.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".draft-")
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@dataclass(frozen=True)
class Preview:
    payload: bytes
    sha256: str

    @property
    def text(self):
        return json.dumps(json.loads(self.payload), indent=2, ensure_ascii=True)


@dataclass(frozen=True)
class Approval:
    payload: bytes
    sha256: str


def approve(preview, confirmed_sha256):
    if not isinstance(preview, Preview) or confirmed_sha256 != preview.sha256 or hashlib.sha256(preview.payload).hexdigest() != preview.sha256:
        raise DiagnosticError("The report changed. Preview it again before sending.")
    return Approval(preview.payload, preview.sha256)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, policy_path, home=None):
        self.policy_path = Path(policy_path).resolve()
        self.policy = json.loads(_read(self.policy_path, 131072))
        self.app = self.policy["app"]
        self.release = self.policy["release"]
        self.operations = self.policy["operations"][self.app]
        if self.policy.get("endpoint") != ENDPOINT:
            raise DiagnosticError("Unrecognized reporting endpoint.")
        self.source_root = (self.policy_path.parent / self.policy["source_root"]).resolve()
        self.home = Path(home).resolve() if home is not None else self.source_root
        self.directory = self.home / ".filetrust-diagnostics"
        self.temporary_storage = False
        self._storage_initialized = False
        self.environment = os.environ.get("FILETRUST_DIAGNOSTICS_ENVIRONMENT", "testnet")
        if self.environment not in ("development", "testnet", "mainnet"):
            raise DiagnosticError("Invalid diagnostic environment.")
        self._lock = threading.RLock()
        self._recent = {}
        self._steps = deque(maxlen=20)
        self._started = time.monotonic()
        self.step("startup", "started")

    def _storage(self):
        if self._storage_initialized:
            return
        try:
            _private_directory(self.directory)
        except (OSError, DiagnosticError):
            # FAT/NTFS mounts may ignore chmod. Use a private OS temporary
            # directory instead of silently leaving readable diagnostic drafts.
            owner = str(os.getuid()) if hasattr(os, "getuid") else "user"
            base = Path(tempfile.gettempdir()) / ("filetrust-diagnostics-" + owner)
            _private_directory(base)
            identity = hashlib.sha256((self.app + str(self.home)).encode()).hexdigest()[:24]
            self.directory = base / identity
            _private_directory(self.directory)
            self.temporary_storage = True
        self._storage_initialized = True

    def validate(self, value):
        required = {"schema_version", "report_id", "app", "release", "environment", "component", "operation", "error_code", "exception_type"}
        def keys(obj, needed, optional=()):
            if type(obj) is not dict or not set(needed) <= obj.keys() or obj.keys() - set(needed) - set(optional):
                raise DiagnosticError("Invalid diagnostic fields.")
        keys(value, required, ("frames", "steps"))
        if value["schema_version"] != 1 or type(value["schema_version"]) is not int or type(value["report_id"]) is not str or not _ID.fullmatch(value["report_id"]):
            raise DiagnosticError("Invalid diagnostic identity.")
        if value["app"] != self.app or value["release"] not in self.policy.get("releases", [self.release]) or value["environment"] not in ("development", "testnet", "mainnet"):
            raise DiagnosticError("Unsupported diagnostic application or release.")
        if value["component"] not in ("python", "go", "supervisor", "prover") or (value["component"] == "go" and self.app != "VK"):
            raise DiagnosticError("Invalid diagnostic component.")
        if value["operation"] not in self.operations or value["exception_type"] not in self.policy["exception_types"] or value["error_code"] not in self.policy["error_codes"]:
            raise DiagnosticError("Invalid diagnostic category.")
        frames, steps = value.get("frames", []), value.get("steps", [])
        if type(frames) is not list or len(frames) > 20 or type(steps) is not list or len(steps) > 20:
            raise DiagnosticError("Too much diagnostic context.")
        for frame in frames:
            keys(frame, ("file", "line"))
            if type(frame["file"]) is not str or frame["file"] not in self.policy["files"] or type(frame["line"]) is not int or not 1 <= frame["line"] <= self.policy["files"][frame["file"]]:
                raise DiagnosticError("Unknown diagnostic code location.")
        previous = -1
        for step in steps:
            keys(step, ("operation", "status", "elapsed_ms"))
            if step["operation"] not in self.operations or step["status"] not in ("started", "completed", "failed") or type(step["elapsed_ms"]) is not int or not 0 <= step["elapsed_ms"] <= 86400000 or step["elapsed_ms"] < previous:
                raise DiagnosticError("Invalid diagnostic step.")
            previous = step["elapsed_ms"]
        result = dict(value, frames=frames, steps=steps)
        if len(canonical(result)) > MAX_BYTES:
            raise DiagnosticError("Diagnostic report is too large.")
        return result

    def step(self, operation, status):
        if operation not in self.operations or status not in ("started", "completed", "failed"):
            return
        elapsed = min(86400000, int((time.monotonic() - self._started) * 1000))
        with self._lock:
            self._steps.append({"operation": operation, "status": status, "elapsed_ms": elapsed})

    def _frames(self, exc):
        frames = []
        tb = exc.__traceback__ if isinstance(exc, BaseException) else None
        while tb is not None:
            try:
                name = Path(tb.tb_frame.f_code.co_filename).resolve().relative_to(self.source_root).as_posix()
                name = self.policy.get("file_prefix", "") + name
                if name in self.policy["files"] and "ft_diagnostics" not in name and 1 <= tb.tb_lineno <= self.policy["files"][name]:
                    frames.append({"file": name, "line": tb.tb_lineno})
            except (OSError, ValueError):
                pass
            tb = tb.tb_next
        return frames[-20:]

    def capture(self, exc=None, operation=None, error_code="FT_UNEXPECTED_ERROR", component="python", deduplicate=True):
        """Best effort: report failures must never break the application."""
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            return None
        try:
            frames = self._frames(exc)
            if operation is None:
                operation = "startup"
                for frame in frames:
                    operation = self.policy.get("file_operations", {}).get(frame["file"], operation)
            kind = type(exc).__name__ if isinstance(exc, BaseException) else "unknown"
            if kind not in self.policy["exception_types"]:
                kind = "unknown"
            self.step(operation, "failed")
            with self._lock:
                value = self.validate({"schema_version": 1, "report_id": str(uuid.uuid4()), "app": self.app,
                    "release": self.release, "environment": self.environment, "component": component,
                    "operation": operation, "error_code": error_code, "exception_type": kind,
                    "frames": frames, "steps": list(self._steps)})
                fingerprint = canonical({k: value[k] for k in ("operation", "error_code", "exception_type", "frames")})
                now = time.monotonic()
                if deduplicate and now - self._recent.get(fingerprint, -3600) < 60:
                    return None
                self._recent = {k: t for k, t in self._recent.items() if now - t < 60}
                self._recent[fingerprint] = now
                self._storage()
                self._prune()
                _atomic(self.directory / (value["report_id"] + ".json"), canonical(value))
                self._prune()
                return value["report_id"]
        except Exception:
            return None

    def _prune(self):
        paths = sorted((p for p in self.directory.glob("*.json") if _ID.fullmatch(p.stem) and not p.is_symlink()), key=lambda p: p.stat().st_mtime)
        for index, path in enumerate(paths):
            if time.time() - path.stat().st_mtime > KEEP_SECONDS or index < len(paths) - MAX_DRAFTS:
                path.unlink(missing_ok=True)

    def drafts(self):
        with self._lock:
            self._storage()
            self._prune()
            return sorted((p.stem for p in self.directory.glob("*.json") if _ID.fullmatch(p.stem) and not p.is_symlink()),
                key=lambda ident: (self.directory / (ident + ".json")).stat().st_mtime, reverse=True)

    def preview(self, report_id):
        if type(report_id) is not str or not _ID.fullmatch(report_id):
            raise DiagnosticError("Invalid report ID.")
        self._storage()
        try:
            value = self.validate(json.loads(_read(self.directory / (report_id + ".json"))))
        except (OSError, ValueError, TypeError, KeyError):
            raise DiagnosticError("Report could not be read safely.") from None
        if value["report_id"] != report_id:
            raise DiagnosticError("Report ID does not match the draft.")
        data = canonical(value)
        return Preview(data, hashlib.sha256(data).hexdigest())

    def export(self, preview, destination):
        if not isinstance(preview, Preview) or preview.sha256 != hashlib.sha256(preview.payload).hexdigest():
            raise DiagnosticError("Preview changed.")
        self.validate(json.loads(preview.payload))
        # Export does not grant permission to send.
        destination = Path(destination)
        if destination.is_symlink():
            raise DiagnosticError("Export destination must not be a symbolic link.")
        _atomic(destination, preview.payload + b"\n")

    def send(self, approval):
        if not isinstance(approval, Approval) or hashlib.sha256(approval.payload).hexdigest() != approval.sha256:
            raise DiagnosticError("Sending requires approval of the exact preview.")
        value = self.validate(json.loads(approval.payload))
        request = urllib.request.Request(ENDPOINT, data=approval.payload, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "FileTrust-Diagnostics/1"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request, timeout=20) as response:
                body = response.read(2049)
                if response.status != 200 or len(body) > 2048:
                    raise DiagnosticError("Reporting service did not accept the report.")
            receipt = json.loads(body)
            if receipt != {"status": "accepted", "event_id": value["report_id"].replace("-", "")}:
                raise DiagnosticError("Invalid reporting receipt.")
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            if code in (429, 503):
                raise DiagnosticError("Reporting is temporarily unavailable. The local draft is retained; retry later after reviewing it.") from None
            raise DiagnosticError("Report was rejected. The local draft is retained.") from None
        except (OSError, ValueError):
            raise DiagnosticError("Report delivery could not be confirmed. The local draft is retained.") from None
        return receipt

    def install_hooks(self, root=None):
        if not getattr(self, "_hooks_installed", False):
            previous = sys.excepthook
            def main_hook(kind, value, tb):
                self.capture(value)
                previous(kind, value, tb)
            sys.excepthook = main_hook
            thread_previous = threading.excepthook
            def thread_hook(args):
                self.capture(args.exc_value)
                thread_previous(args)
            threading.excepthook = thread_hook
            self._hooks_installed = True
        if root is not None and callable(getattr(root, "report_callback_exception", None)) and not getattr(root, "_ft_diagnostics_hook", False):
            previous_callback = root.report_callback_exception
            def callback_hook(kind, value, tb):
                self.capture(value)
                previous_callback(kind, value, tb)
            root.report_callback_exception = callback_hook
            root._ft_diagnostics_hook = True

    def install_asyncio(self, loop):
        previous = loop.get_exception_handler()
        def handler(active_loop, context):
            exc = context.get("exception")
            self.capture(exc if isinstance(exc, BaseException) else None)
            if previous is not None:
                previous(active_loop, context)
            else:
                active_loop.default_exception_handler(context)
        loop.set_exception_handler(handler)


class DiagnosticHandler(logging.Handler):
    def emit(self, record):
        if record.levelno >= logging.ERROR:
            capture_current(record.exc_info[1] if record.exc_info else None, error_code="FT_OPERATION_FAILED")


def start(home=None, root=None):
    global _client
    try:
        with _install_lock:
            if _client is None:
                _client = Client(Path(__file__).with_name("ft_diagnostics_policy.json"),
                    home=home or os.environ.get("FILETRUST_DIAGNOSTICS_HOME"))
            _client.install_hooks(root)
        return _client
    except Exception:
        return None


def capture_current(exc=None, **options):
    client = start()
    if client is not None:
        return client.capture(exc if exc is not None else sys.exc_info()[1], **options)
    return None


def step(operation, status):
    client = start()
    if client is not None:
        client.step(operation, status)


def cli(arguments=None):
    parser = argparse.ArgumentParser(description="Preview/export FileTrust diagnostics; send only an explicitly approved report.")
    parser.add_argument("--home", type=Path, default=None, help="Application or node state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    create = sub.add_parser("create"); create.add_argument("--operation", default="startup")
    create.add_argument("--test", action="store_true", help="Mark a synthetic connection test distinctly")
    for name in ("preview", "export", "send"):
        command = sub.add_parser(name); command.add_argument("report_id")
        if name == "export": command.add_argument("destination", type=Path)
        if name == "send": command.add_argument("--approve-sha256", help="Explicit approval of the preview's exact SHA-256")
    args = parser.parse_args(arguments)
    try:
        client = Client(Path(__file__).with_name("ft_diagnostics_policy.json"), args.home)
        if args.command == "list":
            for ident in client.drafts(): print(ident)
        elif args.command == "create":
            ident = client.capture(operation=args.operation, error_code="FT_DIAGNOSTIC_TEST" if args.test else "FT_OPERATION_FAILED", deduplicate=False)
            if ident is None: raise DiagnosticError("Could not create a private local draft.")
            print(ident)
        else:
            preview = client.preview(args.report_id)
            if args.command == "export": client.export(preview, args.destination)
            else:
                print(preview.text); print("SHA-256:", preview.sha256)
                if args.command == "send":
                    confirmed = args.approve_sha256
                    if confirmed is None:
                        if not sys.stdin.isatty(): raise DiagnosticError("Preview first and supply --approve-sha256 explicitly.")
                        print("This report will be sent through Cloudflare to Sentry. Connection metadata is visible to providers.")
                        if input("Type SEND to submit this exact report: ") != "SEND": return 0
                        confirmed = preview.sha256
                    receipt = client.send(approve(preview, confirmed))
                    print("Accepted:", receipt["event_id"])
        return 0
    except DiagnosticError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print("Diagnostics could not complete. No unapproved report was sent; check the command, report and private storage.", file=sys.stderr)
        return 1


def show_dialog(root):
    from tkinter import filedialog, messagebox, ttk
    import tkinter as tk
    client = start(root=root)
    if client is None:
        messagebox.showerror("Report a problem", "Private diagnostic storage is unavailable.", parent=root)
        return
    window = tk.Toplevel(root); window.title("Report a problem"); window.geometry("760x600")
    tk.Label(window, text="Review the report before sending. Raw logs, file contents and account details are excluded.", wraplength=720).pack(padx=16, pady=10)
    tk.Label(window, text="Sent through FileTrust and Cloudflare to Sentry. Providers can see connection metadata.", wraplength=720).pack(padx=16)
    selector = ttk.Combobox(window, state="readonly", values=client.drafts(), width=50); selector.pack(pady=8)
    operation = ttk.Combobox(window, state="readonly", values=client.operations); operation.set("startup"); operation.pack()
    text = tk.Text(window, wrap="none"); text.pack(fill="both", expand=True, padx=16, pady=8)
    notice = "Nothing is sent until you select Send this report."
    if client.temporary_storage:
        notice = "Drafts use private temporary storage. Export to keep a copy. " + notice
    status = tk.StringVar(value=notice)
    tk.Label(window, textvariable=status, wraplength=720).pack()
    current = {"preview": None, "busy": False}
    def display(*_):
        try: current["preview"] = client.preview(selector.get())
        except Exception: current["preview"] = None
        text.configure(state="normal"); text.delete("1.0", "end")
        if current["preview"] is not None: text.insert("end", current["preview"].text)
        text.configure(state="disabled")
    def create():
        if current["busy"]: return
        ident = client.capture(operation=operation.get(), error_code="FT_OPERATION_FAILED", deduplicate=False)
        selector.configure(values=client.drafts())
        if ident: selector.set(ident); display()
        else: status.set("Could not create a private local draft.")
    def export():
        preview = current["preview"]
        if preview is None: return
        path = filedialog.asksaveasfilename(parent=window, defaultextension=".json", initialfile="filetrust-report.json")
        if path:
            try: client.export(preview, path); status.set("Report exported locally.")
            except Exception: status.set("Could not export the report.")
    def send():
        preview = current["preview"]
        if preview is None or current["busy"]: return
        approval = approve(preview, preview.sha256)
        current["busy"] = True; send_button.configure(state="disabled"); status.set("Sending the displayed report…")
        def work():
            try:
                receipt = client.send(approval); result = "Report accepted. Reference: " + receipt["event_id"]
            except DiagnosticError as error: result = str(error)
            except Exception: result = "Delivery could not be confirmed. The local draft is retained."
            def done():
                if window.winfo_exists():
                    current["busy"] = False; send_button.configure(state="normal"); status.set(result)
            try: root.after(0, done)
            except Exception: pass
        threading.Thread(target=work, daemon=True, name="diagnostic-send").start()
    buttons = tk.Frame(window); buttons.pack(pady=10)
    tk.Button(buttons, text="New report", command=create).pack(side="left", padx=6)
    tk.Button(buttons, text="Export", command=export).pack(side="left", padx=6)
    send_button = tk.Button(buttons, text="Send this report", command=send); send_button.pack(side="left", padx=6)
    selector.bind("<<ComboboxSelected>>", display)
    if selector["values"]: selector.current(0); display()
    else: create()
    return window


def attach_menu(root):
    """Append to an existing menu instead of replacing Updates or app controls."""
    import tkinter as tk
    if root is None or not hasattr(root, "tk") or getattr(root, "_ft_diagnostics_menu", False):
        return
    try:
        start(root=root)
        name = root.cget("menu")
        menu = root.nametowidget(name) if name else tk.Menu(root, tearoff=False)
        menu.add_command(label="Report a problem", command=lambda: show_dialog(root))
        if not name: root.configure(menu=menu)
        root._ft_diagnostics_menu = True
    except (tk.TclError, KeyError, AttributeError, TypeError):
        return
