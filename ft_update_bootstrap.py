"""Standard-library startup lock and interrupted code-update recovery.

This bootstrap is excluded from routine update payloads. Custody files are never
included in its journal. An administrator must recover root-owned installations.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import time

try:
    import fcntl
except ImportError:
    fcntl = None

CONTROL = ".filetrust-updates"
_RUN_LOCKS = []
PROTECTED = {"config.json", "wallet.json", "unlock.key", "keyvault.json", "requester_keys.json",
             "guardian_encryption_key.json", "ft_update_bootstrap.py", "guardians.json", "vk_profiles.json",
             "update-root.json", "update-source.json", "release-key.pub", "installation-selection.json", "app_start.py"}
STATE_PARTS = {".git", ".venv", CONTROL, ".filetrust-activity", "state", "runtime-data", "contracts", "logs", "log", "data", "data_unzipped",
               "pieces", "pid_records", "upload_zips", "transfer_jobs", "keys", "downloads", "artifacts",
               "dkg_local", "pre_local", "dealer_material", "local_gs", "local_vks"}


def code_path(root, relative):
    part = PurePosixPath(relative)
    if not isinstance(relative, str) or "\\" in relative or part.is_absolute() or not part.parts or part.as_posix() != relative or any(p in (".", "..") for p in part.parts):
        raise ValueError("Invalid code path")
    if part.name.lower() in {name.lower() for name in PROTECTED} or any(p.lower() in STATE_PARTS or p.startswith(".") for p in part.parts):
        raise ValueError("Update cannot replace persistent state or bootstrap")
    if part.suffix.lower() in {".key", ".env", ".jsonl", ".log", ".db", ".sqlite", ".mmdb"}:
        raise ValueError("Update cannot replace private or generated files")
    target = Path(root).joinpath(*part.parts)
    if any(p.is_symlink() for p in (target, *list(target.parents)[:len(part.parts) - 1])):
        raise ValueError("Code paths cannot follow symbolic links")
    return target


def atomic_bytes(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_json(path, value):
    atomic_bytes(path, json.dumps(value, sort_keys=True).encode())


def initialize(root):
    control = Path(root) / CONTROL
    if control.is_symlink():
        raise ValueError("Update control directory cannot be a symbolic link")
    control.mkdir(mode=0o755, exist_ok=True)
    for name in ("run.lock", "update.lock"):
        path = control / name
        fd = os.open(path, os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW, 0o644)
        os.close(fd)
    return control


def recover(root, journal):
    root = Path(root)
    control = root / CONTROL
    generation = journal["generation"]
    if not isinstance(generation, str) or not generation.isdigit():
        raise ValueError("Invalid recovery generation")
    backup = control / "backups" / generation
    for entry in reversed(journal["files"]):
        target = code_path(root, entry["path"])
        saved = backup / entry["path"]
        if entry["previous_hash"] is None:
            target.unlink(missing_ok=True)
        else:
            data = saved.read_bytes()
            if hashlib.sha256(data).hexdigest() != entry["previous_hash"]:
                raise ValueError("Recovery backup changed; refusing unsafe recovery")
            atomic_bytes(target, data, entry["previous_mode"])
    env = journal.get("environment")
    if env:
        path = root / ".venv"
        if env["kind"] == "directory":
            saved = control / "backups" / generation / "environment"
            if saved.exists():
                if path.is_symlink():
                    path.unlink()
                if path.exists():
                    raise ValueError("Unexpected environment; manual recovery required")
                os.rename(saved, path)
        elif env["kind"] == "symlink":
            if path.exists() and not path.is_symlink():
                raise ValueError("Unexpected environment; manual recovery required")
            temporary = control / "restore-environment"
            temporary.unlink(missing_ok=True)
            temporary.symlink_to(env["target"])
            os.replace(temporary, path)
        elif env["kind"] == "absent" and path.is_symlink():
            path.unlink()
    journal["phase"] = "rolled-back"
    write_json(control / "journal.json", journal)


def enter(root):
    """Hold a shared startup lock for this process; recover before imports."""
    root = Path(root).resolve()
    if fcntl is None:
        return
    if os.environ.get("FILETRUST_UPDATE_PREFLIGHT") == "1":
        return
    control = initialize(root)
    inherited = os.environ.get("FILETRUST_RUN_LOCK_FD", "")
    if inherited.isdigit():
        try:
            fd = int(inherited)
            if os.fstat(fd).st_ino == (control / "run.lock").stat().st_ino and os.fstat(fd).st_dev == (control / "run.lock").stat().st_dev:
                _RUN_LOCKS.append(os.fdopen(os.dup(fd), "rb"))
                return
        except OSError:
            pass
    lock = (control / "run.lock").open("rb")
    fcntl.flock(lock, fcntl.LOCK_SH)
    journal_path = control / "journal.json"
    if journal_path.exists():
        journal = json.loads(journal_path.read_text())
        if journal["phase"] in ("applying", "recovering"):
            fcntl.flock(lock, fcntl.LOCK_UN)
            fcntl.flock(lock, fcntl.LOCK_EX)
            journal = json.loads(journal_path.read_text())
            if journal["phase"] in ("applying", "recovering"):
                recover(root, journal)
    fcntl.flock(lock, fcntl.LOCK_SH)
    os.set_inheritable(lock.fileno(), True)
    os.environ["FILETRUST_RUN_LOCK_FD"] = str(lock.fileno())
    _RUN_LOCKS.append(lock)


def child_lock_options():
    """Keep an update blocked while a transfer/worker child still runs."""
    descriptors = []
    if os.name == "posix":
        for name in ("FILETRUST_RUN_LOCK_FD", "FILETRUST_GUARDIAN_STATE_LOCK_FD"):
            inherited = os.environ.get(name, "")
            if inherited.isdigit():
                try:
                    fd = int(inherited)
                    os.fstat(fd)
                    descriptors.append(fd)
                except OSError:
                    pass
    return {"pass_fds": tuple(sorted(set(descriptors)))} if descriptors else {}


def ready(code_root, state_root=None):
    """Publish only public startup status; never include wallet/configuration."""
    try:
        code_root = Path(code_root)
        state_root = Path(state_root) if state_root else code_root
        write_json(state_root / ".filetrust-node-health.json", {
            "pid": os.getpid(), "version": (code_root / "VERSION").read_text().strip(),
            "ready_at": time.time(),
        })
        return True
    except OSError:
        return False


if __name__ == "__main__":
    import sys
    root = Path(__file__).resolve().parent
    initialize(root)
    if sys.argv[1:] == ["--installer-check"]:
        from ft_update_install import ensure_no_legacy_process
        try:
            ensure_no_legacy_process(root)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(1)
    elif sys.argv[1:] in (["--recover"], ["--rollback"]):
        control = root / CONTROL
        with (control / "update.lock").open("rb") as update_lock, (control / "run.lock").open("rb") as run_lock:
            try:
                fcntl.flock(update_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SystemExit("Stop the app and wait for other update operations first")
            journal = json.loads((control / "journal.json").read_text())
            allowed = ("applying", "recovering", "installed") if sys.argv[1] == "--rollback" else ("applying", "recovering")
            if journal["phase"] not in allowed:
                raise SystemExit("No eligible update to recover")
            recover(root, journal)
            print("Previous code/environment restored; persistent data was not replaced.")
