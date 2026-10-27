"""Opt-in service update: graceful stop, offline activation and readiness recovery."""
import json
import os
from pathlib import Path
import subprocess
import time

from ft_update_install import apply, recover_or_rollback, load_client, update_lock
from ft_update_bootstrap import CONTROL, write_json


class Service:
    def __init__(self, root, user=False):
        self.root = Path(root).resolve()
        self.product = json.loads((self.root / "update-source.json").read_text())["product"]
        names = {"guardians": "filetrust-guardian.service", "reporter": "filetrust-reporter.service", "vaultkeeper": "filetrust-vaultkeeper.service"}
        if self.product not in names or (self.product in {"guardians","vaultkeeper"} and user):
            raise ValueError("This application has no supported automatic service-update adapter")
        if not user and os.geteuid() != 0:
            raise ValueError("System service updates require sudo")
        self.name = names[self.product]
        self.command = ["systemctl", *(["--user"] if user else [])]

    def property(self, name):
        return subprocess.check_output([*self.command, "show", self.name, "--property=" + name, "--value"], text=True).strip()

    def check(self):
        if str(self.root) + "/" not in self.property("ExecStart"):
            raise ValueError("Service does not execute this installation")
        if (self.property("TimeoutStopUSec") != "infinity" or self.property("SendSIGKILL") != "no"
                or self.property("KillMode") != "mixed"):
            raise ValueError("Install the graceful-stop service unit before using service updates")
        self.state = Path(self.property("WorkingDirectory"))
        if not self.state.is_absolute():
            raise ValueError("Service state path is invalid")
        self.was_active = self.property("ActiveState") == "active"
        if self.was_active:
            status = self.health()
            if status.get("pid") != int(self.property("MainPID")) or status.get("version") != (self.root / "VERSION").read_text().strip():
                raise ValueError("The running service has not adopted the managed startup protocol; update it manually while idle first")

    def health(self):
        try:
            path = self.state / ".filetrust-node-health.json"
            if path.stat().st_size > 4096:
                return {}
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return {}

    def stop(self, timeout):
        subprocess.run([*self.command, "stop", "--no-block", self.name], check=True)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.property("ActiveState") in ("inactive", "failed"):
                return
            time.sleep(0.5)
        raise ValueError("Service is still finishing its work. Code was not changed; inspect service status before continuing")

    def start_and_wait(self, expected_version, timeout):
        since = time.time()
        subprocess.run([*self.command, "start", self.name], check=True)
        deadline = time.monotonic() + timeout
        stable_since = None
        while time.monotonic() < deadline:
            status = self.health()
            if (self.property("ActiveState") == "active" and status.get("version") == expected_version
                    and status.get("ready_at", 0) >= since and status.get("pid") == int(self.property("MainPID"))):
                stable_since = stable_since or time.monotonic()
                if time.monotonic() - stable_since >= 3:
                    return
            else:
                stable_since = None
            time.sleep(0.5)
        raise ValueError("Updated service did not report readiness")


def apply_service(root, user=False, timeout=300, service_factory=Service):
    with update_lock(Path(root).resolve()):
        return _apply_service(root, user, timeout, service_factory)


def _apply_service(root, user, timeout, service_factory):
    root = Path(root).resolve()
    service = service_factory(root, user)
    service.check()
    currently_active = service.was_active
    before = (root / "VERSION").read_text().strip()
    control = root / CONTROL
    prepared = json.loads((control / "prepared.json").read_text())
    if prepared.get("product") == "vaultkeeper":
        from update_artifacts import assert_prepared_artifacts
        assert_prepared_artifacts(root)
    transaction_path = control / "service-transaction.json"
    pending = json.loads(transaction_path.read_text()) if transaction_path.exists() else None
    if pending:
        if pending["generation"] != prepared["generation"] or pending["user_service"] != user or pending["unit"] != service.name:
            raise ValueError("A different service update is unfinished; inspect upgrade status before continuing")
        service.was_active = pending["was_active"]
        before = pending["from_version"]
        if (root / "VERSION").read_text().strip() == pending["version"]:
            journal = json.loads((control / "journal.json").read_text())
            if journal["phase"] != "installed":
                raise ValueError("Recover the interrupted code update with ft_update_bootstrap.py --recover first")
            if service.was_active:
                # A previous invocation may have died during readiness checks.
                # Repeat the full check and recovery path, including when the
                # new process is already running.
                if currently_active:
                    service.stop(timeout)
                try:
                    service.start_and_wait(pending["version"], timeout)
                except BaseException:
                    service.stop(timeout)
                    recover_or_rollback(root, rollback=True, _locked=True)
                    service.start_and_wait(before, timeout)
                    transaction_path.unlink(missing_ok=True)
                    raise ValueError("Updated service failed readiness; previous code was restored and restarted") from None
            transaction_path.unlink()
            print("Previously installed update resumed; original running state restored.")
            return
    else:
        pending = {"schema": 1, "generation": prepared["generation"], "unit": service.name, "user_service": user,
                   "was_active": service.was_active, "from_version": before, "version": prepared["version"], "phase": "stopping"}
        write_json(transaction_path, pending)
    # Verify connectivity/trust before requesting maintenance of a healthy node.
    load_client(root)._verified_check()
    if service.was_active:
        print("Waiting for the current node work to finish; no force-kill is used.", flush=True)
        service.stop(timeout)
    pending["phase"] = "applying"
    write_json(transaction_path, pending)
    try:
        apply(root, _locked=True)
    except BaseException:
        if service.was_active:
            service.start_and_wait(before, timeout)
        raise
    if not service.was_active:
        transaction_path.unlink(missing_ok=True)
        print("The service was stopped before the update and remains stopped.")
        return
    try:
        pending["phase"] = "starting"
        write_json(transaction_path, pending)
        service.start_and_wait((root / "VERSION").read_text().strip(), timeout)
    except BaseException:
        service.stop(timeout)
        recover_or_rollback(root, rollback=True, _locked=True)
        service.start_and_wait(before, timeout)
        transaction_path.unlink(missing_ok=True)
        raise ValueError("Updated service failed readiness; previous code was restored and restarted") from None
    print("Updated service reported readiness. Existing enablement settings were preserved.")
    transaction_path.unlink(missing_ok=True)


def cancel_service(root, user=False, timeout=300, service_factory=Service):
    root = Path(root).resolve()
    with update_lock(root) as control:
        path = control / "service-transaction.json"
        pending = json.loads(path.read_text())
        service = service_factory(root, user)
        service.check()
        if pending["unit"] != service.name or pending["user_service"] != user:
            raise ValueError("Pending maintenance belongs to another service")
        if (root / "VERSION").read_text().strip() != pending["from_version"]:
            raise ValueError("Code was already installed; recover/roll back code before cancelling")
        if pending["was_active"] and not service.was_active:
            service.stop(timeout)
            service.start_and_wait(pending["from_version"], timeout)
        path.unlink()
        print("Pending maintenance cancelled; previous running state restored without replacing data.")
