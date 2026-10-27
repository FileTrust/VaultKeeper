"""Prepare authenticated code updates; replace only named code while offline.

No arbitrary release commands, data migrations, private input or file glob
deletion is accepted. Existing state stays in its original location.
"""
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile

from ft_update_bootstrap import CONTROL, atomic_bytes, code_path, initialize, recover, write_json

MAX_EXPANDED = 200 * 1024 * 1024


def ensure_no_legacy_process(root, process_root=Path("/proc")):
    """Old installs may have no run lock; inspect paths without logging argv."""
    expected = {"DO.py", "REQ.py", "reporter.py", "guardian.py", "vaultmesh",
                "guardians.py", "guardian_manager.py", "start.py", "g_dkg.py", "g_pre.py", "g_share_proof.py", "run_filetrust_guardians.py", "vks.py", "vk_manager.py", "vaultkeeper.py", "storageproof-prover", "run_filetrust_vault_keepers.py"}
    if not process_root.is_dir():
        raise ValueError("Safe process checks require Linux /proc")
    for process in process_root.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            args = (process / "cmdline").read_bytes()[:16384].split(b"\0")
            for raw in args:
                candidate = os.fsdecode(raw)
                if Path(candidate).name not in expected:
                    continue
                path = Path(candidate)
                if not path.is_absolute():
                    path = (process / "cwd").resolve() / path
                resolved = path.resolve()
                if ((resolved.parent == root and path.name in expected)
                        or (root.name in {"G","VK"} and resolved.is_relative_to(root))
                        or (root.name == "G" and resolved == root.parents[1] / "run_filetrust_guardians.py")
                        or (root.name == "VK" and resolved == root.parents[1] / "run_filetrust_vault_keepers.py")
                        or (path.name == "vaultmesh" and resolved.is_relative_to(root))):
                    raise ValueError("An older app process still uses this folder; finish its work and close it before updating")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue


def checksum(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_client(root):
    product = json.loads((root / "update-source.json").read_text())["product"]
    module = importlib.import_module("core.ft_updates" if product in ("do", "req", "vk", "vaultkeeper") else "ft_updates")
    return module.Client(root)


def independent_installation(root):
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    except FileNotFoundError:
        return
    if result.returncode == 0 and Path(result.stdout.strip()).resolve() != root:
        top = Path(result.stdout.strip()).resolve()
        settings_path = root / "update-source.json"
        settings = json.loads(settings_path.read_text()) if settings_path.is_file() else {}
        if (root == top / "App/G" and settings.get("product") == "g") or (root == top / "App/VK" and settings.get("product") == "vk"):
            remote = subprocess.run(["git", "-C", str(top), "remote", "get-url", "origin"], capture_output=True, text=True)
            repository = settings.get("repository", "")
            if remote.returncode == 0 and repository and remote.stdout.strip().removesuffix(".git") in {
                "https://github.com/" + repository, "git@github.com:" + repository,
            }:
                return
        raise ValueError("Use an independent application installation; this folder belongs to a larger repository")


@contextmanager
def update_lock(root):
    control = initialize(root)
    with (control / "update.lock").open("rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another update operation is already running") from None
        yield control


def unpack(package, destination, product, expected_version, bootstrap_hash):
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "software-manifest.json" not in names:
            raise ValueError("Invalid package file table")
        if len(names) > 2000 or sum(item.file_size for item in archive.infolist()) > MAX_EXPANDED:
            raise ValueError("Expanded package exceeds limits")
        if archive.getinfo("software-manifest.json").file_size > 1024 * 1024:
            raise ValueError("Oversized package manifest")
        manifest = json.loads(archive.read("software-manifest.json"))
        if manifest.get("schema") != 1 or manifest.get("data_schema") != 1 or manifest.get("product") != product or manifest.get("version") != expected_version:
            raise ValueError("Incompatible application or data schema")
        if manifest.get("bootstrap_sha256") != bootstrap_hash:
            raise ValueError("This release needs a reviewed bootstrap upgrade")
        files = manifest["files"]
        if not isinstance(files, dict) or set(names) != {"software-manifest.json", *files}:
            raise ValueError("Package members differ from manifest")
        if "VERSION" not in files:
            raise ValueError("Package has no application version")
        for relative, expected in files.items():
            target = code_path(destination, relative)
            member = archive.getinfo(relative)
            mode = member.external_attr >> 16
            if member.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError("Only regular code files are accepted")
            if member.file_size != expected["size"] or expected["mode"] not in (0o644, 0o755):
                raise ValueError("Invalid package file metadata")
            data = archive.read(relative)
            if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                raise ValueError("Code file checksum mismatch")
            if target.suffix == ".py":
                compile(data, relative, "exec")
            atomic_bytes(target, data, expected["mode"])
        if (destination / "VERSION").read_text().strip() != expected_version:
            raise ValueError("Package version file mismatch")
        return manifest


def prepare(root, install_dependencies=True):
    root = Path(root).resolve()
    independent_installation(root)
    if sys.platform != "linux":
        raise ValueError("Update installation currently supports Linux only")
    with update_lock(root) as control:
        client = load_client(root)
        result = client._verified_check()
        if result["state"] != "available":
            raise ValueError("No newer verified application release")
        descriptor = client.verified_descriptor
        target_name = descriptor.get("package_target", "")
        if not isinstance(target_name, str) or not re.fullmatch(r"code-[a-z]+-\d+\.\d+\.\d+\.zip", target_name):
            raise ValueError("This release does not provide a supported code package")
        target = client.verified_updater.get_targetinfo(target_name)
        if target is None or not 0 < target.length <= 64 * 1024 * 1024:
            raise ValueError("Package is not an authenticated target")
        if shutil.disk_usage(root).free < 1024**3:
            raise ValueError("Allow at least 1 GiB free for staging, dependencies and recovery")
        generation = str(int(target.hashes["sha256"][:24], 16))
        staging = control / "staging" / generation
        staging.mkdir(parents=True, exist_ok=True)
        package = staging / "package.zip"
        print("[1/3] Downloading and verifying the signed code package", flush=True)
        if not client.verified_updater.find_cached_target(target, filepath=str(package)):
            client.verified_updater.download_target(target, filepath=str(package))
        else:
            print("Verified code archive already downloaded", flush=True)
        payload = staging / "code"
        bootstrap_hash = checksum(root / "ft_update_bootstrap.py")
        manifest = unpack(package, payload, client.product, descriptor["version"], bootstrap_hash)
        baseline = manifest.get("supported_bases", {}).get(client.current)
        if not isinstance(baseline, dict) or not baseline:
            raise ValueError("This release needs an intermediate/manual upgrade from your version")
        for relative, expected_hash in baseline.items():
            target_path = code_path(root, relative)
            if not target_path.is_file() or checksum(target_path) != expected_hash:
                raise ValueError("Local code differs from the supported baseline; keep your changes and use a manual upgrade")
        print("[2/3] Preparing a separate Python environment", flush=True)
        environment = control / "environments" / generation
        if install_dependencies:
            clean_env = {k: v for k, v in os.environ.items() if not k.startswith(("FILETRUST_", "PIP_"))
                         and k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")
                         and not any(word in k.upper() for word in ("TOKEN", "PASSWORD", "PRIVATE", "SECRET", "CREDENTIAL"))}
            subprocess.run([sys.executable, "-I", "-m", "venv", str(environment)], env=clean_env, check=True)
            python = environment / "bin/python"
            subprocess.run([str(python), "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "-r", str(payload / "requirements.txt")], env=clean_env, check=True)
            subprocess.run([str(python), "-I", "-m", "pip", "check"], env=clean_env, check=True)
        record = {"schema": 1, "generation": generation, "product": client.product, "from_version": client.current,
                  "version": descriptor["version"], "manifest": manifest, "environment_ready": install_dependencies,
                  "package_sha256": checksum(package), "bootstrap_sha256": bootstrap_hash}
        write_json(control / "prepared.json", record)
        print("[3/3] Update prepared. The running app and all user data are unchanged.", flush=True)
        return record


def apply(root, _locked=False):
    root = Path(root).resolve()
    independent_installation(root)
    with (nullcontext(root / CONTROL) if _locked else update_lock(root)) as control:
        record = json.loads((control / "prepared.json").read_text())
        if record.get("product") == "vaultkeeper":
            from update_artifacts import assert_prepared_artifacts
            assert_prepared_artifacts(root)
        if not record["environment_ready"]:
            raise ValueError("Dependency preparation is incomplete")
        if checksum(root / "ft_update_bootstrap.py") != record["bootstrap_sha256"]:
            raise ValueError("Bootstrap changed after preparation")
        if (root / "VERSION").read_text().strip() != record["from_version"]:
            raise ValueError("Installed version changed; prepare again")
        client = load_client(root)
        client._verified_check()
        if client.verified_descriptor["version"] != record["version"]:
            raise ValueError("Release information changed; prepare again")
        with (control / "run.lock").open("rb") as run_lock:
            try:
                fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("The application is running. Wait for work to finish and close/stop it before applying.") from None
            ensure_no_legacy_process(root)
            generation = record["generation"]
            if not generation.isdigit():
                raise ValueError("Invalid prepared generation")
            staging = control / "staging" / generation
            package = staging / "package.zip"
            if checksum(package) != record["package_sha256"]:
                raise ValueError("Prepared package changed")
            target = client.verified_updater.get_targetinfo(client.verified_descriptor["package_target"])
            if target is None:
                raise ValueError("Prepared release is no longer an approved target")
            with package.open("rb") as data:
                target.verify_length_and_hashes(data)
            # Re-extract the checked archive: edits to staging must not enter the installation.
            payload = staging / "apply-code"
            if payload.exists():
                shutil.rmtree(payload)
            manifest = unpack(package, payload, record["product"], record["version"], record["bootstrap_sha256"])
            if manifest != record["manifest"]:
                raise ValueError("Prepared manifest changed")
            for relative, expected_hash in manifest["supported_bases"][record["from_version"]].items():
                existing = code_path(root, relative)
                if not existing.is_file() or checksum(existing) != expected_hash:
                    raise ValueError("Code changed after preparation; nothing installed")
            transaction = str(time.time_ns())
            backup = control / "backups" / transaction
            backup.mkdir(parents=True, exist_ok=False)
            entries = []
            baseline = manifest["supported_bases"][record["from_version"]]
            removed = set(baseline) - set(manifest["files"])
            for relative in sorted(set(manifest["files"]) | removed):
                target = code_path(root, relative)
                entry = {"path": relative, "previous_hash": None, "previous_mode": 0o644, "delete": relative in removed}
                if target.exists():
                    if relative not in baseline:
                        raise ValueError("A new code file would overwrite an existing user file")
                    if not target.is_file():
                        raise ValueError("Code target is not a regular file")
                    entry.update(previous_hash=checksum(target), previous_mode=target.stat().st_mode & 0o777)
                    atomic_bytes(backup / relative, target.read_bytes(), entry["previous_mode"])
                entries.append(entry)
            old_env = root / ".venv"
            if old_env.is_symlink():
                environment = {"kind": "symlink", "target": os.readlink(old_env)}
            elif old_env.is_dir():
                environment = {"kind": "directory"}
            elif old_env.exists():
                raise ValueError("Unexpected installed Python environment")
            else:
                environment = {"kind": "absent"}
            journal = {"schema": 1, "phase": "applying", "generation": transaction, "files": entries,
                       "environment": environment, "from_version": record["from_version"], "version": record["version"]}
            write_json(control / "journal.json", journal)
            try:
                for entry in entries:
                    relative = entry["path"]
                    if entry["delete"]:
                        code_path(root, relative).unlink(missing_ok=True)
                    else:
                        atomic_bytes(code_path(root, relative), (payload / relative).read_bytes(), manifest["files"][relative]["mode"])
                if environment["kind"] == "directory":
                    os.rename(old_env, backup / "environment")
                link = control / "activate-environment"
                link.unlink(missing_ok=True)
                link.symlink_to(control / "environments" / generation)
                os.replace(link, old_env)
                journal["phase"] = "installed"
                write_json(control / "journal.json", journal)
                print("Update installed. Persistent state was not replaced. Start the app and check its status.", flush=True)
            except BaseException:
                recover(root, journal)
                raise
            return journal


def recover_or_rollback(root, rollback=False, _locked=False):
    root = Path(root).resolve()
    with (nullcontext(root / CONTROL) if _locked else update_lock(root)) as control:
        with (control / "run.lock").open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("Stop the application before recovery") from None
            journal = json.loads((control / "journal.json").read_text())
            phases = ("installed", "applying", "recovering") if rollback else ("applying", "recovering")
            if journal["phase"] not in phases:
                raise ValueError("No eligible code update to recover")
            recover(root, journal)
            print("Previous code/environment restored. User data and transaction records were not rolled back.")


def status(root):
    root = Path(root)
    result = {"installed": (root / "VERSION").read_text().strip()}
    for name in ("prepared.json", "journal.json", "service-transaction.json"):
        path = root / CONTROL / name
        if path.exists():
            record = json.loads(path.read_text())
            result[name.removesuffix(".json")] = {key: record[key] for key in
                ("phase", "from_version", "version", "environment_ready", "was_active") if key in record}
    return result
