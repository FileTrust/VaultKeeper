"""Verified release discovery. This module never installs or executes updates."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlparse

try:
    import fcntl
except ImportError:
    fcntl = None

MAX_BYTES = 1024 * 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
INTERVAL = 24 * 3600


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise ValueError("Unsupported application version")
    return tuple(int(part) for part in value.split("."))


def validate_source(source):
    if not isinstance(source, dict):
        raise ValueError("Invalid update source")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source.get("repository", "")):
        raise ValueError("Invalid update repository")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", source.get("metadata_tag", "")):
        raise ValueError("Invalid metadata tag")
    return {key: source[key] for key in ("repository", "metadata_tag")}


def github_token():
    # Tokens never enter state, logs, URLs or subprocess arguments.
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credential_dir:
        credential = Path(credential_dir) / "github-token"
        if credential.is_file():
            return credential.read_text().strip()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    try:
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


class GitHubAssets:
    def __init__(self, source):
        self.source = validate_source(source)
        self.token = github_token()
        self.assets = None

    def read(self, url, accept, max_bytes=MAX_BYTES):
        import requests
        for _ in range(4):
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in {
                "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
            } or parsed.username or parsed.password:
                raise ValueError("Unapproved update download host")
            headers = {"Accept": accept, "User-Agent": "FileTrust-update-check/1"}
            if self.token and parsed.hostname == "api.github.com":
                headers["Authorization"] = "Bearer " + self.token
            with requests.get(url, headers=headers, timeout=(5, 15), stream=True, allow_redirects=False) as response:
                if response.status_code == 401 and self.token and parsed.hostname == "api.github.com":
                    # A revoked private-testing token must not block later public releases.
                    self.token = None
                    continue
                if response.status_code in (301, 302, 303, 307, 308):
                    url = response.headers.get("Location", "")
                    continue
                if response.status_code != 200:
                    from tuf.api.exceptions import DownloadHTTPError
                    raise DownloadHTTPError("Update service unavailable; private releases require GitHub access", response.status_code)
                data = bytearray()
                for chunk in response.iter_content(65536):
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise ValueError("Update response too large")
                return bytes(data)
        raise ValueError("Too many update redirects")

    def fetch(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.(json|zip)", name):
            raise ValueError("Invalid update metadata name")
        if self.assets is None:
            url = f"https://api.github.com/repos/{self.source['repository']}/releases/tags/{self.source['metadata_tag']}"
            release = json.loads(self.read(url, "application/vnd.github+json"))
            self.assets = {asset["name"]: asset["id"] for asset in release["assets"]}
        asset_id = self.assets.get(name)
        if type(asset_id) is not int:
            from tuf.api.exceptions import DownloadHTTPError
            raise DownloadHTTPError("Update metadata is not published", 404)
        url = f"https://api.github.com/repos/{self.source['repository']}/releases/assets/{asset_id}"
        return self.read(url, "application/octet-stream", MAX_PACKAGE_BYTES if name.endswith(".zip") else MAX_BYTES)


class Client:
    def __init__(self, app_dir, state_dir=None):
        self.app_dir = Path(app_dir)
        self.settings = json.loads((self.app_dir / "update-source.json").read_text())
        self.product = self.settings["product"]
        if not re.fullmatch(r"[a-z]+", self.product):
            raise ValueError("Invalid application identity")
        self.current = (self.app_dir / "VERSION").read_text().strip()
        version(self.current)
        if self.settings["channel"] not in ("stable", "testing"):
            raise ValueError("Invalid update channel")
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
        self.state_dir = Path(state_dir) if state_dir else base / "filetrust/updates" / self.product

    def status(self):
        try:
            return json.loads((self.state_dir / "status.json").read_text())
        except FileNotFoundError:
            return {"state": "unchecked", "current": self.current}

    def check(self, force=False):
        if fcntl is None:
            return {"state": "unavailable", "current": self.current, "message": "Managed update checks currently support Linux installations."}
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.state_dir.is_symlink():
            raise ValueError("Update state cannot be a symbolic link")
        self.state_dir.chmod(0o700)
        with (self.state_dir / "check.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return self.status()
            previous = self.status()
            if not force and previous.get("current") == self.current and previous.get("next_check", 0) > time.time():
                return previous
            try:
                result = self._verified_check_unlocked()
                result["next_check"] = time.time() + INTERVAL + random.uniform(0, 3600)
            except Exception as exc:
                # Never log exception text: a transport may include credentials/URLs.
                result = {"state": "unavailable", "message": "Could not verify update information. Check connectivity and GitHub access for private releases.",
                          "error_code": type(exc).__name__,
                          "next_check": time.time() + 3600 + random.uniform(0, 600)}
            result.update(current=self.current, checked_at=time.time())
            atomic_json(self.state_dir / "status.json", result)
            return result

    def _verified_check(self):
        # Installer and maintainer callers need a fresh authenticated result,
        # even before the background checker has ever created its cache.
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.state_dir.is_symlink():
            raise ValueError("Update state cannot be a symbolic link")
        self.state_dir.chmod(0o700)
        with (self.state_dir / "check.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("An update check is already running; retry shortly") from None
            return self._verified_check_unlocked()

    def _verified_check_unlocked(self):
        from tuf.ngclient import Updater
        from tuf.ngclient.config import UpdaterConfig
        from tuf.ngclient.fetcher import FetcherInterface

        source = validate_source(self.settings)
        source_path = self.state_dir / "source.json"
        # A redirect stored here was authenticated as a TUF target on a previous check.
        if source_path.exists():
            source = validate_source(json.loads(source_path.read_text()))
        remote = GitHubAssets(source)

        class Fetcher(FetcherInterface):
            def _fetch(self, url):
                yield remote.fetch(url.rsplit("/", 1)[-1])

        metadata_dir = self.state_dir / "metadata"
        metadata_dir.mkdir(exist_ok=True)
        updater = Updater(str(metadata_dir), "https://updates.invalid/metadata/",
                          target_dir=str(self.state_dir), target_base_url="https://updates.invalid/targets/",
                          fetcher=Fetcher(), bootstrap=(self.app_dir / "update-root.json").read_bytes(),
                          config=UpdaterConfig(root_max_length=MAX_BYTES, timestamp_max_length=MAX_BYTES,
                                               snapshot_max_length=MAX_BYTES, targets_max_length=MAX_BYTES,
                                               max_root_rotations=32, max_delegations=8))
        updater.refresh()
        target = updater.get_targetinfo(f"release-{self.settings['channel']}.json")
        if target is None or target.length > MAX_BYTES:
            raise ValueError("Release descriptor unavailable")
        path = updater.download_target(target, filepath=str(self.state_dir / "verified-release.json"))
        descriptor = json.loads(Path(path).read_text())
        if descriptor.get("schema") != 1 or descriptor.get("product") != self.product or descriptor.get("channel") != self.settings["channel"]:
            raise ValueError("Release identity mismatch")
        newest = descriptor["version"]
        available = version(newest) > version(self.current)
        notes = descriptor.get("notes", "")
        if not isinstance(notes, str) or len(notes) > 4000:
            raise ValueError("Invalid release notes")
        release_repo = validate_source(descriptor["source"])["repository"]
        release_tag = descriptor["release_tag"]
        if not isinstance(release_tag, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", release_tag):
            raise ValueError("Invalid release tag")
        if descriptor.get("next_source"):
            atomic_json(source_path, validate_source(descriptor["next_source"]))
        self.verified_updater = updater
        self.verified_descriptor = descriptor
        return {"state": "available" if available else "current", "latest": newest,
                "installable": isinstance(descriptor.get("package_target"), str),
                "notes": notes, "release_url": f"https://github.com/{release_repo}/releases/tag/{release_tag}"}


def start_watcher(app_dir, log=print, state_dir=None, stop=None, network_home=None):
    stop = stop or threading.Event()

    def work():
        last = None
        while not stop.is_set():
            try:
                result = Client(app_dir, state_dir).check()
                notice = (result["state"], result.get("latest"))
                if notice != last:
                    if result["state"] == "available":
                        log(f"Application update available: {result['current']} -> {result['latest']}. Review {result['release_url']}; installation is manual.")
                    elif result["state"] == "unavailable":
                        log(result["message"])
                    last = notice
            except Exception:
                if last != "unavailable":
                    log("Application update check unavailable; node work continues.")
                    last = "unavailable"
            try:
                from ft_network_config import notify
                product = json.loads((Path(app_dir) / "update-source.json").read_text())["product"]
                if product not in ("do", "req"):
                    home = network_home or (Path(state_dir).parent if state_dir and product in ("guardians", "vaultkeeper") else app_dir)
                    notify(app_dir, home, log)
            except Exception:
                pass  # Failed config checks must not stop code notices or node work.
            stop.wait(300)

    threading.Thread(target=work, daemon=True, name="application-updates").start()
    return stop


def authorize_service(client, user_service=False):
    """Explicit, optional credential setup for private headless release checks."""
    if client.product not in ("guardians", "reporter", "discovery", "vaultkeeper"):
        raise ValueError("Only server apps use service credentials")
    if user_service and client.product in {"guardians","vaultkeeper"}:
        raise ValueError("Guardian uses a system service")
    if not user_service and os.geteuid() != 0:
        raise ValueError("System service authorization requires sudo")
    service = {"guardians": "filetrust-guardian", "reporter": "filetrust-reporter", "discovery": "filetrust-discovery", "vaultkeeper": "filetrust-vaultkeeper"}[client.product]
    base = Path.home() / ".config" if user_service else Path("/etc")
    credential = base / service / "github-token"
    systemd = base / "systemd" / ("user" if user_service else "system")
    dropin = systemd / f"{service}.service.d" / "application-updates.conf"
    for path in (credential, dropin):
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("Credential paths must not contain symbolic links")
        if any(c in str(path) for c in "\r\n\t %\\\""):
            raise ValueError("Unsupported credential path")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        if not sys.stdin.isatty():
            raise ValueError("GitHub access is required; run from a terminal")
        token = getpass.getpass("Read-only GitHub token for private release checks (hidden): ").strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("Invalid GitHub token")
    credential.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    credential.parent.chmod(0o700)
    fd = os.open(credential, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(token)
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text(f"[Service]\nLoadCredential=github-token:{credential}\n")
    subprocess.run(["systemctl", *(["--user"] if user_service else []), "daemon-reload"], check=True)
    print("Private update-check credential saved. It takes effect on the next planned service restart; no restart was performed.")


def cli(app_dir):
    parser = argparse.ArgumentParser(description="Check signed FileTrust application releases; never installs or restarts the app.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Check now (default)")
    group.add_argument("--status", action="store_true", help="Show the last check without network access")
    group.add_argument("--version", action="store_true")
    group.add_argument("--authorize-service", action="store_true", help="Explicitly save GitHub read access as a private systemd credential; does not restart")
    parser.add_argument("--user-service", action="store_true", help="Authorize a Reporter/Discovery user service instead of its system service")
    parser.add_argument("--state-dir", type=Path, help="Use an explicit check-cache directory (for server status)")
    args = parser.parse_args()
    try:
        client = Client(app_dir, args.state_dir)
        if args.authorize_service:
            authorize_service(client, args.user_service)
            return 0
        if args.user_service:
            raise ValueError("--user-service requires --authorize-service")
        if args.version:
            print(client.current)
            return 0
        result = client.status() if args.status else client.check(force=True)
        print(json.dumps(result, indent=2))
        return 1 if result["state"] == "unavailable" else 0
    except Exception:
        print("Update check unavailable. Install the application's requirements and check its update configuration.", file=sys.stderr)
        return 1
