"""Signed manifests, bounded resumable downloads, and strict ZIP extraction."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests
from vk_http import session as http_session
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPOSITORY = "FileTrust/VaultKeeper"
TAG = "vaultkeeper-recovery-2026-10-29.1"
MAX_METADATA = 4 * 1024 * 1024


def digest(path, progress=None):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
            if progress is not None:progress(len(block))
    return h.hexdigest()


def verify_manifest(raw: bytes, signature: bytes, public_key: Path) -> dict:
    if len(raw) > MAX_METADATA: raise ValueError("Manifest too large")
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key.read_text().strip(), validate=True))
    key.verify(base64.b64decode(signature.strip(), validate=True), raw)
    data=json.loads(raw)
    if data.get("schema")!=1 or data.get("product")!="vaultkeeper" or data.get("circuit_version")!="partition-w3-commitment-v1": raise ValueError("Unsupported VK artifact manifest")
    if not isinstance(data.get("bundles"),list) or not isinstance(data.get("networks"),dict): raise ValueError("Incomplete release metadata")
    origin = data.get("artifact_release")
    if origin is not None and (not isinstance(origin, str) or
            not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", origin)):
        raise ValueError("Invalid signed artifact release reference")
    seen=set()
    for bundle in data["bundles"]:
        name=bundle["id"]
        if name in seen or name not in {"partition-128","partition-256","partition-512","partition-1024","runtime-linux-x86_64"}: raise ValueError("Invalid or duplicate VK bundle")
        seen.add(name)
        if bundle["asset"]!=name+".zip" or bundle.get("url"): raise ValueError("Unexpected bundle location")
        expected={"vaultmesh","storageproof-prover","partition_prover_wrapper.sh","prover_wrapper.sh","prover_priority.sh"} if name.startswith("runtime-") else {"storageproof_partition.r1cs","storageproof_partition.pk","storageproof_partition.vk","storageproof_partition.params.json","profile_config.json"}
        if set(bundle["files"])!=expected: raise ValueError("Unexpected bundle contents")
        for row in [bundle,*bundle["files"].values()]:
            if type(row["size"]) is not int or not 0 < row["size"] < 2*1024**3 or not re.fullmatch(r"[a-f0-9]{64}",row["sha256"]): raise ValueError("Invalid signed artifact size/digest")
        if name.startswith("partition-"):
            size=int(name.split("-")[1]);params=bundle["params"]
            if bundle["block_size"]!=size or params["zk_block_size"]!=size or params["zk_tree_depth"]!={128:28,256:27,512:26,1024:25}[size] or params["partition_circuit_version"]!=data["circuit_version"] or params["partition_sectors"]!=16 or params["storageproof_max_challenges"]!=4: raise ValueError("Profile dimensions mismatch")
    if seen != {"partition-128","partition-256","partition-512","partition-1024","runtime-linux-x86_64"}: raise ValueError("Incomplete VK profile release")
    return data


class GitHubRelease:
    def __init__(self, repository=REPOSITORY, tag=TAG):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or not re.fullmatch(r"[\w.-]+", tag):
            raise ValueError("Invalid release location")
        self.session = http_session()
        self.repository = repository
        self.artifact_release = None
        self._artifact_assets = None
        self.session.headers["User-Agent"] = "FileTrust-Vaultkeeper/1"
        self.token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not self.token and shutil.which("gh"):
            result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
            if result.returncode == 0:
                self.token = result.stdout.strip()
        try:
            metadata = self.small(f"https://api.github.com/repos/{repository}/releases/tags/{tag}", metadata=True)
            release = json.loads(metadata)
        except RuntimeError:
            if not self.token:
                raise
            # GitHub omits draft releases from the tag endpoint. Authorized
            # maintainers can still test them through the release listing.
            listing = json.loads(self.small(f"https://api.github.com/repos/{repository}/releases?per_page=100", metadata=True))
            release = next((row for row in listing if row["tag_name"] == tag), None)
            if not release:
                raise RuntimeError("Release unavailable for this GitHub account") from None
        self.assets = {row["name"]: row["url"] for row in release["assets"]}

    def response(self, url, **kwargs):
        if urlparse(url).scheme != "https" or urlparse(url).hostname != "api.github.com":
            raise ValueError("Unexpected release API host")
        headers = dict(kwargs.pop("headers", {}))
        if self.token and urlparse(url).hostname == "api.github.com":
            headers["Authorization"] = "Bearer " + self.token
        # requests strips Authorization when following redirects to the asset CDN.
        response = self.session.get(url, headers=headers, stream=True, timeout=(20, 60), **kwargs)
        if response.status_code == 401 and "Authorization" in headers:
            # A revoked developer login must not block a public download.
            response.close()
            self.token = None
            headers.pop("Authorization")
            response = self.session.get(url, headers=headers, stream=True, timeout=(20, 60), **kwargs)
        if response.status_code in (401, 404):
            response.close()
            raise RuntimeError("Release unavailable. For private testing, run gh auth login first")
        response.raise_for_status()
        if urlparse(response.url).scheme != "https":
            response.close()
            raise RuntimeError("Insecure asset redirect")
        return response

    def small(self, url, metadata=False):
        with self.response(url, headers={"Accept": "application/vnd.github+json" if metadata else "application/octet-stream"}) as response:
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > MAX_METADATA:
                    raise ValueError("Release metadata too large")
            return bytes(body)

    def manifest(self, public_key):
        raw = self.small(self.assets["manifest.json"])
        signature = self.small(self.assets["manifest.sig"])
        manifest = verify_manifest(raw, signature, public_key)
        self.artifact_release = manifest.get("artifact_release")
        return manifest, raw, signature

    def download(self, bundle, cache, progress=print):
        assets = self.assets
        if bundle["asset"] not in assets and self.artifact_release:
            if self._artifact_assets is None:
                self._artifact_assets = GitHubRelease(repository=self.repository,
                    tag=self.artifact_release).assets
            assets = self._artifact_assets
        url = assets[bundle["asset"]]
        return download(self, url, bundle, cache, progress)


def download(remote, url, bundle, cache: Path, progress=print):
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (bundle["sha256"] + ".zip")
    partial = target.with_suffix(".part")
    if target.exists() and target.stat().st_size == bundle["size"] and digest(target) == bundle["sha256"]:
        progress("Cached bundle verified")
        return target
    target.unlink(missing_ok=True)
    for attempt in range(4):
        offset = partial.stat().st_size if partial.exists() else 0
        if offset > bundle["size"]:
            partial.unlink()
            offset = 0
        try:
            if offset < bundle["size"]:
                headers = {"Accept": "application/octet-stream", "Accept-Encoding": "identity"}
                if offset:
                    headers["Range"] = f"bytes={offset}-"
                with remote.response(url, headers=headers) as response:
                    if response.status_code == 206:
                        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                        if not match or int(match[1]) != offset or int(match[3]) != bundle["size"]:
                            raise ValueError("Invalid download resume response")
                    elif response.status_code == 200:
                        offset = 0  # Server ignored Range: safely start over.
                    else:
                        raise ValueError("Unexpected download response")
                    last_percent = -1
                    with partial.open("ab" if offset else "wb") as output:
                        for chunk in response.iter_content(1024 * 1024):
                            offset += len(chunk)
                            if offset > bundle["size"]:
                                raise ValueError("Download exceeds signed size")
                            output.write(chunk)
                            percent = offset * 100 // bundle["size"]
                            if percent != last_percent:
                                progress(f"[{'#' * (percent // 5):<20}] {percent}% ({offset}/{bundle['size']} bytes)")
                                last_percent = percent
            if partial.stat().st_size != bundle["size"]:
                raise requests.ConnectionError("Download interrupted")
            if digest(partial) != bundle["sha256"]:
                partial.unlink()
                raise ValueError("Bundle checksum failed; rerun to download a clean copy")
            os.replace(partial, target)
            return target
        except (requests.RequestException, OSError):
            if attempt == 3:
                raise RuntimeError("Download interrupted; rerun installation to resume") from None
            time.sleep(min(2**attempt, 8))
    raise RuntimeError("Download failed")


def destination(root, bundle):
    return root / bundle["sha256"]


def installed(path, bundle, progress=None):
    if not path.is_dir():return False
    total=sum(row['size'] for row in bundle['files'].values());done=0;last=-1
    def advance(size):
        nonlocal done,last
        done+=size;percent=done*100//total if total else 100
        if progress is not None and (percent//10!=last or done==total):
            progress(f'Checking proof files: {min(percent,100)}%')
            last=percent//10
    if progress is not None:progress('Checking proof files: 0%');last=0
    for name,row in bundle['files'].items():
        file=path/name
        if not file.is_file() or file.is_symlink() or file.stat().st_size!=row['size']:return False
        if digest(file,advance)!=row['sha256']:return False
    return True


def extract(archive, target, bundle):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".artifact-", dir=target.parent) as temporary:
        staging = Path(temporary) / "ready"
        staging.mkdir()
        extract_zip(archive, staging, bundle)
        if target.exists():
            # Verified immutable artifact paths; no private state ever lives here.
            old = Path(temporary) / "old"
            os.replace(target, old)
            try:
                os.replace(staging, target)
            except BaseException:
                os.replace(old, target)
                raise
        else:
            os.replace(staging, target)


def extract_zip(archive, staging, bundle):
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) != len(bundle["files"]) or {e.filename for e in entries} != set(bundle["files"]):
            raise ValueError("ZIP contains unexpected files")
        for entry in entries:
            row = bundle["files"][entry.filename]
            mode = entry.external_attr >> 16
            if entry.file_size != row["size"] or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError("ZIP file type or size mismatch")
            with z.open(entry) as source, (staging / entry.filename).open("wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if digest(staging / entry.filename) != row["sha256"]:
                raise ValueError("Extracted artifact checksum failed")
            (staging / entry.filename).chmod(0o755 if entry.filename in {"vaultmesh","storageproof-prover"} or entry.filename.endswith(".sh") else 0o644)
