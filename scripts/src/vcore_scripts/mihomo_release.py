"""Download the latest official Mihomo release for interop tests without an API."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import os
import platform
import re
import stat
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
import zlib
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from .builds import CORE_DIR

LATEST_VERSION_URL = (
    "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
)
RELEASE_URL = "https://github.com/MetaCubeX/mihomo/releases/download"
SUPPORTED_TARGETS = (
    "darwin-arm64",
    "darwin-amd64",
    "linux-arm64",
    "linux-amd64",
    "windows-arm64",
    "windows-amd64",
)
MAX_VERSION_BYTES = 128
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
TRANSFER_SECONDS = 180


def _target(target: str | None) -> str:
    if target is None:
        system = platform.system().lower()
        machine = platform.machine().lower()
        architecture = {
            "arm64": "arm64",
            "aarch64": "arm64",
            "amd64": "amd64",
            "x86_64": "amd64",
        }.get(machine, machine)
        target = f"{system}-{architecture}"
    if target not in SUPPORTED_TARGETS:
        raise RuntimeError(f"unsupported official mihomo target: {target}")
    return target


def _release_tag(tag: str) -> str:
    if (
        not isinstance(tag, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag) is None
    ):
        raise RuntimeError("invalid official mihomo download tag")
    return tag


def _copy_and_hash(source, output, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + TRANSFER_SECONDS
    # read1 avoids waiting for a complete chunk before checking the deadline.
    read = getattr(source, "read1", source.read)
    while True:
        if time.monotonic() > deadline:
            raise RuntimeError("official mihomo transfer exceeded its time limit")
        chunk = read(min(CHUNK_BYTES, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError("official mihomo payload exceeded its size limit")
        digest.update(chunk)
        output.write(chunk)
    if not total:
        raise RuntimeError("official mihomo payload is empty")
    return digest.hexdigest()


def _https_response(response) -> None:
    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
        raise RuntimeError("official mihomo download redirected outside HTTPS")


def latest_release() -> str:
    """Read the official latest/version.txt asset only to form download filenames."""
    request = urllib.request.Request(
        LATEST_VERSION_URL, headers={"User-Agent": "VCore-interop-scripts"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            _https_response(response)
            contents = io.BytesIO()
            _copy_and_hash(response, contents, MAX_VERSION_BYTES)
        tag = contents.getvalue().decode("utf-8").strip()
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise RuntimeError(
            f"cannot read official mihomo latest version.txt: {error}"
        ) from error
    return _release_tag(tag)


def _asset(tag: str, target: str) -> tuple[str, str]:
    variant = "-v1" if target in {"linux-amd64", "windows-amd64"} else ""
    suffix = "zip" if target.startswith("windows-") else "gz"
    name = f"mihomo-{target}{variant}-{tag}.{suffix}"
    return name, f"{RELEASE_URL}/{tag}/{name}"


@contextmanager
def _payload(archive: Path):
    if archive.suffix == ".gz":
        with gzip.open(archive, "rb") as payload:
            yield payload
        return
    with zipfile.ZipFile(archive) as bundle:
        files = []
        for member in bundle.infolist():
            name = member.filename
            if (
                PurePosixPath(name).is_absolute()
                or ".." in PurePosixPath(name).parts
                or "\\" in name
                or ":" in name
            ):
                raise RuntimeError("unsafe path in official mihomo ZIP")
            if member.is_dir():
                continue
            mode = stat.S_IFMT(member.external_attr >> 16)
            if (
                mode not in {0, stat.S_IFREG}
                or member.flag_bits & 1
                or len(PurePosixPath(name).parts) != 1
                or not name.endswith(".exe")
            ):
                raise RuntimeError("unsafe executable entry in official mihomo ZIP")
            files.append(member)
        if len(files) != 1:
            raise RuntimeError(
                "official mihomo ZIP must contain exactly one executable"
            )
        if not 0 < files[0].file_size <= MAX_BINARY_BYTES:
            raise RuntimeError("official mihomo executable exceeds its size limit")
        with bundle.open(files[0]) as payload:
            yield payload


def _report(
    tag: str, asset: str, url: str, archive_digest: str, digest: str, binary: Path
):
    print(f"Mihomo download release tag: {tag}", flush=True)
    print(f"Official mihomo asset: {asset}", flush=True)
    print(f"Official mihomo download URL: {url}", flush=True)
    print(f"Mihomo archive SHA-256 (downloaded content): {archive_digest}", flush=True)
    print(f"Mihomo binary SHA-256 (downloaded content): {digest}", flush=True)
    print(f"Official mihomo binary: {binary}", flush=True)


def download_mihomo(target: str | None = None, *, release: str | None = None) -> Path:
    """Download a fresh official archive and atomically publish its binary.

    Callers can share a freshly read version.txt tag for multiple architectures.
    Every call downloads again; failures neither replace nor return an old binary.
    Hashes identify downloaded content, without claiming an upstream digest check.
    The harness records the actual version by running the binary with -v.
    """
    target = _target(target)
    if release is None:
        release = latest_release()
    tag = _release_tag(release)
    name, url = _asset(tag, target)
    directory = CORE_DIR / "target/interop/mihomo" / tag / target
    binary = directory / ("mihomo.exe" if target.startswith("windows-") else "mihomo")
    request = urllib.request.Request(
        url, headers={"User-Agent": "VCore-interop-scripts"}
    )
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".download-", dir=directory) as staging:
            staged_archive = Path(staging) / name
            staged_binary = Path(staging) / binary.name
            with (
                urllib.request.urlopen(request, timeout=30) as response,
                staged_archive.open("wb") as output,
            ):
                _https_response(response)
                archive_digest = _copy_and_hash(response, output, MAX_ARCHIVE_BYTES)
            with _payload(staged_archive) as source, staged_binary.open("wb") as output:
                digest = _copy_and_hash(source, output, MAX_BINARY_BYTES)
            staged_binary.chmod(0o755)
            os.replace(staged_binary, binary)
    except (
        OSError,
        EOFError,
        http.client.HTTPException,
        zipfile.BadZipFile,
        zlib.error,
    ) as error:
        raise RuntimeError(f"cannot download official mihomo {tag}: {error}") from error
    _report(tag, name, url, archive_digest, digest, binary)
    return binary
