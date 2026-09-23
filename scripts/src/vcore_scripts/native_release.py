"""Fresh official native peers. No API lookup, source build or stale fallback."""

from __future__ import annotations

import http.client
import os
import platform
import stat
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .mihomo_release import (
    MAX_ARCHIVE_BYTES,
    MAX_BINARY_BYTES,
    _copy_and_hash,
    _https_response,
)
from .protocol_peers import run_command


@dataclass(frozen=True)
class PeerArtifact:
    binary: Path
    identity: dict


def download_native(
    kind: str, directory: Path, target: str | None = None
) -> PeerArtifact:
    try:
        return _download_native(kind, directory, target)
    except (
        OSError,
        ValueError,
        zipfile.BadZipFile,
        http.client.HTTPException,
        subprocess.SubprocessError,
    ):
        raise RuntimeError(
            "official native peer download or version check failed"
        ) from None


def _download_native(kind: str, directory: Path, target: str | None) -> PeerArtifact:
    """Install only a named executable into this run's owned directory."""
    if target is None:
        architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(
            platform.machine().lower(), platform.machine().lower()
        )
        target = f"{platform.system().lower()}-{architecture}"
    assets = {
        "V2": (
            "v2fly/v2ray-core",
            "v2ray",
            {
                "darwin-arm64": "v2ray-macos-arm64-v8a.zip",
                "darwin-amd64": "v2ray-macos-64.zip",
                "linux-arm64": "v2ray-linux-arm64-v8a.zip",
                "linux-amd64": "v2ray-linux-64.zip",
            },
        ),
        "XR": (
            "XTLS/Xray-core",
            "xray",
            {
                "darwin-arm64": "Xray-macos-arm64-v8a.zip",
                "darwin-amd64": "Xray-macos-64.zip",
                "linux-arm64": "Xray-linux-arm64-v8a.zip",
                "linux-amd64": "Xray-linux-64.zip",
            },
        ),
        "H": (
            "HyNetworks/hysteria",
            "hysteria",
            {
                target: f"hysteria-{target}"
                for target in [
                    "darwin-arm64",
                    "darwin-amd64",
                    "linux-arm64",
                    "linux-amd64",
                ]
            },
        ),
    }
    if kind not in assets or target not in assets[kind][2]:
        raise RuntimeError("unsupported official native peer target")
    project, name, targets = assets[kind]
    url = f"https://github.com/{project}/releases/latest/download/{targets[target]}"
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / name
    with tempfile.TemporaryDirectory(prefix=".download-", dir=directory) as temporary:
        archive, executable = Path(temporary) / "archive.zip", Path(temporary) / name
        request = urllib.request.Request(
            url, headers={"User-Agent": "VCore-interop-scripts"}
        )
        with (
            urllib.request.urlopen(request, timeout=30) as response,
            archive.open("wb") as output,
        ):
            _https_response(response)
            archive_hash = _copy_and_hash(response, output, MAX_ARCHIVE_BYTES)
        if kind == "H":
            with archive.open("rb") as source, executable.open("wb") as output:
                binary_hash = _copy_and_hash(source, output, MAX_BINARY_BYTES)
        else:
            binary_hash = _extract_zip(archive, executable, name)
        executable.chmod(0o755)
        result = run_command([str(executable), "version"], timeout=10, limit=4096)
        if result.returncode != 0 or not result.cleanup:
            raise RuntimeError("official native peer version check failed")
        version = result.stdout.decode("utf-8", errors="replace").strip()
        if not version:
            raise RuntimeError("invalid official native peer version output")
        os.replace(executable, binary)
    return PeerArtifact(
        binary,
        {
            "kind": kind,
            "target": target,
            "source_url": url,
            "archive_sha256": archive_hash,
            "binary_sha256": binary_hash,
            "version": version,
        },
    )


def _extract_zip(archive: Path, executable: Path, name: str) -> str:
    with zipfile.ZipFile(archive) as bundle:
        matches = []
        for member in bundle.infolist():
            path = PurePosixPath(member.filename)
            mode = stat.S_IFMT(member.external_attr >> 16)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in member.filename
                or ":" in member.filename
                or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
                or member.flag_bits & 1
            ):
                raise RuntimeError("unsafe official native peer archive")
            if member.filename == name:
                matches.append(member)
        if len(matches) != 1 or not 0 < matches[0].file_size <= MAX_BINARY_BYTES:
            raise RuntimeError("invalid official native peer executable")
        with bundle.open(matches[0]) as source, executable.open("wb") as output:
            binary_hash = _copy_and_hash(source, output, MAX_BINARY_BYTES)
    return binary_hash
