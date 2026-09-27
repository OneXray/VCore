"""Independent native prerequisites. Artifact readiness is not wire acceptance."""

from __future__ import annotations

from pathlib import Path

from .mihomo_release import download_mihomo, latest_release
from .native_release import PeerArtifact, download_native
from .protocol_catalogs import PEERS
from .protocol_peers import run_command


def preflight(directory: Path, kinds: set[str], *, container: bool = False):
    if not kinds <= PEERS:
        raise ValueError("unsupported native peer kind")
    directory.mkdir(parents=True, exist_ok=True)
    artifacts, records = {}, []
    for kind in sorted(kinds):
        record = {
            "kind": kind,
            "status": "BLOCKED",
            "scope": "preflight-only",
            "wire_acceptance": "NOT RUN",
        }
        records.append(record)
        try:
            if kind == "M":
                identity = {}
                release = latest_release()
                binary = download_mihomo(
                    release=release, directory=directory / "M", identity=identity
                )
                version = run_command([str(binary), "-v"], timeout=10, limit=4096)
                if version.returncode != 0 or not version.stdout.strip():
                    raise RuntimeError("official peer version query failed")
                identity["version"] = version.stdout.decode(
                    "utf-8", errors="replace"
                ).strip()
                artifact = PeerArtifact(binary, identity)
                artifacts[kind] = artifact
                record.update(identity, status="READY")
                if container:
                    record["container_status"] = "BLOCKED"
                    status = run_command(
                        ["container", "system", "status"], timeout=10, limit=4096
                    )
                    if status.returncode != 0:
                        raise RuntimeError("Apple Container is not running")
                    container_identity = {}
                    binary = download_mihomo(
                        "linux-arm64",
                        release=release,
                        directory=directory / "M-container",
                        identity=container_identity,
                    )
                    artifacts["M-container"] = PeerArtifact(binary, container_identity)
                    record.update(
                        container_status="READY", container_artifact=container_identity
                    )
            else:
                artifact = download_native(kind, directory / kind)
                artifacts[kind] = artifact
                record.update(artifact.identity, status="READY")
        except (OSError, RuntimeError, ValueError) as error:
            # Never expose URLs with userinfo, paths, config bodies or child output.
            record["reason"] = type(error).__name__
    return artifacts, records
