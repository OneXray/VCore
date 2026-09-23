"""Independent native prerequisites. Artifact readiness is not wire acceptance."""

from __future__ import annotations

import json
import shutil
import uuid
from contextlib import suppress
from pathlib import Path

from .mihomo_release import download_mihomo, latest_release
from .native_release import PeerArtifact, download_native
from .protocol_inputs import redact
from .protocol_peers import run_command


def preflight(directory: Path, kinds: set[str], *, container: bool = False):
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
            if kind == "W":
                record.update(wireguard_environment(directory / "W"))
                continue
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


def wireguard_environment(directory: Path) -> dict:
    """Probe only an owned Linux container; never install a host VPN or routes."""
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "source_url": "https://www.wireguard.com/install/",
        "status": "BLOCKED",
        "cleanup": True,
        "backend": "linux-kernel",
        "host_network_changes": False,
    }
    if shutil.which("container") is None:
        return record | {"reason": "isolated Apple Container backend unavailable"}
    status = run_command(["container", "system", "status"], timeout=10, limit=4096)
    if status.returncode != 0:
        return record | {"reason": "isolated Apple Container backend unavailable"}
    image = "docker.io/library/alpine:latest"
    pull = run_command(["container", "image", "pull", image], timeout=180)
    if pull.returncode != 0:
        return record | {"reason": "official Linux image download failed"}
    inspection = run_command(["container", "image", "inspect", image], timeout=15)
    if inspection.returncode != 0:
        return record | {"reason": "official Linux image identity unavailable"}
    inspected = json.loads(inspection.stdout)
    record["image"] = image
    record["image_identity"] = [
        {
            "digest": item["configuration"]["descriptor"]["digest"],
            "variants": [
                {"digest": variant["digest"], "platform": variant["platform"]}
                for variant in item.get("variants", [])
                if variant.get("platform", {}).get("architecture") == "arm64"
            ],
        }
        for item in inspected
    ]
    name = "vcore-n1-wg-" + uuid.uuid4().hex[:12]
    command = [
        "container",
        "run",
        "--name",
        name,
        "--cap-add",
        "NET_ADMIN",
        "--rm",
        image,
        "sh",
        "-ec",
        "apk add --no-cache wireguard-tools iproute2 >/dev/null; "
        "wg --version; uname -r; apk info -v wireguard-tools; "
        "echo VCORE_WG_PHASE=kernel-interface; ip link add n1-wg type wireguard; "
        "echo VCORE_WG_PHASE=isolated-addresses; "
        "ip address add 10.233.0.1/24 dev n1-wg; "
        "ip -6 address add fd44:233::1/64 dev n1-wg nodad; "
        "ip link set n1-wg up; ip -j address show dev n1-wg; "
        "ip -j address show dev eth0; ip link del n1-wg",
    ]
    try:
        result = run_command(command, timeout=180, limit=65536)
        lines = result.stdout.decode("utf-8", errors="replace").splitlines()
        record["probe_exit_code"] = result.returncode
        record["probe_output"] = redact(
            result.stdout.decode("utf-8", errors="replace")[-8192:]
        )
        record["tools_version"] = next(
            (line for line in lines if line.startswith("wireguard-tools ")), None
        )
        record["kernel"] = next(
            (line for line in lines if line and line[0].isdigit() and " " not in line),
            None,
        )
        arrays = []
        for line in lines:
            if line.startswith("[{"):
                with suppress(ValueError):
                    arrays.append(json.loads(line))
        if result.returncode != 0 or len(arrays) != 2:
            record["reason"] = (
                "kernel WG, permissions, tools or isolated network prerequisite failed"
            )
        else:

            def dual(addresses):
                families = {
                    entry.get("family")
                    for interface in addresses
                    for entry in interface.get("addr_info", [])
                    if entry.get("scope") == "global"
                }
                return {"inet", "inet6"} <= families

            record.update(
                inner_dual_stack=dual(arrays[0]),
                outer_dual_stack=dual(arrays[1]),
                kernel_wireguard=True,
            )
            if record["inner_dual_stack"] and record["outer_dual_stack"]:
                record["status"] = "READY"
            else:
                record["reason"] = "isolated inner/outer dual stack is not ready"
    finally:
        # A timed-out CLI may have left only this named VM. Resolve it before
        # cleanup; never use a global stop/prune or an unresolved name pattern.
        existing = run_command(["container", "inspect", name], timeout=10, limit=65536)
        if existing.returncode == 0:
            run_command(["container", "stop", name], timeout=20)
            remaining = run_command(["container", "inspect", name], timeout=10)
            if remaining.returncode == 0:
                run_command(["container", "delete", name], timeout=20)
            remaining = run_command(["container", "inspect", name], timeout=10)
            record["cleanup"] = remaining.returncode != 0 and remaining.cleanup
            if not record["cleanup"]:
                record.update(status="BLOCKED", reason="owned container cleanup failed")
    return record
