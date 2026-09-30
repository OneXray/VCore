"""Content-verified inputs shared by runs of one committed memory candidate."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

from .protocol_inputs import sha256


def verify_files(root, manifest):
    root = Path(root).resolve()
    for relative, digest in manifest["files"].items():
        path = root / relative
        if (
            Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or Path(relative).parts[0] not in {"artifacts", "rules", "cn-reference"}
            or path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(root)
            or sha256(path) != digest
        ):
            raise ValueError("memory candidate input/artifact identity mismatch")


def read(root, source):
    root = Path(root)
    seal = json.loads((root / "candidate.json").read_text())
    for name in ("manifest", "matrix"):
        if sha256(root / (name + ".json")) != seal[name + "_sha256"]:
            raise ValueError("memory candidate manifest/matrix identity mismatch")
    manifest = json.loads((root / "manifest.json").read_text())
    if not manifest.get("ready") or manifest["source"] != source:
        raise ValueError("memory candidate source/preparation identity mismatch")
    verify_files(root, manifest)
    for relative in ("artifacts/peer-tls/cert.pem", "artifacts/update/cert.pem"):
        if relative in manifest["files"]:
            # Never renew a certificate inside a frozen input set.
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(root / relative),
                    "-noout",
                    "-checkend",
                    "0",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
    return manifest


def restore(candidate, root, manifest):
    from . import memory_protocols as protocols
    from . import memory_updates as updates
    from .memory_events import dns_names

    candidate = Path(candidate)
    frozen = read(candidate, manifest["source"])
    if frozen["geodata_verified"]["status"] != "PASS":
        raise ValueError("memory candidate lacks complete CN reference verification")
    for relative in frozen["files"]:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate / relative, target)
    for key in (
        "library_sha256",
        "toolchain",
        "rules",
        "geodata_reference",
        "geodata_verified",
        "geodata_ledger",
        "peer",
        "image",
    ):
        manifest[key] = copy.deepcopy(frozen[key])
    manifest["workloads"].update(copy.deepcopy(frozen["workloads"]))
    manifest["candidate"] = {
        "directory": str(candidate.resolve()),
        "manifest_sha256": sha256(candidate / "manifest.json"),
        "matrix_sha256": sha256(candidate / "matrix.json"),
    }
    profiles = protocols.selected(manifest)
    if profiles:
        profile = profiles.pop()
        manifest["protocol_profile"] = copy.deepcopy(frozen["protocol_profile"])
        manifest["protocol_profile"].update(
            name=profile, description=protocols.PROFILES[profile]
        )
        if set(protocols.components(profile)) & {"trojan-tls", "vless-xhttp-h3"}:
            manifest["native_peer"] = copy.deepcopy(frozen["native_peer"])
    workloads = manifest["socks_load_workloads"]
    if any(
        any(s.get(k) for k in ("overlap", "events", "lifecycle"))
        for s in workloads.values()
    ):
        manifest["load_dns_names"] = [
            r for r in manifest["geodata_reference"]["routes"] if r["kind"] == "site"
        ] + dns_names(root / "rules" / manifest["rules"]["directory"])
    if updates.required(workloads):
        if "update_fixture" not in frozen:
            raise RuntimeError(
                "BLOCKED: candidate lacks trusted HTTPS update inputs; "
                "freeze a new candidate"
            )
        manifest["update_fixture"] = copy.deepcopy(frozen["update_fixture"])
        manifest["load_dns_names"].append(
            {
                "id": "update-endpoint",
                "kind": "site",
                "value": manifest["update_fixture"]["hostname"],
                "matched": False,
            }
        )
    verify_files(root, frozen)
    manifest["files"] = copy.deepcopy(frozen["files"])
