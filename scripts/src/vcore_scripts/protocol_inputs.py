"""Reproducible, nonsensitive input identity for one local protocol run."""

from __future__ import annotations

import hashlib
import platform
import re
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from .builds import CORE_DIR
from .protocol_peers import run_command

CODE_PATHS = [
    "Cargo.toml",
    "Cargo.lock",
    "src",
    "crates",
    "tests",
    "scripts",
    "include",
]


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command_output(command: list[str]) -> bytes:
    result = run_command(command, cwd=CORE_DIR, timeout=20, limit=8 * 1024 * 1024)
    if result.returncode != 0:
        raise RuntimeError("cannot record protocol input identity")
    return result.stdout


def source_identity() -> dict:
    paths = (
        command_output(
            ["git", "ls-files", "-co", "--exclude-standard", "-z", "--", *CODE_PATHS]
        )
        .decode()
        .split("\0")
    )
    digest = hashlib.sha256()
    for name in sorted(set(paths) - {""}):
        path = CORE_DIR / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("non-file source input")
        digest.update(name.encode() + b"\0" + bytes.fromhex(sha256(path)))
    patch = command_output(["git", "diff", "--binary", "HEAD", "--", *CODE_PATHS])
    return {
        "parent_commit": command_output(["git", "rev-parse", "HEAD"]).decode().strip(),
        "source_tree_sha256": digest.hexdigest(),
        "dirty_patch_sha256": hashlib.sha256(patch).hexdigest(),
        "lock_sha256": sha256(CORE_DIR / "Cargo.lock"),
    }


def run_identity(stage: str, selected: list[dict], preflight: bool) -> dict:
    record = source_identity()
    lock = tomllib.loads((CORE_DIR / "Cargo.lock").read_text())
    tls = [
        {key: package[key] for key in ["name", "version", "source"]}
        for package in lock["package"]
        if package["name"] in {"rustls", "tokio-rustls", "ring"}
    ]
    text = (CORE_DIR / "src/lib.rs").read_text()
    record.update(
        schema_version=1,
        stage=stage,
        mode="preflight" if preflight else "execute",
        started_utc=datetime.now(UTC).isoformat(),
        os=platform.system(),
        os_version=platform.release(),
        architecture=platform.machine(),
        python=platform.python_version(),
        rustls=tls,
        invoke_api_version=int(re.search(r"INVOKE_API_VERSION: u32 = (\d+)", text)[1]),
        config_version=int(re.search(r"CONFIG_VERSION: u8 = (\d+)", text)[1]),
        features=["all-features", "independent-feature-smokes"],
        selected_cases=[case["case_id"] for case in selected],
        commands=[],
        cleanup=False,
        source_unchanged=False,
        artifacts=[],
        suite_timeout_seconds=sum(case["timeout_seconds"] for case in selected) + 1800,
    )
    record["rustc"] = command_output(["rustc", "-Vv"]).decode().strip()
    record["cargo"] = command_output(["cargo", "--version"]).decode().strip()
    if sys.platform == "darwin":
        record["xcode"] = command_output(["xcodebuild", "-version"]).decode().strip()
        record["sdk"] = command_output(["xcrun", "--show-sdk-version"]).decode().strip()
    return record


def redact(text: str) -> str:
    text = text.replace(str(CORE_DIR), "<VCore>")
    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*)(?:Bearer|Basic)\s+[^\s,}]+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----",
        "<private-key>",
        text,
        flags=re.S,
    )
    text = re.sub(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", "<synthetic-id>", text
    )
    text = re.sub(
        r"(?i)((?:password|authorization|private[-_]key|token)\s*[:=]\s*)([^\s,}]+)",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"/(?:Users|home|private/var|var/folders)/[^\s\"']+", "<host-path>", text
    )
    return text
