"""Frozen official assets and append-only case attempts for the memory runner."""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import re
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

from .protocol_inputs import sha256

ASSET_BASE = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"


def bandwidth_complete(
    report: dict, transport: str, direction: str, *, proxy_endpoints: int = 0
) -> bool:
    """Check the public native report against the fixed calibration workload.

    Receiver goodput alone can hide an unpaced burst when divided by the nominal
    window. Every sender must actually spend that window delivering all records.
    """
    size = 1200 if transport == "udp" else 65536
    expected = (125_000_000 // 16 * 10 // size) * size
    try:
        rows = report["flows"]
        duration = report["elapsed_seconds"]
        goodput = report["receiver_goodput_bps"]
        directions = Counter(row["direction"] for row in rows)
        wanted = Counter(
            {"up": 8, "down": 8} if direction == "both" else {direction: 16}
        )
        return bool(
            report["complete"] is True
            and report["rate_pass"] is True
            and report["transport"] == transport
            and report["direction"] == direction
            and report["nominal_seconds"] == 10
            and report["offered_bps"] == 1_000_000_000
            and report["payload_bytes"] == size
            and report["proxy_endpoint_count"] == proxy_endpoints
            and len(rows) == 16
            and directions == wanted
            and report["sent_bytes"] == report["received_bytes"] == expected * 16
            and math.isfinite(duration)
            and 9.9 <= duration <= 10.1
            and math.isfinite(goodput)
            and goodput >= 990_000_000
            and abs(goodput - expected * 16 * 8 / max(10, duration)) < 0.001
            and all(
                not row.get("error")
                and 9.9 <= row["sent"]["seconds"] <= 10.1
                and all(
                    not row[end].get("error")
                    and row[end]["bytes"] == expected
                    and row[end]["packets"] == expected // size
                    for end in ("sent", "received")
                )
                for row in rows
            )
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def save(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class RunStore:
    """Reuse only sealed, hash-verified attempts from the exact frozen identity."""

    def __init__(self, root: Path, identity: dict, *, resume=False):
        self.root = root
        if resume:
            if json.loads((root / "manifest.json").read_text()) != identity:
                raise ValueError("memory resume identity mismatch; start a new run")
        else:
            root.mkdir(parents=True, exist_ok=False)
            save(root / "manifest.json", identity)

    def _attempts(self, case):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", case):
            raise ValueError("invalid memory case ID")
        parent = self.root / "cases" / case
        if (
            parent.is_symlink()
            or parent.parent.is_symlink()
            or not parent.resolve().is_relative_to(self.root.resolve())
        ):
            raise ValueError("memory case escaped owned run")
        attempts = sorted(parent.glob("attempt-*"))
        if any(path.is_symlink() or not path.is_dir() for path in attempts):
            raise ValueError("invalid memory attempt directory")
        return attempts

    def begin(self, case: str) -> Path:
        attempts = self._attempts(case)
        path = self.root / "cases" / case / f"attempt-{len(attempts) + 1:04d}"
        path.mkdir(parents=True)
        save(path / "state.json", {"incomplete": True})
        return path

    def finish(self, case: str, path: Path, result: dict, evidence: list[Path]):
        if path not in self._attempts(case):
            raise ValueError("unowned memory attempt")
        save(path / "result.json", result)
        evidence = [*evidence, path / "result.json"]
        sealed = {}
        for file in evidence:
            relative = file.relative_to(path).as_posix()
            if file.is_symlink() or not file.is_file():
                raise ValueError("non-file memory evidence")
            sealed[relative] = sha256(file)
        save(path / "state.json", {"incomplete": False, "evidence": sealed})

    def completed(self, case: str) -> dict | None:
        attempts = self._attempts(case)
        if not attempts:
            return None
        path = attempts[-1]
        state = json.loads((path / "state.json").read_text())
        if state["incomplete"]:
            return None
        if not state.get("evidence") or "result.json" not in state["evidence"]:
            raise ValueError("missing memory evidence seal")
        for relative, digest in state["evidence"].items():
            file = path / relative
            if (
                file.is_symlink()
                or not file.is_file()
                or not file.resolve().is_relative_to(path.resolve())
                or sha256(file) != digest
            ):
                raise ValueError("memory evidence changed or disappeared")
        return json.loads((path / "result.json").read_text())


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.release = None

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https":
            raise ValueError("asset redirect left HTTPS")
        prefix = "/Loyalsoldier/v2ray-rules-dat/releases/download/"
        if url.hostname == "github.com" and url.path.startswith(prefix):
            tag = url.path[len(prefix) :].split("/", 1)[0]
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", tag):
                raise ValueError("invalid rules release identity")
            self.release = tag
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def _download(name: str, path: Path) -> dict:
    redirects = _Redirects()
    opener = urllib.request.build_opener(redirects)
    request = urllib.request.Request(
        f"{ASSET_BASE}/{name}", headers={"User-Agent": "VCore-memory"}
    )
    size, digest = 0, hashlib.sha256()
    limit = 64 * 1024 * 1024 if name.endswith(".dat") else 1024
    deadline = time.monotonic() + 180
    with opener.open(request, timeout=30) as response, path.open("xb") as stream:
        while chunk := response.read1(65536):
            size += len(chunk)
            if size > limit or time.monotonic() > deadline:
                raise ValueError("rules asset transfer exceeds bound")
            digest.update(chunk)
            stream.write(chunk)
    if not size or not redirects.release:
        raise ValueError("missing official rules release/contents")
    return {
        "url": request.full_url,
        "release": redirects.release,
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def acquire_rules(root: Path) -> dict:
    """Fresh latest per run, freeze a checksum-verified, same-release pair."""
    root.mkdir(parents=True, exist_ok=False)
    for attempt in range(1, 4):
        directory = root / f"download-{attempt}"
        directory.mkdir()
        try:
            assets = {
                name: _download(name, directory / name)
                for name in (
                    "geosite.dat",
                    "geosite.dat.sha256sum",
                    "geoip.dat",
                    "geoip.dat.sha256sum",
                )
            }
            if len({item["release"] for item in assets.values()}) != 1:
                raise ValueError("latest rules release changed during download")
            for name in ("geosite.dat", "geoip.dat"):
                checksum = (directory / (name + ".sha256sum")).read_text().split()
                if checksum != [assets[name]["sha256"], name]:
                    raise ValueError("official rules checksum mismatch")
                assets[name]["cn"] = cn_statistics(directory / name)
            record = {"directory": directory.name, "assets": assets}
            save(root / "identity.json", record)
            return record
        except (OSError, ValueError, http.client.HTTPException) as error:
            save(
                directory / "failure.json",
                {
                    "error": type(error).__name__,
                    "reason": "rules download/checksum/release validation failed",
                },
            )
            if attempt == 3:
                raise RuntimeError(
                    "official rules acquisition failed three times"
                ) from error
    raise AssertionError("unreachable")


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated GeoData field")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("oversized GeoData varint")


def _fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        field, wire = tag >> 3, tag & 7
        if not field:
            raise ValueError("invalid GeoData field")
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, offset = _varint(data, offset)
            else:
                length = 8 if wire == 1 else 4
            end = offset + length
            if end > len(data):
                raise ValueError("truncated GeoData message")
            value, offset = data[offset:end], end
        else:
            raise ValueError("unsupported GeoData wire type")
        yield field, wire, value


def cn_statistics(path: Path) -> dict:
    """Offline count only; never a substitute for the real loader or routing."""
    selected = None
    categories = 0
    for field, wire, message in _fields(memoryview(path.read_bytes())):
        if (field, wire) != (1, 2):
            raise ValueError("unexpected GeoData top-level field")
        categories += 1
        codes = [bytes(v).lower() for f, w, v in _fields(message) if (f, w) == (1, 2)]
        if codes == [b"cn"]:
            if selected is not None:
                raise ValueError("duplicate CN category")
            selected = message
    if selected is None:
        raise ValueError("missing CN category")
    kinds = Counter()
    count = value_bytes = 0
    for field, wire, entry in _fields(selected):
        if (field, wire) != (2, 2):
            continue
        count += 1
        values = {f: v for f, _, v in _fields(entry)}
        if path.name == "geosite.dat":
            kinds[str(values.get(1, 0))] += 1
            value_bytes += len(values[2])
        else:
            kinds[str(len(values[1]) * 8)] += 1
    return {
        "records": count,
        "categories": categories,
        "types": dict(kinds),
        "value_bytes": value_bytes,
        "scope": "offline-count-not-loader-acceptance",
    }
