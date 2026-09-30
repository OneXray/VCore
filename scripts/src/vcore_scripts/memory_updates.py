"""Owned HTTPS update scenarios using the production downloader and scheduler."""

import ipaddress
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from .memory_geodata import IpReference, SiteReference, cn_entries
from .memory_inputs import ASSET_BASE, cn_statistics, save
from .protocol_inputs import sha256

MODES = ("replace", "not-modified", "corrupt", "cancel")


def cases(profiles):
    rows = {}
    for name, spec in list(profiles.items()):
        if not name.endswith("-standard-1"):
            continue
        prefix = name.removesuffix("-standard-1")
        for kind in ("geosite", "geoip"):
            for mode in MODES:
                row = spec | {
                    "warm_reuse": False,
                    "witness_seconds": [35, 70, 245, 280] if mode != "cancel" else [],
                    "cached_witnesses": True,
                    "events": [
                        {"kind": "update", "asset": kind, "mode": mode, "at": 90}
                    ],
                    "updates": True,
                    "expected_cancel": mode == "cancel",
                }
                rows[f"{prefix}-update-{kind}-{mode}"] = row
                for transport in ("tcp", "udp"):
                    rows[f"{prefix}-{transport}-update-{kind}-{mode}-1000"] = row | {
                        "transport": transport,
                        "correctness": False,
                        "mbps": 1000,
                    }
    return rows


def required(workloads):
    return any(spec.get("updates") for spec in workloads.values())


def read_fixture(path):
    if path is None:
        raise RuntimeError(
            "BLOCKED: updates require owned trusted HTTPS certificate/key/domain "
            "and a previous complete official rules snapshot (--update-fixture)"
        )
    path = Path(path).resolve()
    value = json.loads(path.read_text())
    if set(value) != {"hostname", "certificate", "private_key", "previous_rules"}:
        raise ValueError(
            "update fixture requires exactly "
            "hostname/certificate/private_key/previous_rules"
        )
    host = value["hostname"]
    if (
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
        or "." not in host
    ):
        raise ValueError("update endpoint must be an owned DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("update endpoint must not be an IP literal")
    for name in ("certificate", "private_key", "previous_rules"):
        value[name] = (path.parent / value[name]).resolve()
    for name in ("certificate", "private_key"):
        if not value[name].is_file():
            raise RuntimeError("BLOCKED: missing owned trusted HTTPS material")
    subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(value["certificate"]),
            "-noout",
            "-checkhost",
            host,
        ],
        check=True,
        capture_output=True,
        timeout=5,
    )
    # No CA override or skip-verify. Only the actual production WebPKI handshake
    # can establish trust; a host openssl check is not equivalent acceptance.
    return value


def prepare(root, manifest, fixture):
    if not required(manifest["socks_load_workloads"]):
        return
    directory = root / "artifacts/update"
    directory.mkdir()
    identity = json.loads((fixture["previous_rules"] / "identity.json").read_text())
    if len({a["release"] for a in identity["assets"].values()}) != 1:
        raise ValueError("previous rules pair must come from one official release")
    previous = fixture["previous_rules"] / identity["directory"]
    old = directory / "old"
    old.mkdir()
    hashes = {}
    for kind in ("geosite", "geoip"):
        name = kind + ".dat"
        metadata = identity["assets"][name]
        if (
            metadata["url"] != f"{ASSET_BASE}/{name}"
            or sha256(previous / name) != metadata["sha256"]
        ):
            raise ValueError(
                "previous snapshot lacks intact official acquisition evidence"
            )
        checksum = (previous / (name + ".sha256sum")).read_text().split()
        if checksum != [metadata["sha256"], name]:
            raise ValueError("previous official snapshot checksum mismatch")
        cn_statistics(previous / name)
        hashes[kind] = metadata["sha256"]
        shutil.copy2(previous / name, old / name)
    requested = {
        e["asset"]
        for s in manifest["socks_load_workloads"].values()
        for e in s.get("events", [])
        if e["kind"] == "update"
    }
    if any(
        hashes[k] == manifest["rules"]["assets"][k + ".dat"]["sha256"]
        for k in requested
    ):
        raise RuntimeError("BLOCKED: update needs distinct complete official snapshots")
    site = SiteReference(
        [
            (int(v.get(1, 0)), bytes(v[2]).decode())
            for v in cn_entries(old / "geosite.dat")
        ]
    )
    ip = IpReference(
        [
            ipaddress.ip_network(
                (ipaddress.ip_address(bytes(v[1])), int(v[2])), strict=False
            )
            for v in cn_entries(old / "geoip.dat")
        ]
    )
    for row in manifest["geodata_reference"]["routes"]:
        matched = (
            site.matches(row["value"])
            if row["kind"] == "site"
            else ip.matches(ipaddress.ip_address(row["value"]))
        )
        if matched != row["matched"]:
            raise RuntimeError(
                "BLOCKED: choose snapshots with stable frozen traffic witnesses"
            )
    shutil.copy2(fixture["certificate"], directory / "cert.pem")
    shutil.copy2(fixture["private_key"], directory / "key.pem")
    (directory / "key.pem").chmod(0o600)
    manifest["update_fixture"] = {
        "hostname": fixture["hostname"],
        "old_hashes": hashes,
        "previous_identity": identity,
        "trust": "production WebPKI only",
    }
    manifest["load_dns_names"] = manifest.get(
        "load_dns_names",
        [r for r in manifest["geodata_reference"]["routes"] if r["kind"] == "site"],
    ) + [
        {
            "id": "update-endpoint",
            "kind": "site",
            "value": fixture["hostname"],
            "matched": False,
        }
    ]


def install(root, manifest, lab, stack, directories, origin):
    directory = directories["origin"].parent / "updates"
    directory.mkdir()
    directories["updates"] = directory
    shutil.copy2(
        Path(__file__).parents[3] / "tests/memory/geodata_https.py",
        directory / "server.py",
    )
    for name in ("cert.pem", "key.pem"):
        shutil.copy2(root / "artifacts/update" / name, directory / name)
    for kind in ("geosite", "geoip"):
        shutil.copy2(
            root / "rules" / manifest["rules"]["directory"] / (kind + ".dat"),
            directory / (kind + ".dat"),
        )
    save(directory / "control.json", {"mode": "idle"})
    peer = lab.start(
        stack,
        directory,
        "memory-updates",
        [
            "env",
            "VCORE_ISOLATED_ORIGIN=1",
            "python",
            "-B",
            "/data/fixture/server.py",
        ],
    )
    peer.release()
    peer.wait_tcp(24443)
    origin.memory_update_peer = peer
    return peer


def configure(root, manifest, work, config):
    fixture = manifest["update_fixture"]
    asset_dir = work / "data/geodata"
    now = int(time.time())
    urls = {
        k: f"https://{fixture['hostname']}:24443/{k}.dat" for k in ("geosite", "geoip")
    }
    config.update(
        {"geox-url": urls, "geo-auto-update": True, "geo-update-interval": 24}
    )
    state = {"version": 1}
    for kind, digest in fixture["old_hashes"].items():
        shutil.copy2(
            root / "artifacts/update/old" / (kind + ".dat"), asset_dir / (kind + ".dat")
        )
        state[kind] = dict(
            available=True,
            updating=False,
            lastSuccess=now,
            nextCheck=now + 86400,
            lastError=None,
            etag='"' + digest + '"',
            hash=digest,
            sourceUrl=urls[kind],
        )
    save(asset_dir / "state.json", state)


def exercise(event, process, work, root, manifest, origin, witness):
    from .memory_benchmark import _api

    kind, mode = event["asset"], event["mode"]
    peer = origin.memory_update_peer
    directory = work / f"update-{kind}-{mode}"
    directory.mkdir()
    asset_dir = work / "data/geodata"
    before = _api(process, "getGeoDataState")[kind]
    before_hash = sha256(asset_dir / (kind + ".dat"))
    state = json.loads((asset_dir / "state.json").read_text())
    if any(state[k]["updating"] for k in ("geosite", "geoip")):
        raise RuntimeError("update fixture may only schedule an idle owned store")
    token = f"{kind}-{mode}-{time.time_ns()}"
    control = {
        "token": token,
        "asset": kind,
        "mode": mode,
        "etag": before["etag"],
        "release": False,
    }
    save(peer.root / "control.json", control)
    before_route = witness()
    state[kind]["nextCheck"] = int(time.time()) - 1
    save(asset_dir / "state.json", state)
    deadline = time.monotonic() + 70
    response = None
    while time.monotonic() < deadline:
        path = peer.root / "response.json"
        if path.exists():
            candidate = json.loads(path.read_text())
            if candidate.get("token") == token:
                response = candidate
                break
        status = _api(process, "getGeoDataState")[kind]
        if status["lastError"]:
            raise RuntimeError("production HTTPS update failed; no trust fallback")
        time.sleep(0.05)
    if not response:
        raise RuntimeError(
            "production updater did not reach the isolated HTTPS endpoint"
        )
    during = _api(process, "getGeoDataState")[kind]
    if not during["updating"] or during["hash"] != before_hash:
        raise RuntimeError("old snapshot was not retained during candidate transfer")
    if mode in {"replace", "cancel"}:
        while time.monotonic() < deadline:
            staged = list(asset_dir.glob(f".update-*/{kind}.dat"))
            if staged and staged[0].stat().st_size > 0:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError(
                "update did not stream any bytes into production staging"
            )
    during_route = witness()
    if mode == "cancel":
        _api(process, "stop", instance=process.instance)
    save(peer.root / "control.json", control | {"release": True})
    while time.monotonic() < deadline:
        after = _api(process, "getGeoDataState")[kind]
        if not after["updating"]:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError(
            "update did not complete inside the prescribed control window"
        )
    expected = (
        manifest["rules"]["assets"][kind + ".dat"]["sha256"]
        if mode == "replace"
        else before_hash
    )
    if (
        after["hash"] != expected
        or sha256(asset_dir / (kind + ".dat")) != expected
        or list(asset_dir.glob(".update-*"))
        or (mode in {"replace", "not-modified"} and after["lastError"])
        or (
            mode in {"replace", "not-modified"}
            and after["nextCheck"] <= int(time.time())
        )
        or (mode == "corrupt" and not after["lastError"])
    ):
        raise RuntimeError("update publication/rollback/staging cleanup mismatch")
    result = dict(
        kind="update",
        asset=kind,
        mode=mode,
        passed=True,
        before=before,
        during=during,
        after=after,
        before_route=before_route,
        during_route=during_route,
        after_route=witness() if mode != "cancel" else None,
        old_snapshot_retained=True,
        response=response,
        interrupt=mode == "cancel",
        active_file_sha256=expected,
    )
    save(directory / "result.json", result)
    return result
