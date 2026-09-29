"""Four-profile cold processes, distinct from instrumented allocation diagnostics."""

import contextlib
import json
import select
import shutil
import socket
import struct
import time

from . import builds
from .memory_inputs import save
from .memory_process import LIMIT, MeasuredProcess
from .mihomo_isolation import reserve_port
from .protocol_containers import command

PROFILES = {
    "none": (),
    "site": ("geosite",),
    "ip": ("geoip",),
    "both": ("geosite", "geoip"),
}
REPETITIONS = 5
IDLE_SECONDS = 30
DIAGNOSTIC_CASE = "diagnose-cold-both"


def cases():
    # Interleave profiles to expose time/cache drift, without purging OS caches.
    return [
        f"cold-{profile}-{index}"
        for index in range(1, REPETITIONS + 1)
        for profile in PROFILES
    ]


def available(profile, state):
    try:
        required = PROFILES[profile]
        return set(state) == {"geosite", "geoip"} and all(
            row["required"] is (key in required)
            and row["available"] is (key in required)
            and row["lastError"] is None
            for key, row in state.items()
        )
    except (KeyError, TypeError):
        return False


def summarize(results):
    profiles = {}
    pids = []
    valid = set(results) == set(cases())
    for profile in PROFILES:
        rows = [results.get(f"cold-{profile}-{index}", {}) for index in range(1, 6)]
        peaks = []
        for row in rows:
            try:
                measurement = row["measurement"]
                pids.append(measurement["pid"])
                peaks.append(measurement["peak_bytes"])
                valid &= bool(
                    row["accepted"]
                    and row["profile"] == profile
                    and available(profile, row["geodata"])
                    and row["idle_seconds"] >= IDLE_SECONDS
                    and {
                        "initialize",
                        "prepare",
                        "start",
                        "first-hit",
                        "idle",
                        "stop",
                        "destroyInstance",
                    }
                    <= row["phases"].keys()
                    and measurement["status"] == "PASS"
                    and measurement["diagnostic"] is False
                    and measurement["peak_bytes"] <= LIMIT
                    and measurement["final_barrier"]
                    and measurement["business_cleanup"]
                    and measurement["cleanup"]
                    and measurement["exit_code"] == 0
                    and not measurement["sampling_errors"]
                )
            except (KeyError, TypeError):
                valid = False
        profiles[profile] = {
            "peaks_bytes": peaks,
            "worst_peak_bytes": max(peaks) if peaks else None,
            "margin_bytes": LIMIT - max(peaks) if peaks else None,
        }
    return {"complete": bool(valid and len(set(pids)) == 20), "profiles": profiles}


def _allocations(process, work, label, run_command):
    """Native Apple diagnostic on a distinct PID; never part of memory acceptance."""
    pid = str(process.child.pid)
    run_command(["vmmap", "-summary", pid], work, label + "-vmmap", timeout=60)
    run_command(
        ["malloc_history", pid, "-allBySize"],
        work,
        label + "-live",
        timeout=60,
        output_limit=8 * 1024 * 1024,
    )
    run_command(
        ["malloc_history", pid, "-highWaterMark", "-allBySize"],
        work,
        label + "-high-water",
        timeout=60,
        output_limit=8 * 1024 * 1024,
    )


def run_case(name, root, manifest, work, origin, mihomo):
    # Reuse the exact isolated public-ABI/SOCKS5 driver, not a second proxy path.
    from . import memory_benchmark as lab

    diagnostic = name == DIAGNOSTIC_CASE
    profile = "both" if diagnostic else name.split("-")[1]
    enabled = PROFILES[profile]
    record = {
        "case": name,
        "profile": profile,
        "accepted": False,
        "phases": {},
        "cache_condition": {
            "new_process": True,
            "new_application_directory": True,
            "os_page_cache_purged": False,
            "files_read_before_spawn": "download checksum, reference and private copy",
            "first_load_in_process": True,
            "storage_cold_claim": False,
        },
    }
    with contextlib.ExitStack() as stack:
        port, reservation = reserve_port(stack)
        dns, dns_port = lab._origin(stack, origin.ipv4, 17)
        data_dir = work / "data"
        assets = data_dir / "geodata"
        assets.mkdir(parents=True)
        for asset in enabled:
            shutil.copy2(
                root / "rules" / manifest["rules"]["directory"] / (asset + ".dat"),
                assets / (asset + ".dat"),
            )
        config = {
            "socks-port": port,
            "ipv6": True,
            "proxies": [
                {
                    "name": "edge",
                    "type": "socks5",
                    "server": mihomo.ipv4,
                    "port": 1080,
                    "udp": True,
                }
            ],
            "proxy-groups": [{"name": "route", "type": "select", "proxies": ["edge"]}],
            "dns": {
                "enable": True,
                "ipv6": False,
                "nameserver": [f"udp://{origin.ipv4}:{dns_port}#DIRECT"],
            },
            "rules": (["GEOSITE,cn,REJECT"] if "geosite" in enabled else [])
            + (["GEOIP,cn,REJECT,no-resolve"] if "geoip" in enabled else [])
            # Trigger VCore's controlled DNS before SOCKS5 forwarding. A bare
            # MATCH deliberately preserves a domain for the upstream resolver.
            + [f"IP-CIDR,{origin.ipv4}/32,route", "MATCH,route"],
        }
        save(work / "config.json", config)
        process = MeasuredProcess(
            root / "artifacts/vcore-host",
            root / "artifacts/observer.dylib",
            work,
            diagnostic=diagnostic,
        )

        @contextlib.contextmanager
        def phase(label):
            process.boundary(label)
            begin = time.monotonic_ns()
            yield
            end = time.monotonic_ns()
            snapshot = process.boundary(label + ":complete")
            record["phases"][label] = {
                "begin_ns": begin,
                "end_ns": end,
                "seconds": (end - begin) / 1e9,
                "current_bytes": snapshot["footprint"],
                "lifetime_peak_bytes": snapshot["peak"],
                "rss_bytes": snapshot["rss"],
            }

        def invoke(method, payload=None, instance=None):
            with phase(method):
                return lab._api(process, method, payload, instance)

        try:
            version = invoke("version")
            if version["buildIdentity"] != builds.EXPECTED_IDENTITY.decode():
                raise RuntimeError("cold process library identity mismatch")
            invoke("initialize", {"dataDir": str(data_dir)})
            instance = invoke("createInstance")["instanceId"]
            invoke("prepare", {"configYaml": json.dumps(config)}, instance)
            record["geodata"] = invoke("getGeoDataState")
            if not available(profile, record["geodata"]):
                raise RuntimeError("cold profile required/available/error mismatch")
            if diagnostic:
                _allocations(process, work, "prepared", lab._command)
            reservation.release_ipv4()
            reservation.release_ipv6()
            invoke("start", instance=instance)
            if invoke("getState", instance=instance)["state"] != "running":
                raise RuntimeError("cold process is not running")

            def accepts():
                return json.loads(
                    command("exec", mihomo.name, "python", "/data/fixture/metrics.py")
                )["tcp"]["PassiveOpens"]

            rejected = []
            before = accepts()
            for item in manifest["geodata_reference"]["routes"]:
                kind = "geosite" if item["kind"] == "site" else "geoip"
                if not item["matched"] or kind not in enabled:
                    continue
                label = "first-hit" if not rejected else "hit-" + item["id"]
                with phase(label), contextlib.ExitStack() as traffic:
                    lab._socks(traffic, port, item["value"], 443, expected_status=2)
                rejected.append(item["id"])
            if accepts() != before or select.select([dns], [], [], 0.1)[0]:
                raise RuntimeError("cold rule reject opened upstream or DNS")
            forwarded = []
            for case_id, host in (
                ("domain-negative", "vcore-cn-negative.test"),
                ("ip4-negative", origin.ipv4),
                ("ip6-negative", origin.ipv6),
            ):
                label = "first-hit" if profile == "none" and not forwarded else case_id
                with phase(label), contextlib.ExitStack() as traffic:
                    ipv6 = case_id == "ip6-negative"
                    observer, remote = lab._origin(
                        traffic, origin.ipv4, 154 if ipv6 else 26
                    )
                    tcp, _ = lab._socks(traffic, port, host, remote)
                    if lab._exact(observer, 2) != b"A" + bytes([6 if ipv6 else 4]):
                        raise RuntimeError("cold route origin witness missing")
                    peer = socket.inet_ntop(
                        socket.AF_INET6 if ipv6 else socket.AF_INET,
                        lab._exact(observer, 16 if ipv6 else 4),
                    )
                    if peer != (mihomo.ipv6 if ipv6 else mihomo.ipv4):
                        raise RuntimeError("cold route did not use expected proxy")
                    if case_id == "domain-negative":
                        size, _ = struct.unpack("!HH", lab._exact(dns, 4))
                        query = lab._exact(dns, size)
                        if query[12:-4] != b"\x11vcore-cn-negative\x04test\0":
                            raise RuntimeError("cold route did not use controlled DNS")
                    payload = bytes(range(256))
                    tcp.sendall(payload)
                    if lab._exact(tcp, len(payload)) != payload:
                        raise RuntimeError("cold route echo mismatch")
                    tcp.close()
                    if lab._exact(observer, 1) != b"D":
                        raise RuntimeError("cold route origin did not finish")
                forwarded.append(
                    {
                        "id": case_id,
                        "source_verified": True,
                        "bytes_each_direction": 256,
                    }
                )
            record["routes"] = {
                "rejected": rejected,
                "forwarded": forwarded,
                "reject_upstream_accepts": 0,
                "reject_dns_queries": 0,
            }
            with phase("idle"):
                begin = time.monotonic()
                time.sleep(IDLE_SECONDS)
                record["idle_seconds"] = time.monotonic() - begin
            if invoke("getState", instance=instance)["state"] != "running":
                raise RuntimeError("cold runtime died during idle observation")
            invoke("stop", instance=instance)
            # Exercise the synchronous stop contract rather than assuming exit freed it.
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind(("127.0.0.1", port))
                udp.bind(("127.0.0.1", port))
            invoke("destroyInstance", instance=instance)
            if diagnostic:
                _allocations(process, work, "destroyed", lab._command)
            process.finalize()
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            record["failure"] = str(error)
        finally:
            process.close()
        record["measurement"] = process.record
        record["status"] = (
            "INVALID" if record.get("failure") else process.record["status"]
        )
        record["accepted"] = record["status"] == (
            "DIAGNOSTIC" if diagnostic else "PASS"
        )
        return record
