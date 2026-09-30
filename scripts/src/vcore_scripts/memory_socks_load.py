"""Coupled public-SOCKS5 routing, received payload and whole-PID memory evidence."""

import contextlib
import errno
import json
import math
import shutil
import socket
import subprocess
import time
from datetime import datetime

from . import builds
from .memory_cold_start import available
from .memory_inputs import bandwidth_complete, save
from .memory_process import LIMIT, MeasuredProcess
from .mihomo_isolation import reserve_port
from .protocol_containers import command
from .protocol_peers import OwnedProcess

# A deliberately named subset, not the complete Stage 5 matrix. Half the bytes
# are DIRECT: this accepts ingress load, never SOCKS5 outbound at 1 Gbps.
SPLIT_CASES = {
    f"socks-tcp-split-{direction}-16-{repeat}": {
        "direction": direction,
        "flows": 16,
        "seconds": 300,
        "mbps": 1000,
        # Production DNS clamps TTL to at least 30 s. Do not weaken its cache
        # policy to manufacture fresh queries; space route witnesses beyond it.
        "witness_seconds": list(range(35, 300, 35)),
        "family": "IPv4",
        "calibration_seconds": 10,
    }
    for direction in ("up", "down", "both")
    for repeat in range(1, 4)
}
TCP_CASES = {
    f"socks-tcp-{topology}-{family}-{direction}-{flows}-{mbps}-{repeat}": {
        "direction": direction,
        "flows": flows,
        "seconds": 300 if mbps == 1000 else 120,
        "mbps": mbps,
        "witness_seconds": list(range(35, 300 if mbps == 1000 else 120, 35)),
        "family": "IPv6" if family == "v6" else "IPv4",
        "topology": topology,
        "calibration_seconds": 10,
    }
    for topology in ("split", "proxy")
    for family in ("v4", "v6")
    for direction in ("up", "down", "both")
    for flows in (16, 64)
    for mbps in ((250, 500, 750, 1000) if flows == 16 else (1000,))
    for repeat in (range(1, 4) if mbps == 1000 else (1,))
}
TCP_CASES.update(
    {
        f"socks-tcp-{topology}-{family}-{direction}-1-{route}-1000-{repeat}": {
            "direction": direction,
            "flows": 1,
            "seconds": 300,
            "mbps": 1000,
            "witness_seconds": list(range(35, 300, 35)),
            "family": "IPv6" if family == "v6" else "IPv4",
            "topology": topology,
            "primary_route": route,
            "calibration_seconds": 10,
        }
        for topology in ("split", "proxy")
        for family in ("v4", "v6")
        for direction in ("up", "down", "both")
        for route in ("cn", "miss")
        for repeat in range(1, 4)
    }
)
UDP_CASES = {
    name.replace("socks-tcp-", "socks-udp-"): spec
    | {"transport": "udp", "distributed": spec["flows"] > 1}
    for name, spec in TCP_CASES.items()
}
DEVELOPMENT_CASES = {
    f"socks-smoke-{transport}-{family}": {
        "direction": "both",
        "flows": 16,
        "seconds": 5,
        "mbps": 64,
        "witness_seconds": [],
        "family": "IPv6" if family == "v6" else "IPv4",
        "topology": "proxy",
        "transport": transport,
        "calibration_seconds": 5,
        "development": True,
    }
    for transport in ("tcp", "udp")
    for family in ("v4", "v6")
}
DEVELOPMENT_CASES["socks-smoke-udp-single-v6"] = DEVELOPMENT_CASES[
    "socks-smoke-udp-v6"
] | {"flows": 1, "direction": "up", "mbps": 32, "primary_route": "cn"}
DEVELOPMENT_CASES["socks-smoke-udp-pair-v6"] = DEVELOPMENT_CASES[
    "socks-smoke-udp-v6"
] | {"flows": 2, "direction": "up", "mbps": 32}
for family in ("v4", "v6"):
    DEVELOPMENT_CASES[f"socks-smoke-udp-distributed-{family}"] = DEVELOPMENT_CASES[
        f"socks-smoke-udp-{family}"
    ] | {"distributed": True}
    DEVELOPMENT_CASES[f"socks-smoke-dns-{family}"] = DEVELOPMENT_CASES[
        f"socks-smoke-tcp-{family}"
    ] | {
        "seconds": 8,
        "overlap": {"kind": "dns", "at": 1, "cold": 16, "hot": 4, "hot_rounds": 2},
    }
    DEVELOPMENT_CASES[f"socks-smoke-backpressure-{family}"] = DEVELOPMENT_CASES[
        f"socks-smoke-tcp-{family}"
    ] | {"slow_read": {"flows": 4, "every_ms": 1000, "pause_ms": 200}}
    DEVELOPMENT_CASES[f"socks-smoke-churn-{family}"] = DEVELOPMENT_CASES[
        f"socks-smoke-tcp-{family}"
    ] | {
        "seconds": 8,
        "overlap": {"kind": "churn", "at": 1, "rounds": 2, "tcp": 4, "udp": 4},
    }
    DEVELOPMENT_CASES[f"socks-smoke-mixed-{family}"] = DEVELOPMENT_CASES[
        f"socks-smoke-tcp-{family}"
    ] | {"correctness": True, "transport": "mixed", "mbps": 0}
OVERLAP_CASES = {
    f"socks-overlap-dns-{transport}-{family}-{repeat}": {
        "direction": "both",
        "flows": 64,
        "seconds": 300,
        "mbps": 1000,
        "witness_seconds": list(range(35, 300, 35)),
        "family": "IPv6" if family == "v6" else "IPv4",
        "topology": "proxy",
        "transport": transport,
        "distributed": transport == "udp",
        "calibration_seconds": 10,
        "overlap": {"kind": "dns", "at": 10, "cold": 1024, "hot": 32, "hot_rounds": 8},
    }
    for transport in ("tcp", "udp")
    for family in ("v4", "v6")
    for repeat in range(1, 4)
}
OVERLAP_CASES.update(
    {
        f"socks-overlap-backpressure-{family}-{repeat}": {
            "direction": "both",
            "flows": 64,
            "seconds": 300,
            "mbps": 1000,
            "witness_seconds": list(range(35, 300, 35)),
            "family": "IPv6" if family == "v6" else "IPv4",
            "topology": "proxy",
            "transport": "tcp",
            "calibration_seconds": 10,
            "slow_read": {"flows": 8, "every_ms": 10000, "pause_ms": 2000},
        }
        for family in ("v4", "v6")
        for repeat in range(1, 4)
    }
)
OVERLAP_CASES.update(
    {
        f"socks-overlap-churn-{transport}-{family}-{repeat}": spec
        | {
            "overlap": {"kind": "churn", "at": 10, "rounds": 100, "tcp": 32, "udp": 32},
        }
        for family in ("v4", "v6")
        for transport in ("tcp", "udp")
        for repeat in range(1, 4)
        for spec in [OVERLAP_CASES[f"socks-overlap-dns-{transport}-{family}-{repeat}"]]
    }
)
CORRECTNESS_CASES = {
    f"socks-correctness-{transport}-{family}-{flows}-{route}-{repeat}": {
        "direction": "both",
        "flows": flows,
        "seconds": 300,
        "mbps": 0,
        "witness_seconds": list(range(35, 300, 35)),
        "family": "IPv6" if family == "v6" else "IPv4",
        "topology": "proxy",
        "transport": transport,
        "correctness": True,
        "calibration_seconds": 10,
        **({"primary_route": route} if flows == 1 else {}),
    }
    for family in ("v4", "v6")
    for repeat in range(1, 4)
    for transport, flows in (("tcp", 1), ("udp", 1), ("mixed", 16), ("mixed", 64))
    for route in (("cn", "miss") if flows == 1 else ("both",))
}
CORRECTNESS_CASES.update(
    {
        f"socks-correctness-{kind}-{family}-{repeat}": CORRECTNESS_CASES[
            f"socks-correctness-mixed-{family}-"
            f"{16 if kind == 'dns' else 64}-both-{repeat}"
        ]
        | (
            {
                "overlap": OVERLAP_CASES[f"socks-overlap-{kind}-tcp-{family}-{repeat}"][
                    "overlap"
                ]
            }
            if kind in ("dns", "churn")
            else {"slow_read": {"flows": 8, "every_ms": 10000, "pause_ms": 2000}}
        )
        for family in ("v4", "v6")
        for repeat in range(1, 4)
        for kind in ("dns", "churn", "backpressure")
    }
)
CASES = (
    SPLIT_CASES
    | TCP_CASES
    | UDP_CASES
    | OVERLAP_CASES
    | CORRECTNESS_CASES
    | DEVELOPMENT_CASES
)
TUN_CASES = {
    name.replace("socks-", "tun-", 1): spec | {"entrypoint": "fd-TUN"}
    for name, spec in CASES.items()
    if name not in SPLIT_CASES
}
for family in ("v4", "v6"):
    for kind in ("mixed", "sniff", "dns", "churn", "backpressure"):
        TUN_CASES[f"tun-functional-{kind}-{family}"] = (
            TUN_CASES[f"tun-smoke-{'tcp' if kind == 'sniff' else kind}-{family}"]
            | {"correctness": True, "mbps": 0}
            | ({"sniff": True} if kind == "sniff" else {})
        )
    TUN_CASES[f"tun-smoke-sniff-{family}"] = TUN_CASES[f"tun-smoke-tcp-{family}"] | {
        "sniff": True
    }
    for transport in ("tcp", "udp"):
        TUN_CASES[f"tun-smoke-{transport}-single-{family}"] = TUN_CASES[
            f"tun-smoke-{transport}-{family}"
        ] | {
            "flows": 1,
            "primary_route": "cn",
            "mbps": 8,
        }
CASES.update(TUN_CASES)


def address(peer, spec):
    return peer.ipv6 if spec.get("family") == "IPv6" else peer.ipv4


def endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def host_source(peer):
    # Kernel route selection without sending a packet or changing host routes.
    family = socket.AF_INET6 if ":" in peer else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.connect((peer, 24004))
        return probe.getsockname()[0]


def _json_line(stream):
    raw = bytearray()
    while len(raw) < 1024 * 1024:
        byte = stream.recv(1)
        if not byte:
            raise RuntimeError("load oracle early EOF")
        if byte == b"\n":
            return json.loads(raw)
        raw.extend(byte)
    raise RuntimeError("load oracle response exceeded bound")


def _dns_stats(origin):
    with socket.create_connection((origin.ipv4, 24000), timeout=5) as stream:
        return _json_line(stream)


def _accepts(mihomo):
    return json.loads(
        command("exec", mihomo.name, "python", "/data/fixture/metrics.py")
    )["tcp"]["PassiveOpens"]


def _network_counters(work, label, peers):
    """Guest-local counters and host-global diagnostics, never PID attribution."""
    values = {
        role: json.loads(
            command("exec", peer.name, "python", "/data/fixture/metrics.py")
        )
        for role, peer in peers.items()
    }
    result = subprocess.run(
        ["netstat", "-s", "-p", "udp"],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    values["host_global_udp"] = result.stdout
    save(work / (label + "-network.json"), values)


def _route_probe(port, host, source, bandwidth, spec):
    from . import memory_benchmark as lab

    with contextlib.ExitStack() as stack:
        control = stack.enter_context(
            socket.create_connection((address(bandwidth, spec), 24003), timeout=5)
        )
        control.sendall(
            json.dumps(
                {
                    "transport": "tcp",
                    "direction": "up",
                    "seconds": 1,
                    "bytes_per_second": 65536,
                    "seed": 20260929,
                    "expected_source": source,
                    **(
                        {
                            "initial_hello": True,
                            "sniff_host": host if not _is_ip(host) else "",
                        }
                        if spec.get("sniff")
                        else {}
                    ),
                }
            ).encode()
            + b"\n"
        )
        remote = _json_line(control)["port"]
        if spec.get("entrypoint") == "fd-TUN":
            from .memory_tun import connect, resolve

            target = host
            if not _is_ip(host):
                if not spec.get("sniff"):
                    resolve(port, host, address(bandwidth, spec))
                target = address(bandwidth, spec)
            stream = stack.enter_context(connect(port, target, remote))
            if spec.get("sniff"):
                if not _is_ip(host):
                    stream.sendall(
                        f"GET /memory HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
                    )
                stream.sendall(b"*")
        else:
            lab._socks(stack, port, host, remote)
        ready = _json_line(control)
        if ready != {"ready": True, "source_verified": True}:
            raise RuntimeError("load route origin source mismatch")
        # No start token: this new-session witness carries no benchmark payload.
        # Closing the control makes the bounded origin release the data socket.


def _is_ip(host):
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _witnesses(
    port,
    reference,
    origin,
    bandwidth,
    mihomo,
    source,
    spec,
    positive,
    cn_bandwidth=None,
):
    from . import memory_benchmark as lab

    peers = [mihomo] + ([positive] if positive is not None else [])
    before_dns = _dns_stats(origin)
    before_accepts = [_accepts(peer) for peer in peers]
    rejected = []
    for item in reference["routes"]:
        if item["kind"] == "ip" and item["matched"]:
            with contextlib.ExitStack() as stack:
                if spec.get("entrypoint") == "fd-TUN":
                    from .memory_tun import connect

                    try:
                        stream = stack.enter_context(connect(port, item["value"], 443))
                        stream.sendall(b"reject-witness")
                        if stream.recv(1):
                            raise RuntimeError("CN IP TUN rejection returned payload")
                    except EOFError:
                        pass
                    except OSError as error:
                        if error.errno not in (
                            errno.ENOTCONN,
                            errno.ECONNRESET,
                            errno.EPIPE,
                        ):
                            raise
                else:
                    lab._socks(stack, port, item["value"], 443, expected_status=2)
            rejected.append(item["id"])
    if [_accepts(peer) for peer in peers] != before_accepts or _dns_stats(
        origin
    ) != before_dns:
        raise RuntimeError("CN IP reject opened upstream or DNS during load")
    forwarded = []
    for item in reference["routes"]:
        if item["kind"] != "site":
            continue
        _route_probe(
            port,
            item["value"],
            (address(positive, spec) if positive else source)
            if item["matched"]
            else address(mihomo, spec),
            cn_bandwidth if item["matched"] and cn_bandwidth else bandwidth,
            spec,
        )
        forwarded.append(item)
    _route_probe(port, address(bandwidth, spec), address(mihomo, spec), bandwidth, spec)
    after_dns = _dns_stats(origin)
    delta = {
        key: count - before_dns["queries"].get(key, 0)
        for key, count in after_dns["queries"].items()
        if count > before_dns["queries"].get(key, 0)
    }
    if (
        after_dns["rejected"]
        or any(key.endswith(":unknown") for key in after_dns["queries"])
        or (
            not spec.get("sniff")
            and not all(
                delta.get(
                    item["id"]
                    + (":28:" if spec.get("family") == "IPv6" else ":1:")
                    + (
                        "peer"
                        if positive
                        and item["matched"]
                        and spec.get("entrypoint") != "fd-TUN"
                        else "core"
                    ),
                    0,
                )
                > 0
                for item in forwarded
            )
        )
        or (spec.get("sniff") and after_dns != before_dns)
    ):
        raise RuntimeError("new route probes did not exercise controlled core DNS")
    return {
        "passed": True,
        "cn_ip_rejected": rejected,
        "source_verified_routes": [item["id"] for item in forwarded]
        + ["ip6-negative" if spec.get("family") == "IPv6" else "ip4-negative"],
        "reject_upstream_accepts": 0,
        "reject_dns_queries": 0,
        "core_dns_query_delta": delta,
    }


def _selected(branches, spec):
    if spec.get("primary_route"):
        return [branches[0 if spec["primary_route"] == "cn" else 1]]
    return branches


def _peer_proxy(peer, spec):
    count = spec["flows"] // 2 if spec.get("distributed") else 1
    return ",".join(endpoint(address(peer, spec), 1080 + i) for i in range(count))


def _load(root, work, spec, bandwidth, branches, *, witness=None, overlap=None):
    """Simultaneous prescribed paths; one full-rate path for a single flow."""
    processes, outcomes = [], []
    preparation = time.monotonic()
    rounds = []
    events = []
    with contextlib.ExitStack() as stack:
        release = work / "start"
        for branch in branches:
            ready = work / (branch["route"] + "-ready.json")
            argv = [
                str(root / "artifacts/traffic-darwin"),
                "-peer",
                branch.get("origin", endpoint(address(bandwidth, spec), 24003)),
                "-transport",
                branch.get("transport", spec.get("transport", "tcp")),
                "-direction",
                spec["direction"],
                "-seconds",
                str(spec["seconds"]),
                "-flows",
                str(spec["flows"] // len(branches)),
                "-mbps",
                str(
                    1
                    if spec.get("probe") or spec.get("correctness")
                    else spec["mbps"] // len(branches)
                ),
                "-expect-source",
                branch["source"],
                "-ready-file",
                str(ready),
                "-start-file",
                str(release),
            ]
            if branch.get("proxy"):
                argv += ["-proxy", branch["proxy"]]
            if branch.get("tun"):
                argv += ["-tun-control", str(branch["tun"])]
                if spec.get("sniff"):
                    argv += ["-tun-sniff"]
            if branch.get("target"):
                argv += ["-target", branch["target"]]
            if branch.get("selection"):
                config_file = work / (branch["route"] + "-selection.json")
                save(config_file, branch["selection"])
                argv += ["-selection-file", str(config_file)]
            if spec.get("probe"):
                argv += ["-probe", "-probe-rounds", str(spec.get("probe_rounds", 1))]
            if spec.get("correctness"):
                argv.append("-correctness")
            if slow := spec.get("slow_read"):
                argv += [
                    "-slow-flows",
                    str(slow["flows"] // len(branches)),
                    "-pause-every-ms",
                    str(slow["every_ms"]),
                    "-pause-for-ms",
                    str(slow["pause_ms"]),
                ]
            record = {"argv": argv}
            log = work / (branch["route"] + ".log")
            # Register before the owner so exit status/cleanup are serialized
            # after it is joined, including readiness and witness failures.
            stack.callback(save, work / (branch["route"] + "-command.json"), record)
            owner = stack.enter_context(
                OwnedProcess(argv, log, record, limit=2 * 1024 * 1024)
            )
            processes.append((owner, record, log, branch))
        ready_deadline = time.monotonic() + 10
        while True:
            if any(owner.process.poll() is not None for owner, *_ in processes):
                raise RuntimeError("traffic driver exited before common start")
            try:
                all_ready = all(
                    json.loads((work / (branch["route"] + "-ready.json")).read_text())
                    == {
                        "pid": owner.process.pid,
                        "flows": spec["flows"] // len(branches),
                    }
                    for owner, _, _, branch in processes
                )
            except (FileNotFoundError, ValueError):
                all_ready = False
            if all_ready:
                break
            if time.monotonic() > ready_deadline:
                raise TimeoutError("traffic driver readiness exceeded bound")
            time.sleep(0.005)
        begin = time.monotonic()
        with release.open("x") as barrier:
            barrier.write("start\n")
        deadline = begin + spec["seconds"] + 20
        pending = iter(spec.get("witness_seconds", []) if witness else [])
        next_witness = next(pending, math.inf)
        while any(owner.process.poll() is None for owner, *_ in processes):
            elapsed = time.monotonic() - begin
            if time.monotonic() >= deadline:
                raise TimeoutError("joint traffic exceeded fixed window and drain")
            if any(owner.process.poll() not in (None, 0) for owner, *_ in processes):
                break
            if overlap and not events and elapsed >= spec["overlap"]["at"]:
                observed = overlap()
                ended = time.monotonic() - begin
                if any(owner.process.poll() is not None for owner, *_ in processes):
                    raise RuntimeError("resource overlap outlived the background load")
                events.append({"begin": elapsed, "end": ended, **observed})
                save(work / "overlap.json", events)
            if witness and elapsed >= next_witness:
                rounds.append({"elapsed_seconds": elapsed, **witness()})
                save(work / "witnesses.json", rounds)
                next_witness = next(pending, math.inf)
            time.sleep(0.02)
        elapsed = time.monotonic() - begin
    for owner, record, log, branch in processes:
        try:
            report = json.loads(log.read_bytes().splitlines()[0])
        except (ValueError, IndexError):
            report = {}
        outcomes.append(
            {
                "route": branch["route"],
                "traffic": report,
                "driver_joined": record["joined"],
                "driver_exit": owner.process.returncode,
            }
        )
    return {
        "branches": outcomes,
        "load_seconds": elapsed,
        "witness_rounds": rounds,
        "start_barrier": True,
        "setup_seconds": begin - preparation,
        "overlap_events": events,
    }


def _load_valid(row, spec, endpoints):
    return bool(
        row["start_barrier"] is True
        and (
            spec.get("development")
            or spec.get("correctness")
            or spec["seconds"] * 0.99 <= row["load_seconds"] <= spec["seconds"] * 1.01
        )
        and all(
            branch["driver_joined"]
            and branch["driver_exit"] == 0
            and branch["traffic"].get("external_start_barrier") is True
            and all(
                flow.get("source_verified")
                for flow in branch["traffic"].get("flows", [])
            )
            and bandwidth_complete(
                branch["traffic"],
                spec.get("transport", "tcp"),
                spec["direction"],
                proxy_endpoints=count,
                flows=spec["flows"] // len(endpoints),
                seconds=spec["seconds"],
                mbps=spec["mbps"] // len(endpoints),
                require_rate=not spec.get("development", False),
                correctness=spec.get("correctness", False),
            )
            for branch, count in zip(row["branches"], endpoints, strict=True)
        )
    )


def run_case(
    name,
    root,
    manifest,
    work,
    origin,
    bandwidth,
    mihomo,
    positive=None,
    cn_bandwidth=None,
):
    from . import memory_benchmark as lab

    spec = CASES[name]
    is_tun = spec.get("entrypoint") == "fd-TUN"
    if is_tun and cn_bandwidth is None:
        raise ValueError(
            "TUN DNS hints require distinct positive and negative origin IPs"
        )
    source = host_source(address(bandwidth, spec))
    positive = positive if spec.get("topology") == "proxy" else None
    if spec.get("topology") == "proxy" and positive is None:
        raise ValueError("full SOCKS5 load requires a distinct positive-route peer")
    record = {
        "case": name,
        "attempt": str(work.relative_to(root)),
        "status": "INVALID",
        "accepted": False,
        "facility_valid": False,
        "workload": spec,
        "scope": f"{spec.get('entrypoint', 'SOCKS5')}-"
        f"{spec.get('transport', 'tcp').upper()}-"
        f"{spec['family']}-{spec['flows']}-flows-CN-"
        + ("full-outbound" if positive else "split; not full-outbound-1Gbps"),
    }
    calibration_dir = work / "calibration"
    calibration_dir.mkdir()
    calibration_spec = spec | {
        "seconds": spec["calibration_seconds"],
        "slow_read": None,
    }
    calibration = _load(
        root,
        calibration_dir,
        calibration_spec,
        bandwidth,
        _selected(
            [
                (
                    {
                        "route": "positive",
                        "source": address(positive, spec),
                        "proxy": _peer_proxy(positive, spec),
                        **(
                            {"origin": endpoint(address(cn_bandwidth, spec), 24003)}
                            if is_tun
                            else {}
                        ),
                    }
                    if positive
                    else {
                        "route": "direct",
                        "source": source,
                        **(
                            {"origin": endpoint(address(cn_bandwidth, spec), 24003)}
                            if is_tun
                            else {}
                        ),
                    }
                ),
                {
                    "route": "mihomo",
                    "source": address(mihomo, spec),
                    "proxy": _peer_proxy(mihomo, spec),
                },
            ],
            spec,
        ),
    )
    save(work / "calibration.json", calibration)
    record["facility_valid"] = _load_valid(
        calibration,
        calibration_spec,
        _selected(
            [
                (spec["flows"] // 2 if spec.get("distributed") else 1)
                if positive
                else 0,
                spec["flows"] // 2 if spec.get("distributed") else 1,
            ],
            spec,
        ),
    )
    if not record["facility_valid"]:
        record["failure"] = "prescribed branch calibration failed"
        return record

    with contextlib.ExitStack() as stack:
        port, reservation = reserve_port(stack)
        assets = work / "data/geodata"
        assets.mkdir(parents=True)
        for asset in ("geosite", "geoip"):
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
                    "server": address(mihomo, spec),
                    "port": 1080,
                    "udp": True,
                }
            ],
            "proxy-groups": [{"name": "route", "type": "select", "proxies": ["edge"]}],
            "dns": {
                "enable": True,
                "ipv6": spec.get("family") == "IPv6",
                "nameserver": [f"udp://{origin.ipv4}:24004#DIRECT"],
            },
            "rules": [
                "GEOSITE,cn," + ("cn-route" if positive else "DIRECT"),
                "GEOIP,cn,REJECT",
                (
                    f"IP-CIDR6,{bandwidth.ipv6}/128,route"
                    if spec.get("family") == "IPv6"
                    else f"IP-CIDR,{bandwidth.ipv4}/32,route"
                ),
                "MATCH,route",
            ],
        }
        if positive:
            config["proxies"].append(
                {
                    "name": "cn-edge",
                    "type": "socks5",
                    "server": address(positive, spec),
                    "port": 1080,
                    "udp": True,
                }
            )
            config["proxy-groups"].append(
                {"name": "cn-route", "type": "select", "proxies": ["cn-edge"]}
            )
        tun = None
        if is_tun:
            from .memory_tun import TunClient

            config.pop("socks-port")
            config["tun"] = {"enable": True}
            if spec.get("sniff"):
                config["sniffer"] = {
                    "enable": True,
                    "sniff": {"HTTP": {"ports": ["1-65535"]}},
                }
            tun = stack.enter_context(TunClient(root, work))
        selections = {}
        if spec.get("distributed"):
            control_port, control_reservation = reserve_port(stack)
            config["external-controller"] = endpoint("127.0.0.1", control_port)
            config["secret"] = "memory-fixture-controller"
            original = config["proxies"]
            config["proxies"] = []
            for group, node in zip(config["proxy-groups"], original, strict=True):
                members = []
                for index in range(spec["flows"] // 2):
                    member = node["name"] + f"-{index}"
                    members.append(member)
                    config["proxies"].append(
                        node | {"name": member, "port": 1080 + index}
                    )
                group["proxies"] = members
                selections[group["name"]] = {
                    "controller": config["external-controller"],
                    "secret": config["secret"],
                    "group": group["name"],
                    "members": members,
                }
        save(work / "config.json", config)
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        process = MeasuredProcess(
            root / "artifacts/vcore-host",
            root / "artifacts/observer.dylib",
            work,
            pass_fds=(tun.host.fileno(),) if tun else (),
        )
        record["pid"] = process.child.pid
        try:
            if (
                lab._api(process, "version")["buildIdentity"]
                != builds.EXPECTED_IDENTITY.decode()
            ):
                raise RuntimeError("joint process production identity mismatch")
            lab._api(process, "initialize", {"dataDir": str(work / "data")})
            instance = lab._api(process, "createInstance")["instanceId"]
            lab._api(process, "prepare", {"configYaml": json.dumps(config)}, instance)
            record["geodata"] = lab._api(process, "getGeoDataState")
            if not available("both", record["geodata"]):
                raise RuntimeError("joint CN assets unavailable")
            reservation.release_ipv4()
            reservation.release_ipv6()
            if selections:
                control_reservation.release_ipv4()
                control_reservation.release_ipv6()
            if tun:
                record["fd_before"] = process.command(f"D {tun.host.fileno()}")
            lab._api(
                process,
                "start",
                {"tunFd": tun.host.fileno(), "tunFraming": "utun"} if tun else {},
                instance=instance,
            )
            entry = tun.path if tun else port
            routes = {
                item["id"]: item for item in manifest["geodata_reference"]["routes"]
            }
            if tun:
                record["entry_route_witnesses"] = _witnesses(
                    entry,
                    manifest["geodata_reference"],
                    origin,
                    bandwidth,
                    mihomo,
                    source,
                    spec,
                    positive,
                    cn_bandwidth,
                )
            process.boundary("joint-load")
            counter_peers = {"origin": bandwidth, "miss": mihomo}
            if positive:
                counter_peers["cn"] = positive
            if cn_bandwidth:
                counter_peers["cn-origin"] = cn_bandwidth
            _network_counters(work, "before", counter_peers)

            def overlap():
                from .memory_events import churn_overlap, dns_overlap

                process.boundary("overlap:" + spec["overlap"]["kind"])
                if spec["overlap"]["kind"] == "dns":
                    result = dns_overlap(
                        entry,
                        manifest["load_dns_names"],
                        origin,
                        bandwidth,
                        mihomo,
                        spec,
                    )
                else:
                    result = churn_overlap(
                        root,
                        work,
                        entry,
                        manifest["geodata_reference"],
                        bandwidth,
                        mihomo,
                        positive,
                        spec,
                        cn_bandwidth=cn_bandwidth,
                    )
                process.boundary("joint-load")
                return result

            record.update(
                _load(
                    root,
                    work,
                    spec,
                    bandwidth,
                    _selected(
                        [
                            {
                                "route": "cn-proxy" if positive else "cn-direct",
                                "source": address(positive, spec)
                                if positive
                                else source,
                                "proxy": None
                                if tun
                                else endpoint(
                                    "::1"
                                    if spec.get("family") == "IPv6"
                                    else "127.0.0.1",
                                    port,
                                ),
                                "target": routes["domain-first"]["value"],
                                "selection": selections.get("cn-route"),
                                **(
                                    {
                                        "tun": tun.path,
                                        "origin": endpoint(
                                            address(cn_bandwidth, spec), 24003
                                        ),
                                    }
                                    if tun
                                    else {}
                                ),
                            },
                            {
                                "route": "miss-proxy",
                                "source": address(mihomo, spec),
                                "proxy": None
                                if tun
                                else endpoint(
                                    "::1"
                                    if spec.get("family") == "IPv6"
                                    else "127.0.0.1",
                                    port,
                                ),
                                "target": routes["domain-negative"]["value"],
                                "selection": selections.get("route"),
                                **({"tun": tun.path} if tun else {}),
                            },
                        ],
                        spec,
                    ),
                    witness=lambda: _witnesses(
                        entry,
                        manifest["geodata_reference"],
                        origin,
                        bandwidth,
                        mihomo,
                        source,
                        spec,
                        positive,
                        cn_bandwidth,
                    ),
                    overlap=overlap if spec.get("overlap") else None,
                )
            )
            for branch in record["branches"]:
                branch.update(pid=record["pid"], attempt=record["attempt"])
            record["dns"] = _dns_stats(origin)
            record["upstream_endpoint_count_per_proxy_branch"] = (
                spec["flows"] // 2 if spec.get("distributed") else 1
            )
            _network_counters(work, "after", counter_peers)
            process.boundary("joint-load:complete")
        except (OSError, RuntimeError, ValueError) as error:
            # Private artifacts retain a bounded reason; no config/questions in logs.
            record["failure"] = str(error)
        finally:
            try:
                if process.instance is not None:
                    lab._api(process, "stop", instance=process.instance)
                    if tun:
                        record["fd_after_stop"] = process.command(
                            f"D {tun.host.fileno()}"
                        )
                    lab._api(process, "destroyInstance", instance=process.instance)
                process.finalize()
            except (OSError, RuntimeError, ValueError) as error:
                record["cleanup_failure"] = str(error)
            finally:
                process.close()
        record["measurement"] = process.record
        from .memory_resources import capture

        record["resource_diagnostics"] = capture(record["pid"], started, work)
        if tun:
            tun.close()
            record["tun_client"] = tun.record
        record["status"] = joint_status(record, spec)
        record["accepted"] = record["status"] in {"PASS", "DIAGNOSTIC"}
        record["development"] = spec.get("development", False)
    return record


def joint_status(row, spec):
    """No routing-only, low-rate, diagnostic or other-PID result can sign off load."""
    try:
        measured = row["measurement"]
        cn_route = "cn-proxy" if spec.get("topology") == "proxy" else "cn-direct"
        primary = spec.get("primary_route")
        if primary not in {None, "cn", "miss"} or (spec["flows"] == 1) != (
            primary in {"cn", "miss"}
        ):
            return "INVALID"
        routes = _selected([cn_route, "miss-proxy"], spec)
        if not (
            row["facility_valid"]
            and row["start_barrier"] is True
            and available("both", row["geodata"])
            and measured["pid"] == row["pid"]
            and measured["status"] in {"PASS", "FAIL_MEMORY"}
            and measured["diagnostic"] is False
            and measured["final_barrier"]
            and measured["business_cleanup"]
            and measured["cleanup"]
            and measured["exit_code"] == 0
            and not measured["sampling_errors"]
            and "failure" not in row
            and "cleanup_failure" not in row
            and len(row["branches"]) == len(routes)
            and {b["route"] for b in row["branches"]} == set(routes)
            and all(
                b["pid"] == row["pid"]
                and b["attempt"] == row["attempt"]
                and b["driver_joined"]
                and b["driver_exit"] == 0
                and b["traffic"].get("external_start_barrier") is True
                for b in row["branches"]
            )
            and len(row["witness_rounds"]) == len(spec["witness_seconds"])
            and all(
                planned <= observed["elapsed_seconds"] < planned + 5
                for planned, observed in zip(
                    spec["witness_seconds"], row["witness_rounds"], strict=True
                )
            )
            and all(w["passed"] for w in row["witness_rounds"])
            and (
                spec.get("development")
                or all(
                    any(
                        interval * spec["seconds"] / 3
                        <= w["elapsed_seconds"]
                        < (interval + 1) * spec["seconds"] / 3
                        for w in row["witness_rounds"]
                    )
                    for interval in range(3)
                )
            )
        ):
            return "INVALID"
        if any(
            not flow.get("source_verified")
            for branch in row["branches"]
            for flow in branch["traffic"]["flows"]
        ):
            return "FAIL_CORRECTNESS"
        if spec.get("entrypoint") == "fd-TUN":
            driver = row.get("tun_client", {})
            if not (
                driver.get("joined")
                and driver.get("exit_code") == 0
                and driver.get("traffic", {}).get("complete") is True
                and driver["traffic"]["ip_packets_sent"] > 0
                and driver["traffic"]["ip_packets_received"] > 0
                and row["fd_before"] == row["fd_after_stop"]
                and row["fd_after_stop"]["original_open"]
                and row["fd_after_stop"]["nonblocking"]
                and row["entry_route_witnesses"]["passed"]
                and all(
                    branch["traffic"].get("entrypoint") == "fd-TUN"
                    for branch in row["branches"]
                )
            ):
                return "INVALID"
        if spec.get("overlap"):
            events = row.get("overlap_events", [])
            wanted = spec["overlap"]
            if len(events) != 1:
                return "FAIL_CORRECTNESS"
            event = events[0]
            if not (
                event["passed"] is True
                and wanted["at"] <= event["begin"] < wanted["at"] + 5
                and event["begin"] < event["end"] < spec["seconds"]
                and event["kind"] == wanted["kind"]
                and (
                    event["cold_names"] == wanted["cold"]
                    and event["hot_names"] == wanted["hot"]
                    and event["hot_rounds"] == wanted["hot_rounds"]
                    if wanted["kind"] == "dns"
                    else event["rounds"] == wanted["rounds"]
                    and event["tcp_per_round"] == wanted["tcp"]
                    and event["udp_per_round"] == wanted["udp"]
                    and event["warm_connections"] == wanted["tcp"] + wanted["udp"]
                    and event["warm_exchanges_per_connection"] == wanted["rounds"]
                )
            ):
                return "FAIL_CORRECTNESS"
        if spec.get("distributed") and (
            row.get("upstream_endpoint_count_per_proxy_branch") != spec["flows"] // 2
            or any(
                branch["traffic"].get("selected_flow_members")
                != [
                    ("cn-edge" if branch["route"] == "cn-proxy" else "edge") + f"-{i}"
                    for i in range(spec["flows"] // 2)
                ]
                for branch in row["branches"]
                if branch["route"] != "cn-direct"
            )
        ):
            return "FAIL_CORRECTNESS"
        if not all(
            bandwidth_complete(
                branch["traffic"],
                spec.get("transport", "tcp"),
                spec["direction"],
                proxy_endpoints=0 if spec.get("entrypoint") == "fd-TUN" else 1,
                flows=spec["flows"] // len(routes),
                seconds=spec["seconds"],
                mbps=spec["mbps"] // len(routes),
                require_rate=not (spec.get("development") or spec.get("slow_read")),
                correctness=spec.get("correctness", False),
            )
            for branch in row["branches"]
        ):
            return "FAIL_BANDWIDTH"
        elapsed = row["load_seconds"]
        received = sum(b["traffic"]["received_bytes"] for b in row["branches"])
        if slow := spec.get("slow_read"):
            expected_pauses = (spec["seconds"] * 1000 - 1) // slow["every_ms"]
            paused = [
                flow["received"].get("read_pauses_ms", [])
                for branch in row["branches"]
                for flow in branch["traffic"]["flows"]
                if flow["received"].get("read_pauses_ms")
            ]
            if (
                len(paused) != slow["flows"] * (2 if spec.get("correctness") else 1)
                or any(len(events) < expected_pauses for events in paused)
                or elapsed > spec["seconds"] + 3
            ):
                return "FAIL_CORRECTNESS"
            return (
                "DIAGNOSTIC"
                if spec.get("development")
                else "FAIL_MEMORY"
                if measured["peak_bytes"] > LIMIT
                else "PASS"
            )
        if spec.get("development"):
            return "DIAGNOSTIC"
        if spec.get("correctness"):
            return "FAIL_MEMORY" if measured["peak_bytes"] > LIMIT else "PASS"
        if not (
            math.isfinite(elapsed)
            and spec["seconds"] * 0.99 <= elapsed <= spec["seconds"] * 1.01
            and received * 8 / max(spec["seconds"], elapsed) >= spec["mbps"] * 990_000
        ):
            return "FAIL_BANDWIDTH"
        return "FAIL_MEMORY" if measured["peak_bytes"] > LIMIT else "PASS"
    except (KeyError, TypeError, ValueError, ZeroDivisionError, OverflowError):
        return "INVALID"
