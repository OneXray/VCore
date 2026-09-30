"""Bounded resource overlap clients; all DNS and application origins stay guests."""

import concurrent.futures
import time

from .memory_geodata import SiteReference, cn_entries
from .memory_inputs import save


def dns_names(asset_directory):
    reference = SiteReference(
        [
            (int(item.get(1, 0)), bytes(item[2]).decode("utf-8"))
            for item in cn_entries(asset_directory / "geosite.dat")
        ]
    )
    names = [
        {
            "id": f"dns-{kind}-{index:04d}",
            "value": f"memory-{kind}-{index:04d}.vcore-cn-negative.test",
            "kind": "site",
            "matched": False,
        }
        for kind, count in (("cold", 1024), ("hot", 32))
        for index in range(count)
    ]
    if any(reference.matches(item["value"]) for item in names):
        raise ValueError("controlled DNS workload is not a CN miss in frozen rules")
    return names


def dns_overlap(port, names, origin, bandwidth, mihomo, spec):
    from .memory_socks_load import _dns_stats, _route_probe, address

    wanted = spec["overlap"]
    cold = [item for item in names if item["id"].startswith("dns-cold-")][
        : wanted["cold"]
    ]
    hot = [item for item in names if item["id"].startswith("dns-hot-")][: wanted["hot"]]
    if len(cold) != wanted["cold"] or len(hot) != wanted["hot"]:
        raise ValueError("frozen DNS workload is incomplete")
    qtype = "28" if spec["family"] == "IPv6" else "1"

    def counter(stats, item):
        return stats["queries"].get(item["id"] + ":" + qtype + ":core", 0)

    def probe(item):
        _route_probe(port, item["value"], address(mihomo, spec), bandwidth, spec)

    def batch(items):
        # Submit at most 32 at once: no task/future list proportional to domains.
        for offset in range(0, len(items), 32):
            pending = [pool.submit(probe, item) for item in items[offset : offset + 32]]
            for future in pending:
                future.result(timeout=10)

    began = time.monotonic()
    before = _dns_stats(origin)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        batch(cold)
        after_cold = _dns_stats(origin)
        if not all(counter(after_cold, item) > counter(before, item) for item in cold):
            raise RuntimeError("cold DNS did not execute every controlled query")
        warm_begin = time.monotonic()
        batch(hot)
        warmed = _dns_stats(origin)
        if not all(counter(warmed, item) > counter(before, item) for item in hot):
            raise RuntimeError("hot DNS set was not fully warmed")
        for _ in range(wanted["hot_rounds"]):
            batch(hot)
        after_hot = _dns_stats(origin)
        if time.monotonic() - warm_begin >= 30 or any(
            counter(after_hot, item) != counter(warmed, item) for item in hot
        ):
            raise RuntimeError("hot DNS did not reuse the production cache window")
    if after_hot["rejected"] != before["rejected"]:
        raise RuntimeError("DNS workload escaped the isolated allowlist")
    return {
        "passed": True,
        "kind": "dns",
        "cold_names": len(cold),
        "hot_names": len(hot),
        "hot_rounds": wanted["hot_rounds"],
        "max_concurrency": 32,
        "source_verified_probes": len(cold) + len(hot) * (1 + wanted["hot_rounds"]),
        "core_cold_queries": sum(
            counter(after_cold, item) - counter(before, item) for item in cold
        ),
        "core_hot_queries_after_warmup": 0,
        "seconds": time.monotonic() - began,
    }


def churn_overlap(
    root, work, port, reference, bandwidth, mihomo, positive, spec, cn_bandwidth=None
):
    from .memory_socks_load import _load, address, endpoint

    wanted = spec["overlap"]
    if wanted["tcp"] != wanted["udp"] or positive is None:
        raise ValueError("churn requires equal TCP/UDP and two prescribed proxy paths")
    routes = {item["id"]: item for item in reference["routes"]}
    branches = [
        {
            "route": route + "-" + transport,
            "transport": transport,
            "source": address(peer, spec),
            **(
                {
                    "tun": port,
                    "origin": endpoint(
                        address(
                            cn_bandwidth if route == "domain-first" else bandwidth, spec
                        ),
                        24003,
                    ),
                }
                if spec.get("entrypoint") == "fd-TUN"
                else {
                    "proxy": endpoint(
                        "::1" if spec["family"] == "IPv6" else "127.0.0.1", port
                    ),
                }
            ),
            "target": routes[route]["value"],
        }
        for route, peer in (("domain-first", positive), ("domain-negative", mihomo))
        for transport in ("tcp", "udp")
    ]
    began = time.monotonic()

    def run_probe(directory, exchanges):
        directory.mkdir()
        probe_spec = spec | {
            "flows": wanted["tcp"] + wanted["udp"],
            "mbps": 1,
            "seconds": (exchanges + 19) // 20,
            "direction": "both",
            "witness_seconds": [],
            "probe": True,
            "probe_rounds": exchanges,
            "correctness": False,
            "slow_read": None,
        }
        report = _load(root, directory, probe_spec, bandwidth, branches)
        expected_flows = (wanted["tcp"] + wanted["udp"]) // 4
        for branch in report["branches"]:
            traffic = branch["traffic"]
            if not (
                branch["driver_joined"]
                and branch["driver_exit"] == 0
                and traffic.get("probe") is True
                and traffic.get("probe_rounds") == exchanges
                and traffic.get("complete") is True
                and traffic.get("data_connection_count") == expected_flows
                and len(traffic["flows"]) == expected_flows * 2
                and all(
                    flow["source_verified"]
                    and not flow.get("error")
                    and all(
                        flow[end]["bytes"] == 32 * exchanges
                        and flow[end]["packets"] == exchanges
                        and not flow[end].get("error")
                        for end in ("sent", "received")
                    )
                    for flow in traffic["flows"]
                )
            ):
                save(directory / "result.json", report)
                raise RuntimeError(
                    "churn connection did not complete both probe directions"
                )
        save(directory / "result.json", report)
        return report

    rows = []
    for index in range(wanted["rounds"]):
        run_probe(work / f"churn-{index + 1:03d}", 1)
        rows.append({"round": index + 1, "end_seconds": time.monotonic() - began})
    warm = run_probe(work / "warm-control", wanted["rounds"])
    return {
        "passed": True,
        "kind": "churn",
        "rounds": len(rows),
        "tcp_per_round": wanted["tcp"],
        "udp_per_round": wanted["udp"],
        "background_flows": spec["flows"],
        "max_prescribed_connections": spec["flows"] + wanted["tcp"] + wanted["udp"],
        "probe_bytes_not_bandwidth": (wanted["tcp"] + wanted["udp"]) * 128 * len(rows),
        "warm_connections": wanted["tcp"] + wanted["udp"],
        "warm_exchanges_per_connection": wanted["rounds"],
        "warm_setup_seconds": warm["setup_seconds"],
        "warm_load_seconds": warm["load_seconds"],
        "round_timeline": rows,
        "seconds": time.monotonic() - began,
    }
