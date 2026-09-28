"""Recompute lifecycle/pressure gates from bounded, persisted observations."""

from __future__ import annotations

from math import isfinite
from statistics import median

from .protocol_evidence import RESOURCE_KINDS, idle_resources

NEW = ["trojan", "vmess", "vless", "hysteria2"]
QUEUES = {
    "socks_udp": 16,
    "hysteria2_udp": 32,
    "quic_incoming": 32,
    "quic_outgoing": 32,
}


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def resources(value, *, active=False):
    rows = value.get("counts", [])
    if len(rows) != 8 or {r.get("kind") for r in rows} != RESOURCE_KINDS:
        return False
    if not all(
        integer(r.get("current"))
        and integer(r.get("peak"))
        and r["current"] <= r["peak"]
        for r in rows
    ):
        return False
    counts = {r["kind"]: r["current"] for r in rows}
    return not active or all(
        counts[k] > 0 for k in ("task", "socket", "session", "association")
    )


def sample(value, *, active=True):
    queues = value.get("queues", [])
    return (
        integer(value.get("heap_in_use"), 1)
        and integer(value.get("rss_kib"), 1)
        and integer(value.get("fd"), 1)
        and resources(value.get("resources", {}), active=active)
        and len(queues) == 4
        and {q.get("kind"): q.get("capacity") for q in queues} == QUEUES
        and all(
            integer(q.get("peak"), 1) and q["peak"] <= q["capacity"] for q in queues
        )
    )


def lifetimes(value, events):
    cycles = value.get("cycles", [])
    passes = [e for e in events if e.get("status") == "PASS"]
    if value.get("count") != 100 or len(cycles) != 100 or len(passes) != 100:
        return False
    for index, (row, event) in enumerate(zip(cycles, passes, strict=True)):
        stop = row.get("after_stop", {})
        checkpoints = event.get("checkpoints", [])
        mode = index % 5
        retained = {0: 0, 1: 10, 2: 1, 3: 0, 4: 8}[mode]
        if not (
            row.get("cycle") == index
            and row.get("protocol") == NEW[(index // 5) % 4]
            and row.get("mode") == mode
            and integer(row.get("baseline_fd"), 1)
            and row.get("retained_fixture_fd") == retained
            and integer(row.get("after_stop_fd"), 1)
            and row["after_stop_fd"] <= row["baseline_fd"] + retained
            and integer(row.get("final_fd"), 1)
            and row["final_fd"] <= row["baseline_fd"]
            and integer(row.get("stop_ms"))
            and row["stop_ms"] < 5000
            and isfinite(row.get("quiet_seconds", 0))
            and row.get("quiet_seconds", 0) >= 5
            and row.get("ports_rebound") is True
            and idle_resources(stop)
            and row.get("quiet") == stop == event.get("resources")
            and len(checkpoints) == 4
            and [p.get("phase") for p in checkpoints]
            == ["baseline", "active", "after-stop", "quiet"]
            and idle_resources(checkpoints[0].get("resources"))
            and checkpoints[1].get("resources") == row.get("active")
            and resources(row.get("active", {}))
            and checkpoints[2].get("resources")
            == stop
            == checkpoints[3].get("resources")
        ):
            return False
        if mode in (1, 4) and not resources(row["active"], active=True):
            return False
    return True


def stopped(value, event):
    cold, baseline = value.get("cold_fd"), value.get("baseline_fd")
    row = value.get("stopped", {})
    after, quiet = row.get("after_stop", {}), row.get("quiet", {})
    return (
        integer(cold, 1)
        and integer(baseline, 1)
        and 0 <= baseline - cold <= 2
        and integer(row.get("stop_ms"))
        and row["stop_ms"] < 5000
        and isfinite(row.get("quiet_seconds", 0))
        and row.get("quiet_seconds", 0) >= 5
        and row.get("ports_rebound") is True
        and sample(after, active=False)
        and sample(quiet, active=False)
        and idle_resources(after.get("resources"))
        and quiet.get("resources") == after.get("resources") == event.get("resources")
        and after["fd"] <= baseline
        and quiet["fd"] <= baseline
    )


def setup(values):
    return (
        isinstance(values, list)
        and len(values) == 40
        and all(integer(v, 1) and v < 10_000_000 for v in values)
    )


def rebuild(value, event):
    rows = value.get("cycles", [])
    return (
        value.get("count") == 100
        and value.get("same_running_session") is True
        and value.get("protocols") == NEW
        and len(rows) == 100
        and stopped(value, event)
        and all(
            row.get("generation") == i
            and row.get("tcp") == row.get("udp") == 20
            and row.get("per_protocol_tcp") == row.get("per_protocol_udp") == 5
            and sample(row.get("active", {}))
            and sample(row.get("after_clients", {}), active=False)
            and setup(row.get("setup_us"))
            and row.get("fault") == "owned-peer-connections-closed"
            and row.get("new_clients") is True
            for i, row in enumerate(rows)
        )
    )


def soak(value, event, curve):
    points, faults, switches = (
        value.get("samples", []),
        value.get("faults", []),
        value.get("switches", []),
    )
    if not (
        value.get("requested_seconds") == 1800
        and 1800 <= value.get("seconds", 0) < 1860
        and value.get("protocols") == NEW
        and value.get("tcp") == value.get("udp") == 20
        and value.get("per_protocol_tcp") == value.get("per_protocol_udp") == 5
        and integer(value.get("waves"), 1)
        and value.get("normal_verified_bytes") == value["waves"] * 20 * 2 * 2 * 257
        and all(
            value.get(k) == 0
            for k in (
                "normal_corruption",
                "normal_misdirection",
                "normal_unexpected_loss",
            )
        )
        and len(points) >= 25
        and points == curve
        and 29 <= len(faults) <= 30
        and len(switches) >= 1799
        and all(i <= t < i + 5 for i, t in enumerate(switches, 1))
        and all(
            60 * i <= row.get("start", 0) < 60 * i + 5
            and row["start"] <= row.get("end", 0) < row["start"] + 10
            and row.get("old_tcp_closed")
            == row.get("new_tcp")
            == row.get("new_udp")
            == 20
            and row.get("replay") is False
            for i, row in enumerate(faults, 1)
        )
        and all(
            sample(p) and 300 + 60 * i <= p.get("seconds", 0) < 310 + 60 * i
            for i, p in enumerate(points)
        )
        and stopped(value, event)
        and sample(value.get("active_end", {}))
        and setup(value.get("first_setup_us"))
        and setup(value.get("last_setup_us"))
    ):
        return False
    first_setup, last_setup = (
        int(median(value[k])) for k in ("first_setup_us", "last_setup_us")
    )
    early, late = points[:10], points[-10:]
    first, last = (
        int(median(p["heap_in_use"] for p in rows)) for rows in (early, late)
    )
    allowed = max(1024 * 1024, first // 20)

    def counts(rows, kind):
        return max(
            next(r["current"] for r in p["resources"]["counts"] if r["kind"] == kind)
            for p in rows
        )

    return (
        first_setup == value.get("first_setup_median_us")
        and last_setup == value.get("last_setup_median_us") <= 2 * first_setup
        and value.get("heap")
        == dict(early_median=first, late_median=last, allowed_growth=allowed)
        and last <= first + allowed
        and all(counts(late, kind) <= counts(early, kind) for kind in RESOURCE_KINDS)
        and max(p["fd"] for p in late) <= max(p["fd"] for p in early)
    )
