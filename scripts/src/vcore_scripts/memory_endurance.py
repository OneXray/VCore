"""Production-ABI lifecycle and frozen endurance schedules; no core test hooks."""

import contextlib
import copy
import json
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path

from .memory_inputs import save
from .memory_resources import capture


def cases(profiles):
    rows = {}
    for entry in ("socks", "tun"):
        for family in ("v4", "v6"):
            for mode in ("lifetimes", "rebuild"):
                for size in ("smoke", "full"):
                    development = size == "smoke"
                    base = profiles[f"profile-{entry}-socks5-{family}-smoke"]
                    rows[f"lifecycle-{entry}-{mode}-{family}-{size}"] = base | {
                        "warm_reuse": False,
                        "development": development,
                        "lifecycle": {
                            "kind": mode,
                            "rounds": 3 if development else 100,
                            "quiet_seconds": 0.25 if development else 5,
                            "cancel_modes": ["active", "query", "handshake"],
                        },
                    }
            base = profiles[f"profile-{entry}-mixed-eight-{family}-standard-1"]
            rows[f"profile-{entry}-mixed-eight-{family}-soak"] = base | {
                "seconds": 1800,
                "warm_reuse": False,
                # The overlap probes themselves verify new routes. Separate
                # control windows avoid racing two clients' select changes.
                "witness_seconds": [35, 280, 875] + list(range(1120, 1800, 35)),
                "events": [
                    {"kind": "dns", "at": 60, "cold": 1024, "hot": 32, "hot_rounds": 8},
                    {"kind": "churn", "at": 300, "rounds": 100, "tcp": 32, "udp": 32},
                    {
                        "kind": "dns",
                        "at": 900,
                        "cold": 1024,
                        "hot": 32,
                        "hot_rounds": 8,
                    },
                ],
            }
            rows[f"profile-{entry}-mixed-eight-{family}-soak-smoke"] = base | {
                "seconds": 20,
                "flows": 32,
                "development": True,
                "warm_reuse": False,
                "witness_seconds": [],
                "events": [
                    {"kind": "churn", "at": 2, "rounds": 2, "tcp": 32, "udp": 32},
                    {"kind": "dns", "at": 12, "cold": 16, "hot": 4, "hot_rounds": 2},
                ],
            }
    for name, spec in list(profiles.items()):
        if not name.endswith("-standard-1"):
            continue
        prefix = name.removesuffix("-standard-1")
        for transport in ("tcp", "udp"):
            for label, seconds in (("soak", 1800), ("pressure", 300)):
                rows[f"{prefix}-{label}-{transport}-1000"] = spec | {
                    "seconds": seconds,
                    "mbps": 1000,
                    "correctness": False,
                    "transport": transport,
                    "warm_reuse": False,
                    "updates": True,
                    "cached_witnesses": True,
                    "witness_seconds": (
                        [35, 280, 875, 1015, 1155] + list(range(1400, 1800, 35))
                    )
                    if label == "soak"
                    else [10, 115, 280],
                    "events": [
                        {
                            "kind": "dns",
                            "at": 60,
                            "cold": 1024,
                            "hot": 32,
                            "hot_rounds": 8,
                        },
                        {
                            "kind": "churn",
                            "at": 300,
                            "rounds": 100,
                            "tcp": 32,
                            "udp": 32,
                        },
                        {
                            "kind": "update",
                            "at": 900,
                            "asset": "geosite",
                            "mode": "replace",
                        },
                        {
                            "kind": "update",
                            "at": 1050,
                            "asset": "geoip",
                            "mode": "replace",
                        },
                        {
                            "kind": "dns",
                            "at": 1200,
                            "cold": 1024,
                            "hot": 32,
                            "hot_rounds": 8,
                        },
                    ]
                    if label == "soak"
                    else [
                        {
                            "kind": "update",
                            "at": 35,
                            "asset": "geosite",
                            "mode": "replace",
                        },
                        {
                            "kind": "dns",
                            "at": 130,
                            "cold": 1024,
                            "hot": 32,
                            "hot_rounds": 8,
                        },
                        {
                            "kind": "churn",
                            "at": 180,
                            "rounds": 100,
                            "tcp": 32,
                            "udp": 32,
                        },
                    ],
                }
    return rows


def install(lab, stack, root, origin):
    directory = root / "cancellation"
    directory.mkdir()
    shutil.copy2(
        Path(__file__).with_name("container_udp_origin.py"), directory / "origin.py"
    )
    peer = lab.start(
        stack,
        directory,
        "memory-cancellation",
        [
            "env",
            "VCORE_ISOLATED_ORIGIN=1",
            "python",
            "-B",
            "/data/fixture/origin.py",
        ],
    )
    peer.release()
    peer.wait_tcp(24000)
    origin.memory_cancel_peer = peer
    return peer


class Pending:
    """Only owned client IPC and existing container origin/DNS blackholes."""

    def __init__(
        self, stack, entry, config, spec, origin, bandwidth, names, index, mode
    ):
        from . import memory_benchmark as lab
        from .memory_socks_load import address

        self.entry, self.spec, self.origin, self.mode = entry, spec, origin, mode
        self.bandwidth, self.thread = bandwidth, None
        self.closed, self.error = False, None
        self.control = None
        if mode == "handshake":
            peer = origin.memory_cancel_peer
            self.control, remote = lab._origin(stack, peer.ipv4, 15)
            self.target = address(peer, spec)
            config["proxies"].append(
                {
                    "name": "pending-handshake",
                    "type": "socks5",
                    "server": peer.ipv4,
                    "port": remote,
                }
            )
            config["rules"].insert(
                0,
                f"{'IP-CIDR6' if ':' in self.target else 'IP-CIDR'},"
                f"{self.target}/{'128' if ':' in self.target else '32'},"
                "pending-handshake,no-resolve",
            )
        elif mode == "query":
            self.item = [n for n in names if n["id"].startswith("dns-cold-")][index]
            self.target = self.item["value"]

    def begin(self):
        from . import memory_benchmark as lab
        from .memory_socks_load import _dns_stats, address
        from .memory_tun import connect, resolve

        if self.mode == "active":
            return
        before = _dns_stats(self.origin) if self.mode == "query" else None
        if before is not None:
            save(
                self.origin.root / "load-dns-control.json",
                {"drop_ids": [self.item["id"]]},
            )

        def client():
            try:
                with contextlib.ExitStack() as stack:
                    if self.spec.get("entrypoint") == "fd-TUN":
                        if self.mode == "query":
                            resolve(
                                self.entry,
                                self.target,
                                address(self.bandwidth, self.spec),
                            )
                        else:
                            stream = stack.enter_context(
                                connect(self.entry, self.target, 443)
                            )
                            stream.sendall(b"pending-handshake")
                            if stream.recv(1):
                                self.error = (
                                    "blackhole unexpectedly sent application bytes"
                                )
                    else:
                        lab._socks(
                            stack, self.entry, self.target, 443, prefix=b"pending"
                        )
                        self.error = "pending SOCKS request unexpectedly completed"
            except (OSError, RuntimeError, EOFError):
                pass
            finally:
                self.closed = True

        self.thread = threading.Thread(target=client, daemon=True)
        self.thread.start()
        if self.control:
            if lab._exact(self.control, 1) != b"A":
                raise RuntimeError("handshake did not reach isolated blackhole")
        else:
            deadline = time.monotonic() + 3
            prefix = self.item["id"] + ":"
            while not any(
                k.startswith(prefix) and v > before["queries"].get(k, 0)
                for k, v in _dns_stats(self.origin)["queries"].items()
            ):
                if time.monotonic() >= deadline:
                    raise RuntimeError("cancellation did not reach owned DNS query")
                time.sleep(0.01)
        if not self.thread.is_alive():
            raise RuntimeError("pending operation ended before Stop")

    def join(self):
        if self.thread:
            self.thread.join(timeout=6)
            if self.thread.is_alive() or not self.closed or self.error:
                raise RuntimeError(self.error or "cancelled client did not join")
        if self.mode == "query":
            save(self.origin.root / "load-dns-control.json", {"drop_ids": []})


def cycles(process, spec, config, work, entry, origin, bandwidth, names, load_at, tun):
    from . import memory_benchmark as lab

    wanted = spec["lifecycle"]
    rows = []
    # The primary data round warms process-global runtime setup before comparing
    # fd retention, but it remains inside the same lifetime peak.
    lab._api(process, "stop", instance=process.instance)
    fd_command = f"D {tun.host.fileno() if tun else 0}"
    baseline = process.command(fd_command)
    for index in range(wanted["rounds"]):
        directory = work / f"cycle-{index + 1:03d}"
        directory.mkdir()
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mode = wanted["cancel_modes"][index % len(wanted["cancel_modes"])]
        with contextlib.ExitStack() as stack:
            if wanted["kind"] == "lifetimes":
                lab._api(process, "destroyInstance", instance=process.instance)
                lab._api(process, "createInstance")
            instance = process.instance
            rejected = process.invoke(
                "prepare", {"configYaml": '{"unknown-memory-key":true}'}, instance
            )
            if rejected.get("success"):
                raise RuntimeError("invalid prepare unexpectedly succeeded")
            current = copy.deepcopy(config)
            pending = Pending(
                stack, entry, current, spec, origin, bandwidth, names, index, mode
            )
            lab._api(process, "prepare", {"configYaml": json.dumps(current)}, instance)
            lab._api(
                process,
                "start",
                {"tunFd": tun.host.fileno(), "tunFraming": "utun"} if tun else {},
                instance,
            )
            stop = {}

            def interrupt(instance=instance, stop=stop):
                start = time.monotonic()
                lab._api(process, "stop", instance=instance)
                stop.update(
                    seconds=time.monotonic() - start, fd=process.command(fd_command)
                )
                if stop["seconds"] >= 5 or stop["fd"] != baseline:
                    raise RuntimeError("Stop did not synchronously restore fd baseline")
                stop["snapshot"] = process.boundary("cycle-stop-returned")

            try:
                load = load_at(directory, interrupt=interrupt, on_ready=pending.begin)
            finally:
                # Every helper is joined, including failure/early-return paths.
                if not stop:
                    lab._api(process, "stop", instance=instance)
                pending.join()
            if not (
                stop
                and load["interrupted"]
                and all(b["driver_joined"] for b in load["branches"])
            ):
                raise RuntimeError("active-load Stop was not actually exercised")
            diagnostics = capture(process.child.pid, started, directory)
            if not diagnostics.get("final_current_zero"):
                raise RuntimeError("Stop resource-zero production evidence unavailable")
            quiet_start = time.monotonic()
            while time.monotonic() - quiet_start < wanted["quiet_seconds"]:
                if process.command(fd_command) != baseline:
                    raise RuntimeError("new fd activity after Stop")
                time.sleep(0.05)
            row = dict(
                cycle=index + 1,
                instance=instance,
                mode=mode,
                prepare_recovered=True,
                stop=stop,
                quiet_seconds=time.monotonic() - quiet_start,
                resources_zero=True,
                clients_joined=True,
                sample=process.boundary("cycle-quiet"),
            )
            save(directory / "load.json", load)
            save(directory / "cycle.json", row)
            rows.append(row)
    return {
        "kind": wanted["kind"],
        "rounds": rows,
        "pid": process.child.pid,
        "baseline_fds": baseline,
        "passed": True,
    }
