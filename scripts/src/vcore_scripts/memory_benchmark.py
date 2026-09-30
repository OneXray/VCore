"""Production-ABI memory experiments; not physical mobile Provider acceptance."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from . import builds
from . import memory_cold_start as cold
from . import memory_socks_load as socks_load
from .memory_geodata import generate as geodata_reference
from .memory_inputs import RunStore, acquire_rules, bandwidth_complete, save
from .memory_process import (
    FIXTURES,
    MeasuredProcess,
    Observer,
    build_observer,
    calibration,
)
from .mihomo_isolation import exclusive_run, reserve_port
from .mihomo_release import download_mihomo
from .protocol_containers import NETWORK, ContainerLab, command, frozen_image, listing
from .protocol_inputs import redact, sha256, source_identity
from .protocol_peers import OwnedProcess, run_command

ROOT = builds.CORE_DIR / "target/memory"
CALIBRATIONS = (
    "empty",
    "transient",
    "over-limit",
    "sampling-failure",
    "crash",
    "missing-final",
    "wrong-pid",
)
CASES = (
    tuple(f"calibrate-{name}" for name in CALIBRATIONS)
    + (
        "smoke-1",
        "smoke-2",
        "smoke-3",
        "full-cn-loader",
        "early-load",
        "cleanup-failure",
    )
    + tuple(
        f"bandwidth-{path}-{transport}-{direction}"
        for path in ("direct", "mihomo")
        for transport in ("tcp", "udp")
        for direction in ("up", "down", "both")
    )
)
CAPACITY_CASES = {
    f"capacity-{path}-{transport}-{direction}-{flows}-{repeat}": {
        "path": path,
        "transport": transport,
        "direction": direction,
        "flows": flows,
        "seconds": 10,
        "mbps": 1000,
    }
    for repeat in range(1, 4)
    for flows in (1, 16, 64)
    for direction in ("up", "down", "both")
    if direction != "both" or flows != 1
    for transport in ("tcp", "udp")
    for path in ("direct", "mihomo")
}


def _source():
    identity = source_identity()
    manifest = tomllib.loads((builds.CORE_DIR / "Cargo.toml").read_text())
    dependency = manifest["dependencies"]["boring"]
    if "path" in dependency:
        fork = (builds.CORE_DIR / dependency["path"]).resolve()

        def git(*args):
            return subprocess.check_output(
                ["git", *args], cwd=fork, text=True, timeout=20
            ).strip()

        if git("status", "--porcelain", "--untracked-files=normal"):
            raise ValueError("memory evidence needs a clean local boring fork")
        identity["boring"] = {
            "commit": git("rev-parse", "HEAD"),
            "tree": git("rev-parse", "HEAD^{tree}"),
        }
    else:
        lock = tomllib.loads((builds.CORE_DIR / "Cargo.lock").read_text())
        identity["boring"] = next(p for p in lock["package"] if p["name"] == "boring")
    return identity


def _command(argv, directory, name, *, env=None, timeout=120, output_limit=1024 * 1024):
    outcome = run_command(
        [str(arg) for arg in argv],
        timeout=timeout,
        cwd=builds.CORE_DIR,
        env=env,
        limit=output_limit,
    )
    (directory / (name + ".log")).write_bytes(outcome.stdout)
    save(
        directory / (name + ".command.json"),
        {
            "argv": [str(arg) for arg in argv],
            "exit_code": outcome.returncode,
            "joined": outcome.cleanup,
            "seconds": outcome.seconds,
            "output_limit_bytes": output_limit,
        },
    )
    if outcome.returncode != 0 or not outcome.cleanup:
        raise RuntimeError(f"memory tool command failed: {name}")
    return outcome.stdout.decode(errors="replace").strip()


def _build(directory):
    hidden = [
        key
        for key in os.environ
        if key
        in {
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WRAPPER",
            "CARGO_TARGET_DIR",
            "VCORE_FEATURES",
        }
        or key.startswith(("CARGO_PROFILE_", "DYLD_", "Malloc"))
    ]
    if hidden:
        raise ValueError(
            "unset hidden build/instrumentation overrides for production measurement"
        )
    artifacts = build_observer(directory)
    features = builds.DEFAULT_FEATURES
    _command(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--lib",
            "--target",
            "aarch64-apple-darwin",
            "--no-default-features",
            "--features",
            features,
        ],
        directory,
        "cargo-build",
        env=os.environ
        | {
            "MACOSX_DEPLOYMENT_TARGET": "10.15",
            "CARGO_PROFILE_RELEASE_PANIC": "unwind",
        },
        timeout=1800,
    )
    library = builds.CORE_DIR / "target/aarch64-apple-darwin/release/libvcore.a"
    builds._require_identity(library, "memory")
    host = directory / "vcore-host"
    _command(
        [
            "xcrun",
            "clang",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            builds.CORE_DIR / "include",
            FIXTURES / "host.c",
            FIXTURES / "observer.c",
            library,
            "-lc++",
            "-lresolv",
            "-framework",
            "Security",
            "-framework",
            "SystemConfiguration",
            "-framework",
            "CoreFoundation",
            "-framework",
            "Foundation",
            "-o",
            host,
        ],
        directory,
        "link-host",
    )
    artifacts["host"] = host
    for target in ("darwin", "linux"):
        binary = directory / f"traffic-{target}"
        _command(
            ["go", "build", "-trimpath", "-o", binary, FIXTURES / "traffic.go"],
            directory,
            "build-traffic-" + target,
            env=os.environ | {"GOOS": target, "GOARCH": "arm64", "CGO_ENABLED": "0"},
        )
        artifacts["traffic-" + target] = binary
    return artifacts, sha256(library)


def prerequisites():
    """Read-only inventory. A signing identity alone is not an NE entitlement."""
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("memory process runner requires native Apple Silicon macOS")
    inventory = run_command(["xcrun", "devicectl", "list", "devices"], timeout=30)
    signing = run_command(
        ["security", "find-identity", "-v", "-p", "codesigning"], timeout=30
    )
    identities = re.search(rb"(\d+) valid identities found", signing.stdout)
    physical = sum(
        "physical" in line.lower() for line in inventory.stdout.decode().splitlines()
    )
    return {
        "host": {"os": platform.platform(), "architecture": platform.machine()},
        "device_inventory_exit": inventory.returncode,
        "physical_devices_detected": physical,
        "signing_identity_count": int(identities[1]) if identities else None,
        "external_gates": {
            "ios_tvos_provider": {
                "status": "BLOCKED",
                "needs": "physical devices and production Release Packet Tunnel host "
                "with verified entitlements",
            },
            "device_peer_network": {
                "status": "BLOCKED",
                "needs": "approved device-reachable isolated test network; "
                "host-only is not device evidence",
            },
            "trusted_tls_update_identity": {
                "status": "BLOCKED",
                "needs": "owned domain and production-trusted TLS/update certificate; "
                "no test trust injection",
            },
        },
    }


def _recover_resources(root):
    journal = root / "resources.json"
    if not journal.exists():
        return
    previous = json.loads(journal.read_text())
    names = {p["name"] for p in previous.get("peers", [])}
    for item in listing():
        if item["id"] not in names:
            continue
        labels = item["configuration"].get("labels", {})
        if (
            labels.get("purpose") != NETWORK
            or labels.get("vcore-run") != previous["run_id"]
        ):
            raise RuntimeError(
                "owned memory container identity changed; refusing cleanup"
            )
        if item["status"]["state"] == "running":
            command("stop", "--time", "5", item["id"], timeout=15)
        command("delete", "--force", item["id"], timeout=15)
    if any(item["id"] in names for item in listing()):
        raise RuntimeError("memory recovery did not clean owned peers")
    save(
        root / ("recovery-" + str(time.time_ns()) + ".json"),
        {"previous": previous, "cleanup": True},
    )


@contextlib.contextmanager
def _peers(root, manifest):
    _recover_resources(root)
    record = {}
    lab = ContainerLab(
        record,
        mtu=1500,
        image_digest=manifest["image"]["digest"],
        checkpoint=lambda value: save(root / "resources.json", value),
    )
    with tempfile.TemporaryDirectory(prefix="peers-", dir=root) as temporary:
        directories = {}
        workloads = manifest.get("socks_load_workloads", {})
        family = next(iter(workloads.values()), {}).get("family", "IPv4")
        needs_positive = any(
            spec.get("topology") == "proxy" for spec in workloads.values()
        )
        needs_tun = any(
            spec.get("entrypoint") == "fd-TUN" for spec in workloads.values()
        )
        positive = None
        cn_bandwidth = None
        try:
            with contextlib.ExitStack() as stack:
                for role in (
                    ("origin", "bandwidth", "mihomo")
                    + (("positive",) if needs_positive else ())
                    + (("cn-bandwidth",) if needs_tun else ())
                ):
                    directory = Path(temporary) / role
                    directory.mkdir()
                    directories[role] = directory
                    shutil.copy2(
                        FIXTURES / "guest_metrics.py", directory / "metrics.py"
                    )
                shutil.copy2(
                    Path(__file__).with_name("container_udp_origin.py"),
                    directories["origin"] / "origin.py",
                )
                origin_script = "origin.py"
                if manifest.get("socks_load_workloads"):
                    origin_script = "load_dns.py"
                    shutil.copy2(
                        FIXTURES / origin_script, directories["origin"] / origin_script
                    )
                elif "geodata_reference" in manifest:
                    origin_script = "cn_origin.py"
                    shutil.copy2(
                        FIXTURES / origin_script, directories["origin"] / origin_script
                    )
                    save(
                        directories["origin"] / "cn-names.json",
                        sorted(
                            {
                                item["value"]
                                for item in manifest["geodata_reference"]["routes"]
                                if item["kind"] == "site"
                            }
                            | {"vcore-fixture.test"}
                        ),
                    )
                shutil.copy2(
                    root / "artifacts/traffic-linux",
                    directories["bandwidth"] / "traffic",
                )
                shutil.copy2(
                    root / "artifacts/mihomo", directories["mihomo"] / "mihomo"
                )
                mihomo_config = {
                    "socks-port": 1080,
                    "allow-lan": True,
                    "bind-address": "*",
                    "ipv6": True,
                    "log-level": "warning",
                    # High-rate UDP flows must not funnel into one peer
                    # receive socket. This is one official process with
                    # unchanged socket defaults, not single-flow acceptance.
                    "listeners": [
                        {
                            "name": f"memory-{index}",
                            "type": "socks",
                            "listen": "::",
                            "port": 1080 + index,
                            "udp": True,
                        }
                        for index in range(1, manifest.get("peer_udp_listeners", 16))
                    ],
                }
                origin = lab.start(
                    stack,
                    directories["origin"],
                    "memory-origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "python",
                        "-B",
                        "/data/fixture/" + origin_script,
                    ],
                )
                bandwidth = lab.start(
                    stack,
                    directories["bandwidth"],
                    "memory-bandwidth",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "/data/fixture/traffic",
                        "-mode",
                        "origin",
                        "-udp-pacing-credit",
                        str(manifest.get("udp_pacing_credit_records", 16)),
                    ],
                    cpus=4,
                )
                if needs_tun:
                    shutil.copy2(
                        root / "artifacts/traffic-linux",
                        directories["cn-bandwidth"] / "traffic",
                    )
                    cn_bandwidth = lab.start(
                        stack,
                        directories["cn-bandwidth"],
                        "memory-cn-bandwidth",
                        [
                            "env",
                            "VCORE_ISOLATED_ORIGIN=1",
                            "/data/fixture/traffic",
                            "-mode",
                            "origin",
                        ],
                        cpus=4,
                    )
                # A failed CN reject test must never dial a public rule target.
                mihomo_config["rules"] = [
                    f"IP-CIDR,{origin.ipv4}/32,DIRECT,no-resolve",
                    f"IP-CIDR6,{origin.ipv6}/128,DIRECT,no-resolve",
                    f"IP-CIDR,{bandwidth.ipv4}/32,DIRECT,no-resolve",
                    f"IP-CIDR6,{bandwidth.ipv6}/128,DIRECT,no-resolve",
                    "MATCH,REJECT",
                ]
                if cn_bandwidth:
                    mihomo_config["rules"][:0] = [
                        f"IP-CIDR,{cn_bandwidth.ipv4}/32,DIRECT,no-resolve",
                        f"IP-CIDR6,{cn_bandwidth.ipv6}/128,DIRECT,no-resolve",
                    ]
                if workloads:
                    # CN hits remain domain targets when VCore delegates DNS to
                    # SOCKS5. IP-only no-resolve fences would reject them before
                    # the peer can query the isolated DNS oracle. Allow exactly
                    # the controlled names, retaining REJECT for everything else.
                    mihomo_config["rules"] = [
                        f"DOMAIN,{item['value']},DIRECT"
                        for item in manifest.get(
                            "load_dns_names", manifest["geodata_reference"]["routes"]
                        )
                        if item["kind"] == "site"
                    ] + mihomo_config["rules"]
                    mihomo_config["dns"] = {
                        "enable": True,
                        "ipv6": family == "IPv6",
                        "use-hosts": False,
                        "use-system-hosts": False,
                        "nameserver": [f"udp://{origin.ipv4}:24004"],
                    }
                save(directories["mihomo"] / "config.json", mihomo_config)
                mihomo = lab.start(
                    stack,
                    directories["mihomo"],
                    "memory-mihomo",
                    [
                        "/data/fixture/mihomo",
                        "-d",
                        "/data",
                        "-f",
                        "/data/fixture/config.json",
                    ],
                    cpus=manifest.get("peer_cpus", 8),
                )
                if needs_positive:
                    shutil.copy2(
                        root / "artifacts/mihomo", directories["positive"] / "mihomo"
                    )
                    save(directories["positive"] / "config.json", mihomo_config)
                    positive = lab.start(
                        stack,
                        directories["positive"],
                        "memory-positive",
                        [
                            "/data/fixture/mihomo",
                            "-d",
                            "/data",
                            "-f",
                            "/data/fixture/config.json",
                        ],
                        cpus=manifest.get("peer_cpus", 8),
                    )
                from . import memory_protocols

                auxiliary = memory_protocols.install(
                    root,
                    manifest,
                    lab,
                    stack,
                    directories,
                    origin,
                    bandwidth,
                    cn_bandwidth,
                    mihomo,
                    positive,
                    mihomo_config,
                )
                if any(spec.get("lifecycle") for spec in workloads.values()):
                    from . import memory_endurance

                    auxiliary.append(
                        memory_endurance.install(
                            lab,
                            stack,
                            Path(temporary),
                            origin,
                        )
                    )
                if "update_fixture" in manifest:
                    from . import memory_updates

                    auxiliary.append(
                        memory_updates.install(
                            root,
                            manifest,
                            lab,
                            stack,
                            directories,
                            origin,
                        )
                    )
                if manifest.get("socks_load_workloads"):
                    save(
                        directories["origin"] / "load-dns.json",
                        {
                            "names": [
                                item
                                for item in manifest.get(
                                    "load_dns_names",
                                    manifest["geodata_reference"]["routes"],
                                )
                                if item["kind"] == "site"
                            ],
                            "target": bandwidth.ipv6
                            if family == "IPv6"
                            else bandwidth.ipv4,
                            "core_source": socks_load.host_source(bandwidth.ipv4),
                            "peer_source": mihomo.ipv4,
                            "peer_sources": [mihomo.ipv4]
                            + ([positive.ipv4] if positive else [])
                            + [peer.ipv4 for peer in auxiliary],
                            "targets": (
                                {
                                    item["id"]: socks_load.address(
                                        cn_bandwidth, {"family": family}
                                    )
                                    for item in manifest["geodata_reference"]["routes"]
                                    if cn_bandwidth
                                    and item["kind"] == "site"
                                    and item["matched"]
                                }
                                | (
                                    {
                                        "update-endpoint": socks_load.address(
                                            origin.memory_update_peer,
                                            {"family": family},
                                        )
                                    }
                                    if "update_fixture" in manifest
                                    else {}
                                )
                            ),
                        },
                    )
                version = command(
                    "exec", mihomo.name, "/data/fixture/mihomo", "-v"
                ).strip()
                digest = command(
                    "exec", mihomo.name, "sha256sum", "/data/fixture/mihomo"
                ).split()[0]
                if (
                    digest != manifest["peer"]["binary_sha256"]
                    or manifest["peer"]["release"] not in version
                ):
                    raise RuntimeError("actual official peer identity mismatch")
                record["peer_version"] = version
                if positive:
                    positive_version = command(
                        "exec", positive.name, "/data/fixture/mihomo", "-v"
                    ).strip()
                    positive_digest = command(
                        "exec", positive.name, "sha256sum", "/data/fixture/mihomo"
                    ).split()[0]
                    if positive_digest != digest or positive_version != version:
                        raise RuntimeError("positive-route peer identity mismatch")
                    positive.release()
                    positive.wait_tcp(1080)
                    positive.record.update(ipv4=positive.ipv4, ipv6=positive.ipv6)
                for peer, port in ((origin, 24000), (bandwidth, 24003), (mihomo, 1080)):
                    peer.release()
                    peer.wait_tcp(port)
                    peer.record.update(ipv4=peer.ipv4, ipv6=peer.ipv6)
                if cn_bandwidth:
                    cn_bandwidth.release()
                    cn_bandwidth.wait_tcp(24003)
                    cn_bandwidth.record.update(
                        ipv4=cn_bandwidth.ipv4, ipv6=cn_bandwidth.ipv6
                    )
                save(root / "resources.json", record)
                yield origin, bandwidth, mihomo, positive, cn_bandwidth
                for peer in (origin, bandwidth, mihomo) + (
                    (positive,) if positive else ()
                ):
                    peer.ensure_alive()
                if cn_bandwidth:
                    cn_bandwidth.ensure_alive()
                for peer in auxiliary:
                    peer.ensure_alive()
        finally:
            save(root / "resources.json", record)
            logs = root / ("peer-logs-" + str(time.time_ns()))
            logs.mkdir()
            for role, directory in directories.items():
                if (directory / "peer.log").exists():
                    (logs / (role + ".log")).write_text(
                        redact((directory / "peer.log").read_text(errors="replace"))
                    )
    if not all(p["joined"] and p.get("log_cleanup") for p in record["peers"]):
        raise RuntimeError("memory container cleanup incomplete")


def _exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError("traffic driver received early EOF")
        data.extend(chunk)
    return bytes(data)


def _origin(stack, host, mode):
    control = stack.enter_context(socket.create_connection((host, 24000), timeout=5))
    control.sendall(bytes([mode]))
    return control, struct.unpack("!H", _exact(control, 2))[0]


def _address(host, port):
    try:
        raw = b"\x01" + socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            raw = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            value = host.encode("ascii")
            raw = bytes([3, len(value)]) + value
    return raw + struct.pack("!H", port)


def _socks(stack, port, host, remote, command_id=1, *, expected_status=0, prefix=b""):
    stream = stack.enter_context(
        socket.create_connection(("127.0.0.1", port), timeout=5)
    )
    stream.sendall(b"\x05\x01\x00")
    if _exact(stream, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed")
    stream.sendall(bytes([5, command_id, 0]) + _address(host, remote) + prefix)
    header = _exact(stream, 4)
    if header != bytes([5, expected_status, 0, 1]):
        raise RuntimeError("SOCKS request failed")
    reply = _exact(stream, 6)
    return stream, (
        socket.inet_ntop(socket.AF_INET, reply[:4]),
        struct.unpack("!H", reply[4:])[0],
    )


def _api(process, method, payload=None, instance=None):
    response = process.invoke(method, payload, instance)
    if not response.get("success"):
        raise RuntimeError(f"Invoke {method} failed")
    return response["data"]


def _available_cn(state):
    return set(state) == {"geosite", "geoip"} and all(
        value["required"] and value["available"] and value["lastError"] is None
        for value in state.values()
    )


def _cn_routes(process, instance, config, dns, origin, mihomo, reference):
    def accepts():
        return json.loads(
            command("exec", mihomo.name, "python", "/data/fixture/metrics.py")
        )["tcp"]["PassiveOpens"]

    port = config["socks-port"]
    before = accepts()
    rejected = []
    for item in reference["routes"]:
        if item["matched"]:
            with contextlib.ExitStack() as traffic:
                _socks(traffic, port, item["value"], 443, expected_status=2)
            rejected.append(
                {
                    "id": item["id"],
                    "status": 2,
                    "rule": "GEOSITE" if item["kind"] == "site" else "GEOIP",
                }
            )
    after = accepts()
    if after != before or select.select([dns], [], [], 0.1)[0]:
        raise RuntimeError("CN reject opened upstream transport or DNS")
    process.boundary("cn-reject-complete")
    _api(process, "stop", instance=instance)
    # Second public lifecycle: GeoSite hits must really reach the isolated
    # origin directly, misses must use the proxy. No public CN IP is forwarded.
    config["rules"][0] = "GEOSITE,cn,DIRECT"
    _api(process, "prepare", {"configYaml": json.dumps(config)}, instance)
    if not _available_cn(_api(process, "getGeoDataState")):
        raise RuntimeError("complete CN lost availability on reprepare")
    _api(process, "start", instance=instance)
    forwarded = []
    items = [item for item in reference["routes"] if item["kind"] == "site"] + [
        {"id": "ip4-negative", "kind": "ip", "value": origin.ipv4, "matched": False},
        {"id": "ip6-negative", "kind": "ip", "value": origin.ipv6, "matched": False},
    ]
    for item in items:
        before_route = accepts()
        with contextlib.ExitStack() as traffic:
            ipv6 = item["id"] == "ip6-negative"
            observer, remote = _origin(traffic, origin.ipv4, 154 if ipv6 else 26)
            tcp, _ = _socks(traffic, port, item["value"], remote)
            if _exact(observer, 1) != b"A":
                raise RuntimeError("CN route missing isolated origin witness")
            family = 6 if ipv6 else 4
            if _exact(observer, 1) != bytes([family]):
                raise RuntimeError("CN route origin address family mismatch")
            source = socket.inet_ntop(
                socket.AF_INET6 if ipv6 else socket.AF_INET,
                _exact(observer, 16 if ipv6 else 4),
            )
            expected_source = (
                observer.getsockname()[0]
                if item["matched"]
                else mihomo.ipv6
                if ipv6
                else mihomo.ipv4
            )
            if source != expected_source:
                raise RuntimeError(
                    f"CN DIRECT/proxy origin source mismatch: {item['id']}"
                )
            if item["kind"] == "site":
                size, _ = struct.unpack("!HH", _exact(dns, 4))
                query = _exact(dns, size)
                wire = (
                    b"".join(
                        bytes([len(label)]) + label.encode("ascii")
                        for label in item["value"].split(".")
                    )
                    + b"\0"
                )
                if query[12 : 12 + len(wire)] != wire:
                    raise RuntimeError("CN route did not use controlled DNS")
            payload = bytes(range(256))
            tcp.sendall(payload)
            if _exact(tcp, len(payload)) != payload:
                raise RuntimeError("CN route payload mismatch")
            tcp.close()
            if _exact(observer, 1) != b"D":
                raise RuntimeError("CN origin did not finish")
        after_route = accepts()
        delta = after_route - before_route
        # Guest-wide PassiveOpens is not an application accept count. The
        # origin's exact peer identity above is the per-connection route proof.
        forwarded.append(
            {
                "id": item["id"],
                "action": "DIRECT" if item["matched"] else "route",
                "source_verified": True,
                "guest_passive_opens": delta,
                "bytes_each_direction": 256,
            }
        )
    process.boundary("cn-routes-complete")
    return {
        "rejected": rejected,
        "reject_peer_accepts": after - before,
        "reject_dns_queries": 0,
        "forwarded": forwarded,
    }


def _smoke(name, root, manifest, work, origin, mihomo):
    artifacts = root / "artifacts"
    with contextlib.ExitStack() as stack:
        port, reservation = reserve_port(stack)
        dns, dns_port = _origin(stack, origin.ipv4, 17)
        data_dir = work / "data"
        data_dir.mkdir()
        full_cn = name == "full-cn-loader"
        if full_cn:
            geodata = data_dir / "geodata"
            geodata.mkdir()
            for asset in ("geosite.dat", "geoip.dat"):
                shutil.copy2(
                    root / "rules" / manifest["rules"]["directory"] / asset,
                    geodata / asset,
                )
        config = {
            "socks-port": port,
            "ipv6": full_cn,
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
            "rules": (
                ["GEOSITE,cn,REJECT", "GEOIP,CN,REJECT,no-resolve"] if full_cn else []
            )
            + [f"IP-CIDR,{origin.ipv4}/32,route", "MATCH,route"],
        }
        process = MeasuredProcess(
            artifacts / "vcore-host", artifacts / "observer.dylib", work
        )
        data = {"expected_tcp_bytes": 1024 * 1024, "expected_udp_packets": 30}
        record = {"case": name, "data": data, "accepted": False}
        try:
            version = _api(process, "version")
            if version["buildIdentity"] != builds.EXPECTED_IDENTITY.decode():
                raise RuntimeError("measured library identity mismatch")
            _api(process, "initialize", {"dataDir": str(data_dir)})
            instance = _api(process, "createInstance")["instanceId"]
            _api(process, "prepare", {"configYaml": json.dumps(config)}, instance)
            geostate = _api(process, "getGeoDataState")
            record["geodata"] = geostate
            if full_cn:
                # A degraded snapshot may coexist with successful prepare. It
                # must never become a low-memory PASS for complete CN.
                record["geodata_available"] = _available_cn(geostate)
                if not record["geodata_available"]:
                    raise RuntimeError(
                        "complete CN loader unavailable; invalid memory evidence"
                    )
            else:
                if any(item["required"] for item in geostate.values()):
                    raise RuntimeError("no-GeoData smoke unexpectedly needs assets")
            if not full_cn or record.get("geodata_available"):
                reservation.release_ipv4()
                if full_cn:
                    reservation.release_ipv6()
                _api(process, "start", instance=instance)
                if _api(process, "getState", instance=instance)["state"] != "running":
                    raise RuntimeError("runtime failed before traffic")
                process.boundary("traffic")
                if full_cn:
                    record["routes"] = _cn_routes(
                        process,
                        instance,
                        config,
                        dns,
                        origin,
                        mihomo,
                        manifest["geodata_reference"],
                    )
                with contextlib.ExitStack() as traffic:
                    observer, remote = _origin(traffic, origin.ipv4, 13)
                    tcp, _ = _socks(traffic, port, "vcore-fixture.test", remote)
                    if _exact(observer, 1) != b"A":
                        raise RuntimeError("TCP origin did not witness accept")
                    question_size, _ = struct.unpack("!HH", _exact(dns, 4))
                    query = _exact(dns, question_size)
                    if b"vcore-fixture" not in query:
                        raise RuntimeError("controlled DNS was not used")
                    data["dns_witness"] = True
                    sent, received = hashlib.sha256(), hashlib.sha256()
                    blocks = 1 if name == "early-load" else 16
                    for sequence in range(blocks):
                        payload = bytes([sequence]) * 65536
                        tcp.sendall(payload)
                        sent.update(payload)
                        received.update(_exact(tcp, len(payload)))
                    data.update(
                        tcp_bytes=blocks * 65536,
                        tcp_sha256=received.hexdigest(),
                        tcp_correct=sent.digest() == received.digest(),
                    )
                    tcp.close()
                    if _exact(observer, 1) != b"D":
                        raise RuntimeError("TCP origin did not finish")
                    observer, remote = _origin(traffic, origin.ipv4, 4)
                    _, relay = _socks(traffic, port, "0.0.0.0", 0, 3)
                    udp = traffic.enter_context(socket.socket(type=socket.SOCK_DGRAM))
                    udp.settimeout(5)
                    header = b"\0\0\0" + _address(origin.ipv4, remote)
                    for sequence in range(30):
                        size = (64, 512, 1200)[sequence % 3]
                        payload = struct.pack("!I", sequence) + bytes([sequence]) * (
                            size - 4
                        )
                        udp.sendto(header + payload, relay)
                        reply, source = udp.recvfrom(1300)
                        observed_size, _ = struct.unpack("!HH", _exact(observer, 4))
                        if (
                            source != relay
                            or reply != header + payload
                            or _exact(observer, observed_size) != payload
                        ):
                            raise RuntimeError("UDP source/sequence/content mismatch")
                    data["udp_packets"] = 30
                process.boundary("load-complete")
                _api(process, "stop", instance=instance)
                # Probe port ownership after synchronous Stop, not after a grace.
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    with socket.socket(type=kind) as probe:
                        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        probe.bind(("127.0.0.1", port))
                data["port_released_at_stop"] = True
            if name != "cleanup-failure":
                _api(process, "destroyInstance", instance=instance)
            process.finalize()
        except (OSError, ValueError, RuntimeError) as error:
            record["failure"] = str(error)
        finally:
            process.close()
        record["measurement"] = process.record
        valid = process.record["status"] in {"PASS", "FAIL_MEMORY"}
        record["status"] = process.record["status"]
        if name == "cleanup-failure":
            record["accepted"] = (
                not valid and process.record.get("business_cleanup") is False
            )
        elif name == "early-load":
            record["status"] = "INVALID"
            record["accepted"] = valid and data.get("tcp_bytes") == 65536
            record["reason"] = "driver ended before prescribed workload"
        else:
            record["accepted"] = (
                valid
                and "failure" not in record
                and data.get("tcp_bytes") == data["expected_tcp_bytes"]
                and data.get("udp_packets") == data["expected_udp_packets"]
                and data.get("tcp_correct") is True
                and (
                    not full_cn
                    or record.get("geodata_available")
                    and bool(record.get("routes"))
                )
            )
            if not record["accepted"]:
                record["status"] = "INVALID"
        return record


def _bandwidth(name, root, work, bandwidth, mihomo, *, pacing_credit=16):
    if name in CAPACITY_CASES:
        workload = CAPACITY_CASES[name]
        path, transport, direction = (
            workload[key] for key in ("path", "transport", "direction")
        )
        flows = workload["flows"]
    else:
        _, path, transport, direction = name.split("-")
        flows = 16
    argv = [
        str(root / "artifacts/traffic-darwin"),
        "-peer",
        f"{bandwidth.ipv4}:24003",
        "-transport",
        transport,
        "-direction",
        direction,
        "-seconds",
        "10",
        "-flows",
        str(flows),
        "-mbps",
        "1000",
        "-udp-pacing-credit",
        str(pacing_credit),
    ]
    proxy_endpoints = 0
    if path == "mihomo":
        proxy_endpoints = flows if transport == "udp" else 1
        argv += [
            "-proxy",
            ",".join(
                f"{mihomo.ipv4}:{1080 + index}" for index in range(proxy_endpoints)
            ),
        ]

    def counters():
        return {
            peer.record["role"]: json.loads(
                command("exec", peer.name, "python", "/data/fixture/metrics.py")
            )
            for peer in (bandwidth, mihomo)
        }

    before = counters()
    process_record = {}
    observer = Observer(root / "artifacts/observer.dylib")
    gaps = []
    last = time.monotonic_ns()
    sampling_errors = []
    with (
        (work / "driver-timeline.jsonl").open("w") as timeline,
        OwnedProcess(
            argv, work / "traffic.log", process_record, limit=128 * 1024
        ) as child,
    ):
        deadline = time.monotonic() + 30
        while child.process.poll() is None and time.monotonic() < deadline:
            now = time.monotonic_ns()
            gaps.append(now - last)
            last = now
            try:
                row = observer.sample(child.process.pid)
                timeline.write(json.dumps({"monotonic_ns": now, **row}) + "\n")
                timeline.flush()
            except OSError:
                if child.process.poll() is None:
                    sampling_errors.append("driver observation failed")
            time.sleep(0.02)
        timed_out = child.process.poll() is None
    after = counters()
    save(work / "command.json", {"argv": argv, **process_record, "timeout": timed_out})
    try:
        report = json.loads((work / "traffic.log").read_bytes().splitlines()[0])
    except (ValueError, IndexError):
        report = {}
    verified = bandwidth_complete(
        report, transport, direction, proxy_endpoints=proxy_endpoints, flows=flows
    )
    accepted = (
        child.process.returncode == 0
        and process_record.get("joined")
        and not timed_out
        and not sampling_errors
        and verified
        and report.get("udp_pacing_credit_records") == pacing_credit
    )
    return {
        "case": name,
        "status": "PASS" if accepted else "INVALID",
        "accepted": bool(accepted),
        "scope": "facility-calibration-not-VCore-bandwidth",
        "topology": "local-container-loop",
        "peer_proxy_endpoints": proxy_endpoints,
        "workload": {
            "flows": flows,
            "seconds": 10,
            "mbps": 1000,
            "udp_pacing_credit_records": pacing_credit,
        },
        "traffic": report,
        "workload_verified": verified,
        "guest_counters": {"before": before, "after": after},
        "observer": {
            "sample_errors": sampling_errors,
            "max_sample_gap_ns": max(gaps, default=0),
        },
    }


def _report(root, manifest, results, *, complete, failure=None):
    journal = root / "resources.json"
    resources = json.loads(journal.read_text()) if journal.exists() else {"peers": []}
    remaining = [p["name"] for p in resources["peers"] if not p.get("joined")]
    unchanged = manifest["source"] == _source()
    accepted = bool(
        complete
        and not failure
        and not remaining
        and unchanged
        and len(results) == len(manifest["cases"])
        and all(r.get("accepted") for r in results.values())
    )
    whole = manifest["cases"] == list(CASES)
    coupled = all(name in socks_load.CASES for name in manifest["cases"])
    development = any(
        spec.get("development")
        for spec in manifest.get("socks_load_workloads", {}).values()
    )
    cn_only = manifest["cases"] == ["full-cn-loader"]
    cn_accepted = (
        accepted
        and results.get("full-cn-loader", {}).get("accepted", False)
        and manifest.get("geodata_verified", {}).get("status") == "PASS"
    )
    cold_summary = cold.summarize(
        {k: v for k, v in results.items() if k.startswith("cold-")}
    )
    cold_accepted = (
        accepted
        and cold_summary["complete"]
        and results.get(cold.DIAGNOSTIC_CASE, {}).get("accepted", False)
    )
    report = {
        "complete": complete,
        "instrumentation_accepted": accepted,
        "stage_complete": accepted
        and whole
        or cn_only
        and cn_accepted
        or cold_accepted,
        "cold_start": cold_summary,
        "facility_suite_complete": accepted and whole,
        "coupled_load_subset_accepted": accepted and coupled and not development,
        "development_checks_complete": accepted and development,
        "final_matrix_accepted": False,
        "cn_compatibility_accepted": cn_accepted,
        "geodata_diagnostic": manifest.get("geodata_verified"),
        "geodata_ledger": manifest.get("geodata_ledger"),
        "source_unchanged": unchanged,
        "cleanup": not remaining,
        "cases": results,
        "mobile_acceptance": "NOT RUN",
        "failure": failure,
        "scope": "full-facility-suite"
        if whole
        else "development-diagnostic-not-acceptance"
        if development
        else "coupled-selected-subset"
        if coupled
        else "selected-cases",
    }
    save(root / "results.json", report)
    resume_command = (
        "uv run --project scripts --locked vcore-scripts check memory --resume "
        + str(root.relative_to(builds.CORE_DIR))
    )
    save(
        ROOT / "progress.json",
        {
            "current_stage": "cold-start-geodata-attribution"
            if manifest.get("suite") == "cold-start"
            else "full-cn-compatibility"
            if cn_only
            else "socks5-peer-capacity"
            if manifest.get("suite") == "peer-capacity"
            else "coupled-load"
            if coupled
            else "isolated-memory-measurement-harness",
            "status": ("DIAGNOSTIC" if development else "PASS")
            if accepted
            else "INVALID",
            "stage_complete": report["stage_complete"],
            "run_dir": str(root.relative_to(builds.CORE_DIR)),
            "source": manifest["source"],
            "next_command": resume_command,
            "owned_live_resources": remaining,
            "pending_cases": [
                name
                for name in manifest["cases"]
                if not results.get(name, {}).get("accepted")
            ],
            "external_gates": manifest["prerequisites"]["external_gates"],
            "last_accepted_commit": manifest.get("previous_accepted_commit"),
        },
    )
    lines = [
        "# Memory measurement facilities",
        "",
        "Scope: native macOS measurement infrastructure, "
        "not iOS/tvOS Provider acceptance.",
        "",
        f"Instrumentation accepted: {accepted}. "
        f"Full facility suite complete: {report['facility_suite_complete']}.",
        f"Complete CN compatibility accepted: {cn_accepted}.",
        f"Four-profile cold-start baseline accepted: {cold_accepted}.",
        f"Development checks complete: {accepted and development}.",
        f"Coupled load subset accepted: {accepted and coupled and not development}; "
        "not complete load; each case records its actual route topology.",
        f"Cleanup: {not remaining}. Source unchanged: {unchanged}.",
        "",
        "| Case | Observed result | Expected behavior verified "
        "| Peak bytes / receiver bit/s |",
        "| --- | --- | --- | --- |",
    ]
    for name, row in results.items():
        value = row.get("measurement", {}).get(
            "peak_bytes", row.get("traffic", {}).get("receiver_goodput_bps", "")
        )
        lines.append(
            f"| {name} | {row['status']} | {row.get('accepted', False)} | {value} |"
        )
    lines += [
        "",
        "Expected INVALID/FAIL_MEMORY calibrations do not become memory PASS results.",
        "Complete CN requires both assets available, the independent reference "
        "and real route witnesses; an unavailable asset remains INVALID.",
        "bandwidth-/capacity- cases are 10-second facility calibrations. "
        "socks-tcp- cases are coupled VCore/CN/peak subsets, "
        "not complete SOCKS5 or mobile acceptance.",
        "UDP peer calibration uses one official process with a listener per "
        "flow; it does not accept single-listener or single-flow 1 Gbps.",
        "Physical Provider hosts, device networking and trusted "
        "TLS/update identities remain BLOCKED.",
        "",
        "Resume only unchanged source, binaries, inputs and sealed evidence:",
        "",
        f"`{resume_command}`",
        "",
    ]
    if any(name.startswith("cold-") for name in manifest["cases"]):
        lines += [
            "## Cold-start profile summary",
            "",
            "Fresh process/application cache, not cold OS page cache. "
            "Input verification/copy precede each first in-process read.",
            "",
            "| Profile | Five lifetime peaks (bytes) | Worst margin (bytes) |",
            "| --- | --- | --- |",
        ]
        for profile, row in cold_summary["profiles"].items():
            lines.append(
                f"| {profile} | {row['peaks_bytes']} | {row['margin_bytes']} |"
            )
        lines += [
            "",
            "Do not subtract peaks across PIDs to attribute GeoData. "
            "Allocator ledgers and traced runs are diagnostic, not footprint gates.",
            "",
        ]
    (root / "summary.md").write_text("\n".join(lines))
    return accepted


def _prepare(root, manifest, selected, fixture):
    from . import memory_updates

    for tool, argv in (
        ("rustc", ["rustc", "-Vv"]),
        ("xcode", ["xcodebuild", "-version"]),
        ("sdk", ["xcrun", "--show-sdk-version"]),
        ("go", ["go", "version"]),
    ):
        manifest["toolchain"][tool] = _command(argv, root, tool)
    artifacts, library_hash = _build(root / "artifacts")
    if any(
        socks_load.CASES.get(name, {}).get("entrypoint") == "fd-TUN"
        for name in selected
    ):
        _command(
            [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--manifest-path",
                FIXTURES / "tun-driver/Cargo.toml",
                "--target-dir",
                builds.CORE_DIR / "target/memory-tun-driver",
            ],
            root / "artifacts",
            "tun-driver-build",
            timeout=300,
        )
        shutil.copy2(
            builds.CORE_DIR
            / "target/memory-tun-driver/release/vcore-memory-tun-driver",
            root / "artifacts/tun-driver",
        )
    manifest["library_sha256"] = library_hash
    manifest["rules"] = acquire_rules(root / "rules")
    if (
        "full-cn-loader" in selected
        or cold.DIAGNOSTIC_CASE in selected
        or any(name.startswith("cold-") for name in selected)
        or any(name in socks_load.CASES for name in selected)
    ):
        asset_dir = root / "rules" / manifest["rules"]["directory"]
        reference_dir = root / "cn-reference"
        manifest["geodata_reference"] = geodata_reference(asset_dir, reference_dir)
        routes = manifest["geodata_reference"]["routes"]
        if any(
            any(
                socks_load.CASES.get(name, {}).get(key)
                for key in ("overlap", "events", "lifecycle")
            )
            for name in selected
        ):
            from .memory_events import dns_names

            manifest["load_dns_names"] = [
                item for item in routes if item["kind"] == "site"
            ] + dns_names(asset_dir)
        manifest["workloads"]["full_cn"] = {
            "entrypoint": "SOCKS5",
            "rules": "complete-enhanced-cn",
            "families": ["IPv4", "IPv6"],
            "lifecycles_same_process": 2,
            "reject_witnesses": sum(item["matched"] for item in routes),
            "forward_witnesses": sum(item["kind"] == "site" for item in routes) + 2,
            "route_tcp_bytes_each_direction": 256,
            "post_route_tcp_bytes_each_direction": 1048576,
            "post_route_udp_packets": 30,
            "udp_payload_bytes": [64, 512, 1200],
            "route_oracle": "exact origin peer address and data",
        }
        manifest["workloads"]["cold_start"] = {
            "profiles": cold.PROFILES,
            "repetitions": cold.REPETITIONS,
            "idle_seconds": cold.IDLE_SECONDS,
            "lifecycles_per_pid": 1,
            "forward_witnesses": [
                "domain-negative",
                "ip4-negative",
                "ip6-negative",
            ],
            "bytes_each_direction_per_witness": 256,
            "reject_witnesses": "all positive routes for enabled assets",
            "cache": "fresh PID and app directory; OS cache not purged; "
            "verified/copied inputs",
            "first_hit": "first CN REJECT or MATCH proxy for no-GeoData profile",
            "timing": "external wall time includes public ABI IPC or SOCKS5 exchange",
        }
        if all(socks_load.CASES.get(name, {}).get("development") for name in selected):
            # These IDs are diagnostic-only. Complete assets and real
            # routing still run, but exhaustive semantics belong to
            # the unchanged formal matrix, never an implicit smoke.
            manifest["geodata_verified"] = {
                "status": "NOT RUN",
                "scope": "development-smoke; exhaustive reference deferred",
            }
        else:
            _command(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--release",
                    "--no-default-features",
                    "--features",
                    builds.DEFAULT_FEATURES,
                    "--test",
                    "geodata_cn",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                root,
                "cn-reference",
                timeout=1200,
                env=os.environ
                | {
                    "VCORE_GEODATA_DIR": str(asset_dir),
                    "VCORE_GEODATA_REFERENCE": str(reference_dir),
                },
            )
            manifest["geodata_verified"] = json.loads(
                (reference_dir / "verified.json").read_text()
            )
            manifest["geodata_ledger"] = json.loads(
                (reference_dir / "ledger.json").read_text()
            )
            if manifest["geodata_verified"]["status"] != "PASS":
                raise RuntimeError("complete CN reference verification failed")
    manifest["peer"] = {}
    download_mihomo(
        "linux-arm64",
        directory=root / "artifacts",
        identity=manifest["peer"],
    )
    from . import memory_protocols

    memory_protocols.prepare(root, manifest)
    if fixture:
        memory_updates.prepare(root, manifest, fixture)
    with frozen_image(root / "image-pull.log") as image:
        manifest["image"] = image
    manifest["files"] = {
        file.relative_to(root).as_posix(): sha256(file)
        for directory in (
            root / "artifacts",
            root / "rules",
            root / "cn-reference",
        )
        for file in directory.rglob("*")
        if file.is_file()
    }


def run(
    *,
    identifiers=None,
    run_dir=None,
    resume=None,
    list_only=False,
    preflight_only=False,
    suite=None,
    udp_pacing_credit=None,
    peer_cpus=None,
    update_fixture=None,
    prepare_only=False,
    candidate=None,
):
    if prepare_only and (resume or candidate):
        raise ValueError("prepare-only requires a new independently acquired bundle")
    if candidate:
        if update_fixture:
            raise ValueError(
                "candidate inputs are immutable; freeze a new update bundle"
            )
        candidate = Path(candidate).absolute()
        if candidate.is_symlink() or candidate.resolve().parent != ROOT.resolve():
            raise ValueError("candidate must be a direct child of target/memory")
    if udp_pacing_credit not in (None, 0, 16) or peer_cpus not in (None, 2, 4, 8):
        raise ValueError("unsupported explicit peer-capacity experiment")
    if identifiers and suite:
        raise ValueError("choose a suite or specific cases, not both")
    selected = identifiers or (
        [
            name
            for name, spec in socks_load.TUN_CASES.items()
            if spec["family"] == ("IPv6" if suite.endswith("v6") else "IPv4")
            and (
                spec.get("development", False)
                if suite.startswith("tun-smoke-")
                else name.startswith(suite.removesuffix("v4").removesuffix("v6"))
            )
        ]
        if suite and suite.startswith("tun-")
        else cold.cases() + [cold.DIAGNOSTIC_CASE]
        if suite == "cold-start"
        else list(CAPACITY_CASES)
        if suite == "peer-capacity"
        else list(socks_load.SPLIT_CASES)
        if suite == "socks-tcp-split"
        else [
            name
            for name, spec in socks_load.TCP_CASES.items()
            if spec["family"] == ("IPv6" if suite == "socks-tcp-v6" else "IPv4")
        ]
        if suite in ("socks-tcp-v4", "socks-tcp-v6")
        else [
            name
            for name, spec in (
                socks_load.DEVELOPMENT_CASES
                if suite.startswith("socks-smoke-")
                else socks_load.OVERLAP_CASES
                if suite.startswith("socks-overlap-")
                else socks_load.CORRECTNESS_CASES
                if suite.startswith("socks-correctness-")
                else socks_load.UDP_CASES
            ).items()
            if spec["family"] == ("IPv6" if suite.endswith("v6") else "IPv4")
        ]
        if suite
        in (
            "socks-smoke-v4",
            "socks-smoke-v6",
            "socks-udp-v4",
            "socks-udp-v6",
            "socks-overlap-v4",
            "socks-overlap-v6",
            "socks-correctness-v4",
            "socks-correctness-v6",
        )
        else list(CASES)
    )
    known = (
        *CASES,
        *CAPACITY_CASES,
        *socks_load.CASES,
        *cold.cases(),
        cold.DIAGNOSTIC_CASE,
    )
    if len(set(selected)) != len(selected) or any(
        case not in known for case in selected
    ):
        raise ValueError("unknown or repeated memory case")
    if any(name in socks_load.CASES for name in selected) and not all(
        name in socks_load.CASES for name in selected
    ):
        raise ValueError(
            "coupled load requires its dedicated DNS fixture; select it separately"
        )
    if (
        len(
            {
                socks_load.CASES[name]["family"]
                for name in selected
                if name in socks_load.CASES
            }
        )
        > 1
    ):
        raise ValueError("coupled load freezes one DNS address family per run")
    profiles = {
        socks_load.CASES[name].get("profile")
        for name in selected
        if name in socks_load.CASES
    }
    if len(profiles) > 1:
        raise ValueError("freeze one protocol profile per memory run")
    if list_only:
        print("\n".join(selected))
        return
    from . import memory_updates

    fixture = None
    if (
        not resume
        and not candidate
        and memory_updates.required(
            {n: socks_load.CASES[n] for n in selected if n in socks_load.CASES}
        )
    ):
        fixture = memory_updates.read_fixture(update_fixture)
    inventory = prerequisites()
    if preflight_only:
        print(json.dumps(inventory, indent=2))
        return
    ROOT.mkdir(parents=True, exist_ok=True)
    if run_dir is not None and resume is not None:
        raise ValueError("choose a fresh run or resume, not both")
    root = Path(
        resume
        or run_dir
        or ROOT
        / ("run-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}")
    )
    if not root.is_absolute():
        root = builds.CORE_DIR / root
    if root.is_symlink() or root.resolve().parent != ROOT.resolve():
        raise ValueError(
            "memory runs must be direct non-symlink children of target/memory"
        )
    previous_signal = signal.getsignal(signal.SIGTERM)

    def interrupted(*_):
        raise KeyboardInterrupt("memory run interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    results = {}
    owned = False
    finished = False
    failure = None
    try:
        with exclusive_run():
            if resume:
                manifest = json.loads((root / "manifest.json").read_text())
                if manifest.get("ready") is not True or manifest["source"] != _source():
                    raise ValueError(
                        "memory resume source/preparation identity mismatch"
                    )
                if (
                    udp_pacing_credit is not None
                    and udp_pacing_credit
                    != manifest.get("udp_pacing_credit_records", 16)
                    or peer_cpus is not None
                    and peer_cpus != manifest.get("peer_cpus", 8)
                ):
                    raise ValueError("memory resume capacity experiment changed")
                if (identifiers or suite) and selected != manifest["cases"]:
                    raise ValueError("resume must retain the frozen case selection")
                selected = manifest["cases"]
                from .memory_candidate import read, verify_files

                verify_files(root, manifest)
                if frozen := manifest.get("candidate"):
                    if candidate and candidate != Path(frozen["directory"]):
                        raise ValueError("resume candidate changed")
                    candidate = Path(frozen["directory"])
                    read(candidate, manifest["source"])
                    if (
                        sha256(candidate / "manifest.json") != frozen["manifest_sha256"]
                        or sha256(candidate / "matrix.json") != frozen["matrix_sha256"]
                    ):
                        raise ValueError("resume candidate manifest changed")
                elif candidate:
                    raise ValueError("cannot attach a candidate to an existing run")
                store = RunStore(root, manifest, resume=True)
                owned = True
            else:
                checkpoint = ROOT / "progress.json"
                previous = (
                    json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
                )
                manifest = {
                    "schema": 1,
                    "ready": False,
                    "source": _source(),
                    "cases": selected,
                    "suite": "cold-start"
                    if any(n.startswith("cold-") for n in selected)
                    else "peer-capacity"
                    if any(n in CAPACITY_CASES for n in selected)
                    else "coupled-selected"
                    if any(n in socks_load.CASES for n in selected)
                    else "allocation-diagnostic"
                    if cold.DIAGNOSTIC_CASE in selected
                    else "facilities",
                    "profile": "release",
                    "features": builds.DEFAULT_FEATURES.split(","),
                    "limit_bytes": 50_000_000,
                    "prerequisites": inventory,
                    "rule_profile": "complete-enhanced-cn",
                    "resource_profile": "standard",
                    "seed": 20260929,
                    "udp_pacing_credit_records": 16
                    if udp_pacing_credit is None
                    else udp_pacing_credit,
                    "peer_cpus": peer_cpus or 8,
                    "peer_udp_listeners": max(
                        [16]
                        + [
                            CAPACITY_CASES[name]["flows"]
                            for name in selected
                            if name in CAPACITY_CASES
                            and CAPACITY_CASES[name]["path"] == "mihomo"
                            and CAPACITY_CASES[name]["transport"] == "udp"
                        ]
                        + [
                            socks_load.CASES[name]["flows"] // 2
                            for name in selected
                            if name in socks_load.CASES
                            and socks_load.CASES[name].get("distributed")
                        ]
                    ),
                    "peer_capacity_workloads": {
                        name: CAPACITY_CASES[name]
                        for name in selected
                        if name in CAPACITY_CASES
                    },
                    "socks_load_workloads": {
                        name: socks_load.CASES[name]
                        for name in selected
                        if name in socks_load.CASES
                    },
                    "sample_interval_ms": 20,
                    "allocator_environment": "system-default; no inherited "
                    "Malloc/DYLD overrides",
                    "toolchain": {},
                    "previous_accepted_commit": previous.get(
                        "last_accepted_commit", previous.get("accepted_commit")
                    ),
                    "workloads": {
                        "smoke": {
                            "tcp_bytes_each_direction": 1048576,
                            "udp_packets": 30,
                            "udp_payload_bytes": [64, 512, 1200],
                            "dns_queries": 1,
                            "rules": "no-GeoData",
                            "entrypoint": "SOCKS5",
                            "family": "IPv4",
                        },
                        "bandwidth": {
                            "seconds": 10,
                            "flows": 16,
                            "aggregate_offered_bps": 1000000000,
                            "tcp_record_bytes": 65536,
                            "udp_payload_bytes": 1200,
                            "directions": ["up", "down", "both-500Mbps-each"],
                            "topology": "local-container-loop",
                            "mihomo_udp_listeners": 16,
                            "udp_max_pacing_credit_records": 16
                            if udp_pacing_credit is None
                            else udp_pacing_credit,
                            "origin_cpus": 4,
                            "mihomo_cpus": peer_cpus or 8,
                            "vcore_in_path": False,
                        },
                    },
                }
                store = RunStore(root, manifest)
                owned = True
                print(f"Memory run: {root}", flush=True)
                if candidate:
                    from .memory_candidate import restore

                    restore(candidate, root, manifest)
                else:
                    _prepare(root, manifest, selected, fixture)
                if manifest["source"] != _source():
                    raise RuntimeError("source changed during memory preparation")
                manifest["ready"] = True
                save(root / "manifest.json", manifest)
            if prepare_only:
                return root
            with _peers(root, manifest) as (
                origin,
                bandwidth,
                mihomo,
                positive,
                cn_bandwidth,
            ):
                for name in selected:
                    old = store.completed(name)
                    if old is not None and old.get("accepted"):
                        results[name] = old
                        print(f"REUSE {name}: {old['status']}", flush=True)
                        continue
                    work = store.begin(name)
                    with (root / "timeline.jsonl").open("a") as timeline:
                        timeline.write(
                            json.dumps(
                                {
                                    "monotonic_ns": time.monotonic_ns(),
                                    "case": name,
                                    "attempt": str(work.relative_to(root)),
                                    "event": "begin",
                                }
                            )
                            + "\n"
                        )
                    print(f"RUN {name}", flush=True)
                    if name.startswith("calibrate-"):
                        mode = name.removeprefix("calibrate-")
                        outcome = calibration(
                            mode,
                            {
                                "empty": root / "artifacts/empty-host",
                                "observer": root / "artifacts/observer.dylib",
                            },
                            work,
                        )
                        expected = (
                            "PASS"
                            if mode == "empty"
                            else "FAIL_MEMORY"
                            if mode in {"transient", "over-limit"}
                            else "INVALID"
                        )
                        result = {
                            "case": name,
                            "status": outcome["status"],
                            "measurement": outcome,
                            "accepted": outcome["status"] == expected
                            and outcome["cleanup"],
                        }
                    elif name.startswith(("bandwidth-", "capacity-")):
                        result = _bandwidth(
                            name,
                            root,
                            work,
                            bandwidth,
                            mihomo,
                            pacing_credit=manifest.get("udp_pacing_credit_records", 16),
                        )
                    elif name in socks_load.CASES:
                        result = socks_load.run_case(
                            name,
                            root,
                            manifest,
                            work,
                            origin,
                            bandwidth,
                            mihomo,
                            positive,
                            cn_bandwidth,
                        )
                    elif name.startswith("cold-") or name == cold.DIAGNOSTIC_CASE:
                        result = cold.run_case(
                            name, root, manifest, work, origin, mihomo
                        )
                    else:
                        result = _smoke(name, root, manifest, work, origin, mihomo)
                    result["peers"] = json.loads((root / "resources.json").read_text())
                    evidence = [
                        path
                        for path in work.rglob("*")
                        if path.is_file()
                        and path.name not in {"state.json", "result.json"}
                    ]
                    store.finish(name, work, result, evidence)
                    results[name] = result
                    save(root / "results.json", {"complete": False, "cases": results})
                    save(
                        ROOT / "progress.json",
                        {
                            "current_stage": manifest.get("suite", "facilities"),
                            "status": "RUNNING",
                            "run_dir": str(root.relative_to(builds.CORE_DIR)),
                            "source": manifest["source"],
                            "cases": results,
                            "next_command": "uv run --project scripts --locked "
                            "vcore-scripts check memory --resume "
                            f"{root.relative_to(builds.CORE_DIR)}",
                        },
                    )
                    check = "PASS" if result["accepted"] else "FAIL"
                    print(
                        f"{name}: {result['status']} (case acceptance {check})",
                        flush=True,
                    )
            finished = True
            accepted = _report(root, manifest, results, complete=True)
            if not accepted:
                raise RuntimeError(
                    "memory case acceptance failed; retain original results"
                )
            diagnostic = any(
                socks_load.CASES.get(name, {}).get("development") for name in selected
            )
            print(
                f"{'DIAGNOSTIC' if diagnostic else 'PASS'} selected memory cases "
                f"({len(selected)}); scope is recorded "
                f"in results.json, not complete load or mobile acceptance: {root}",
                flush=True,
            )
    except BaseException as error:
        failure = str(error)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_signal)
        if owned and prepare_only:
            save(
                root / "preparation.json",
                {
                    "status": "READY_NOT_ACCEPTED"
                    if manifest.get("ready") and not failure
                    else "INVALID",
                    "final_matrix_accepted": False,
                    "failure": failure,
                },
            )
        elif owned:
            _report(root, manifest, results, complete=finished, failure=failure)
