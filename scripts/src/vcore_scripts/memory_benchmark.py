"""Production-ABI measurement infrastructure; not mobile or full-CN acceptance."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
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


def _command(argv, directory, name, *, env=None, timeout=120):
    outcome = run_command(
        [str(arg) for arg in argv], timeout=timeout, cwd=builds.CORE_DIR, env=env
    )
    (directory / (name + ".log")).write_bytes(outcome.stdout)
    save(
        directory / (name + ".command.json"),
        {
            "argv": [str(arg) for arg in argv],
            "exit_code": outcome.returncode,
            "joined": outcome.cleanup,
            "seconds": outcome.seconds,
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
        or key.startswith(("CARGO_PROFILE_", "DYLD_"))
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
        try:
            with contextlib.ExitStack() as stack:
                for role in ("origin", "bandwidth", "mihomo"):
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
                shutil.copy2(
                    root / "artifacts/traffic-linux",
                    directories["bandwidth"] / "traffic",
                )
                shutil.copy2(
                    root / "artifacts/mihomo", directories["mihomo"] / "mihomo"
                )
                save(
                    directories["mihomo"] / "config.json",
                    {
                        "socks-port": 1080,
                        "allow-lan": True,
                        "bind-address": "*",
                        "ipv6": True,
                        "log-level": "warning",
                        "rules": ["MATCH,DIRECT"],
                        # High-rate UDP flows must not funnel into one peer
                        # receive socket. This is one official process with
                        # unchanged socket defaults, not single-flow acceptance.
                        "listeners": [
                            {
                                "name": f"memory-{index}",
                                "type": "socks",
                                "listen": "0.0.0.0",
                                "port": 1080 + index,
                                "udp": True,
                            }
                            for index in range(1, 16)
                        ],
                    },
                )
                origin = lab.start(
                    stack,
                    directories["origin"],
                    "memory-origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "python",
                        "-B",
                        "/data/fixture/origin.py",
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
                    ],
                    cpus=4,
                )
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
                    cpus=8,
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
                for peer, port in ((origin, 24000), (bandwidth, 24003), (mihomo, 1080)):
                    peer.release()
                    peer.wait_tcp(port)
                    peer.record.update(ipv4=peer.ipv4, ipv6=peer.ipv6)
                save(root / "resources.json", record)
                yield origin, bandwidth, mihomo
                for peer in (origin, bandwidth, mihomo):
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
        value = host.encode("ascii")
        raw = bytes([3, len(value)]) + value
    return raw + struct.pack("!H", port)


def _socks(stack, port, host, remote, command_id=1):
    stream = stack.enter_context(
        socket.create_connection(("127.0.0.1", port), timeout=5)
    )
    stream.sendall(b"\x05\x01\x00")
    if _exact(stream, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed")
    stream.sendall(bytes([5, command_id, 0]) + _address(host, remote))
    header = _exact(stream, 4)
    if header != bytes([5, 0, 0, 1]):
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
            "ipv6": False,
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
                site = geostate["geosite"]
                record["expected_loader_failure"] = bool(
                    site["required"]
                    and not site["available"]
                    and "GeoSite Domain records" in (site["lastError"] or "")
                )
            else:
                if any(item["required"] for item in geostate.values()):
                    raise RuntimeError("no-GeoData smoke unexpectedly needs assets")
                reservation.release_ipv4()
                _api(process, "start", instance=instance)
                if _api(process, "getState", instance=instance)["state"] != "running":
                    raise RuntimeError("runtime failed before traffic")
                process.boundary("traffic")
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
        if full_cn:
            record["status"] = "INVALID"
            record["accepted"] = valid and record.get("expected_loader_failure", False)
            record["reason"] = "full CN loader unavailable; not a memory PASS"
        elif name == "cleanup-failure":
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
            )
        return record


def _bandwidth(name, root, work, bandwidth, mihomo):
    _, path, transport, direction = name.split("-")
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
        "16",
        "-mbps",
        "1000",
    ]
    proxy_endpoints = 0
    if path == "mihomo":
        proxy_endpoints = 16 if transport == "udp" else 1
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
        report, transport, direction, proxy_endpoints=proxy_endpoints
    )
    accepted = (
        child.process.returncode == 0
        and process_record.get("joined")
        and not timed_out
        and not sampling_errors
        and verified
    )
    return {
        "case": name,
        "status": "PASS" if accepted else "INVALID",
        "accepted": bool(accepted),
        "scope": "facility-calibration-not-VCore-bandwidth",
        "topology": "local-container-loop",
        "peer_proxy_endpoints": proxy_endpoints,
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
    report = {
        "complete": complete,
        "instrumentation_accepted": accepted,
        "stage_complete": accepted and whole,
        "source_unchanged": unchanged,
        "cleanup": not remaining,
        "cases": results,
        "mobile_acceptance": "NOT RUN",
        "failure": failure,
        "scope": "full-facility-suite" if whole else "selected-cases",
    }
    save(root / "results.json", report)
    resume_command = (
        "uv run --project scripts --locked vcore-scripts check memory --resume "
        + str(root.relative_to(builds.CORE_DIR))
    )
    save(
        ROOT / "progress.json",
        {
            "current_stage": "isolated-memory-measurement-harness",
            "status": "PASS" if accepted else "INVALID",
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
        f"Full facility suite complete: {report['stage_complete']}.",
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
        "Complete CN loader failure remains INVALID; "
        "no CN or mobile memory acceptance.",
        "Bandwidth is a 10-second facility calibration, "
        "not the later 300-second VCore gate.",
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
    (root / "summary.md").write_text("\n".join(lines))
    return accepted


def run(
    *,
    identifiers=None,
    run_dir=None,
    resume=None,
    list_only=False,
    preflight_only=False,
):
    selected = identifiers or list(CASES)
    if len(set(selected)) != len(selected) or any(
        case not in CASES for case in selected
    ):
        raise ValueError("unknown or repeated memory case")
    if list_only:
        print("\n".join(selected))
        return
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
                if identifiers and selected != manifest["cases"]:
                    raise ValueError("resume must retain the frozen case selection")
                selected = manifest["cases"]
                for path, digest in manifest["files"].items():
                    if sha256(root / path) != digest:
                        raise ValueError(
                            "memory resume input/artifact identity mismatch"
                        )
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
                    "profile": "release",
                    "features": builds.DEFAULT_FEATURES.split(","),
                    "limit_bytes": 50_000_000,
                    "prerequisites": inventory,
                    "rule_profile": "complete-enhanced-cn",
                    "resource_profile": "standard",
                    "seed": 20260929,
                    "sample_interval_ms": 20,
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
                            "udp_max_pacing_credit_records": 16,
                            "origin_cpus": 4,
                            "mihomo_cpus": 8,
                            "vcore_in_path": False,
                        },
                    },
                }
                store = RunStore(root, manifest)
                owned = True
                print(f"Memory run: {root}", flush=True)
                for tool, argv in (
                    ("rustc", ["rustc", "-Vv"]),
                    ("xcode", ["xcodebuild", "-version"]),
                    ("sdk", ["xcrun", "--show-sdk-version"]),
                    ("go", ["go", "version"]),
                ):
                    manifest["toolchain"][tool] = _command(argv, root, tool)
                artifacts, library_hash = _build(root / "artifacts")
                manifest["library_sha256"] = library_hash
                manifest["rules"] = acquire_rules(root / "rules")
                manifest["peer"] = {}
                download_mihomo(
                    "linux-arm64",
                    directory=root / "artifacts",
                    identity=manifest["peer"],
                )
                with frozen_image(root / "image-pull.log") as image:
                    manifest["image"] = image
                manifest["files"] = {
                    file.relative_to(root).as_posix(): sha256(file)
                    for directory in (root / "artifacts", root / "rules")
                    for file in directory.rglob("*")
                    if file.is_file()
                }
                if manifest["source"] != _source():
                    raise RuntimeError("source changed during memory preparation")
                manifest["ready"] = True
                save(root / "manifest.json", manifest)
            with _peers(root, manifest) as (origin, bandwidth, mihomo):
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
                    elif name.startswith("bandwidth-"):
                        result = _bandwidth(name, root, work, bandwidth, mihomo)
                    else:
                        result = _smoke(name, root, manifest, work, origin, mihomo)
                    result["peers"] = json.loads((root / "resources.json").read_text())
                    evidence = [
                        path
                        for path in work.iterdir()
                        if path.is_file()
                        and path.name not in {"state.json", "result.json"}
                    ]
                    store.finish(name, work, result, evidence)
                    results[name] = result
                    save(root / "results.json", {"complete": False, "cases": results})
                    save(
                        ROOT / "progress.json",
                        {
                            "current_stage": "isolated-memory-measurement-harness",
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
                        f"{name}: {result['status']} (instrument check {check})",
                        flush=True,
                    )
            finished = True
            accepted = _report(root, manifest, results, complete=True)
            if not accepted:
                raise RuntimeError(
                    "memory facility acceptance failed; retain original results"
                )
            print(
                f"PASS measurement facilities ({len(selected)} selected cases), "
                f"not mobile/full-CN acceptance: {root}",
                flush=True,
            )
    except BaseException as error:
        failure = str(error)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_signal)
        if owned:
            _report(root, manifest, results, complete=finished, failure=failure)
