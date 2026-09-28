"""Hybrid REALITY checks; not complete security suite acceptance."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .protocol_containers import ContainerLab, command
from .protocol_evidence import read_events
from .protocol_fixtures import certificates
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command
from .protocol_vless_peers import configuration
from .protocol_vless_public import events_pass

MODES = {
    "tcp": ("tcp-reality", None),
    "ws": ("ws-reality", None),
    "upgrade": ("upgrade-reality", None),
    "upgrade-fast": ("upgrade-fast-reality", None),
    "grpc": ("grpc-reality", None),
    "vision": ("vision-reality", None),
    **{
        f"{version}-{mode}": (
            f"xhttp-{mode}{'-download' if mode != 'stream-one' else ''}-reality",
            alpn,
        )
        for version, alpn in (("h1", "http/1.1"), ("h2", "h2"))
        for mode in ("stream-one", "stream-up", "packet-up")
    },
}


def cases():
    result = {}
    for profile in ("none", "chrome"):
        for mode in MODES:
            result[f"{profile}-{mode}-base"] = (profile, mode, "public_base", "hybrid")
        for variant in ("main-classic", "download-classic"):
            for version in ("h1", "h2"):
                result[f"{profile}-{version}-{variant}"] = (
                    profile,
                    f"{version}-stream-up",
                    "public_base",
                    variant,
                )
        for mode in ("tcp", "h1-stream-up", "h2-stream-up"):
            result[f"{profile}-{mode}-security"] = (
                profile,
                mode,
                "native_hybrid_fail_closed",
                "hybrid",
            )
        result[f"{profile}-vision-inner-tls"] = (
            profile,
            "vision",
            "native_vision_inner_tls",
            "hybrid",
        )
        for test in (
            "runtime::public_graph",
            "runtime::public_ipv6_and_gates",
            "runtime::public_entrypoints",
        ):
            result[f"{profile}-tcp-{test.split('::')[-1]}"] = (
                profile,
                "tcp",
                test,
                "hybrid",
            )
    for mode in ("tcp", "grpc", "vision", "h2-stream-up"):
        for suffix, test in (
            ("life", "runtime::public_lifecycle"),
            ("owned", "runtime::owned_resources"),
        ):
            result[f"chrome-{mode}-{suffix}"] = ("chrome", mode, test, "hybrid")
    return result


def observed_events(observer):
    raw = command(
        "exec",
        observer.name,
        "python",
        "-c",
        "from pathlib import Path; p=Path('/data/events.jsonl'); "
        "assert p.stat().st_size <= 8388608; print(p.read_text(),end='')",
    )
    return [json.loads(line) for line in raw.splitlines()]


def wire_pass(events, expectations):
    for port, (hybrid, profile) in expectations.items():
        shares = (
            [[4588, 1216], [29, 32]]
            if hybrid and profile == "chrome"
            else [[4588, 1216]]
            if hybrid
            else [[29, 32]]
        )
        hellos = [
            e
            for e in events
            if e.get("port") == port and e.get("event") == "client-hello"
        ]
        selections = [
            e
            for e in events
            if e.get("port") == port and e.get("event") == "server-hello"
        ]
        if (
            not hellos
            or not selections
            or not all(e["shares"] == shares for e in hellos)
        ):
            return False
        if not all(e["group"] == (4588 if hybrid else 29) for e in selections):
            return False
    return True


def negative_wire_pass(events, profile, front=25000, legs=1):
    for offset, cover, group in ((2, 24432, 29), (3, 24433, 24)):
        observed = [e for e in events if e.get("port") == front + offset]
        hellos = [e for e in observed if e.get("event") == "client-hello"]
        replies = [e for e in observed if e.get("event") == "server-hello"]
        if len(hellos) != legs:
            return False
        if profile == "chrome":
            if (
                len(replies) != legs
                or not all(
                    e.get("group") == group and e.get("hrr") is (offset == 3)
                    for e in replies
                )
                or not all(
                    e.get("shares") == [[4588, 1216], [29, 32]]
                    and e.get("groups") == [4588, 29, 23, 24]
                    for e in hellos
                )
            ):
                return False
        else:
            # A hybrid-only offer has no common group with these peers. A
            # missing ServerHello alone is not proof: require the cover's
            # native no-shared-group error and an empty, closed server flight.
            rejected = [
                e
                for e in events
                if e.get("port") == cover and e.get("event") == "no-shared-group"
            ]
            closed = [
                e
                for e in observed
                if e.get("event") == "server-close" and e.get("bytes") == 0
            ]
            if (
                replies
                or len(rejected) != legs
                or len(closed) != legs
                or not all(
                    e.get("shares") == [[4588, 1216]] and e.get("groups") == [4588]
                    for e in hellos
                )
            ):
                return False
    return True


def run(output: Path, selected=None, *, encryption=None, supplied=None):
    output = output.resolve()
    if not output.is_relative_to(CORE_DIR / "target/interop/runs"):
        raise ValueError("use a fresh child of target/interop/runs")
    required = cases()
    selected = list(required) if selected is None else selected
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not set(selected) <= required.keys()
    ):
        raise ValueError("invalid SECURITY.reality selection")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="SECURITY.reality",
        scope="S03/D16-production",
        encryption_profile=encryption,
        complete_selection=set(selected) == set(required),
        required=list(required),
        source=source_identity(),
        cases=[],
        isolation={},
        peers={},
        status="NOT RUN",
    )
    try:
        if supplied is None:
            identity = {}
            binary = download_mihomo(
                "linux-arm64", directory=output / "binaries", identity=identity
            )
        else:
            binary, identity = supplied["M"]
        report["peers"]["M"] = identity
        built = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "vless_public",
                "--test",
                "vless_native",
                "--no-run",
            ],
            timeout=240,
        )
        (output / "build.log").write_text(redact(built.stdout.decode(errors="replace")))
        if built.returncode or not built.cleanup:
            raise RuntimeError("SECURITY.reality consumer build failed")
        lab = ContainerLab(report["isolation"], mtu=1500)
        with (
            tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
            contextlib.ExitStack() as stack,
        ):
            root = Path(temporary)
            origin_dir, server_dir, observer_dir, hop_dir = [
                root / p for p in ("origin", "server", "observer", "hop")
            ]
            for directory in (origin_dir, server_dir, observer_dir, hop_dir):
                directory.mkdir()
            shutil.copy2(
                Path(__file__).with_name("container_udp_origin.py"),
                origin_dir / "origin.py",
            )
            shutil.copy2(
                Path(__file__).with_name("container_reality_hybrid.py"),
                observer_dir / "observer.py",
            )
            shutil.copy2(binary, server_dir / "peer")
            shutil.copy2(binary, hop_dir / "peer")
            cert, key, pin = certificates(origin_dir)
            certificates(observer_dir)
            origin = lab.start(
                stack,
                origin_dir,
                "security-origin",
                [
                    "env",
                    "VCORE_ISOLATED_ORIGIN=1",
                    f"VCORE_ORIGIN_CERT=/data/fixture/{cert.name}",
                    f"VCORE_ORIGIN_KEY=/data/fixture/{key.name}",
                    "python",
                    "-B",
                    "/data/fixture/origin.py",
                ],
            )
            observer = lab.start(
                stack,
                observer_dir,
                "security-observer",
                [
                    "env",
                    "VCORE_ISOLATED_ORIGIN=1",
                    "python",
                    "-B",
                    "/data/fixture/observer.py",
                ],
            )
            server = lab.start(
                stack,
                server_dir,
                "security-mihomo",
                [
                    "/data/fixture/peer",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )
            hop = lab.start(
                stack,
                hop_dir,
                "security-upstream",
                [
                    "/data/fixture/peer",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )
            listeners, routes, nodes, ports = [], {}, {}, {}
            for index, (name, (mode, alpn)) in enumerate(MODES.items()):
                node, config = configuration(
                    mode,
                    observer.ipv4,
                    origin.ipv4,
                    Path("/data/fixture/cert.pem"),
                    Path("/data/fixture/key.pem"),
                )
                backend, front = 23010 + index * 10, 25000 + index * 10
                listener = config["listeners"][0]
                if encryption:
                    from .protocol_encryption_public import configuration as encrypt

                    encrypt(encryption, node, config)
                listener.update(name=name, port=backend)
                listener["reality-config"]["dest"] = f"{observer.ipv4}:24431"
                listeners.append(listener)
                routes[str(front)] = routes[str(front + 1)] = [server.ipv4, backend]
                if name == "tcp":
                    for offset, cover in ((2, 24432), (3, 24433)):
                        negative = copy.deepcopy(listener)
                        negative.update(name=f"reject-{cover}", port=backend + offset)
                        negative["reality-config"]["dest"] = f"{observer.ipv4}:{cover}"
                        listeners.append(negative)
                        routes[str(front + offset)] = [server.ipv4, backend + offset]
                node.update(name="peer", port=front)
                node["reality-opts"]["support-x25519mlkem768"] = True
                if alpn:
                    node["alpn"] = [alpn]
                if "download-settings" in node.get("xhttp-opts", {}):
                    node["xhttp-opts"]["download-settings"] = {
                        "server": observer.ipv4,
                        "port": front + 1,
                    }
                nodes[name], ports[name] = node, front
            (observer_dir / "routes.json").write_text(json.dumps(routes))
            (server_dir / "config.json").write_text(
                json.dumps(
                    {
                        "ipv6": True,
                        "log-level": "silent",
                        "listeners": listeners,
                        "hosts": {"vcore-fixture.test": origin.ipv4},
                        "rules": ["MATCH,DIRECT"],
                    }
                )
            )
            (hop_dir / "config.json").write_text(
                json.dumps(
                    {
                        "socks-port": 23001,
                        "allow-lan": True,
                        "bind-address": "*",
                        "log-level": "silent",
                        "ipv6": True,
                        "hosts": {"peer.fixture.test": observer.ipv4},
                        "rules": ["MATCH,DIRECT"],
                    }
                )
            )
            for peer, port in (
                (origin, 24000),
                (observer, 24431),
                (server, 23010),
                (hop, 23001),
            ):
                peer.release()
                peer.wait_tcp(port)
            identity["version"] = command(
                "exec", server.name, "/data/fixture/peer", "-v"
            ).strip()
            if (
                command("exec", server.name, "sha256sum", "/data/fixture/peer").split()[
                    0
                ]
                != identity["binary_sha256"]
            ):
                raise RuntimeError("native peer identity mismatch")
            report["openssl"] = command(
                "exec",
                observer.name,
                "python",
                "-c",
                "import ssl; print(ssl.OPENSSL_VERSION)",
            ).strip()
            for case in selected:
                profile, mode, test, variant = required[case]
                node = copy.deepcopy(nodes[mode])
                node["client-fingerprint"] = profile
                expectations = {ports[mode]: (True, profile)}
                if node.get("xhttp-opts", {}).get("download-settings") is not None:
                    expectations[ports[mode] + 1] = (True, profile)
                if variant != "hybrid":
                    down = node["xhttp-opts"]["download-settings"]
                    down["reality-opts"] = copy.deepcopy(node["reality-opts"])
                    if variant == "main-classic":
                        node["reality-opts"]["support-x25519mlkem768"] = False
                        expectations[ports[mode]] = (False, profile)
                    else:
                        down["reality-opts"]["support-x25519mlkem768"] = False
                        expectations[ports[mode] + 1] = (False, profile)
                f = dict(
                    isolation="containers",
                    node=node,
                    origin_control=f"{origin.ipv4}:24000",
                    origin_ipv4=origin.ipv4,
                    origin_ipv6=origin.ipv6,
                    server_ipv6=observer.ipv6,
                    origin_pin=pin,
                    data_dir=str(root / "data"),
                    peer_kind="M",
                    vision_probe=mode == "vision",
                    hop=dict(
                        name="hop", type="socks5", server=hop.ipv4, port=23001, udp=True
                    ),
                    downgrade_port=ports["tcp"] + 2,
                    hrr_port=ports["tcp"] + 3,
                    ordinary_tls_port=24431,
                    tls12_port=24434,
                )
                fixture = root / "input.json"
                fixture.write_text(json.dumps(f))
                before = len(observed_events(observer))
                events_path = output / f"{case}-events.jsonl"
                test_command = [
                    "cargo",
                    "test",
                    "--locked",
                    "--all-features",
                    "--test",
                    "vless_native" if test.startswith("native_") else "vless_public",
                    test,
                    "--",
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ]
                print(case, flush=True)
                result = run_command(
                    test_command,
                    timeout=240,
                    env=dict(
                        os.environ,
                        VCORE_VLESS_INPUT=str(fixture),
                        VCORE_CASE_EVENTS=str(events_path),
                        VCORE_PROTOCOL_STAGE="SECURITY",
                    ),
                )
                (output / f"{case}.log").write_text(
                    redact(result.stdout.decode(errors="replace"))
                )
                observed = observed_events(observer)[before:]
                wire_path = output / f"{case}-wire.json"
                wire_path.write_text(json.dumps(observed, indent=2) + "\n")
                events = read_events(events_path) if events_path.exists() else []
                remapped = [
                    dict(e, suite=e.get("suite", "").replace("SECURITY-", "VLESS-", 1))
                    for e in events
                ]
                assertions = (
                    remapped
                    == [
                        dict(
                            schema_version=1,
                            suite="VLESS-WIRE",
                            assertion=test,
                            status=status,
                        )
                        for status in ("BEGIN", "PASS")
                    ]
                    if test.startswith("native_")
                    else events_pass(remapped, test, MODES[mode][0])
                )
                # Security matrices deliberately contain rejected peers; their
                # strict per-attempt assertions require errors, never timeouts.
                wire_valid = wire_pass(observed, expectations)
                if test == "native_hybrid_fail_closed":
                    wire_valid &= negative_wire_pass(
                        observed, profile, ports["tcp"], len(expectations)
                    )
                passed = (
                    result.returncode == 0
                    and result.cleanup
                    and assertions
                    and wire_valid
                )
                report["cases"].append(
                    dict(
                        id=case,
                        test=test,
                        variant=variant,
                        profile=profile,
                        status="PASS" if passed else "FAIL",
                        exit_code=result.returncode,
                        command_cleanup=result.cleanup,
                        seconds=result.seconds,
                        command=test_command,
                        wire_sha256=hashlib.sha256(wire_path.read_bytes()).hexdigest(),
                        assertions=assertions,
                        wire_valid=wire_valid,
                    )
                )
                print(f"{case}: {report['cases'][-1]['status']}", flush=True)
                for peer in (origin, observer, server, hop):
                    peer.ensure_alive()
                if not passed:
                    raise RuntimeError(f"SECURITY.reality case failed: {case}")
        report["status"] = "PASS"
    except KeyboardInterrupt:
        report.update(status="INTERRUPTED", reason="user interruption")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        report.update(
            status="FAIL",
            reason=str(error)
            if isinstance(error, RuntimeError)
            else type(error).__name__,
        )
    finally:
        report["cleanup"] = all(
            p["joined"] for p in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = same_source(report["source"], source_identity())
        if not report["cleanup"] or not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "reality-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return 0 if report["status"] == "PASS" else 1


def main(output, selected=None):
    with exclusive_run():
        return run(output, selected)
