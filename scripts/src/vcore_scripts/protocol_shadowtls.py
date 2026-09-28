"""SS2022 ShadowTLS v3 through public consumers and isolated official peers."""

from __future__ import annotations

import contextlib
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .protocol_completion_peers import CASES, peer_configuration
from .protocol_containers import ContainerLab, command, frozen_image
from .protocol_fixtures import certificates
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command

PROFILES = ("none", "chrome120", "chrome", "firefox", "safari")
POLICIES = (
    "alpn-default",
    "alpn-empty",
    "alpn-custom",
    "hrr",
    "wrong-password",
    "wrong-pin",
    "wrong-pin-with-skip",
    "untrusted",
    "tls12",
)


def policy_inputs(node, listener):
    for index, policy in enumerate(POLICIES):
        client, peer = copy.deepcopy(node), copy.deepcopy(listener)
        client["port"] = peer["port"] = 23500 + index
        peer["name"] += "-" + policy
        port, alpn = 24001, "h2"
        if policy == "alpn-empty":
            client["plugin-opts"]["alpn"] = []
            alpn = None
        elif policy == "alpn-custom":
            client["plugin-opts"]["alpn"] = ["fixture-custom"]
            alpn = "fixture-custom"
        elif policy == "hrr":
            port = 24002
        elif policy == "wrong-password":
            client["plugin-opts"]["password"] = "wrong-synthetic-password"
        elif policy.startswith("wrong-pin"):
            client["plugin-opts"]["fingerprint"] = "07" * 32
            client["plugin-opts"]["skip-cert-verify"] = policy.endswith("skip")
        elif policy == "untrusted":
            del client["plugin-opts"]["fingerprint"]
        elif policy == "tls12":
            port = 24003
        host = peer["shadow-tls"]["handshake"]["dest"].rsplit(":", 1)[0]
        peer["shadow-tls"]["handshake"]["dest"] = f"{host}:{port}"
        yield (
            policy,
            client,
            peer,
            policy.startswith("alpn-") or policy == "hrr",
            port,
            alpn,
        )


def run(
    output: Path,
    *,
    profiles=("none",),
    selected=None,
    checks="data",
    supplied=None,
    image=None,
):
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError("ShadowTLS evidence must stay inside target/interop/runs")
    cases = tuple(c for c in CASES if c.shadow_tls and not c.uot)
    if (
        checks not in {"data", "policy", "fault"}
        or not profiles
        or len(set(profiles)) != len(profiles)
        or not set(profiles) <= set(PROFILES)
    ):
        raise ValueError("invalid ShadowTLS checks or profiles")
    if selected is not None:
        if len(set(selected)) != len(selected) or not set(selected) <= {
            c.identifier for c in cases
        }:
            raise ValueError("unknown or duplicate ShadowTLS case")
        cases = tuple(c for c in cases if c.identifier in selected)
    if checks != "data":
        cases = cases[:1]
    if not cases:
        raise ValueError("empty ShadowTLS selection")
    report = dict(
        source=source_identity(), status="NOT RUN", peer={}, isolation={}, cases=[]
    )
    output.mkdir(parents=True, exist_ok=False)
    try:
        with (
            exclusive_run() if supplied is None else contextlib.nullcontext(),
            (
                frozen_image(output / "image-pull.log")
                if image is None
                else contextlib.nullcontext(image)
            ) as image,
        ):
            report["container_image"] = image
            if supplied is None:
                binary = download_mihomo(
                    "linux-arm64", directory=output / "binary", identity=report["peer"]
                )
            else:
                binary, report["peer"] = supplied
            built = run_command(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--all-features",
                    "--test",
                    "vless_public",
                    "--no-run",
                ],
                cwd=CORE_DIR,
                timeout=180,
            )
            (output / "build.log").write_text(
                redact(built.stdout.decode(errors="replace"))
            )
            if built.returncode or not built.cleanup:
                raise RuntimeError("ShadowTLS consumer build failed")
            lab = ContainerLab(report["isolation"], mtu=1500)
            with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temp:
                root = Path(temp)
                directories = {}
                try:
                    with contextlib.ExitStack() as stack:
                        for role in ("origin", "server"):
                            directory = root / role
                            directory.mkdir()
                            directories[role] = directory
                        cert = certificates(directories["server"])
                        for source, name in zip(
                            cert[:2], ("cert.pem", "key.pem"), strict=True
                        ):
                            shutil.copy2(source, directories["origin"] / name)
                        shutil.copy2(
                            Path(__file__).with_name("container_udp_origin.py"),
                            directories["origin"] / "origin.py",
                        )
                        shutil.copy2(
                            Path(__file__).with_name("container_shadowtls_peer.py"),
                            directories["origin"] / "peer.py",
                        )
                        origin = lab.start(
                            stack,
                            directories["origin"],
                            "origin",
                            [
                                "env",
                                "VCORE_ISOLATED_ORIGIN=1",
                                "VCORE_ORIGIN_CERT=/data/fixture/cert.pem",
                                "VCORE_ORIGIN_KEY=/data/fixture/key.pem",
                                "python",
                                "-B",
                                "/data/fixture/peer.py",
                            ],
                        )
                        shutil.copy2(binary, directories["server"] / "mihomo")
                        server = lab.start(
                            stack,
                            directories["server"],
                            "server",
                            [
                                "/data/fixture/mihomo",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ],
                        )
                        report["peer"]["version"] = command(
                            "exec", server.name, "/data/fixture/mihomo", "-v"
                        ).strip()
                        if (
                            command(
                                "exec", server.name, "sha256sum", "/data/fixture/mihomo"
                            ).split()[0]
                            != report["peer"]["binary_sha256"]
                        ):
                            raise RuntimeError("ShadowTLS peer identity mismatch")
                        nodes, listeners = [], []
                        for index, case in enumerate(cases):
                            node, listener = peer_configuration(
                                case,
                                server=server.ipv4,
                                cover=f"{origin.ipv4}:24001",
                                port=23000 + index,
                                certificate=cert,
                            )
                            node["name"] = "peer"
                            if checks == "data":
                                nodes.append((case.identifier, node, True, 24001, "h2"))
                                listeners.append(listener)
                            elif checks == "policy":
                                for (
                                    label,
                                    client,
                                    peer,
                                    success,
                                    port,
                                    alpn,
                                ) in policy_inputs(node, listener):
                                    nodes.append((label, client, success, port, alpn))
                                    listeners.append(peer)
                            else:
                                listeners.append(listener)
                                hrr = copy.deepcopy(listener)
                                hrr["name"] += "-hrr"
                                hrr["port"] = 23001
                                hrr["shadow-tls"]["handshake"]["dest"] = (
                                    f"{origin.ipv4}:24002"
                                )
                                listeners.append(hrr)
                                directory = root / "fault"
                                directory.mkdir()
                                directories["fault"] = directory
                                shutil.copy2(
                                    Path(__file__).with_name(
                                        "container_shadowtls_fault.py"
                                    ),
                                    directory / "fault.py",
                                )
                                fault = lab.start(
                                    stack,
                                    directory,
                                    "fault",
                                    [
                                        "env",
                                        "VCORE_ISOLATED_ORIGIN=1",
                                        "python",
                                        "-B",
                                        "/data/fixture/fault.py",
                                    ],
                                )
                                routes = []
                                for index, label in enumerate(
                                    (
                                        "fragment",
                                        "hrr-wire",
                                        "cover-mac",
                                        "business-mac",
                                        "business-truncated",
                                        "stall",
                                        "native-udp-disabled",
                                    )
                                ):
                                    port = 23600 + index
                                    routes.append(
                                        dict(
                                            port=port,
                                            mode="fragment"
                                            if label == "hrr-wire"
                                            else label,
                                            server=server.ipv4,
                                            server_port=23001
                                            if label == "hrr-wire"
                                            else 23000,
                                        )
                                    )
                                    client = copy.deepcopy(node)
                                    client.update(server=fault.ipv4, port=port)
                                    nodes.append(
                                        (
                                            label,
                                            client,
                                            label not in {"cover-mac", "stall"},
                                            24002 if label == "hrr-wire" else 24001,
                                            "h2",
                                        )
                                    )
                                (directory / "config.json").write_text(
                                    json.dumps(routes)
                                )
                        (directories["server"] / "config.json").write_text(
                            json.dumps(
                                {
                                    "socks-port": 23999,
                                    "allow-lan": True,
                                    "bind-address": "*",
                                    "ipv6": True,
                                    "log-level": "warning",
                                    "listeners": listeners,
                                    "rules": ["MATCH,DIRECT"],
                                }
                            )
                        )
                        origin.release()
                        server.release()
                        origin.wait_tcp(24000)
                        origin.wait_tcp(24001)
                        origin.wait_tcp(24002)
                        origin.wait_tcp(24003)
                        server.wait_tcp(23999)
                        if checks == "fault":
                            fault.release()
                            fault.wait_tcp(23998)
                            for route in routes:
                                fault.wait_tcp(route["port"])
                        for label, node, success, cover_port, alpn in nodes:
                            for profile in profiles:
                                identifier = f"{label}-{profile}"
                                before = len(
                                    command(
                                        "exec",
                                        origin.name,
                                        "cat",
                                        "/data/cover-events.jsonl",
                                    ).splitlines()
                                )
                                fault_before = (
                                    len(
                                        command(
                                            "exec",
                                            fault.name,
                                            "cat",
                                            "/data/fault-events.jsonl",
                                        ).splitlines()
                                    )
                                    if checks == "fault"
                                    else 0
                                )
                                consumer = (
                                    checks
                                    if checks != "fault"
                                    else {
                                        "fragment": "native_tcp",
                                        "hrr-wire": "native_tcp",
                                        "cover-mac": "policy",
                                        "stall": "stall",
                                        "native-udp-disabled": "native_udp_disabled",
                                    }.get(label, "corrupt")
                                )
                                node["client-fingerprint"] = profile
                                fixture = root / "fixture.json"
                                fixture.write_text(
                                    json.dumps(
                                        dict(
                                            isolation="containers",
                                            node=node,
                                            origin_ipv4=origin.ipv4,
                                            origin_ipv6=origin.ipv6,
                                            origin_control=f"{origin.ipv4}:24000",
                                            data_dir=str(root / "data"),
                                            expected_success=success,
                                            fault_control=f"{fault.ipv4}:23998"
                                            if checks == "fault"
                                            else None,
                                        )
                                    )
                                )
                                observations = (
                                    output / f"{identifier}-observations.json"
                                )
                                argv = [
                                    "cargo",
                                    "test",
                                    "--locked",
                                    "--all-features",
                                    "--test",
                                    "vless_public",
                                    f"shadowtls::{consumer}",
                                    "--",
                                    "--ignored",
                                    "--exact",
                                    "--nocapture",
                                ]
                                result = run_command(
                                    argv,
                                    cwd=CORE_DIR,
                                    timeout=240,
                                    env=dict(
                                        os.environ,
                                        VCORE_VLESS_INPUT=str(fixture),
                                        VCORE_SHADOWTLS_OBSERVATIONS=str(observations),
                                        VCORE_CASE_EVENTS=str(
                                            output / f"{identifier}-events.jsonl"
                                        ),
                                    ),
                                )
                                (output / f"{identifier}.log").write_text(
                                    redact(result.stdout.decode(errors="replace"))
                                )
                                observed = (
                                    json.loads(observations.read_text())
                                    if observations.is_file()
                                    else None
                                )
                                expected = (
                                    dict(
                                        tcp_bytes_each_direction=10 * 1024 * 1024,
                                        udp_packets=500 if consumer == "data" else 0,
                                        udp_sizes=[1, 64, 512, 1200, 4096]
                                        if consumer == "data"
                                        else [],
                                        stop_idle=True,
                                    )
                                    if consumer in {"data", "native_tcp"}
                                    else dict(
                                        origin_connected=True,
                                        delivered_bytes=0,
                                        stop_idle=True,
                                    )
                                    if consumer == "corrupt"
                                    else dict(
                                        stop_idle=True,
                                        stop_handshake_cancelled=True,
                                        measure_deadline=True,
                                        origin_connected=False,
                                        closed_handshakes=2,
                                    )
                                    if consumer == "stall"
                                    else dict(
                                        tcp_accepted=True,
                                        udp_delivered=False,
                                        stop_idle=True,
                                    )
                                    if consumer == "native_udp_disabled"
                                    else dict(
                                        accepted=success,
                                        origin_connected=success,
                                        stop_idle=True,
                                    )
                                )
                                cover = [
                                    json.loads(line)
                                    for line in command(
                                        "exec",
                                        origin.name,
                                        "cat",
                                        "/data/cover-events.jsonl",
                                    ).splitlines()[before:]
                                ]
                                cover_pass = (
                                    not success
                                    or dict(
                                        port=cover_port, version="TLSv1.3", alpn=alpn
                                    )
                                    in cover
                                )
                                fault_events = (
                                    [
                                        json.loads(line)
                                        for line in command(
                                            "exec",
                                            fault.name,
                                            "cat",
                                            "/data/fault-events.jsonl",
                                        ).splitlines()[fault_before:]
                                    ]
                                    if checks == "fault"
                                    else []
                                )
                                fault_pass = True
                                if checks == "fault":
                                    required = (
                                        "split_record"
                                        if label == "fragment"
                                        else "hrr_seen"
                                        if label == "hrr-wire"
                                        else "injected"
                                    )
                                    fault_pass = any(
                                        event.get(required) is True
                                        for event in fault_events
                                    ) and not any(
                                        event.get("upload_join_failed")
                                        for event in fault_events
                                    )
                                    if label == "stall":
                                        fault_pass = not cover and all(
                                            sum(
                                                event.get(key) is True
                                                for event in fault_events
                                            )
                                            == 2
                                            for key in ("hello_seen", "client_closed")
                                        )
                                    elif label == "native-udp-disabled":
                                        fault_pass = not any(
                                            event.get("upload_join_failed")
                                            for event in fault_events
                                        )
                                passed = (
                                    result.returncode == 0
                                    and result.cleanup
                                    and observed == expected
                                    and cover_pass
                                    and fault_pass
                                )
                                report["cases"].append(
                                    dict(
                                        case_id=identifier,
                                        status="PASS" if passed else "FAIL",
                                        command=argv,
                                        exit_code=result.returncode,
                                        command_cleanup=result.cleanup,
                                        observations=observed,
                                        cover=cover,
                                        fault=fault_events,
                                    )
                                )
                                print(
                                    f"{identifier}: {'PASS' if passed else 'FAIL'}",
                                    flush=True,
                                )
                                if not passed:
                                    raise RuntimeError(
                                        "ShadowTLS public data validation failed"
                                    )
                finally:
                    for role, directory in directories.items():
                        if (directory / "peer.log").is_file():
                            (output / f"{role}.log").write_text(
                                redact(
                                    (directory / "peer.log").read_text(errors="replace")
                                )
                            )
            report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAIL"
        (output / "failure.log").write_text(redact(str(error)))
        raise
    finally:
        report["cleanup"] = all(
            p.get("joined") is True for p in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = same_source(report["source"], source_identity())
        if not report["cleanup"] or not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "PASS":
        raise RuntimeError("ShadowTLS source or cleanup validation failed")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--profile", action="append")
    parser.add_argument("--case", action="append")
    parser.add_argument("--checks", choices=("data", "policy", "fault"), default="data")
    args = parser.parse_args()
    run(
        args.output,
        profiles=args.profile or ["none"],
        selected=args.case,
        checks=args.checks,
    )
