"""N2 public Trojan consumer acceptance against owned official native peers."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import reserve_port
from .protocol_evidence import idle_resources, read_events
from .protocol_fixtures import certificate_chain, certificates
from .protocol_fixtures import trojan_peer_config as peer_config
from .protocol_inputs import redact, source_identity
from .protocol_peers import OwnedProcess, run_command
from .protocol_preflight import preflight

CASES = {
    "N2-M-TCP": ("M", "tcp", "public_trojan_native_base"),
    "N2-M-WS": ("M", "ws", "public_trojan_native_base"),
    "N2-M-GRPC": ("M", "grpc", "public_trojan_native_base"),
    "N2-M-WS-ED-1": ("M", "ws-ed-1", "public_trojan_native_base"),
    "N2-M-WS-ED-2048": ("M", "ws-ed-2048", "public_trojan_native_base"),
    "N2-M-WS-POLICY": ("M", "ws", "public_trojan_native_policy_and_group_snapshots"),
    "N2-M-GRPC-POLICY": (
        "M",
        "grpc",
        "public_trojan_native_policy_and_group_snapshots",
    ),
    "N2-M-WS-NEGATIVE": ("M", "ws", "public_trojan_native_transport_negative"),
    "N2-M-GRPC-NEGATIVE": ("M", "grpc", "public_trojan_native_transport_negative"),
    "N2-M-ALPN-NEGATIVE": ("M", "ws-alpn", "public_trojan_native_transport_negative"),
    "N2-V2-WS-HEADER": ("V2", "ws-header", "public_trojan_native_extended_early_data"),
    "N2-V2-WS-PATH": ("V2", "ws-path", "public_trojan_native_extended_early_data"),
    "N2-M-TCP-POLICY": ("M", "tcp", "public_trojan_native_policy_and_group_snapshots"),
    "N2-XR-UDP-DOMAIN": ("XR", "tcp", "public_trojan_native_udp_domain"),
    "N2-XR-WS-UDP-DOMAIN": ("XR", "ws", "public_trojan_native_udp_domain"),
    "N2-XR-GRPC-UDP-DOMAIN": ("XR", "grpc", "public_trojan_native_udp_domain"),
}
for _mode in ("tcp", "ws", "grpc"):
    for _suffix, _test in (
        ("LIFE", "runtime::public_trojan_native_lifecycle"),
        ("ENTRYPOINTS", "runtime::public_trojan_native_entrypoints"),
        ("UDP-ISOLATION", "runtime::public_trojan_native_udp_isolation_and_limit"),
    ):
        CASES[f"N2-M-{_mode.upper()}-{_suffix}"] = ("M", _mode, _test)
    CASES[f"N2-M-{_mode.upper()}-IPV6"] = (
        "M",
        _mode + "-ipv6",
        "public_trojan_native_base",
    )
    CASES[f"N2-M-{_mode.upper()}-OWNED"] = ("M", _mode, "trojan_native_owned_resources")
    CASES[f"N2-M-{_mode.upper()}-CERTIFICATE"] = (
        "M",
        _mode + "-ca",
        "runtime::public_trojan_native_certificate_names",
    )
CASES["N2-M-GRPC-CUSTOM"] = ("M", "grpc-custom", "public_trojan_native_base")


def native_events_pass(events, test):
    suites = {"N2-NATIVE"}
    if test == "runtime::public_trojan_native_lifecycle":
        suites.add("N2-LIFE-CYCLE")
    elif test == "trojan_native_owned_resources":
        suites.add("N2-OWNED-CYCLE")
    main = [event for event in events if event.get("suite") == "N2-NATIVE"]
    if (
        len(main) != 2
        or any(
            event.get("assertion") != test or event.get("schema_version") != 1
            for event in main
        )
        or [event.get("status") for event in main] != ["BEGIN", "PASS"]
    ):
        return False
    if test in {
        "runtime::public_trojan_native_lifecycle",
        "trojan_native_owned_resources",
    }:
        suite = (
            "N2-OWNED-CYCLE"
            if test == "trojan_native_owned_resources"
            else "N2-LIFE-CYCLE"
        )
        cycles = [event for event in events if event.get("suite") == suite]
        if len(cycles) != 40:
            return False
        for begin, end in zip(cycles[::2], cycles[1::2], strict=True):
            if (
                begin.get("status") != "BEGIN"
                or end.get("status") != "PASS"
                or end.get("seconds", 0) < 5
                or any(
                    event.get("assertion") != "stop_and_remain_quiet"
                    or event.get("schema_version") != 1
                    for event in (begin, end)
                )
            ):
                return False
            if suite == "N2-OWNED-CYCLE":
                points = end.get("checkpoints", [])
                phases = {point["phase"]: point["resources"] for point in points}
                if (
                    len(points) != 3
                    or set(phases) != {"baseline", "after-stop", "quiet"}
                    or not all(idle_resources(value) for value in phases.values())
                    or phases["after-stop"] != phases["quiet"]
                    or not idle_resources(end.get("resources"))
                ):
                    return False
    return all(
        event.get("status") in {"BEGIN", "PASS"}
        and event.get("schema_version") == 1
        and event.get("suite") in suites
        for event in events
    )


def run(output: Path, selected=None, *, artifacts=None):
    selected = list(CASES) if selected is None else selected
    if (
        not selected
        or len(selected) != len(set(selected))
        or not set(selected) <= CASES.keys()
    ):
        raise ValueError("invalid N2 case selection")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "stage": "N2",
        "scope": "protocol-consumer",
        "source": source_identity(),
        "selected_cases": selected,
        "cases": [],
        "cleanup": False,
    }
    try:
        if artifacts is None:
            artifacts, report["preflight"] = preflight(
                output / "binaries", {CASES[case][0] for case in selected}
            )
        for case_id in selected:
            kind, mode, test = CASES[case_id]
            record = {
                "case_id": case_id,
                "mode": mode,
                "cleanup": {},
                "status": "NOT RUN",
            }
            report["cases"].append(record)
            if kind not in artifacts:
                record.update(
                    status="BLOCKED", reason="required official native peer unavailable"
                )
                continue
            record["peer"] = artifacts[kind].identity
            print(f"N2: {case_id}", flush=True)
            with (
                tempfile.TemporaryDirectory(prefix="private-", dir=output) as directory,
                contextlib.ExitStack() as stack,
            ):
                directory = Path(directory)
                cert, key, pin = (
                    certificate_chain if mode.endswith("-ca") else certificates
                )(directory)
                port, reservation = reserve_port(stack)
                password = " synthetic N2 密码 "
                config = peer_config(kind, mode, port, password, cert, key)
                path = directory / "peer.json"
                path.write_text(json.dumps(config))
                node = {
                    "name": "peer",
                    "type": "trojan",
                    "server": "127.0.0.1",
                    "port": port,
                    "password": password,
                    "udp": True,
                    "sni": "localhost",
                    "fingerprint": pin,
                }
                if mode.startswith("ws"):
                    node.update(
                        network="ws",
                        **{
                            "ws-opts": {
                                "path": "/n2-ws?q=1",
                                "headers": {
                                    "Host": "cover.example:443",
                                    "X-N2": "fixture",
                                },
                            }
                        },
                    )
                if mode.startswith("grpc"):
                    node.update(
                        network="grpc",
                        **{"grpc-opts": {"grpc-service-name": "n2-grpc"}},
                    )
                if mode.startswith("ws") and kind != "M":
                    node["ws-opts"]["path"] = "/n2-ws/"
                if mode in {"ws-ed-1", "ws-ed-2048", "ws-header", "ws-path"}:
                    node["ws-opts"]["max-early-data"] = 1 if mode == "ws-ed-1" else 2048
                if mode in {"ws-header", "ws-path"}:
                    node["ws-opts"]["early-data-header-name"] = (
                        "x-vcore-ed" if mode == "ws-header" else ""
                    )
                if mode == "ws-alpn":
                    node["alpn"] = ["h2", "http/1.1"]
                if mode == "grpc-custom":
                    node["grpc-opts"]["grpc-service-name"] = "/n2-grpc/Tun"
                if mode.endswith("-ipv6"):
                    node["server"] = "::1"
                command = (
                    [str(artifacts[kind].binary), "-d", str(directory), "-f", str(path)]
                    if kind == "M"
                    else [str(artifacts[kind].binary), "run", "-c", str(path)]
                )
                if mode.endswith("-ipv6"):
                    reservation.release_ipv6()
                else:
                    reservation.release_ipv4()
                with OwnedProcess(
                    command, directory / "peer.log", record["cleanup"]
                ) as peer:
                    peer.wait_tcp(port, host=node["server"])
                    hop = None
                    if test == "public_trojan_native_policy_and_group_snapshots":
                        # Two independently owned peers, not one process proxying
                        # back into its own loopback detector.
                        hop_dir = directory / "hop"
                        hop_dir.mkdir()
                        hop_cert, hop_key, hop_pin = certificates(hop_dir)
                        hop_port, hop_reservation = reserve_port(stack)
                        hop_path = hop_dir / "peer.json"
                        hop_path.write_text(
                            json.dumps(
                                peer_config(
                                    kind, mode, hop_port, password, hop_cert, hop_key
                                )
                            )
                        )
                        record["upstream_cleanup"] = {}
                        hop_reservation.release_ipv4()
                        hop_peer = stack.enter_context(
                            OwnedProcess(
                                [
                                    str(artifacts[kind].binary),
                                    "-d",
                                    str(hop_dir),
                                    "-f",
                                    str(hop_path),
                                ],
                                hop_dir / "peer.log",
                                record["upstream_cleanup"],
                            )
                        )
                        hop_peer.wait_tcp(hop_port)
                        hop = dict(node, name="hop", port=hop_port, fingerprint=hop_pin)
                    env = dict(
                        os.environ,
                        VCORE_CASE_EVENTS=str(output / f"{case_id}-events.jsonl"),
                        VCORE_TROJAN_FIXTURE=json.dumps(
                            {
                                "node": node,
                                "hop": hop,
                                "mode": mode,
                                "udp_payload_max": 2048
                                if kind == "V2"
                                else 8166
                                if kind == "XR"
                                else 8192,
                                "data_dir": str(directory / "core"),
                            }
                        ),
                    )
                    target = (
                        "trojan_lifecycle"
                        if test == "trojan_native_owned_resources"
                        else "mihomo_interop"
                    )
                    test_name = (
                        test if target == "trojan_lifecycle" else f"trojan::{test}"
                    )
                    command = [
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        target,
                        test_name,
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ]
                    result = run_command(
                        command,
                        cwd=CORE_DIR,
                        env=env,
                        timeout=180,
                        limit=4 * 1024 * 1024,
                    )
                    (output / f"{case_id}.log").write_text(
                        redact(result.stdout.decode(errors="replace"))
                    )
                    record.update(
                        status="PASS"
                        if result.returncode == 0
                        and result.cleanup
                        and native_events_pass(
                            read_events(output / f"{case_id}-events.jsonl")
                            if (output / f"{case_id}-events.jsonl").exists()
                            else [],
                            test,
                        )
                        else "FAIL",
                        exit_code=result.returncode,
                        command_cleanup=result.cleanup,
                        seconds=result.seconds,
                        command=command,
                    )
                    peer.ensure_alive()
        report["cleanup"] = all(
            case["cleanup"].get("joined")
            and case.get("upstream_cleanup", {"joined": True}).get("joined")
            for case in report["cases"]
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        return (
            0
            if report["cleanup"]
            and report["source_unchanged"]
            and all(case["status"] == "PASS" for case in report["cases"])
            else 1
        )
    finally:
        (output / "trojan-results.json").write_text(json.dumps(report, indent=2) + "\n")
