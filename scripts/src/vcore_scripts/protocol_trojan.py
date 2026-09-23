"""N2 public Trojan consumer acceptance against owned official native peers."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run, reserve_port
from .protocol_inputs import redact, source_identity
from .protocol_peers import OwnedProcess, run_command
from .protocol_preflight import preflight
from .protocol_streams import certificates

CASES = {
    "N2-M-TCP": ("M", "tcp", "public_trojan_native_base"),
    "N2-M-TCP-POLICY": ("M", "tcp", "public_trojan_native_policy_and_group_snapshots"),
    "N2-XR-UDP-DOMAIN": ("XR", "tcp", "public_trojan_native_udp_domain"),
}


def peer_config(kind, mode, port, password, cert, key):
    if kind == "M":
        listener = {
            "name": "n2",
            "type": "trojan",
            "listen": "127.0.0.1",
            "port": port,
            "users": [{"username": "fixture", "password": password}],
            "certificate": str(cert),
            "private-key": str(key),
        }
        return {
            "mode": "rule",
            "log-level": "silent",
            "ipv6": True,
            "hosts": {"vcore-fixture.test": "127.0.0.1"},
            "listeners": [listener],
            "rules": ["MATCH,DIRECT"],
        }
    return {
        "log": {"loglevel": "none"},
        "dns": {"hosts": {"vcore-fixture.test": "127.0.0.1"}},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "trojan",
                "settings": {"clients": [{"password": password}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {"certificateFile": str(cert), "keyFile": str(key)}
                        ]
                    },
                },
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}],
    }


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
                cert, key, pin = certificates(directory)
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
                command = (
                    [str(artifacts[kind].binary), "-d", str(directory), "-f", str(path)]
                    if kind == "M"
                    else [str(artifacts[kind].binary), "run", "-c", str(path)]
                )
                reservation.release_ipv4()
                with OwnedProcess(
                    command, directory / "peer.log", record["cleanup"]
                ) as peer:
                    peer.wait_tcp(port)
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
                        VCORE_TROJAN_FIXTURE=json.dumps(
                            {
                                "node": node,
                                "hop": hop,
                                "data_dir": str(directory / "core"),
                            }
                        ),
                    )
                    result = run_command(
                        [
                            "cargo",
                            "test",
                            "--locked",
                            "--all-features",
                            "--test",
                            "mihomo_interop",
                            f"trojan::{test}",
                            "--",
                            "--ignored",
                            "--exact",
                            "--nocapture",
                        ],
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
                        if result.returncode == 0 and result.cleanup
                        else "FAIL",
                        exit_code=result.returncode,
                        command_cleanup=result.cleanup,
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


if __name__ == "__main__":
    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:] or None))
