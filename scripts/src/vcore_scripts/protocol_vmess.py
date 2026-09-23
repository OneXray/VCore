"""N3 wire gate against a freshly downloaded, owned official Mihomo process."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run, reserve_port
from .protocol_evidence import read_events
from .protocol_inputs import redact, source_identity
from .protocol_peers import OwnedProcess, run_command
from .protocol_preflight import preflight
from .protocol_streams import certificates

CASES = {"N3-M-IDENTITY": ("M", "tcp", False, "native_identity_time_replay_rejection")}
CASES["N3-M-RAW-UDP"] = ("M", "tcp", False, "native_raw_udp_boundaries")
CASES["N3-M-ENCODED-UDP"] = ("M", "tcp", False, "native_encoded_udp_boundaries")
for _mode in ("tcp", "ws", "grpc", "http", "h2"):
    for _tls in (False, True):
        _kind = "V2" if _mode in {"http", "h2"} else "M"
        CASES[f"N3-{_kind}-{_mode.upper()}-{'TLS' if _tls else 'PLAIN'}"] = (
            _kind,
            _mode,
            _tls,
            "native_cipher_matrix",
        )
        CASES[f"N3-{_kind}-{_mode.upper()}-{'TLS' if _tls else 'PLAIN'}-CLOSE"] = (
            _kind,
            _mode,
            _tls,
            "native_mihomo_close_alignment",
        )
        if _mode != "tcp" or _tls:
            for _encoding in ("raw", "encoded"):
                CASES[
                    f"N3-{_kind}-{_mode.upper()}-{'TLS' if _tls else 'PLAIN'}"
                    f"-{_encoding.upper()}-UDP"
                ] = (
                    _kind,
                    _mode,
                    _tls,
                    f"native_{_encoding}_udp_boundaries",
                )


def udp_path_limit():
    # The native peer and the echo endpoint use ordinary host UDP sockets.
    # Darwin enforces the default send-buffer size as a datagram ceiling;
    # measure it without changing host sysctls or the peer's socket options.
    if sys.platform == "darwin":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            return min(15000, probe.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
    return 15000


def peer_config(kind, mode, encrypted, port, cert, key):
    identity = "07070707-0707-0707-0707-070707070707"
    if kind == "M":
        listener = dict(
            name="n3",
            type="vmess",
            listen="127.0.0.1",
            port=port,
            users=[dict(username="fixture", uuid=identity, alterId=0)],
        )
        if encrypted:
            listener.update(certificate=str(cert), **{"private-key": str(key)})
        if mode == "ws":
            listener["ws-path"] = "/n3-ws"
        if mode == "grpc":
            listener["grpc-service-name"] = "n3-grpc"
        return {
            "mode": "rule",
            "log-level": "silent",
            "ipv6": True,
            "hosts": {"vcore-fixture.test": "127.0.0.1"},
            "listeners": [listener],
            "rules": ["MATCH,DIRECT"],
        }
    stream = dict(network="tcp", security="tls" if encrypted else "none")
    if mode == "http":
        stream["tcpSettings"] = {
            "header": {"type": "http", "request": {"path": ["/n3-http"]}}
        }
    elif mode == "h2":
        stream.update(
            network="http", httpSettings=dict(host=["localhost"], path="/n3-h2")
        )
    if encrypted:
        stream["tlsSettings"] = {
            "alpn": ["h2"] if mode == "h2" else ["http/1.1"],
            "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}],
        }
    return {
        "log": {"loglevel": "none"},
        "dns": {"hosts": {"vcore-fixture.test": "127.0.0.1"}},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vmess",
                "settings": {"clients": [{"id": identity, "alterId": 0}]},
                "streamSettings": stream,
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}],
    }


def run(output: Path, selected=None):
    selected = list(CASES) if selected is None else selected
    if (
        not selected
        or len(selected) != len(set(selected))
        or not set(selected) <= CASES.keys()
    ):
        raise ValueError("invalid N3 native selection")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "stage": "N3",
        "scope": "wire-only",
        "source": source_identity(),
        "status": "NOT RUN",
        "cases": [],
        "udp_path_limit": udp_path_limit(),
    }
    try:
        artifacts, report["preflight"] = preflight(
            output / "binaries", {CASES[case][0] for case in selected}
        )
        for case in selected:
            kind, mode, encrypted, test = CASES[case]
            record = dict(case_id=case, status="NOT RUN", cleanup={})
            report["cases"].append(record)
            if kind not in artifacts:
                record["status"] = "BLOCKED"
                continue
            artifact = artifacts[kind]
            record["peer"] = artifact.identity
            print(case, flush=True)
            with (
                tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
                contextlib.ExitStack() as stack,
            ):
                directory = Path(temporary)
                cert, key, pin = certificates(directory)
                port, reservation = reserve_port(stack)
                path = directory / "peer.json"
                path.write_text(
                    json.dumps(peer_config(kind, mode, encrypted, port, cert, key))
                )
                reservation.release_ipv4()
                peer_command = (
                    [str(artifact.binary), "-d", str(directory), "-f", str(path)]
                    if kind == "M"
                    else [str(artifact.binary), "run", "-c", str(path)]
                )
                with OwnedProcess(
                    peer_command, directory / "peer.log", record["cleanup"]
                ) as peer:
                    peer.wait_tcp(port)
                    events = output / f"{case}-events.jsonl"
                    command = [
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        "vmess_native",
                        test,
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ]
                    result = run_command(
                        command,
                        cwd=CORE_DIR,
                        env=dict(
                            os.environ,
                            VCORE_VMESS_PEER=f"127.0.0.1:{port}",
                            VCORE_VMESS_TRANSPORT=json.dumps(
                                dict(
                                    mode=mode,
                                    tls=encrypted,
                                    pin=pin,
                                    peer_kind=kind,
                                    udp_path_limit=report["udp_path_limit"],
                                )
                            ),
                            VCORE_CASE_EVENTS=str(events),
                        ),
                        timeout=180,
                        limit=4 * 1024 * 1024,
                    )
                    (output / f"{case}.log").write_text(
                        redact(result.stdout.decode(errors="replace"))
                    )
                    observed = read_events(events) if events.exists() else []
                    record.update(
                        command=command,
                        exit_code=result.returncode,
                        command_cleanup=result.cleanup,
                        seconds=result.seconds,
                        status="PASS"
                        if result.returncode == 0
                        and result.cleanup
                        and observed
                        == [
                            dict(
                                schema_version=1,
                                suite="N3-WIRE",
                                assertion=test,
                                status=status,
                            )
                            for status in ("BEGIN", "PASS")
                        ]
                        else "FAIL",
                    )
                    peer.ensure_alive()
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        report["status"] = (
            "PASS"
            if all(case["status"] == "PASS" for case in report["cases"])
            else "FAIL"
        )
        report["cleanup"] = all(
            case["cleanup"].get("joined") for case in report["cases"]
        )
        return (
            0
            if report["status"] == "PASS"
            and report["source_unchanged"]
            and report["cleanup"]
            else 1
        )
    finally:
        (output / "vmess-results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:] or None))
