"""Native-client differential for N3 upload EOF. Does not sign off VCore."""

from __future__ import annotations

import contextlib
import json
import socket
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path

from .mihomo_isolation import exclusive_run, reserve_port
from .protocol_inputs import source_identity
from .protocol_peers import OwnedProcess
from .protocol_preflight import preflight
from .protocol_streams import certificates
from .protocol_vmess import peer_config

PAYLOAD = b"synthetic-native-close-probe"
TAIL = b"native-after-upload-eof"


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.server.state["accepted"] += 1
        try:
            self.request.sendall(b"hello")
            received = b""
            while len(received) < len(PAYLOAD):
                data = self.request.recv(len(PAYLOAD) - len(received))
                if not data:
                    raise RuntimeError("truncated native request")
                received += data
            self.server.state["payload_correct"] = received == PAYLOAD
            self.request.sendall(received)
            self.server.state["upload_eof"] = self.request.recv(1) == b""
            if self.server.state["upload_eof"]:
                self.request.sendall(TAIL)
                self.server.state["tail_written"] = True
        except (OSError, RuntimeError) as error:
            self.server.state["error"] = type(error).__name__
        finally:
            self.server.finished.set()


def read_exact(stream, count):
    data = b""
    while len(data) < count:
        part = stream.recv(count - len(data))
        if not part:
            raise RuntimeError("truncated native response")
        data += part
    return data


def exchange(port, target):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(b"\x05\x01\x00")
        if read_exact(client, 2) != b"\x05\x00":
            raise RuntimeError("native SOCKS method rejected")
        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.to_bytes(2, "big"))
        reply = read_exact(client, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise RuntimeError("native SOCKS connect rejected")
        read_exact(client, {1: 4, 4: 16}[reply[3]] + 2)
        greeting = read_exact(client, 5)
        client.sendall(PAYLOAD)
        echo = read_exact(client, len(PAYLOAD))
        started = time.monotonic()
        client.shutdown(socket.SHUT_WR)
        tail = b""
        while len(tail) <= 128:
            data = client.recv(128)
            if not data:
                break
            tail += data
        return dict(
            server_first=greeting == b"hello",
            echo_correct=echo == PAYLOAD,
            tail_bytes=len(tail),
            tail_correct=tail == TAIL,
            close_seconds=round(time.monotonic() - started, 3),
        )


def run(output):
    raise RuntimeError(
        "BLOCKED: archived host-server diagnostic; use container-only N3 acceptance"
    )


def _historical_run(output):
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        scope="native-to-native-close-differential",
        source=source_identity(),
        cases=[],
        cleanup=False,
    )
    try:
        artifacts, report["preflight"] = preflight(output / "binaries", {"M", "V2"})
        if set(artifacts) != {"M", "V2"}:
            raise RuntimeError("official peer unavailable")
        report["peers"] = {
            kind: artifact.identity for kind, artifact in artifacts.items()
        }
        for kind, mode in [
            ("M", "tcp"),
            ("M", "ws"),
            ("M", "grpc"),
            ("V2", "tcp"),
            ("V2", "http"),
            ("V2", "h2"),
        ]:
            for encrypted in [False, True]:
                case = dict(
                    server=kind,
                    mode=mode,
                    tls=encrypted,
                    server_cleanup={},
                    client_cleanup={},
                )
                report["cases"].append(case)
                print(f"native-close: M -> {kind} {mode} tls={encrypted}", flush=True)
                with (
                    tempfile.TemporaryDirectory(
                        prefix="private-", dir=output
                    ) as temporary,
                    contextlib.ExitStack() as stack,
                ):
                    root = Path(temporary)
                    server_port, server_guard = reserve_port(stack)
                    client_port, client_guard = reserve_port(stack)
                    server_dir = root / "server"
                    client_dir = root / "client"
                    server_dir.mkdir()
                    client_dir.mkdir()
                    cert, key, _ = certificates(server_dir)
                    server_config = server_dir / "config.json"
                    server_config.write_text(
                        json.dumps(
                            peer_config(kind, mode, encrypted, server_port, cert, key)
                        )
                    )
                    node = dict(
                        name="edge",
                        type="vmess",
                        server="127.0.0.1",
                        port=server_port,
                        uuid="07070707-0707-0707-0707-070707070707",
                        alterId=0,
                        cipher="auto",
                        network=mode,
                        tls=encrypted,
                    )
                    if encrypted:
                        node.update(
                            servername="localhost", **{"skip-cert-verify": True}
                        )
                    if mode == "http":
                        node["http-opts"] = dict(
                            method="GET",
                            path=["/n3-http"],
                            headers={"Host": ["localhost"]},
                        )
                    if mode == "ws":
                        node["ws-opts"] = dict(
                            path="/n3-ws", headers={"Host": "localhost"}
                        )
                    if mode == "grpc":
                        node["grpc-opts"] = {"grpc-service-name": "n3-grpc"}
                    if mode == "h2":
                        node["h2-opts"] = dict(host=["localhost"], path="/n3-h2")
                    client_config = client_dir / "config.json"
                    client_config.write_text(
                        json.dumps(
                            {
                                "mode": "rule",
                                "log-level": "silent",
                                "listeners": [
                                    dict(
                                        name="fixture",
                                        type="socks",
                                        listen="127.0.0.1",
                                        port=client_port,
                                    )
                                ],
                                "proxies": [node],
                                "rules": ["MATCH,edge"],
                            }
                        )
                    )
                    server_command = (
                        [
                            str(artifacts[kind].binary),
                            "-d",
                            str(server_dir),
                            "-f",
                            str(server_config),
                        ]
                        if kind == "M"
                        else [
                            str(artifacts[kind].binary),
                            "run",
                            "-c",
                            str(server_config),
                        ]
                    )
                    server_guard.release_ipv4()
                    server = stack.enter_context(
                        OwnedProcess(
                            server_command,
                            server_dir / "peer.log",
                            case["server_cleanup"],
                        )
                    )
                    server.wait_tcp(server_port)
                    client_guard.release_ipv4()
                    client = stack.enter_context(
                        OwnedProcess(
                            [
                                str(artifacts["M"].binary),
                                "-d",
                                str(client_dir),
                                "-f",
                                str(client_config),
                            ],
                            client_dir / "peer.log",
                            case["client_cleanup"],
                        )
                    )
                    client.wait_tcp(client_port)
                    with socketserver.TCPServer(("127.0.0.1", 0), Origin) as origin:
                        origin.state = dict(
                            accepted=0,
                            payload_correct=False,
                            upload_eof=False,
                            tail_written=False,
                        )
                        origin.finished = threading.Event()
                        worker = threading.Thread(target=origin.handle_request)
                        origin.timeout = 5
                        worker.start()
                        try:
                            case["client"] = exchange(
                                client_port, origin.server_address[1]
                            )
                        except (OSError, RuntimeError) as error:
                            case["error"] = type(error).__name__
                            if isinstance(error, RuntimeError):
                                # Only our own constant fixture diagnostics; do
                                # not retain addresses or arbitrary OS messages.
                                case["fixture_error"] = str(error)
                        finally:
                            worker.join(timeout=7)
                            case["origin"] = origin.state
                            case["origin_joined"] = not worker.is_alive()
                            if worker.is_alive():
                                raise RuntimeError("owned origin did not stop")
                    server.ensure_alive()
                    client.ensure_alive()
        report["cleanup"] = all(
            case["server_cleanup"].get("joined")
            and case["client_cleanup"].get("joined")
            and case.get("origin_joined")
            for case in report["cases"]
        )
        report["observations_complete"] = all(
            case.get("client", {}).get("server_first")
            and case.get("client", {}).get("echo_correct")
            and case.get("origin", {}).get("payload_correct")
            and case.get("origin", {}).get("accepted") == 1
            and not case.get("error")
            # Tail delivery is an observation, not a universal requirement.
            for case in report["cases"]
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        return (
            0
            if report["cleanup"]
            and report["observations_complete"]
            and report["source_unchanged"]
            else 1
        )
    finally:
        (output / "native-close.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve()))
