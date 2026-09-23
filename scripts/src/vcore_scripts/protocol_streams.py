"""N1 transport-only native cases; synthetic VLESS is not public YAML support."""

from __future__ import annotations

import contextlib
import hashlib
import json
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import reserve_port
from .protocol_peers import OwnedProcess, run_command
from .protocol_preflight import preflight

CLIENT_ID = "b831381d-6324-4d53-ad4f-8cda48b30811"  # Public synthetic identity.
GREETING, TRAILER = b"N1-server-first\n", b"N1-half-close\n"
STREAM_CASES = {
    "N1-M-WS": ("M", "ws"),
    "N1-M-WSS": ("M", "wss"),
    "N1-M-GRPC": ("M", "grpc"),
    "N1-M-GRPC-TLS": ("M", "grpc-tls"),
    "N1-M-WS-ED": ("M", "ws-header"),
    "N1-V2-HTTP": ("V2", "http"),
    "N1-V2-H2": ("V2", "h2"),
    "N1-V2-WS-HEADER": ("V2", "ws-header"),
    "N1-V2-WS-PATH": ("V2", "ws-path"),
}


def abnormal_cleanup(binary: Path, directory: Path, cert: Path, key: Path) -> dict:
    """A real native peer must be joined even when its calling case unwinds."""

    class InjectedFailure(Exception):
        pass

    record = {}
    with contextlib.ExitStack() as stack:
        port, reservation = reserve_port(stack)
        config = directory / "cleanup-peer.json"
        config.write_text(json.dumps(peer_config("M", "ws", port, cert, key)))
        reservation.release_ipv4()
        owner = OwnedProcess(
            [str(binary), "-d", str(directory), "-f", str(config)],
            directory / "cleanup-peer.log",
            record,
        )
        try:
            with owner:
                owner.wait_tcp(port)
                raise InjectedFailure
        except InjectedFailure:
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rebind:
            rebind.bind(("127.0.0.1", port))
        if not record.get("joined") or owner.process.poll() is None:
            raise RuntimeError("native abnormal cleanup failed")
    return {
        "passed": True,
        "kind": "M",
        "failure_injected": True,
        "joined": True,
        "port_rebound": True,
    }


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.accepted += 1
        self.request.settimeout(15)
        try:
            self.request.sendall(GREETING)
            while data := self.request.recv(8192):
                self.server.received += len(data)
                self.request.sendall(data)
                if self.server.received >= 65536:
                    break
            self.request.sendall(TRAILER)
        except OSError:
            self.server.failed = True
        finally:
            self.server.finished.set()


@contextlib.contextmanager
def origin():
    with socketserver.TCPServer(("127.0.0.1", 0), Echo) as server:
        server.accepted, server.received, server.failed = 0, 0, False
        server.finished = threading.Event()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=20)
            if thread.is_alive():
                raise RuntimeError("origin cleanup failed")


def certificates(directory: Path):
    cert, key = directory / "cert.pem", directory / "key.pem"
    generated = run_command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        timeout=20,
        limit=65536,
    )
    der = run_command(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        timeout=10,
        limit=65536,
    )
    if (
        generated.returncode != 0
        or der.returncode != 0
        or not generated.cleanup
        or not der.cleanup
    ):
        raise RuntimeError("synthetic certificate generation failed")
    return cert, key, hashlib.sha256(der.stdout).hexdigest()


def peer_config(kind, mode, port, cert, key):
    encrypted = mode in {"wss", "grpc-tls", "h2"}
    if kind == "M":
        listener = {
            "name": "n1-stream",
            "type": "vless",
            "listen": "127.0.0.1",
            "port": port,
            "users": [{"uuid": CLIENT_ID}],
        }
        if encrypted:
            listener.update(certificate=str(cert), **{"private-key": str(key)})
        else:
            listener["allow-insecure"] = True  # Explicit loopback-only plaintext.
        if mode.startswith("ws"):
            listener["ws-path"] = "/n1-ws"
        if mode.startswith("grpc"):
            listener["grpc-service-name"] = "n1-grpc"
        return {
            "mode": "rule",
            "log-level": "silent",
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "listeners": [listener],
            "rules": ["MATCH,DIRECT"],
        }
    stream = {"network": "tcp", "security": "tls" if encrypted else "none"}
    if mode == "http":
        stream["tcpSettings"] = {
            "header": {"type": "http", "request": {"path": ["/n1-http"]}}
        }
    elif mode == "h2":
        stream.update(
            network="http", httpSettings={"host": ["localhost"], "path": "/n1-h2"}
        )
    else:
        stream.update(
            network="ws",
            wsSettings={
                "path": "/n1-ws",
                "maxEarlyData": 2048,
                "earlyDataHeaderName": "x-vcore-ed" if mode == "ws-header" else "",
            },
        )
    if encrypted:
        stream["tlsSettings"] = {
            "alpn": ["h2"],
            "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}],
        }
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {"clients": [{"id": CLIENT_ID}], "decryption": "none"},
                "streamSettings": stream,
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }


def run_streams(output: Path, selected: list[str] | None = None, *, artifacts=None):
    selected = list(STREAM_CASES) if selected is None else selected
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not set(selected) <= STREAM_CASES.keys()
    ):
        raise RuntimeError("invalid native stream case selection")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "scope": "N1-shared-transport-only",
        "cases": [],
        "peers": [],
        "cleanup": False,
    }
    try:
        kinds = {STREAM_CASES[case][0] for case in selected}
        if artifacts is None:
            artifacts, report["preflight"] = preflight(output / "binaries", kinds)
        peers = {kind: item.binary for kind, item in artifacts.items() if kind in kinds}
        report["peers"] = [
            item.identity for kind, item in artifacts.items() if kind in kinds
        ]
        with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary:
            temporary = Path(temporary)
            cert, key, pin = certificates(temporary)
            if "M" in peers:
                report["abnormal_cleanup"] = abnormal_cleanup(
                    peers["M"], temporary, cert, key
                )
            for case_id in selected:
                kind, mode = STREAM_CASES[case_id]
                record = {
                    "case_id": case_id,
                    "peer_kind": kind,
                    "mode": mode,
                    "status": "NOT RUN",
                    "cleanup": {},
                }
                report["cases"].append(record)
                if kind not in peers:
                    record.update(
                        status="BLOCKED",
                        reason="required peer unavailable",
                        cleanup={"joined": True, "started": False},
                    )
                    continue
                started = time.monotonic()
                try:
                    with contextlib.ExitStack() as stack:
                        port, reservation = reserve_port(stack)
                        config = temporary / "peer.json"
                        config.write_text(
                            json.dumps(peer_config(kind, mode, port, cert, key))
                        )
                        command = (
                            [str(peers[kind]), "-d", str(temporary), "-f", str(config)]
                            if kind == "M"
                            else [str(peers[kind]), "run", "-c", str(config)]
                        )
                        reservation.release_ipv4()
                        peer = stack.enter_context(
                            OwnedProcess(
                                command, temporary / "peer.log", record["cleanup"]
                            )
                        )
                        peer.wait_tcp(port)
                        with origin() as echo:
                            fixture = {
                                "mode": mode,
                                "server": f"127.0.0.1:{port}",
                                "target": f"127.0.0.1:{echo.server_address[1]}",
                                "pin": pin,
                                "ed_header": "sec-websocket-protocol"
                                if kind == "M"
                                else "x-vcore-ed",
                            }
                            probe_config = temporary / "probe.json"
                            probe_config.write_text(json.dumps(fixture))
                            completed = run_command(
                                [
                                    str(
                                        CORE_DIR
                                        / "target/debug/examples/protocol-stream-probe"
                                    ),
                                    str(probe_config),
                                ],
                                timeout=20,
                                limit=65536,
                            )
                            result = json.loads(completed.stdout)
                            record["rust_event"] = result
                            record["command_exit_code"] = completed.returncode
                            record["origin"] = {
                                "finished": echo.finished.wait(3),
                                "accepted": echo.accepted,
                                "received": echo.received,
                                "failed": echo.failed,
                            }
                            peer.ensure_alive()
                            record["status"] = (
                                "PASS"
                                if completed.returncode == 0
                                and result["outcome"] == "pass"
                                and result["driver_joined"]
                                and result["protect_calls"] == 1
                                and result.get("resources_idle") is True
                                and result.get("server_first") is True
                                and result.get("payload_bytes") == 65536
                                and result.get("tail_bytes") == len(TRAILER)
                                and completed.cleanup
                                and record["origin"]
                                == {
                                    "finished": True,
                                    "accepted": 1,
                                    "received": 65536,
                                    "failed": False,
                                }
                                else "FAIL"
                            )
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as error:
                    record.update(status="FAIL", reason=type(error).__name__)
                finally:
                    record["seconds"] = round(time.monotonic() - started, 3)
                    if not record["cleanup"].get("joined"):
                        record["status"] = "FAIL"
                    print(json.dumps(record), flush=True)
        report["cleanup"] = True
    finally:
        (output / "stream-cases.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["cleanup"] or any(
        case["status"] != "PASS" for case in report["cases"]
    ):
        raise RuntimeError("native stream cases did not pass; see structured report")
    return report
