"""N0-B only: injected streams, official latest Mihomo, owned loopback peers."""

import contextlib
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

SPIKE = Path(__file__).resolve().parent
CORE = SPIKE.parents[3]
# Reuse repository-local synthetic certificates/echo and the official downloader.
# No reference checkout, external repository or fixed peer version is required.
sys.path.insert(0, str(SPIKE.parent / "hysteria2"))
from run import (  # noqa: E402
    GREETING,
    TRAILER,
    certificates,
    download_mihomo,
    origin,
)
from vcore_scripts.mihomo_isolation import exclusive_run, reserve_port  # noqa: E402

CLIENT_ID = "b831381d-6324-4d53-ad4f-8cda48b30811"  # Public synthetic fixture.
MODES = ("tls", "ws", "wss", "grpc", "grpc-tls")


@contextlib.contextmanager
def peer(binary, directory, config, ready_port, output):
    directory.mkdir()
    for listener in config.get("listeners", []):
        for field in ("certificate", "private-key"):
            if field in listener:
                destination = directory / f"{field}.pem"
                shutil.copyfile(listener[field], destination)
                listener[field] = str(destination)
    path = directory / "config.json"
    path.write_text(json.dumps(config))
    log_path = output / f"{directory.name}.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(binary), "-d", str(directory), "-f", str(path)],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Mihomo fixture exited during startup")
                text = log_path.read_text(errors="replace")
                if "level=error" in text or "level=fatal" in text:
                    raise RuntimeError(
                        "Mihomo fixture startup error; inspect local log"
                    )
                try:
                    with socket.create_connection(("127.0.0.1", ready_port), 0.2):
                        if (
                            not config.get("listeners")
                            or "Vless[n0-stream] proxy listening" in text
                        ):
                            break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Mihomo fixture readiness timeout")
                time.sleep(0.05)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def recv_exact(stream, length):
    result = bytearray()
    while len(result) < length:
        data = stream.recv(length - len(result))
        if not data:
            raise RuntimeError("Mihomo closed before fixture data completed")
        result.extend(data)
    return bytes(result)


def client_close(socks_port, mode):
    with origin(half_close=True) as echo:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as stream:
            stream.sendall(b"\x05\x01\x00")
            assert recv_exact(stream, 2) == b"\x05\x00"
            stream.sendall(
                b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                + echo.server_address[1].to_bytes(2, "big")
            )
            assert recv_exact(stream, 4) == b"\x05\x00\x00\x01"
            recv_exact(stream, 6)
            assert recv_exact(stream, len(GREETING)) == GREETING
            payload = bytes(n % 251 for n in range(65536))
            for offset in range(0, len(payload), 4096):
                fragment = payload[offset : offset + 4096]
                stream.sendall(fragment)
                assert recv_exact(stream, len(fragment)) == fragment
            stream.shutdown(socket.SHUT_WR)
            tail = bytearray()
            while data := stream.recv(256):
                tail.extend(data)
                if len(tail) > 256:
                    raise RuntimeError("Mihomo close exceeded fixture tail budget")
            expected = b"" if mode.startswith("grpc") else TRAILER
            if tail != expected:
                raise RuntimeError(
                    "Mihomo close differed from source-derived expectation"
                )
        if not echo.finished.wait(3):
            raise RuntimeError("Mihomo close left origin open")
        return {
            "name": f"mihomo-client-{mode}-close",
            "status": "PASS",
            "payload_bytes": len(payload),
            "tail_bytes": len(tail),
            "origin_finished": True,
        }


def run_case(binary, output, temporary, mode, server, cert, name, changes, expected):
    close = changes.get("close", False)
    with origin(half_close=close) as echo:
        fixture = {
            "mode": mode,
            "server": f"127.0.0.1:{server}",
            "target": f"127.0.0.1:{echo.server_address[1]}",
            "ca": str(cert),
        } | changes
        path = temporary / "probe.json"
        path.write_text(json.dumps(fixture))
        process = subprocess.run(
            [str(binary), str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        result = json.loads(process.stdout)
        result["name"] = name
        result["expected"] = expected
        if expected == "pass":
            finished = echo.finished.wait(3)
            passed = finished and echo.received == 65536 and echo.accepted == 1
        else:
            finished = echo.finished.is_set()
            passed = echo.accepted == 0
        result["origin_finished"] = finished
        result["origin_connections"] = echo.accepted
        result["status"] = (
            "PASS"
            if passed
            and result["outcome"] == expected
            and result["protect_calls"] == 1
            and result["driver_joined"]
            else "FAIL"
        )
        (output / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        return result


def main():
    runs = CORE / "target/interop/runs"
    runs.mkdir(parents=True, exist_ok=True)
    output = Path(
        tempfile.mkdtemp(
            prefix="n0-stream-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-",
            dir=runs,
        )
    )
    report = {"phase": "N0-B", "scope": "test-only stream feasibility", "cases": []}
    try:
        with exclusive_run():
            with (output / "build.log").open("wb") as log:
                subprocess.run(
                    [
                        "cargo",
                        "build",
                        "--locked",
                        "--manifest-path",
                        str(SPIKE / "Cargo.toml"),
                        "--target-dir",
                        str(CORE / "target/interop/n0-stream-build"),
                    ],
                    cwd=CORE,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=True,
                    timeout=240,
                )
            executable = (
                CORE / "target/interop/n0-stream-build/debug/vcore-n0-stream-spike"
            )
            mihomo = download_mihomo()
            report["mihomo"] = {
                "version": subprocess.check_output(
                    [str(mihomo), "-v"], text=True, timeout=10
                ).strip(),
                "sha256": hashlib.sha256(mihomo.read_bytes()).hexdigest(),
                "source": "official latest release, fresh download, no API, no local build",
            }
            with tempfile.TemporaryDirectory(
                prefix="fixture-", dir=output
            ) as temporary:
                temporary = Path(temporary)
                cert, key = certificates(temporary, "openssl")
                for mode in MODES:
                    with contextlib.ExitStack() as stack:
                        server, server_guard = reserve_port(stack)
                        upstream, upstream_guard = reserve_port(stack)
                        listener = {
                            "name": "n0-stream",
                            "type": "vless",
                            "listen": "127.0.0.1",
                            "port": server,
                            "users": [{"uuid": CLIENT_ID}],
                        }
                        encrypted = mode in ("tls", "wss", "grpc-tls")
                        if encrypted:
                            listener |= {
                                "certificate": str(cert),
                                "private-key": str(key),
                            }
                        else:
                            listener["allow-insecure"] = (
                                True  # Explicit plain loopback fixture only.
                            )
                        if mode in ("ws", "wss"):
                            listener["ws-path"] = "/n0-ws"
                        if mode.startswith("grpc"):
                            listener["grpc-service-name"] = "n0-grpc"
                        server_guard.release_ipv4()
                        upstream_guard.release_ipv4()
                        stack.enter_context(
                            peer(
                                mihomo,
                                temporary / f"server-{mode}",
                                {
                                    "mode": "rule",
                                    "log-level": "info",
                                    "allow-lan": False,
                                    "bind-address": "127.0.0.1",
                                    "listeners": [listener],
                                    "rules": ["MATCH,DIRECT"],
                                },
                                server,
                                output,
                            )
                        )
                        # Two distinct peers: routing the server back through its
                        # own SOCKS listener triggers Mihomo's loop protection.
                        stack.enter_context(
                            peer(
                                mihomo,
                                temporary / f"upstream-{mode}",
                                {
                                    "mode": "rule",
                                    "log-level": "warning",
                                    "allow-lan": False,
                                    "bind-address": "127.0.0.1",
                                    "socks-port": upstream,
                                    "rules": ["MATCH,DIRECT"],
                                },
                                upstream,
                                output,
                            )
                        )
                        cases = [
                            ("normal", {}, "pass"),
                            ("close", {"close": True}, "pass"),
                            (
                                "socks5",
                                {"socks5": f"127.0.0.1:{upstream}", "close": True},
                                "pass",
                            ),
                            ("protect-reject", {"reject": True}, "connect"),
                        ]
                        if encrypted:
                            cases.append(
                                ("wrong-name", {"sni": "wrong.invalid"}, "tls")
                            )
                        if mode in ("ws", "wss"):
                            cases.append(("wrong-path", {"path": "/missing"}, "ws"))
                        if mode.startswith("grpc"):
                            cases.append(
                                ("wrong-service", {"service": "missing"}, "response")
                            )
                        for suffix, changes, expected in cases:
                            report["cases"].append(
                                run_case(
                                    executable,
                                    output,
                                    temporary,
                                    mode,
                                    server,
                                    cert,
                                    f"{mode}-{suffix}",
                                    changes,
                                    expected,
                                )
                            )
                        client_port, client_guard = reserve_port(stack)
                        proxy = {
                            "name": "stream",
                            "type": "vless",
                            "server": "127.0.0.1",
                            "port": server,
                            "uuid": CLIENT_ID,
                            "tls": encrypted,
                            "servername": "localhost",
                            "network": "grpc"
                            if mode.startswith("grpc")
                            else "ws"
                            if mode in ("ws", "wss")
                            else "tcp",
                        }
                        if mode in ("ws", "wss"):
                            proxy["ws-opts"] = {"path": "/n0-ws"}
                        if mode.startswith("grpc"):
                            proxy["grpc-opts"] = {"grpc-service-name": "n0-grpc"}
                        client_guard.release_ipv4()
                        stack.enter_context(
                            peer(
                                mihomo,
                                temporary / f"client-{mode}",
                                {
                                    "mode": "rule",
                                    "log-level": "warning",
                                    "allow-lan": False,
                                    "bind-address": "127.0.0.1",
                                    "socks-port": client_port,
                                    "tls": {"custom-certifactes": [cert.read_text()]},
                                    "proxies": [proxy],
                                    "rules": ["MATCH,stream"],
                                },
                                client_port,
                                output,
                            )
                        )
                        for iteration in range(3):
                            result = client_close(client_port, mode)
                            result["iteration"] = iteration + 1
                            report["cases"].append(result)
                            print(json.dumps(result), flush=True)
        report["status"] = (
            "PASS"
            if all(case["status"] == "PASS" for case in report["cases"])
            else "FAIL"
        )
    except Exception as error:
        report["status"] = "FAIL"
        report["error_class"] = type(error).__name__
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"N0-B report: {output.relative_to(CORE) / 'report.json'}", flush=True)
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
