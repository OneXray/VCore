"""N0-D: official Xray VLESS/XHTTP stream-one over protected HTTP/3."""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
import zipfile

from run import (
    CORE,
    SPIKE,
    PAYLOAD_BYTES,
    GREETING,
    TRAILER,
    certificates,
    origin,
    peer,
    download_mihomo,
)
from vcore_scripts.mihomo_isolation import exclusive_run, reserve_port

CLIENT_ID = "b831381d-6324-4d53-ad4f-8cda48b30811"  # Public synthetic fixture only.


def download_xray(directory):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("this native Xray fixture currently requires macOS ARM64")
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-arm64-v8a.zip"
    request = urllib.request.Request(url, headers={"User-Agent": "VCore-N0-interop"})
    deadline = time.monotonic() + 90
    total = 0
    with tempfile.TemporaryDirectory(prefix="download-", dir=directory) as temporary:
        stage = Path(temporary)
        archive = stage / "xray.zip"
        with (
            urllib.request.urlopen(request, timeout=30) as response,
            archive.open("wb") as output,
        ):
            if not response.geturl().startswith("https://"):
                raise RuntimeError("Xray asset redirected outside HTTPS")
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024 or time.monotonic() > deadline:
                    raise RuntimeError("Xray download exceeded its budget")
                output.write(chunk)
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        with zipfile.ZipFile(archive) as bundle:
            candidates = [item for item in bundle.infolist() if item.filename == "xray"]
            if len(candidates) != 1 or candidates[0].file_size > 128 * 1024 * 1024:
                raise RuntimeError("unexpected Xray executable member")
            # Read only the exact executable, not archive paths or bundled scripts.
            data = bundle.read(candidates[0])
        staged = stage / "xray"
        staged.write_bytes(data)
        staged.chmod(0o755)
        binary = directory / "xray"
        os.replace(staged, binary)
    version = subprocess.check_output(
        [str(binary), "version"], text=True, timeout=10
    ).strip()
    return binary, {
        "url": url,
        "version": version,
        "archive_sha256": archive_hash,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@contextlib.contextmanager
def xray_peer(binary, directory, config, output):
    path = directory / "xray.json"
    path.write_text(json.dumps(config))
    subprocess.run(
        [str(binary), "run", "-test", "-config", str(path)],
        check=True,
        capture_output=True,
        timeout=15,
    )
    log_path = output / "peer.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(binary), "run", "-config", str(path)],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Xray exited during startup")
                text = log_path.read_text(errors="replace")
                # Core starts after its configured listener was constructed.
                # Do not probe a TCP port to claim readiness of a UDP listener.
                if "core: Xray" in text and "started" in text:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("Xray startup deadline")
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


def recv_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise RuntimeError("Mihomo closed before the expected response")
        result.extend(chunk)
    return bytes(result)


def compare_mihomo_close(binary, directory, cert, xray_port, socks_port):
    """Use the official client, not just a Mihomo server, as the close oracle."""
    config = {
        "mode": "rule",
        "log-level": "warning",
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "socks-port": socks_port,
        "tls": {"custom-certifactes": [cert.read_text()]},
        "proxies": [
            {
                "name": "xhttp",
                "type": "vless",
                "server": "127.0.0.1",
                "port": xray_port,
                "uuid": CLIENT_ID,
                "network": "xhttp",
                "tls": True,
                "servername": "localhost",
                "alpn": ["h3"],
                "xhttp-opts": {
                    "host": "localhost",
                    "path": "/n0-xhttp/",
                    "mode": "stream-one",
                },
            }
        ],
        "rules": ["MATCH,xhttp"],
    }
    results = []
    with peer(binary, directory / "mihomo-client", config, socks_port):
        for close in (False, True):
            with origin(half_close=close) as echo:
                with socket.create_connection(("127.0.0.1", socks_port), 5) as stream:
                    stream.settimeout(5)
                    stream.sendall(b"\x05\x01\x00")
                    assert recv_exact(stream, 2) == b"\x05\x00"
                    stream.sendall(
                        b"\x05\x01\x00\x01"
                        + socket.inet_aton("127.0.0.1")
                        + echo.server_address[1].to_bytes(2, "big")
                    )
                    reply = recv_exact(stream, 4)
                    assert reply[:3] == b"\x05\x00\x00"
                    assert reply[3] in (1, 4)
                    recv_exact(stream, (4 if reply[3] == 1 else 16) + 2)
                    assert recv_exact(stream, len(GREETING)) == GREETING
                    payload = bytes(index % 251 for index in range(PAYLOAD_BYTES))
                    stream.sendall(payload)
                    assert recv_exact(stream, PAYLOAD_BYTES) == payload
                    if close:
                        # The same application upload EOF which makes VCore's
                        # relay call shutdown makes Mihomo fall back to Close.
                        started = time.monotonic()
                        stream.shutdown(socket.SHUT_WR)
                        try:
                            assert stream.recv(1) == b""
                        except ConnectionResetError:
                            pass
                        close_ms = (time.monotonic() - started) * 1000
                    else:
                        assert recv_exact(stream, len(TRAILER)) == TRAILER
                        assert stream.recv(1) == b""
                        close_ms = None
                assert echo.finished.wait(5), "Mihomo left the target connection open"
                assert echo.accepted == 1 and echo.received == PAYLOAD_BYTES
                if not close:
                    assert not echo.failed
                results.append(
                    {
                        "name": "mihomo-client-h3-close"
                        if close
                        else "mihomo-client-h3-response",
                        "outcome": "closed" if close else "pass",
                        "payload_bytes": PAYLOAD_BYTES,
                        "server_first": True,
                        "response_after_close": False if close else None,
                        "origin_finished": True,
                        "origin_failed": echo.failed,
                        "close_ms": close_ms,
                    }
                )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--half-close",
        action="store_true",
        help="add the separate request-EOF/response-tail diagnostic gate",
    )
    parser.add_argument(
        "--compare-mihomo-close",
        action="store_true",
        help="compare with an official Mihomo XHTTP/H3 client against the same Xray",
    )
    args = parser.parse_args()
    artifact = CORE / "target/interop/n0-xray-h3"
    artifact.mkdir(parents=True, exist_ok=True)
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    )
    output = artifact / run_id
    output.mkdir()
    report_path = output / "result.json"
    executable = (
        CORE / "target/interop/n0-hysteria2-build/debug/vcore-n0-hysteria2-spike"
    )
    report = {
        "status": "incomplete",
        "run_id": run_id,
        "cases": [],
        "vcore_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=CORE, text=True
        ).strip(),
        "lock_sha256": hashlib.sha256((CORE / "Cargo.lock").read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "inputs": {
            str(path.relative_to(SPIKE)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                SPIKE / "Cargo.toml",
                SPIKE / "Cargo.lock",
                *sorted((SPIKE / "src").glob("*.rs")),
                SPIKE / "run.py",
                Path(__file__),
            ]
        },
    }

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        binary, report["xray"] = download_xray(artifact)
        upstream_binary = download_mihomo()
        report["mihomo"] = {
            "version": subprocess.check_output(
                [str(upstream_binary), "-v"], text=True, timeout=10
            ).strip(),
            "sha256": hashlib.sha256(upstream_binary.read_bytes()).hexdigest(),
        }
        save()
        with (
            contextlib.ExitStack() as ports,
            tempfile.TemporaryDirectory(prefix="fixture-", dir=artifact) as temporary,
        ):
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            cert, key = certificates(directory, "openssl")
            port, guard = reserve_port(ports)
            socks, socks_guard = reserve_port(ports)
            client_socks, client_guard = reserve_port(ports)
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": port,
                        "protocol": "vless",
                        "settings": {
                            "clients": [{"id": CLIENT_ID}],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "xhttp",
                            "security": "tls",
                            "tlsSettings": {
                                "alpn": ["h3"],
                                "certificates": [
                                    {"certificateFile": str(cert), "keyFile": str(key)}
                                ],
                            },
                            "xhttpSettings": {
                                "host": "localhost",
                                "path": "/n0-xhttp/",
                                "mode": "stream-one",
                            },
                        },
                    }
                ],
                "outbounds": [{"protocol": "freedom", "settings": {}}],
            }
            guard.release_ipv4()
            socks_guard.release_ipv4()
            client_guard.release_ipv4()
            upstream_config = {
                "mode": "rule",
                "log-level": "warning",
                "allow-lan": False,
                "bind-address": "127.0.0.1",
                "socks-port": socks,
                "rules": ["MATCH,DIRECT"],
            }
            upstream = {"socks5": f"127.0.0.1:{socks}"}
            with (
                xray_peer(binary, directory, config, output),
                peer(upstream_binary, directory / "socks", upstream_config, socks),
            ):
                for name, changes, outcome, calls, status in [
                    ("xray-h3-direct", {}, "pass", 1, 200),
                    ("xray-h3-socks5-udp", upstream, "pass", 2, 200),
                    (
                        "xray-h3-wrong-name",
                        {"server_name": "invalid.example"},
                        "tls_rejected",
                        1,
                        None,
                    ),
                    (
                        "xray-h3-wrong-path",
                        {"path": "/invalid/"},
                        "xhttp_status",
                        1,
                        404,
                    ),
                    (
                        "xray-h3-wrong-uuid",
                        {"uuid": "00000000-0000-0000-0000-000000000000"},
                        "vless_rejected",
                        1,
                        200,
                    ),
                    (
                        "xray-h3-reject-direct",
                        {"reject_at": 1},
                        "protect_rejected",
                        1,
                        None,
                    ),
                    (
                        "xray-h3-reject-socks-control",
                        upstream | {"reject_at": 1},
                        "protect_rejected",
                        1,
                        None,
                    ),
                    (
                        "xray-h3-reject-socks-udp",
                        upstream | {"reject_at": 2},
                        "protect_rejected",
                        2,
                        None,
                    ),
                    (
                        "xray-h3-close",
                        {"close_after_echo": True},
                        "closed",
                        1,
                        200,
                    ),
                ] + (
                    [("xray-h3-half-close", {"half_close": True}, "pass", 1, 200)]
                    if args.half_close
                    else []
                ):
                    with origin(
                        changes.get("half_close", False)
                        or changes.get("close_after_echo", False)
                    ) as echo:
                        fixture = {
                            "protocol": "xray-h3",
                            "peer": f"127.0.0.1:{port}",
                            "ca": str(cert),
                            "server_name": "localhost",
                            "uuid": CLIENT_ID,
                            "path": "/n0-xhttp/",
                            "half_close": False,
                            "target": f"127.0.0.1:{echo.server_address[1]}",
                        } | changes
                        path = directory / "probe.json"
                        path.write_text(json.dumps(fixture))
                        probe = subprocess.run(
                            [str(executable), str(path)],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        result = json.loads(probe.stdout)
                        result.update(
                            {
                                "name": name,
                                "origin_connections": echo.accepted,
                                "origin_bytes": echo.received,
                                "origin_failed": echo.failed,
                            }
                        )
                        report["cases"].append(result)
                        save()
                        assert result["outcome"] == outcome, result
                        assert (
                            result["protect_calls"] == calls
                            and result["stopped"] is True
                        ), result
                        if status is not None:
                            assert result["http_status"] == status, result
                        if outcome == "pass":
                            assert (
                                result["vless_response"] is True
                                and result["server_first"] is True
                            ), result
                            assert result["controller_builds"] == 1 and result[
                                "tcp_half_close"
                            ] == changes.get("half_close", False), result
                            assert (
                                echo.accepted == 1
                                and echo.received == PAYLOAD_BYTES
                                and not echo.failed
                            )
                        elif outcome == "closed":
                            assert result["vless_response"] is True
                            assert result["payload_bytes"] == PAYLOAD_BYTES
                            assert result["response_after_close"] is False
                            assert echo.finished.wait(5), (
                                "VCore left the target connection open"
                            )
                            assert echo.accepted == 1 and echo.received == PAYLOAD_BYTES
                            result["origin_finished"] = True
                            result["origin_failed"] = echo.failed
                            save()
                        else:
                            assert (
                                echo.accepted == 0
                                and echo.received == 0
                                and not echo.failed
                            ), result
                            if outcome == "protect_rejected":
                                assert result["sent_packets"] == 0, result
                        if outcome == "vless_rejected":
                            assert result["vless_response"] is False, result
                        assert (
                            result.get("peak_incoming", 0) <= 32
                            and result.get("peak_outgoing", 0) <= 32
                        ), result
                        print(f"PASS {name}", flush=True)
                if args.compare_mihomo_close:
                    for result in compare_mihomo_close(
                        upstream_binary, directory, cert, port, client_socks
                    ):
                        report["cases"].append(result)
                        save()
                        print(f"PASS {result['name']}", flush=True)
        report["status"] = "pass"
    except BaseException:
        report["status"] = "fail"
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()
        print(f"Report: {report_path}", flush=True)


if __name__ == "__main__":
    with exclusive_run():
        main()
