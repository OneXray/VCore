"""N0 only: official latest Mihomo, loopback fixtures, no production config."""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

CORE = Path(__file__).resolve().parents[4]
SPIKE = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE / "scripts/src"))
from vcore_scripts.mihomo_release import download_mihomo  # noqa: E402
from vcore_scripts.mihomo_isolation import exclusive_run, reserve_port  # noqa: E402

PAYLOAD_BYTES = 65536
GREETING = b"N0-server-first\n"
TRAILER = b"N0-half-close\n"


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.accepted += 1
        self.request.settimeout(15)
        try:
            self.request.sendall(GREETING)
            while data := self.request.recv(8192):
                self.server.received += len(data)
                self.request.sendall(data)
                if not self.server.half_close and self.server.received == PAYLOAD_BYTES:
                    break
            self.request.sendall(TRAILER)
            self.request.shutdown(socket.SHUT_WR)
        except OSError:
            self.server.failed = True
        finally:
            self.server.finished.set()


@contextlib.contextmanager
def origin(half_close=True, *, host="127.0.0.1"):
    with socketserver.TCPServer((host, 0), Echo) as server:
        server.accepted = 0
        server.received = 0
        server.failed = False
        server.finished = threading.Event()
        server.half_close = half_close
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=20)
            if thread.is_alive():
                raise RuntimeError("origin did not stop")


@contextlib.contextmanager
def peer(binary, directory, config, ready_port=None, native=False):
    directory.mkdir()
    # Respect Mihomo's per-instance safe-path policy without disabling it.
    for index, listener in enumerate(config.get("listeners", [])):
        for field in ["certificate", "private-key"]:
            destination = directory / f"{index}-{field}.pem"
            shutil.copyfile(listener[field], destination)
            listener[field] = str(destination)
    config_file = directory / "config.json"
    config_file.write_text(json.dumps(config))
    with (directory / "peer.log").open("wb") as log:
        process = subprocess.Popen(
            (
                [str(binary), "server", "-c", str(config_file)]
                if native
                else [str(binary), "-d", str(directory), "-f", str(config_file)]
            ),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("peer fixture exited during startup")
                output = (directory / "peer.log").read_text(errors="replace")
                if "level=error" in output or "level=fatal" in output:
                    raise RuntimeError(
                        "peer fixture reported a startup error; inspect the local peer log"
                    )
                if native and "server up and running" in output:
                    break
                try:
                    if not native:
                        with socket.create_connection(("127.0.0.1", ready_port), 0.2):
                            if (
                                not config.get("listeners")
                                or "Hysteria2[n0-hy2] proxy listening" in output
                            ):
                                break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("peer fixture readiness timed out") from None
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
            log.flush()
            shutil.copyfile(
                directory / "peer.log",
                directory.parent.parent / f"{directory.name}.log",
            )


def certificates(directory, openssl):
    config = directory / "openssl.cnf"
    config.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
        "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n"
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-config",
            str(config),
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
    )
    return cert, key


def check_case(
    executable, directory, template, name, changes, outcome, protect_calls, udp=True
):
    with origin(changes.get("half_close", True)) as echo:
        fixture = template | changes | {"target": f"127.0.0.1:{echo.server_address[1]}"}
        path = directory / "probe.json"
        path.write_text(json.dumps(fixture))
        completed = subprocess.run(
            [str(executable), str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        result = json.loads(completed.stdout)
        if result["outcome"] != outcome:
            failure = {
                "name": name,
                "origin_connections": echo.accepted,
                "origin_bytes": echo.received,
                "origin_failed": echo.failed,
                **result,
            }
            (directory.parent / "last-failure.json").write_text(
                json.dumps(failure, indent=2) + "\n"
            )
        assert result["outcome"] == outcome, (name, result)
        assert result["protect_calls"] == protect_calls, (name, result)
        assert result["stopped"] is True, (name, result)
        if outcome == "pass":
            assert result["udp_enabled"] is udp, (name, result)
            assert result["controller_builds"] >= 1, (name, result)
            assert (
                echo.accepted == 1
                and echo.received == PAYLOAD_BYTES
                and not echo.failed
            )
        else:
            assert echo.accepted == 0 and echo.received == 0 and not echo.failed
            if outcome == "protect_rejected":
                assert result["sent_packets"] == 0, (name, result)
        assert (
            result.get("peak_outgoing", 0) <= 32
            and result.get("peak_incoming", 0) <= 32
        )
        print(f"PASS {name}", flush=True)
        return {
            "name": name,
            "origin_connections": echo.accepted,
            "origin_bytes": echo.received,
            **result,
        }


def download_hysteria(directory, *, target=None):
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(
        platform.machine()
    )
    if target is None and (not system or not arch):
        raise RuntimeError(
            "native Hysteria fixture asset mapping unavailable for this host"
        )
    selected = target or f"{system}-{arch}"
    if selected not in {"darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64"}:
        raise RuntimeError("unsupported native Hysteria asset target")
    url = f"https://github.com/HyNetworks/hysteria/releases/latest/download/hysteria-{selected}"
    binary = directory / "hysteria"
    request = urllib.request.Request(url, headers={"User-Agent": "VCore-N0-interop"})
    deadline = time.monotonic() + 90
    digest = hashlib.sha256()
    total = 0
    # Always download a fresh official asset; partial/old files are never run.
    with tempfile.TemporaryDirectory(prefix="download-", dir=directory) as staging:
        staged = Path(staging) / "hysteria"
        with (
            urllib.request.urlopen(request, timeout=30) as response,
            staged.open("wb") as output,
        ):
            if not response.geturl().startswith("https://"):
                raise RuntimeError("native Hysteria redirected outside HTTPS")
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024 or time.monotonic() > deadline:
                    raise RuntimeError("native Hysteria download exceeded its budget")
                output.write(chunk)
                digest.update(chunk)
        staged.chmod(0o755)
        os.replace(staged, binary)
    version = (
        None
        if target is not None
        else subprocess.check_output(
            [str(binary), "version"], text=True, timeout=10
        ).strip()
    )
    return binary, {"url": url, "version": version, "sha256": digest.hexdigest()}


def save_report(path, results, case=None):
    if case is not None:
        results["cases"].append(case)
    path.write_text(json.dumps(results, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument(
        "--native-hysteria",
        action="store_true",
        help="also verify UDP-disabled auth against official Hysteria latest",
    )
    parser.add_argument(
        "--native-half-close",
        action="store_true",
        help="require the separate native half-close gate (implies --native-hysteria)",
    )
    args = parser.parse_args()
    args.native_hysteria = args.native_hysteria or args.native_half_close
    build = CORE / "target/interop/n0-hysteria2-build"
    executable = build / "debug/vcore-n0-hysteria2-spike"
    if not executable.is_file():
        raise RuntimeError("build the N0 Hysteria2 probe binary first")
    binary = download_mihomo()
    version = subprocess.check_output(
        [str(binary), "-v"], text=True, timeout=10
    ).strip()
    artifact = CORE / "target/interop/n0-hysteria2"
    artifact.mkdir(parents=True, exist_ok=True)
    results = {
        "status": "incomplete",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "vcore_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=CORE, text=True
        ).strip(),
        "production_lock_sha256": hashlib.sha256(
            (CORE / "Cargo.lock").read_bytes()
        ).hexdigest(),
        "probe_binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "spike_sources_sha256": {
            str(path.relative_to(SPIKE)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                SPIKE / "Cargo.toml",
                SPIKE / "Cargo.lock",
                SPIKE / "run.py",
                *sorted((SPIKE / "src").glob("*.rs")),
            ]
        },
        "peer_version": version,
        "peer_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "cases": [],
    }
    report_path = artifact / (
        "half-close-result.json" if args.native_half_close else "result.json"
    )
    save_report(report_path, results)
    if args.native_hysteria:
        native, results["native_hysteria"] = download_hysteria(artifact)
        save_report(report_path, results)
    with (
        contextlib.ExitStack() as reservations,
        tempfile.TemporaryDirectory(prefix="fixtures-", dir=artifact) as temporary,
    ):
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        cert, key = certificates(directory, args.openssl)
        ready, ready_guard = reserve_port(reservations)
        hy2, hy2_guard = reserve_port(reservations)
        socks, socks_guard = reserve_port(reservations)
        base = {
            "mode": "rule",
            "log-level": "info",
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "rules": ["MATCH,DIRECT"],
        }
        config = base | {
            "socks-port": ready,
            "listeners": [
                {
                    "name": "n0-hy2",
                    "type": "hysteria2",
                    "listen": "127.0.0.1",
                    "port": hy2,
                    "users": {"n0": "n0-fixture-password"},
                    "certificate": str(cert),
                    "private-key": str(key),
                    "alpn": ["h3"],
                    "ignore-client-bandwidth": True,
                }
            ],
        }
        ready_guard.release_ipv4()
        hy2_guard.release_ipv4()
        socks_guard.release_ipv4()
        with (
            peer(binary, directory / "mihomo", config, ready),
            peer(binary, directory / "socks", base | {"socks-port": socks}, socks),
        ):
            fixture = {
                "peer": f"127.0.0.1:{hy2}",
                "ca": str(cert),
                "server_name": "localhost",
                "password": "n0-fixture-password",
            }
            upstream = {"socks5": f"127.0.0.1:{socks}"}
            for name, changes, outcome, calls in [
                ("mihomo-direct", {}, "pass", 1),
                ("mihomo-socks5-udp", upstream, "pass", 2),
                (
                    "mihomo-wrong-password",
                    {"password": "n0-wrong-password"},
                    "auth_rejected",
                    1,
                ),
                (
                    "mihomo-wrong-name",
                    {"server_name": "invalid.example"},
                    "tls_rejected",
                    1,
                ),
                ("reject-direct", {"reject_at": 1}, "protect_rejected", 1),
                (
                    "reject-socks-control",
                    upstream | {"reject_at": 1},
                    "protect_rejected",
                    1,
                ),
                (
                    "reject-socks-udp",
                    upstream | {"reject_at": 2},
                    "protect_rejected",
                    2,
                ),
            ]:
                save_report(
                    report_path,
                    results,
                    check_case(
                        executable, directory, fixture, name, changes, outcome, calls
                    ),
                )
        if args.native_hysteria:
            native_port, native_guard = reserve_port(reservations)
            config = {
                "listen": f"127.0.0.1:{native_port}",
                "tls": {"cert": str(cert), "key": str(key)},
                "auth": {"type": "password", "password": "n0-fixture-password"},
                "ignoreClientBandwidth": True,
                "disableUDP": True,
            }
            native_guard.release_ipv4()
            with peer(native, directory / "hysteria", config, native=True):
                save_report(
                    report_path,
                    results,
                    check_case(
                        executable,
                        directory,
                        fixture,
                        "hysteria-udp-disabled-tcp",
                        {"peer": f"127.0.0.1:{native_port}", "half_close": False},
                        "pass",
                        1,
                        udp=False,
                    ),
                )
                if args.native_half_close:
                    save_report(
                        report_path,
                        results,
                        check_case(
                            executable,
                            directory,
                            fixture,
                            "hysteria-half-close",
                            {"peer": f"127.0.0.1:{native_port}"},
                            "pass",
                            1,
                            udp=False,
                        ),
                    )
    results["status"] = "pass"
    save_report(report_path, results)
    print(f"Report: {report_path}")


if __name__ == "__main__":
    with exclusive_run():
        main()
