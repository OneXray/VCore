"""Local, opt-in interoperability; this never changes system proxy or TUN state."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run, reserve_port
from .mihomo_release import download_mihomo, latest_release


def _stop_peer(peer: subprocess.Popen) -> None:
    if peer.poll() is None:
        peer.terminate()
    try:
        peer.wait(timeout=5)
    except subprocess.TimeoutExpired:
        peer.kill()
        peer.wait(timeout=5)


def _wait_ready(peer, port: int, host: str = "127.0.0.1") -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if peer.poll() is not None:
            raise RuntimeError("mihomo exited before its local listener was ready")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("mihomo did not become ready within 10 seconds")


def run_mihomo_interop(
    *,
    extended: bool = False,
    soak_seconds: int = 0,
    container: bool = False,
) -> None:
    if not 0 <= soak_seconds <= 7200 or (soak_seconds and not extended):
        raise ValueError("soak seconds must be 0..7200 and require --extended")
    with exclusive_run():
        # One fresh release snapshot per run keeps native and container peers
        # aligned even if upstream publishes another release during downloads.
        release = latest_release()
        binary = download_mihomo(release=release)
        container_binary = (
            download_mihomo("linux-arm64", release=release) if container else None
        )
        _run_mihomo_interop(
            binary,
            extended=extended,
            soak_seconds=soak_seconds,
            container_binary=container_binary,
        )


def _run_mihomo_interop(
    binary: Path,
    *,
    extended: bool,
    soak_seconds: int,
    container_binary: Path | None = None,
) -> None:
    version = subprocess.run(
        [binary, "-v"], check=True, text=True, capture_output=True, timeout=5
    )
    with binary.open("rb") as artifact:
        digest = hashlib.file_digest(artifact, "sha256").hexdigest()
    print(version.stdout.strip(), flush=True)
    print(f"mihomo binary SHA-256: {digest}", flush=True)
    print(
        "Local interop limits: readiness 10s; socket I/O 5s; "
        f"cargo run {300 + soak_seconds}s; peer stop 5s",
        flush=True,
    )
    with (
        tempfile.TemporaryDirectory(prefix="vcore-mihomo-") as temporary,
        ExitStack() as stack,
    ):
        directory = Path(temporary)
        containers = None
        if container_binary is not None:
            from .mihomo_container import ContainerPeers

            containers = ContainerPeers(directory, stack, container_binary.resolve())
        reservations = [reserve_port(stack) for _ in range(10)]
        (
            upstream_port,
            downstream_port,
            socks_downstream_port,
            core_port,
            socks_port,
            anytls_port,
            *ss_ports,
            ss_health_port,
        ) = [port for port, _ in reservations]
        ss_fixtures = [
            {
                "cipher": name,
                "port": port,
                "password": base64.b64encode(bytes([7]) * key_length).decode("ascii"),
            }
            for (name, key_length), port in zip(
                [
                    ("2022-blake3-aes-128-gcm", 16),
                    ("2022-blake3-aes-256-gcm", 32),
                    ("2022-blake3-chacha20-poly1305", 32),
                ],
                ss_ports,
                strict=True,
            )
        ]
        # mihomo intentionally rejects certificate paths outside its dataDir.
        certificate_directory = directory / "0"
        certificate_directory.mkdir(exist_ok=True)
        certificate = certificate_directory / "fixture.crt"
        private_key = certificate_directory / "fixture.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                private_key,
                "-out",
                certificate,
                "-days",
                "2",
                "-subj",
                "/CN=fixture.invalid",
                "-addext",
                "subjectAltName=DNS:fixture.invalid",
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        fingerprint = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
        ).hexdigest()
        for _, reservation in reservations[5:]:
            reservation.release_ipv4()
        base = {
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "ipv6": True,
            "mode": "rule",
            "log-level": "warning",
            "skip-auth-prefixes": [],
            "dns": {"enable": False},
            "hosts": {
                "vcore-fixture.test": "127.0.0.1",
                "vcore-peer.test": "127.0.0.1",
            },
            "profile": {"store-selected": False},
        }
        configs = [
            {
                **base,
                "mixed-port": upstream_port,
                "authentication": ["fixture:password"],
                "listeners": [
                    {
                        "name": "anytls-fixture",
                        "type": "anytls",
                        "listen": "127.0.0.1",
                        "port": anytls_port,
                        "users": {"fixture": "password"},
                        "certificate": str(certificate),
                        "private-key": str(private_key),
                    },
                ],
                "rules": ["MATCH,DIRECT"],
            },
            {
                **base,
                "mixed-port": downstream_port,
                "proxies": [
                    {
                        "name": "vcore",
                        "type": "http",
                        "server": "127.0.0.1",
                        "port": core_port,
                        "username": "fixture",
                        "password": "password",
                    }
                ],
                "rules": ["MATCH,vcore"],
            },
            {
                **base,
                "mixed-port": socks_downstream_port,
                "proxies": [
                    {
                        "name": "vcore",
                        "type": "socks5",
                        "server": "127.0.0.1",
                        "port": socks_port,
                        "username": "fixture",
                        "password": "password",
                        "udp": True,
                    }
                ],
                "rules": ["MATCH,vcore"],
            },
            {
                # Use a separate process for the second hop: mihomo correctly
                # rejects a connection re-entering its own loopback detector.
                **base,
                "mixed-port": ss_health_port,
                "listeners": [
                    {
                        "name": f"ss-fixture-{index}",
                        "type": "shadowsocks",
                        "listen": "127.0.0.1",
                        "udp": True,
                        **fixture,
                    }
                    for index, fixture in enumerate(ss_fixtures)
                ],
                "rules": ["MATCH,DIRECT"],
            },
        ]
        extended_environment = {}
        if extended:
            from .mihomo_extended import prepare_extended

            extended_environment = prepare_extended(
                directory,
                stack,
                configs,
                ss_fixtures,
                certificate,
                private_key,
                host_address=containers.host if containers else "127.0.0.1",
                peer_hosts=containers.addresses if containers else None,
            )
        peer_ids = []
        for index, config in enumerate(configs):
            peer_directory = directory / str(index)
            peer_directory.mkdir(exist_ok=True)
            config_path = peer_directory / "config.yaml"
            if containers:
                containers.configure(index, config)
            # JSON is a YAML subset; fixtures never contain real user credentials.
            staging_path = peer_directory / "config.pending"
            staging_path.write_text(json.dumps(config), encoding="utf-8")
            staging_path.replace(config_path)
            log = stack.enter_context((peer_directory / "peer.log").open("wb"))
            reservations[[0, 1, 2, 9][index]][1].release_ipv4()
            if containers and index in containers.peers:
                peer = containers.peers[index]
            else:
                peer = subprocess.Popen(
                    [binary, "-d", peer_directory, "-f", config_path],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                peer_ids.append(str(peer.pid))
                stack.callback(_stop_peer, peer)
            peer_host = containers.addresses[index] if containers else "127.0.0.1"
            try:
                _wait_ready(peer, config["mixed-port"], peer_host)
                if "external-controller" in config:
                    _wait_ready(
                        peer,
                        int(config["external-controller"].rsplit(":", 1)[1]),
                        peer_host,
                    )
                if index == 0:
                    _wait_ready(peer, anytls_port, peer_host)
                if index == 3:
                    for ss_port in ss_ports:
                        _wait_ready(peer, ss_port, peer_host)
            except RuntimeError:
                # Only this harness's generated fixtures can reach this path.
                print(
                    containers.peers[index].logs()
                    if containers and index in containers.peers
                    else (peer_directory / "peer.log").read_text(errors="replace")[
                        -4096:
                    ],
                    flush=True,
                )
                raise
        # VCore itself binds both families. Its reservations must fully release;
        # the IPv4-only external peers retain their IPv6 guards until exit.
        for _, reservation in reservations[3:5]:
            reservation.close()
        environment = dict(
            os.environ,
            VCORE_MIHOMO_UPSTREAM=str(upstream_port),
            VCORE_MIHOMO_DOWNSTREAM=str(downstream_port),
            VCORE_MIHOMO_HTTP_PORT=str(core_port),
            VCORE_MIHOMO_SOCKS_PORT=str(socks_port),
            VCORE_MIHOMO_SOCKS_DOWNSTREAM=str(socks_downstream_port),
            VCORE_MIHOMO_ANYTLS_PORT=str(anytls_port),
            VCORE_MIHOMO_ANYTLS_PIN=fingerprint,
            VCORE_MIHOMO_SS_FIXTURES=json.dumps(ss_fixtures),
            VCORE_MIHOMO_SOAK_SECONDS=str(soak_seconds),
            VCORE_MIHOMO_PEER_PIDS=",".join(peer_ids),
            **extended_environment,
        )
        if containers:
            environment.update(containers.environment())
        try:
            subprocess.run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--features",
                    "ffi",
                    "--test",
                    "mihomo_interop",
                    "--",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ],
                cwd=CORE_DIR,
                env=environment,
                check=True,
                timeout=300 + soak_seconds,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            for index in range(len(configs)):
                print(f"Generated fixture peer {index} diagnostics (last 4096 bytes):")
                print(
                    containers.peers[index].logs()
                    if containers and index in containers.peers
                    else (directory / str(index) / "peer.log")
                    .read_bytes()[-4096:]
                    .decode("utf-8", errors="replace"),
                    flush=True,
                )
            raise
    print("mihomo peers stopped; temporary configurations removed", flush=True)
