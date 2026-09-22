"""Extra loopback-only peers for the explicit cross-protocol acceptance run."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from contextlib import ExitStack
from pathlib import Path

PRIVATE_KEY = "eNc1RW_wzi_qpuGZFwV-d6end6xbUyvVuKDrCpz5Z0Q"
PUBLIC_KEY = "TrotdL9Y_dMWo-eqNe5dGfx7AbY1vNJjuEvRs4WR2y4"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SHORT_ID = "0123456789abcdef"


def prepare_extended(
    directory: Path,
    stack: ExitStack,
    configs: list[dict],
    ss_fixtures: list[dict],
    certificate: Path,
    private_key: Path,
    *,
    host_address: str = "127.0.0.1",
    peer_hosts: list[str] | None = None,
) -> dict[str, str]:
    from .mihomo import _stop_peer, _wait_ready, reserve_port

    openssl = next(
        (
            candidate
            for candidate in [
                os.environ.get("OPENSSL_BIN"),
                "/opt/homebrew/opt/openssl@3/bin/openssl",
                "/usr/local/opt/openssl@3/bin/openssl",
                shutil.which("openssl3"),
            ]
            if candidate and Path(candidate).is_file()
        ),
        None,
    )
    if openssl is None:
        raise RuntimeError("OpenSSL 3 is required for the local REALITY camouflage")
    reserved = [reserve_port(stack) for _ in range(7)]
    (
        first_ss,
        first_vless,
        last_anytls,
        last_vless,
        decoy_port,
        control_first,
        control_last,
    ) = [port for port, _ in reserved]
    reserved[4][1].release_ipv4()
    decoy_log = stack.enter_context((directory / "camouflage.log").open("wb"))
    decoy = subprocess.Popen(
        [
            openssl,
            "s_server",
            "-accept",
            f"{host_address}:{decoy_port}",
            "-cert",
            str(certificate),
            "-key",
            str(private_key),
            "-tls1_3",
            "-groups",
            "X25519",
            "-alpn",
            "h2,http/1.1",
            "-quiet",
            "-ign_eof",
        ],
        stdin=subprocess.DEVNULL,
        stdout=decoy_log,
        stderr=subprocess.STDOUT,
    )
    stack.callback(_stop_peer, decoy)
    _wait_ready(decoy, decoy_port, host_address)
    last_directory = directory / "3"
    last_directory.mkdir(exist_ok=True)
    last_cert, last_key = last_directory / "fixture.crt", last_directory / "fixture.key"
    shutil.copyfile(certificate, last_cert)
    shutil.copyfile(private_key, last_key)
    configs[3]["listeners"].append(
        {
            "name": "anytls-last",
            "type": "anytls",
            "listen": "127.0.0.1",
            "port": last_anytls,
            "users": {"fixture": "password"},
            "certificate": str(last_cert),
            "private-key": str(last_key),
        }
    )
    configs[0]["listeners"].append(
        {
            **ss_fixtures[0],
            "name": "ss-first",
            "type": "shadowsocks",
            "listen": "127.0.0.1",
            "port": first_ss,
            "udp": True,
        }
    )
    for index, port in [(0, first_vless), (3, last_vless)]:
        configs[index]["listeners"].append(
            {
                "name": "vless-fixture",
                "type": "vless",
                "listen": "127.0.0.1",
                "port": port,
                "users": [{"username": "fixture", "uuid": UUID}],
                "xhttp-config": {"path": "/onev", "mode": "auto"},
                "reality-config": {
                    "dest": f"{host_address}:{decoy_port}",
                    "private-key": PRIVATE_KEY,
                    "short-id": [SHORT_ID],
                    "server-names": ["fixture.invalid"],
                },
            }
        )

    for index, port in [(0, control_first), (3, control_last)]:
        configs[index]["external-controller"] = f"127.0.0.1:{port}"
        configs[index]["secret"] = "fixture-controller-only"

    def nodes(
        index: int, anytls_port: int, ss_port: int, vless_port: int
    ) -> list[dict]:
        common = {
            "server": peer_hosts[index] if peer_hosts else "127.0.0.1",
            "udp": True,
        }
        socks = {**common, "type": "socks5", "port": configs[index]["mixed-port"]}
        if index == 0:
            socks.update(username="fixture", password="password")
        return [
            socks,
            {
                **common,
                "type": "anytls",
                "port": anytls_port,
                "password": "password",
                "sni": "fixture.invalid",
                "skip-cert-verify": True,
            },
            {**ss_fixtures[0], **common, "type": "ss", "port": ss_port},
            {
                **common,
                "type": "vless",
                "port": vless_port,
                "uuid": UUID,
                "network": "xhttp",
                "tls": True,
                "servername": "fixture.invalid",
                "reality-opts": {"public-key": PUBLIC_KEY, "short-id": SHORT_ID},
                "xhttp-opts": {
                    "host": "fixture.invalid",
                    "path": "/onev",
                    "mode": "stream-one",
                },
            },
        ]

    value = {
        "first": nodes(0, configs[0]["listeners"][0]["port"], first_ss, first_vless),
        "last": nodes(3, last_anytls, ss_fixtures[0]["port"], last_vless),
        "controllers": [control_first, control_last],
    }
    for _, sock in reserved:
        sock.release_ipv4()
    return {"VCORE_MIHOMO_CHAIN_FIXTURES": json.dumps(value)}
