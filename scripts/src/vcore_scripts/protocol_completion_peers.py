"""Official peer capability fixtures, never VCore protocol acceptance."""

from __future__ import annotations

import base64
import contextlib
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .protocol_containers import ContainerLab, frozen_image
from .protocol_fixtures import certificates
from .protocol_hysteria2_hop import guest
from .protocol_inputs import redact, same_source, source_identity


@dataclass(frozen=True)
class PeerCase:
    identifier: str
    protocol: str
    cipher: str = ""
    shadow_tls: bool = False
    uot: bool = False
    tls: bool = False
    fast_open: bool = False
    udp_mode: str = ""


CASES = (
    tuple(
        PeerCase(
            f"ss-{algorithm}-{mode}",
            "ss",
            f"2022-blake3-{algorithm}",
            shadow_tls=shadow_tls,
            uot=uot,
        )
        for algorithm in ("aes-128-gcm", "aes-256-gcm", "chacha20-poly1305")
        for mode, shadow_tls, uot in (
            ("shadowtls", True, False),
            ("uot-v2", False, True),
            ("shadowtls-uot-v2", True, True),
        )
    )
    + tuple(
        PeerCase(f"tuic-v5-{mode}", "tuic", tls=True, udp_mode=mode)
        for mode in ("native", "quic")
    )
    + tuple(
        PeerCase(
            f"{protocol}-upgrade-{'tls' if tls else 'plain'}"
            f"-{'fast' if fast else 'normal'}",
            protocol,
            tls=tls,
            fast_open=fast,
        )
        for protocol, tls in (("vmess", False), ("vmess", True), ("trojan", True))
        for fast in (False, True)
    )
    + (PeerCase("socks5-upstream", "socks5"),)
)


def peer_configuration(case, *, server, cover, port, certificate):
    """Build matched Mihomo endpoints with explicit latest-only wire choices."""
    cert, key, pin = certificate
    if case.protocol != "ss":
        password = "synthetic-protocol-fixture"
        identity = "07070707-0707-0707-0707-070707070707"
        listener = dict(
            name=case.identifier, type=case.protocol, listen="::", port=port
        )
        node = dict(
            name=case.identifier, type=case.protocol, server=server, port=port, udp=True
        )
        if case.tls:
            listener.update(
                certificate=f"/data/fixture/{cert.name}",
                **{"private-key": f"/data/fixture/{key.name}"},
            )
            node.update(fingerprint=pin)
        if case.protocol == "socks5":
            listener.update(type="socks", udp=True)
        elif case.protocol == "tuic":
            listener.update(users={identity: password}, alpn=["h3"])
            node.update(uuid=identity, password=password, sni="localhost", alpn=["h3"])
            node["udp-relay-mode"] = case.udp_mode
        else:
            if case.protocol == "vmess":
                listener["users"] = [dict(username="fixture", uuid=identity, alterId=0)]
                node.update(uuid=identity, alterId=0, cipher="auto", tls=case.tls)
                node["packet-encoding"] = "xudp"
                if case.tls:
                    node["servername"] = "localhost"
            elif case.protocol == "trojan":
                listener["users"] = [dict(username="fixture", password=password)]
                node.update(password=password, sni="localhost")
            else:
                raise ValueError("unsupported peer capability")
            listener["ws-path"] = "/protocol-upgrade"
            node["network"] = "ws"
            node["ws-opts"] = {
                "path": "/protocol-upgrade",
                "headers": {"Host": "localhost"},
                "v2ray-http-upgrade": True,
                "v2ray-http-upgrade-fast-open": case.fast_open,
            }
        return node, listener
    password = base64.b64encode(
        bytes([7]) * (16 if case.cipher == "2022-blake3-aes-128-gcm" else 32)
    ).decode()
    listener = dict(
        name=case.identifier,
        type="shadowsocks",
        listen="::",
        port=port,
        cipher=case.cipher,
        password=password,
        udp=not case.uot,
    )
    node = dict(
        name=case.identifier,
        type="ss",
        server=server,
        port=port,
        cipher=case.cipher,
        password=password,
        udp=True,
    )
    if case.uot:
        node.update({"udp-over-tcp": True, "udp-over-tcp-version": 2})
    if case.shadow_tls:
        credential = "synthetic-shadowtls-fixture"
        listener["shadow-tls"] = {
            "enable": True,
            "version": 3,
            "users": [dict(name="fixture", password=credential)],
            "handshake": dict(dest=cover),
            "strict-mode": True,
        }
        node["plugin"] = "shadow-tls"
        node["plugin-opts"] = dict(
            host="localhost", password=credential, version=3, fingerprint=pin
        )
    return node, listener


def run(output, *, identifiers=None):
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError("peer evidence must stay inside target/interop/runs")
    selected = (
        CASES
        if identifiers is None
        else tuple(case for case in CASES if case.identifier in identifiers)
    )
    if not selected or (
        identifiers is not None
        and (
            len(identifiers) != len(set(identifiers))
            or len(selected) != len(identifiers)
        )
    ):
        raise ValueError("unknown or repeated peer capability selection")
    report = dict(
        scope="official-peer-capability-only",
        vcore_behavior="NOT RUN",
        status="NOT RUN",
        source=source_identity(),
        peer={},
        isolation={},
        selected=[case.identifier for case in selected],
        cases=[],
        cleanup=False,
    )
    output.mkdir(parents=True, exist_ok=False)
    try:
        with exclusive_run(), frozen_image(output / "image-pull.log") as image:
            report["container_image"] = image
            binary = download_mihomo(
                "linux-arm64", directory=output / "binary", identity=report["peer"]
            )
            lab = ContainerLab(report["isolation"], mtu=1500)
            with tempfile.TemporaryDirectory(
                prefix="private-", dir=output
            ) as temporary:
                root = Path(temporary)
                directories, peers = {}, {}
                try:
                    with contextlib.ExitStack() as stack:
                        for role in ("origin", "server", "client"):
                            directory = root / role
                            directory.mkdir()
                            directories[role] = directory
                            if role == "origin":
                                shutil.copy2(
                                    Path(__file__).with_name("container_udp_origin.py"),
                                    directory / "origin.py",
                                )
                                argv = [
                                    "env",
                                    "VCORE_ISOLATED_ORIGIN=1",
                                    "VCORE_ORIGIN_CERT=/data/fixture/cert.pem",
                                    "VCORE_ORIGIN_KEY=/data/fixture/key.pem",
                                    "python",
                                    "-B",
                                    "/data/fixture/origin.py",
                                ]
                            else:
                                shutil.copy2(binary, directory / "mihomo")
                                argv = [
                                    "/data/fixture/mihomo",
                                    "-d",
                                    "/data",
                                    "-f",
                                    "/data/fixture/config.json",
                                ]
                            peers[role] = lab.start(stack, directory, role, argv)
                        origin, server, client = (
                            peers[r] for r in ("origin", "server", "client")
                        )
                        report["peer"]["version"] = guest(
                            server, "/data/fixture/mihomo", "-v"
                        ).strip()
                        for peer in (server, client):
                            if (
                                guest(
                                    peer, "sha256sum", "/data/fixture/mihomo"
                                ).split()[0]
                                != report["peer"]["binary_sha256"]
                            ):
                                raise RuntimeError(
                                    "container peer differs from official download"
                                )
                        certificate = certificates(directories["server"])
                        for path, name in zip(
                            certificate[:2], ("cert.pem", "key.pem"), strict=True
                        ):
                            shutil.copy2(path, directories["origin"] / name)
                        nodes, listeners, ingresses, options = [], [], [], []
                        for index, case in enumerate(selected):
                            node, listener = peer_configuration(
                                case,
                                server=server.ipv4,
                                cover=f"{origin.ipv4}:24001",
                                port=23000 + index,
                                certificate=certificate,
                            )
                            nodes.append(node)
                            listeners.append(listener)
                            ingresses.append(
                                dict(
                                    name=case.identifier,
                                    type="socks",
                                    listen=client.ipv4,
                                    port=25000 + index,
                                    udp=True,
                                    proxy=case.identifier,
                                )
                            )
                            options.append(
                                dict(
                                    case_id=case.identifier,
                                    socks_host=client.ipv4,
                                    socks_port=25000 + index,
                                )
                            )
                        server_config = {
                            "socks-port": 23999,
                            "allow-lan": True,
                            "bind-address": "*",
                            "ipv6": True,
                            "log-level": "warning",
                            "listeners": listeners,
                            "rules": ["MATCH,DIRECT"],
                        }
                        client_config = {
                            "ipv6": True,
                            "log-level": "warning",
                            "proxies": nodes,
                            "listeners": ingresses,
                            "rules": ["MATCH,REJECT"],
                        }
                        for role, configuration in (
                            ("server", server_config),
                            ("client", client_config),
                        ):
                            (directories[role] / "config.json").write_text(
                                json.dumps(configuration)
                            )
                        shutil.copy2(
                            Path(__file__).with_name("container_protocol_client.py"),
                            directories["client"] / "probe.py",
                        )
                        (directories["client"] / "fixture.json").write_text(
                            json.dumps(dict(origin=origin.ipv4, cases=options))
                        )
                        for peer in peers.values():
                            peer.release()
                        origin.wait_tcp(24000)
                        origin.wait_tcp(24001)
                        server.wait_tcp(23999)
                        client.wait_tcp(25000)
                        raw = guest(
                            client,
                            "env",
                            "VCORE_ISOLATED_CLIENT=1",
                            "python",
                            "-B",
                            "/data/fixture/probe.py",
                            "/data/fixture/fixture.json",
                            timeout=30 * len(selected),
                        )
                        (output / "observations.jsonl").write_text(raw)
                        rows = [
                            json.loads(line)
                            for line in raw.splitlines()
                            if line.strip()
                        ]
                        expected = [
                            dict(
                                case_id=case.identifier,
                                status="PASS",
                                tcp_bytes_each_direction=1024,
                                udp_origin_packets=2,
                                udp_reply_packets=2,
                                udp_sizes=[64, 1200],
                            )
                            for case in selected
                        ]
                        if rows != expected:
                            raise RuntimeError(
                                "official peer data evidence is incomplete"
                            )
                        report["cases"] = rows
                finally:
                    # A failed start may already own a VM/log before returning
                    # its peer. ExitStack has joined it; preserve that log too.
                    for role, directory in directories.items():
                        log = directory / "peer.log"
                        if log.is_file():
                            (output / f"{role}.log").write_text(
                                redact(log.read_text(errors="replace"))
                            )
            report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAIL"
        report["failure_kind"] = type(error).__name__
        (output / "failure.log").write_text(redact(str(error)))
        raise
    finally:
        report["cleanup"] = all(
            peer.get("joined") is True for peer in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = same_source(report["source"], source_identity())
        if not report["cleanup"] or not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "PASS":
        raise RuntimeError("peer capability ownership or source evidence failed")
    print(f"Official peer capabilities: {len(selected)} PASS; VCore behavior: NOT RUN")
