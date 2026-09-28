"""Eight-protocol integration with owned official peers and container origins."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .native_release import download_native
from .protocol_containers import ContainerLab, command, frozen_image
from .protocol_fixtures import certificates
from .protocol_inputs import redact, sha256, source_identity
from .protocol_integration_catalog import CHAINS, ORDERED
from .protocol_peers import run_command


def peer_configuration(protocol, server, origin, directory, *, certificate=None):
    cert, key, pin = certificate or certificates(directory)
    listener = dict(name="integration", type=protocol, listen="::", port=23000)
    node = dict(name="peer", type=protocol, server=server, port=23000, udp=True)
    password = "synthetic-integration-fixture"
    identity = "07070707-0707-0707-0707-070707070707"
    if protocol == "socks5":
        listener.update(
            type="socks", udp=True, users=[dict(username="fixture", password=password)]
        )
        node.update(username="fixture", password=password)
    elif protocol == "ss":
        password = base64.b64encode(bytes([7]) * 16).decode()
        cipher = "2022-blake3-aes-128-gcm"
        listener.update(type="shadowsocks", udp=True, cipher=cipher, password=password)
        node.update(cipher=cipher, password=password)
    elif protocol == "tuic":
        listener.update(users={identity: password}, alpn=["h3"])
        node.update(
            uuid=identity,
            password=password,
            sni="localhost",
            fingerprint=pin,
            alpn=["h3"],
            **{"udp-relay-mode": "native"},
        )
    elif protocol in {"trojan", "anytls", "hysteria2"}:
        node.update(password=password, sni="localhost", fingerprint=pin)
        listener["users"] = (
            [dict(username="fixture", password=password)]
            if protocol == "trojan"
            else {"fixture": password}
        )
    else:
        node.update(uuid=identity, tls=True, servername="localhost", fingerprint=pin)
        listener["users"] = [dict(username="fixture", uuid=identity)]
        if protocol == "vmess":
            node.update(cipher="auto", alterId=0)
            listener["users"][0]["alterId"] = 0
        node["packet-encoding"] = "xudp"
    if protocol not in {"socks5", "ss"}:
        listener.update(
            certificate=f"/data/fixture/{cert.name}",
            **{"private-key": f"/data/fixture/{key.name}"},
        )
    return node, {
        "socks-port": 23999,
        "allow-lan": True,
        "bind-address": "*",
        "ipv6": True,
        "log-level": "silent",
        "hosts": {"vcore-fixture.test": origin},
        "listeners": [listener],
        "rules": ["MATCH,DIRECT"],
    }


def rust_command(consumer="ordered_pair"):
    return [
        "cargo",
        "test",
        "--locked",
        "--all-features",
        "--test",
        "vless_public",
        f"integration::{consumer}",
        "--",
        "--exact",
        "--ignored",
        "--nocapture",
    ]


def run(
    output: Path, selected, *, supplied=None, consumer="ordered_pair", domain_peer=None
):
    if (
        not selected
        or len(selected) != len(set(selected))
        or not set(selected) <= ORDERED.keys()
    ):
        raise ValueError("invalid INTEGRATION pair selection")
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError(
            "INTEGRATION evidence must stay inside the owned run directory"
        )
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="INTEGRATION",
        scope="ordered-pair-subset" if consumer == "ordered_pair" else "diagnostic",
        source=source_identity(),
        status="NOT RUN",
        cases=[],
        peers={},
        isolation={},
    )
    try:
        if supplied is None:
            identity = {}
            binary = download_mihomo(
                "linux-arm64", directory=output / "binaries", identity=identity
            )
        else:
            binary, identity = supplied
            if sha256(binary) != identity["binary_sha256"]:
                raise RuntimeError("INTEGRATION native peer identity mismatch")
        report["peers"]["M"] = identity
        if any(ORDERED[key][1] == "trojan" for key in selected):
            if domain_peer is None:
                artifact = download_native(
                    "XR", output / "binary-xray", "linux-arm64", defer_version=True
                )
                domain_peer = (artifact.binary, artifact.identity)
            if sha256(domain_peer[0]) != domain_peer[1]["binary_sha256"]:
                raise RuntimeError("INTEGRATION domain terminal identity mismatch")
            report["peers"]["XR"] = domain_peer[1]
        lab = ContainerLab(report["isolation"], mtu=1500)
        for index, identifier in enumerate(selected):
            first_kind, last_kind = ORDERED[identifier]
            variant = CHAINS.get(identifier)
            print(f"INTEGRATION: {identifier}", flush=True)
            with tempfile.TemporaryDirectory(
                prefix="private-", dir=output
            ) as temporary:
                root = Path(temporary)
                with contextlib.ExitStack() as stack:
                    origin_dir = root / "origin"
                    origin_dir.mkdir()
                    shutil.copyfile(
                        Path(__file__).with_name("container_udp_origin.py"),
                        origin_dir / "origin.py",
                    )
                    origin_command = ["env", "VCORE_ISOLATED_ORIGIN=1"]
                    cover_certificate = None
                    if variant:
                        cover_certificate = certificates(origin_dir)
                        shutil.copyfile(
                            Path(__file__).with_name("container_shadowtls_peer.py"),
                            origin_dir / "cover.py",
                        )
                        origin_command += [
                            "VCORE_ORIGIN_CERT=/data/fixture/cert.pem",
                            "VCORE_ORIGIN_KEY=/data/fixture/key.pem",
                        ]
                    origin_command += [
                        "python",
                        "-B",
                        "/data/fixture/cover.py"
                        if variant
                        else "/data/fixture/origin.py",
                    ]
                    origin = lab.start(
                        stack,
                        origin_dir,
                        f"{index}-origin",
                        origin_command,
                    )
                    origin.release()
                    origin.wait_tcp(24000)
                    if variant:
                        origin.wait_tcp(24001)
                    fixture = dict(
                        isolation="containers",
                        origin_control=f"{origin.ipv4}:24000",
                        origin_ipv4=origin.ipv4,
                        origin_ipv6=origin.ipv6,
                        data_dir=str(root / "core"),
                    )
                    if variant:
                        fixture["variant"] = variant
                    for role, protocol in (("first", first_kind), ("last", last_kind)):
                        directory = root / role
                        directory.mkdir()
                        shutil.copy2(binary, directory / "peer")
                        peer = lab.start(
                            stack,
                            directory,
                            f"{index}-{role}",
                            [
                                "/data/fixture/peer",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ],
                        )
                        identity["version"] = command(
                            "exec", peer.name, "/data/fixture/peer", "-v"
                        ).strip()
                        if (
                            command(
                                "exec", peer.name, "sha256sum", "/data/fixture/peer"
                            ).split()[0]
                            != identity["binary_sha256"]
                        ):
                            raise RuntimeError(
                                "INTEGRATION container binary differs from download"
                            )
                        node, config = peer_configuration(
                            protocol, peer.ipv4, origin.ipv4, directory
                        )
                        if variant and role == "first":
                            node["udp-relay-mode"] = variant["udp_mode"]
                        elif variant:
                            from .protocol_completion_peers import PeerCase
                            from .protocol_completion_peers import (
                                peer_configuration as profile,
                            )

                            node, listener = profile(
                                PeerCase(
                                    identifier, "ss", variant["cipher"], shadow_tls=True
                                ),
                                server=peer.ipv4,
                                cover=f"{origin.ipv4}:24001",
                                port=23000,
                                certificate=cover_certificate,
                            )
                            node["name"] = "peer"
                            config["listeners"] = [listener]
                        (directory / "config.json").write_text(json.dumps(config))
                        fixture[role], fixture[role + "_ipv6"] = node, peer.ipv6
                        peer.release()
                        peer.wait_tcp(23999)
                    if last_kind == "trojan":
                        from .protocol_fixtures import trojan_peer_config as peer_config

                        directory = root / "domain"
                        directory.mkdir()
                        shutil.copy2(domain_peer[0], directory / "peer")
                        peer = lab.start(
                            stack,
                            directory,
                            f"{index}-domain",
                            [
                                "/data/fixture/peer",
                                "run",
                                "-c",
                                "/data/fixture/config.json",
                            ],
                        )
                        domain_peer[1]["version"] = command(
                            "exec", peer.name, "/data/fixture/peer", "version"
                        ).strip()
                        if (
                            command(
                                "exec", peer.name, "sha256sum", "/data/fixture/peer"
                            ).split()[0]
                            != domain_peer[1]["binary_sha256"]
                        ):
                            raise RuntimeError(
                                "INTEGRATION domain container binary identity mismatch"
                            )
                        certificate = certificates(directory)
                        node, _ = peer_configuration(
                            "trojan",
                            peer.ipv4,
                            origin.ipv4,
                            directory,
                            certificate=certificate,
                        )
                        cert, key, _ = certificate
                        config = peer_config(
                            "XR",
                            "tcp",
                            23000,
                            node["password"],
                            f"/data/fixture/{cert.name}",
                            f"/data/fixture/{key.name}",
                        )
                        config["inbounds"][0]["listen"] = "::"
                        config["dns"]["hosts"] = {"vcore-fixture.test": origin.ipv4}
                        (directory / "config.json").write_text(json.dumps(config))
                        fixture["domain_last"], fixture["domain_last_ipv6"] = (
                            node,
                            peer.ipv6,
                        )
                        peer.release()
                        peer.wait_tcp(23000)
                    path = root / "fixture.json"
                    path.write_text(json.dumps(fixture))
                    events = output / (identifier + "-events.jsonl")
                    observations = output / (identifier + "-observations.json")
                    env = dict(
                        os.environ,
                        VCORE_VLESS_INPUT=str(path),
                        VCORE_PROTOCOL_STAGE="INTEGRATION",
                        VCORE_CASE_EVENTS=str(events),
                        VCORE_INTEGRATION_OBSERVATIONS=str(observations),
                    )
                    argv = rust_command(consumer)
                    result = run_command(argv, cwd=CORE_DIR, env=env, timeout=300)
                    (output / (identifier + ".log")).write_text(
                        redact(result.stdout.decode(errors="replace"))
                    )
                    report["cases"].append(
                        dict(
                            case_id=identifier,
                            command=argv,
                            exit_code=result.returncode,
                            command_cleanup=result.cleanup,
                            seconds=result.seconds,
                        )
                    )
                    if result.returncode != 0 or not result.cleanup:
                        raise RuntimeError("INTEGRATION ordered-pair consumer failed")
        report["status"] = "PASS"
    except BaseException as error:
        report.update(status="FAIL", failure_kind=type(error).__name__)
        raise
    finally:
        report["source_unchanged"] = source_identity() == report["source"]
        report["cleanup"] = all(
            peer.get("joined") is True for peer in report["isolation"].get("peers", [])
        )
        if not report["cleanup"] or not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "integration-native.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return report


if __name__ == "__main__":
    output = Path(sys.argv[1]).resolve()
    with exclusive_run(), frozen_image(None):
        run(output, sys.argv[2:] or list(ORDERED))
