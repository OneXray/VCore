"""INTEGRATION public-runtime gates against seven listeners in an owned native peer."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
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
from .protocol_integration_catalog import PROTOCOLS
from .protocol_integration_native import peer_configuration, rust_command
from .protocol_peers import run_command

CONSUMERS = {
    "INTEGRATION-ENTRYPOINTS": "entrypoints",
    "INTEGRATION-GRAPH": "graph",
    "INTEGRATION-DNS-MEASURE": "dns_measure",
    "INTEGRATION-RESOURCE-TRACER": "resource_tracer",
    "INTEGRATION-LIFECYCLE": "lifecycle::public_lifetimes",
    "INTEGRATION-LIFECYCLE-TRACER": "lifecycle::lifecycle_tracer",
    "INTEGRATION-REBUILD": "pressure::rebuild",
    "INTEGRATION-REBUILD-TRACER": "pressure::rebuild_tracer",
    "INTEGRATION-SOAK": "pressure::soak",
    "INTEGRATION-SOAK-TRACER": "pressure::soak_tracer",
    "INTEGRATION-SS-ALGORITHMS": "shadowsocks::algorithms",
    "INTEGRATION-SS-EIH": "shadowsocks::eih",
    "INTEGRATION-FAILURES": "connector::protect_failure",
}


def run(output: Path, selected, *, supplied=None):
    if (
        not selected
        or len(selected) != len(set(selected))
        or not set(selected) <= CONSUMERS.keys()
    ):
        raise ValueError("invalid INTEGRATION public gate selection")
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError(
            "INTEGRATION evidence must stay inside the owned run directory"
        )
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="INTEGRATION",
        scope="public-runtime-subset",
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
        lab = ContainerLab(report["isolation"], mtu=1500)
        with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary:
            root = Path(temporary)
            with contextlib.ExitStack() as stack:
                origin_dir = root / "origin"
                origin_dir.mkdir()
                shutil.copyfile(
                    Path(__file__).with_name("container_udp_origin.py"),
                    origin_dir / "origin.py",
                )
                origin = lab.start(
                    stack,
                    origin_dir,
                    "origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "VCORE_ORIGIN_PROFILE=INTEGRATION",
                        "python",
                        "-B",
                        "/data/fixture/origin.py",
                    ],
                )
                origin.release()
                origin.wait_tcp(24000)
                upstream_dir = root / "upstream"
                upstream_dir.mkdir()
                shutil.copy2(binary, upstream_dir / "peer")
                upstream = lab.start(
                    stack,
                    upstream_dir,
                    "upstream",
                    [
                        "/data/fixture/peer",
                        "-d",
                        "/data",
                        "-f",
                        "/data/fixture/config.json",
                    ],
                )
                hop, upstream_config = peer_configuration(
                    "socks5", upstream.ipv4, origin.ipv4, upstream_dir
                )
                hop["name"] = "hop"
                (upstream_dir / "config.json").write_text(json.dumps(upstream_config))
                upstream.release()
                upstream.wait_tcp(23999)
                if (
                    command(
                        "exec", upstream.name, "sha256sum", "/data/fixture/peer"
                    ).split()[0]
                    != identity["binary_sha256"]
                ):
                    raise RuntimeError(
                        "INTEGRATION upstream binary differs from download"
                    )
                directory = root / "native"
                directory.mkdir()
                shutil.copy2(binary, directory / "peer")
                peer = lab.start(
                    stack,
                    directory,
                    "native",
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
                certificate = certificates(directory)
                nodes, listeners = {}, []
                config = None
                for index, protocol in enumerate(PROTOCOLS):
                    node, current = peer_configuration(
                        protocol,
                        peer.ipv4,
                        origin.ipv4,
                        directory,
                        certificate=certificate,
                    )
                    port = 23000 + index
                    node["port"] = port
                    current["listeners"][0].update(name=protocol, port=port)
                    nodes[protocol] = node
                    listeners.extend(current["listeners"])
                    config = current
                ss_nodes = [nodes["ss"].copy()]
                for index, cipher in enumerate(
                    ("2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305")
                ):
                    node = nodes["ss"].copy()
                    node.update(
                        port=23010 + index,
                        cipher=cipher,
                        password=base64.b64encode(bytes([7]) * 32).decode(),
                    )
                    listeners.append(
                        dict(
                            name=cipher,
                            type="shadowsocks",
                            listen="::",
                            port=node["port"],
                            cipher=cipher,
                            password=node["password"],
                            udp=True,
                        )
                    )
                    ss_nodes.append(node)
                config.update(
                    listeners=listeners,
                    **{
                        "external-controller": "0.0.0.0:23998",
                        "secret": "synthetic-integration-control",
                    },
                )
                (directory / "config.json").write_text(json.dumps(config))
                peer.release()
                peer.wait_tcp(23999)
                fixture = dict(
                    isolation="containers",
                    origin_control=f"{origin.ipv4}:24000",
                    origin_ipv4=origin.ipv4,
                    origin_ipv6=origin.ipv6,
                    nodes=nodes,
                    ss_nodes=ss_nodes,
                    hop=hop,
                    server_ipv6=peer.ipv6,
                    peer_controller=f"{peer.ipv4}:23998",
                    data_dir=str(root / "core"),
                )
                if "INTEGRATION-SS-EIH" in selected:
                    artifact = download_native(
                        "SS", output / "binaries-ss", "linux-arm64", defer_version=True
                    )
                    ss_dir = root / "ssserver"
                    ss_dir.mkdir()
                    shutil.copy2(artifact.binary, ss_dir / "ssserver")
                    ss = lab.start(
                        stack,
                        ss_dir,
                        "ssserver",
                        ["/data/fixture/ssserver", "-c", "/data/fixture/config.json"],
                    )
                    artifact.identity["version"] = command(
                        "exec", ss.name, "/data/fixture/ssserver", "--version"
                    ).strip()
                    if (
                        command(
                            "exec", ss.name, "sha256sum", "/data/fixture/ssserver"
                        ).split()[0]
                        != artifact.identity["binary_sha256"]
                    ):
                        raise RuntimeError("INTEGRATION SS binary identity mismatch")
                    report["peers"]["SS"] = artifact.identity
                    servers, eih_nodes = [], []
                    for index, length in enumerate((16, 32)):
                        cipher = f"2022-blake3-aes-{length * 8}-gcm"
                        identity_key, user_key = [
                            base64.b64encode(bytes([v]) * length).decode()
                            for v in (9, 8)
                        ]
                        port = 23020 + index
                        servers.append(
                            dict(
                                server="::",
                                server_port=port,
                                method=cipher,
                                password=identity_key,
                                users=[dict(name="fixture", password=user_key)],
                                mode="tcp_and_udp",
                            )
                        )
                        eih_nodes.append(
                            dict(
                                name="peer",
                                type="ss",
                                server=ss.ipv4,
                                port=port,
                                cipher=cipher,
                                password=f"{identity_key}:{user_key}",
                                udp=True,
                            )
                        )
                    (ss_dir / "config.json").write_text(
                        json.dumps(
                            dict(
                                servers=servers,
                                outbound_udp_allow_fragmentation=True,
                                inbound_udp_allow_fragmentation=True,
                            )
                        )
                    )
                    report["ssserver_policy"] = dict(
                        outbound_udp_allow_fragmentation=True,
                        inbound_udp_allow_fragmentation=True,
                        guest_mtu=1500,
                    )
                    ss.release()
                    ss.wait_tcp(23020)
                    fixture["eih_nodes"] = eih_nodes
                    fixture["eih_ipv6"] = ss.ipv6
                path = root / "fixture.json"
                path.write_text(json.dumps(fixture))
                for identifier in selected:
                    print(f"INTEGRATION: {identifier}", flush=True)
                    env = dict(
                        os.environ,
                        VCORE_VLESS_INPUT=str(path),
                        VCORE_PROTOCOL_STAGE="INTEGRATION",
                        VCORE_CASE_EVENTS=str(output / (identifier + "-events.jsonl")),
                        VCORE_INTEGRATION_OBSERVATIONS=str(
                            output / (identifier + "-observations.json")
                        ),
                    )
                    argv = rust_command(CONSUMERS[identifier])
                    result = run_command(argv, cwd=CORE_DIR, env=env, timeout=3600)
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
                    if "INTEGRATION-SS-EIH" in selected:
                        # The follow-log owner buffers while live; snapshot via
                        # the CLI so a short failed run retains real diagnostics.
                        text = command("logs", ss.name)
                        for server in servers:
                            for key in (
                                server["password"],
                                server["users"][0]["password"],
                            ):
                                text = text.replace(key, "<synthetic-key>")
                        text = re.sub(r"(?:\d{1,3}\.){3}\d{1,3}", "<fixture-ip>", text)
                        (output / "ssserver.log").write_text(redact(text))
                    if result.returncode != 0 or not result.cleanup:
                        raise RuntimeError("INTEGRATION public-runtime consumer failed")
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
        (output / "integration-suite.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return report


if __name__ == "__main__":
    with exclusive_run(), frozen_image(None):
        run(Path(sys.argv[1]), sys.argv[2:] or list(CONSUMERS))
