"""Official Mihomo-client UDP differential; observations, not VCore sign-off."""

from __future__ import annotations

import contextlib
import json
import socket
import sys
import tempfile
from pathlib import Path

from .mihomo_isolation import exclusive_run, reserve_port
from .protocol_inputs import source_identity
from .protocol_peers import OwnedProcess
from .protocol_preflight import preflight
from .protocol_streams import certificates
from .protocol_vmess import peer_config


def observe(client_port, origin, size):
    result = dict(size=size, origin_lengths=[], origin_content=False, reply=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as incoming:
        incoming.bind(("127.0.0.1", 0))
        incoming.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        incoming.settimeout(1)
        payload = bytes([size % 251]) * size
        incoming.sendto(payload, ("127.0.0.1", client_port))
        fragments = []
        try:
            origin.settimeout(1)
            data, source = origin.recvfrom(20000)
            fragments.append(data)
            origin.settimeout(0.02)
            while True:
                try:
                    part, other = origin.recvfrom(20000)
                    fragments.append(part)
                    if other != source:
                        result["mixed_sources"] = True
                except TimeoutError:
                    break
            result["origin_lengths"] = [len(part) for part in fragments]
            result["origin_content"] = fragments == [payload]
            if result["origin_content"]:
                origin.sendto(data, source)
                echo, _ = incoming.recvfrom(20000)
                result["reply"] = echo == payload
        except OSError as error:
            result["error"] = type(error).__name__
    return result


def run(output):
    raise RuntimeError(
        "BLOCKED: archived host-server diagnostic; use protocol_vmess_udp_ab"
    )


def _historical_run(output):
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        scope="native-to-native-udp-differential", source=source_identity(), cases=[]
    )
    try:
        artifacts, report["preflight"] = preflight(output / "binaries", {"M", "V2"})
        if set(artifacts) != {"M", "V2"}:
            raise RuntimeError("official peer unavailable")
        report["peers"] = {
            kind: artifact.identity for kind, artifact in artifacts.items()
        }
        for kind, mode in [("M", "tcp"), ("V2", "http"), ("V2", "h2")]:
            for codec in ["raw", "xudp", "packetaddr"]:
                for cipher in ["none", "aes-128-gcm"]:
                    case = dict(
                        server=kind,
                        mode=mode,
                        codec=codec,
                        cipher=cipher,
                        server_cleanup={},
                        client_cleanup={},
                        sizes=[],
                    )
                    report["cases"].append(case)
                    print(
                        f"native-udp: M -> {kind} {mode} {codec} {cipher}", flush=True
                    )
                    with (
                        tempfile.TemporaryDirectory(
                            prefix="private-", dir=output
                        ) as temporary,
                        contextlib.ExitStack() as stack,
                        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin,
                    ):
                        root = Path(temporary)
                        origin.bind(("127.0.0.1", 0))
                        origin.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                        server_port, server_guard = reserve_port(stack)
                        client_port, client_guard = reserve_port(stack)
                        server_dir, client_dir = root / "server", root / "client"
                        server_dir.mkdir()
                        client_dir.mkdir()
                        cert, key, _ = certificates(server_dir)
                        server_config = server_dir / "config.json"
                        server_config.write_text(
                            json.dumps(
                                peer_config(kind, mode, False, server_port, cert, key)
                            )
                        )
                        node = dict(
                            name="edge",
                            type="vmess",
                            server="127.0.0.1",
                            port=server_port,
                            uuid="07070707-0707-0707-0707-070707070707",
                            alterId=0,
                            cipher=cipher,
                            network=mode,
                            tls=False,
                            udp=True,
                        )
                        if codec != "raw":
                            node["packet-encoding"] = codec
                        if mode == "http":
                            node["http-opts"] = dict(
                                method="GET",
                                path=["/n3-http"],
                                headers={"Host": ["localhost"]},
                            )
                        if mode == "h2":
                            node["h2-opts"] = dict(host=["localhost"], path="/n3-h2")
                        client_config = client_dir / "config.json"
                        client_config.write_text(
                            json.dumps(
                                {
                                    "mode": "rule",
                                    "log-level": "silent",
                                    "ipv6": True,
                                    "listeners": [
                                        dict(
                                            name="fixture",
                                            type="tunnel",
                                            listen="127.0.0.1",
                                            port=client_port,
                                            network=["tcp", "udp"],
                                            target=f"127.0.0.1:{origin.getsockname()[1]}",
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
                        for size in [1, 1200, 2048, 2049, 4096, 9216]:
                            record = observe(client_port, origin, size)
                            case["sizes"].append(record)
                            print(json.dumps(record), flush=True)
                        server.ensure_alive()
                        client.ensure_alive()
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        report["cleanup"] = all(
            case["server_cleanup"].get("joined")
            and case["client_cleanup"].get("joined")
            for case in report["cases"]
        )
        report["observations_complete"] = len(report["cases"]) == 18 and all(
            len(case["sizes"]) == 6 for case in report["cases"]
        )
        return (
            0
            if report["source_unchanged"]
            and report["cleanup"]
            and report["observations_complete"]
            else 1
        )
    finally:
        (output / "vmess-udp-diagnostic.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )


if __name__ == "__main__":
    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve()))
