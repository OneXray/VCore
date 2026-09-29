"""SS UoT v2 public consumers against unmodified TCP-only Mihomo listeners."""

from __future__ import annotations

import base64
import contextlib
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .protocol_completion_peers import CASES, peer_configuration
from .protocol_containers import ContainerLab, command, frozen_image
from .protocol_fixtures import certificates
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command
from .protocol_security_acceptance import rust_command


def expected_observation(consumer, via_socks5=False):
    if consumer == "group":
        return dict(
            nested_select=True,
            old_association_snapshot=True,
            new_direct=True,
            reject_no_fallback=True,
            native_udp_packets=0,
            stop_idle=True,
        )
    if consumer == "rejected":
        return dict(
            origin_packets=0, received_packets=0, native_udp_packets=0, stop_idle=True
        )
    if consumer != "data":
        raise ValueError("unknown UoT consumer")
    return dict(
        udp_packets=2100,
        udp_sizes=[0, 1, 64, 512, 1200, 4096, 16384],
        families=["ipv4", "ipv6", "domain"],
        alternating_origins=True,
        controlled_dns=True,
        tcp_regression=True,
        stop_idle=True,
        tcp_only_upstream=via_socks5,
        peer_oversize_rejected=True,
        native_udp_packets=0,
    )


def run(
    output,
    *,
    selected=None,
    via_socks5=False,
    supplied=None,
    image=None,
    checks="data",
    native=False,
):
    if (
        checks not in {"data", "negative", "group"}
        or (checks == "group" and not via_socks5)
        or (native and (checks != "negative" or via_socks5))
    ):
        raise ValueError("unsupported UoT peer checks")
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError("UoT evidence must stay inside target/interop/runs")
    cases = tuple(c for c in CASES if c.uot and (not native or not c.shadow_tls))
    if selected is not None:
        if len(set(selected)) != len(selected) or not set(selected) <= {
            c.identifier for c in cases
        }:
            raise ValueError("unknown or duplicate UoT selection")
        cases = tuple(c for c in cases if c.identifier in selected)
    if not cases:
        raise ValueError("empty UoT selection")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        source=source_identity(),
        status="NOT RUN",
        peer={},
        isolation={},
        cases=[],
        tcp_only_upstream=via_socks5,
    )
    try:
        with (
            exclusive_run() if supplied is None else contextlib.nullcontext(),
            (
                frozen_image(output / "image-pull.log")
                if image is None
                else contextlib.nullcontext(image)
            ) as image,
        ):
            report["container_image"] = image
            if supplied is None:
                if native:
                    from .native_release import download_native

                    artifact = download_native(
                        "SS", output / "binary", "linux-arm64", defer_version=True
                    )
                    binary, report["peer"] = artifact.binary, artifact.identity
                else:
                    binary = download_mihomo(
                        "linux-arm64",
                        directory=output / "binary",
                        identity=report["peer"],
                    )
            else:
                binary, report["peer"] = supplied
            built = run_command(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--all-features",
                    "--test",
                    "vless_public",
                    "--no-run",
                ],
                cwd=CORE_DIR,
                timeout=180,
            )
            (output / "build.log").write_text(
                redact(built.stdout.decode(errors="replace"))
            )
            if built.returncode or not built.cleanup:
                raise RuntimeError("UoT public consumer build failed")
            lab = ContainerLab(report["isolation"], mtu=1500)
            with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temp:
                root = Path(temp)
                directories = {
                    role: root / role
                    for role in (
                        "origin",
                        "server",
                        *(["upstream"] if via_socks5 else []),
                    )
                }
                for d in directories.values():
                    d.mkdir()
                certificate = certificates(directories["server"])
                for source, name in zip(
                    certificate[:2], ("cert.pem", "key.pem"), strict=True
                ):
                    shutil.copy2(source, directories["origin"] / name)
                for source, target in (
                    ("container_udp_origin.py", "origin.py"),
                    ("container_shadowtls_peer.py", "peer.py"),
                ):
                    shutil.copy2(
                        Path(__file__).with_name(source), directories["origin"] / target
                    )
                try:
                    with contextlib.ExitStack() as stack:
                        origin = lab.start(
                            stack,
                            directories["origin"],
                            "origin",
                            [
                                "env",
                                "VCORE_ISOLATED_ORIGIN=1",
                                "VCORE_ORIGIN_CERT=/data/fixture/cert.pem",
                                "VCORE_ORIGIN_KEY=/data/fixture/key.pem",
                                "python",
                                "-B",
                                "/data/fixture/peer.py",
                            ],
                        )
                        peers = {}
                        peer_name = "ssserver" if native else "mihomo"
                        for role in ("server", *(["upstream"] if via_socks5 else [])):
                            shutil.copy2(binary, directories[role] / peer_name)
                            shutil.copy2(
                                Path(__file__).with_name("container_uot_watch.py"),
                                directories[role] / "watch.py",
                            )
                            peer_argv = (
                                [
                                    f"/data/fixture/{peer_name}",
                                    "-c",
                                    "/data/fixture/config.json",
                                ]
                                if native
                                else [
                                    "/data/fixture/mihomo",
                                    "-d",
                                    "/data",
                                    "-f",
                                    "/data/fixture/config.json",
                                ]
                            )
                            peers[role] = lab.start(
                                stack,
                                directories[role],
                                role,
                                [
                                    "env",
                                    "VCORE_ISOLATED_ORIGIN=1",
                                    "python",
                                    "-B",
                                    "/data/fixture/watch.py",
                                    *peer_argv,
                                ],
                            )
                            if (
                                command(
                                    "exec",
                                    peers[role].name,
                                    "sha256sum",
                                    f"/data/fixture/{peer_name}",
                                ).split()[0]
                                != report["peer"]["binary_sha256"]
                            ):
                                raise RuntimeError(
                                    "UoT peer identity differs from official download"
                                )
                        server = peers["server"]
                        report["peer"]["version"] = command(
                            "exec",
                            server.name,
                            f"/data/fixture/{peer_name}",
                            "--version" if native else "-v",
                        ).strip()
                        nodes, listeners = [], []
                        for index, case in enumerate(cases):
                            node, listener = peer_configuration(
                                case,
                                server=server.ipv4,
                                cover=f"{origin.ipv4}:24001",
                                port=23000 + index,
                                certificate=certificate,
                            )
                            node["name"] = "peer"
                            if case.shadow_tls:
                                node["client-fingerprint"] = "chrome"
                            else:
                                del node["udp-over-tcp-version"]
                            assert listener["udp"] is False
                            if native:
                                nodes.append((case.identifier + "-unsupported", node))
                            elif checks == "negative":
                                bad_key = copy.deepcopy(node)
                                bad_key["password"] = base64.b64encode(
                                    bytes([9])
                                    * (16 if "aes-128" in node["cipher"] else 32)
                                ).decode()
                                nodes.append((case.identifier + "-key", bad_key))
                                if case.shadow_tls:
                                    bad_cover = copy.deepcopy(node)
                                    bad_cover["plugin-opts"]["password"] = (
                                        "incorrect-synthetic-cover"
                                    )
                                    nodes.append(
                                        (case.identifier + "-identity", bad_cover)
                                    )
                            else:
                                nodes.append((case.identifier, node))
                            listeners.append(
                                dict(
                                    server="::",
                                    server_port=node["port"],
                                    method=node["cipher"],
                                    password=node["password"],
                                    mode="tcp_only",
                                )
                                if native
                                else listener
                            )

                        def configuration(listeners):
                            return {
                                "socks-port": 23999,
                                "allow-lan": True,
                                "bind-address": "*",
                                "ipv6": True,
                                "log-level": "warning",
                                "listeners": listeners,
                                "rules": ["MATCH,DIRECT"],
                            }

                        (directories["server"] / "config.json").write_text(
                            json.dumps(
                                dict(servers=listeners)
                                if native
                                else configuration(listeners)
                            )
                        )
                        upstream = None
                        if via_socks5:
                            upstream = dict(
                                name="hop",
                                type="socks5",
                                server=peers["upstream"].ipv4,
                                port=23050,
                                udp=False,
                            )
                            (directories["upstream"] / "config.json").write_text(
                                json.dumps(
                                    configuration(
                                        [
                                            dict(
                                                name="hop",
                                                type="socks",
                                                listen="::",
                                                port=23050,
                                                udp=False,
                                            )
                                        ]
                                    )
                                )
                            )
                        origin.release()
                        origin.wait_tcp(24000)
                        origin.wait_tcp(24001)
                        for peer in peers.values():
                            peer.release()
                            peer.wait_tcp(23998)
                            peer.wait_tcp(23000 if native else 23999)
                        for identifier, node in nodes:
                            fixture = root / "fixture.json"
                            value = dict(
                                isolation="containers",
                                node=node,
                                origin_ipv4=origin.ipv4,
                                origin_ipv6=origin.ipv6,
                                origin_control=f"{origin.ipv4}:24000",
                                udp_observer=f"{server.ipv4}:23998",
                                data_dir=str(root / "data"),
                            )
                            if upstream is not None:
                                value["upstream"] = upstream
                            fixture.write_text(json.dumps(value))
                            observations = output / (identifier + "-observations.json")
                            consumer = "rejected" if checks == "negative" else checks
                            argv = rust_command("vless_public", "uot::" + consumer)
                            result = run_command(
                                argv,
                                cwd=CORE_DIR,
                                timeout=240,
                                env=dict(
                                    os.environ,
                                    VCORE_VLESS_INPUT=str(fixture),
                                    VCORE_UOT_OBSERVATIONS=str(observations),
                                    VCORE_CASE_EVENTS=str(
                                        output / (identifier + "-events.jsonl")
                                    ),
                                ),
                            )
                            (output / (identifier + ".log")).write_text(
                                redact(result.stdout.decode(errors="replace"))
                            )
                            observed = (
                                json.loads(observations.read_text())
                                if observations.is_file()
                                else None
                            )
                            expected = expected_observation(consumer, via_socks5)
                            from .protocol_evidence import read_events
                            from .protocol_hysteria2_catalog import assertions_pass

                            good = (
                                result.returncode == 0
                                and result.cleanup
                                and observed == expected
                                and assertions_pass(
                                    read_events(
                                        output / (identifier + "-events.jsonl")
                                    ),
                                    {("UOT-PUBLIC", consumer): 1},
                                )
                            )
                            report["cases"].append(
                                dict(
                                    case_id=identifier,
                                    command=argv,
                                    exit_code=result.returncode,
                                    command_cleanup=result.cleanup,
                                    observations=observed,
                                    listener_native_udp=False,
                                    status="PASS" if good else "FAIL",
                                )
                            )
                            print(
                                identifier + (": PASS" if good else ": FAIL"),
                                flush=True,
                            )
                            if not good:
                                raise RuntimeError("UoT public data failed")
                finally:
                    for role, d in directories.items():
                        if (d / "peer.log").is_file():
                            (output / (role + ".log")).write_text(
                                redact((d / "peer.log").read_text(errors="replace"))
                            )
            report["status"] = "PASS"
    except BaseException as error:
        report["status"] = "FAIL"
        (output / "failure.log").write_text(redact(str(error)))
        raise
    finally:
        report["cleanup"] = all(
            p.get("joined") is True for p in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = same_source(report["source"], source_identity())
        if not report["cleanup"] or not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "PASS":
        raise RuntimeError("UoT source or cleanup failed")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--case", action="append")
    parser.add_argument("--via-socks5", action="store_true")
    parser.add_argument(
        "--checks", choices=("data", "negative", "group"), default="data"
    )
    parser.add_argument("--native", action="store_true")
    args = parser.parse_args()
    run(
        args.output,
        selected=args.case,
        via_socks5=args.via_socks5,
        checks=args.checks,
        native=args.native,
    )
