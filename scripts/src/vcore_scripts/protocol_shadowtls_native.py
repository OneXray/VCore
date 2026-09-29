"""Supplementary native ShadowTLS + unmodified ssserver TCP acceptance."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .native_release import download_native
from .protocol_completion_peers import CASES, peer_configuration
from .protocol_containers import ContainerLab, command, frozen_image
from .protocol_fixtures import certificates
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command


def run(output: Path, *, supplied=None, image=None):
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError("native ShadowTLS evidence must stay in the owned run root")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        source=source_identity(), status="NOT RUN", peers={}, isolation={}, cases=[]
    )
    directories = {}
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
            artifacts = supplied or {
                kind: download_native(
                    kind, output / kind, "linux-arm64", defer_version=True
                )
                for kind in ("ST", "SS")
            }
            for kind, artifact in artifacts.items():
                report["peers"][kind] = artifact.identity
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
                raise RuntimeError("native ShadowTLS consumer build failed")
            lab = ContainerLab(report["isolation"], mtu=1500)
            with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temp:
                root = Path(temp)
                try:
                    with contextlib.ExitStack() as stack:
                        for role in (
                            "origin",
                            "ssserver",
                            "shadow0",
                            "shadow1",
                            "shadow2",
                        ):
                            directories[role] = root / role
                            directories[role].mkdir()
                        cert = certificates(directories["origin"])
                        shutil.copy2(
                            Path(__file__).with_name("container_udp_origin.py"),
                            directories["origin"] / "origin.py",
                        )
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
                                "/data/fixture/origin.py",
                            ],
                        )
                        shutil.copy2(
                            artifacts["SS"].binary, directories["ssserver"] / "ssserver"
                        )
                        ss = lab.start(
                            stack,
                            directories["ssserver"],
                            "ssserver",
                            [
                                "/data/fixture/ssserver",
                                "-c",
                                "/data/fixture/config.json",
                            ],
                        )
                        peers = {"SS": ss}
                        servers, nodes, relays = [], [], []
                        for index, case in enumerate(
                            c for c in CASES if c.shadow_tls and not c.uot
                        ):
                            directory = directories[f"shadow{index}"]
                            shutil.copy2(
                                artifacts["ST"].binary, directory / "shadow-tls"
                            )
                            relay = lab.start(
                                stack,
                                directory,
                                f"shadow{index}",
                                [
                                    "env",
                                    "RUST_LOG=error",
                                    "/data/fixture/shadow-tls",
                                    "--threads",
                                    "1",
                                    "--v3",
                                    "--strict",
                                    "server",
                                    "--listen",
                                    "0.0.0.0:23000",
                                    "--server",
                                    f"{ss.ipv4}:{23100 + index}",
                                    "--tls",
                                    f"{origin.ipv4}:24001",
                                    "--password",
                                    "synthetic-shadowtls-fixture",
                                ],
                            )
                            peers.setdefault("ST", relay)
                            node, _ = peer_configuration(
                                case,
                                server=relay.ipv4,
                                cover=f"{origin.ipv4}:24001",
                                port=23000,
                                certificate=cert,
                            )
                            node.update(name="peer", udp=False)
                            node["client-fingerprint"] = "chrome"
                            nodes.append((case.identifier, node))
                            relays.append(relay)
                            servers.append(
                                dict(
                                    server="::",
                                    server_port=23100 + index,
                                    method=node["cipher"],
                                    password=node["password"],
                                    mode="tcp_only",
                                )
                            )
                        for kind, peer in peers.items():
                            name = artifacts[kind].binary.name
                            identity = report["peers"][kind]
                            identity["version"] = command(
                                "exec", peer.name, f"/data/fixture/{name}", "--version"
                            ).strip()
                            if (
                                not identity["version"]
                                or command(
                                    "exec",
                                    peer.name,
                                    "sha256sum",
                                    f"/data/fixture/{name}",
                                ).split()[0]
                                != identity["binary_sha256"]
                            ):
                                raise RuntimeError(
                                    "native ShadowTLS peer identity mismatch"
                                )
                        (directories["ssserver"] / "config.json").write_text(
                            json.dumps(dict(servers=servers))
                        )
                        origin.release()
                        origin.wait_tcp(24000)
                        origin.wait_tcp(24001)
                        ss.release()
                        for index in range(3):
                            ss.wait_tcp(23100 + index)
                        for relay in relays:
                            relay.release()
                            relay.wait_tcp(23000)
                        for identifier, node in nodes:
                            fixture = root / "fixture.json"
                            fixture.write_text(
                                json.dumps(
                                    dict(
                                        isolation="containers",
                                        node=node,
                                        origin_ipv4=origin.ipv4,
                                        origin_ipv6=origin.ipv6,
                                        origin_control=f"{origin.ipv4}:24000",
                                        data_dir=str(root / "data"),
                                    )
                                )
                            )
                            observations = output / f"{identifier}-observations.json"
                            argv = [
                                "cargo",
                                "test",
                                "--locked",
                                "--all-features",
                                "--test",
                                "vless_public",
                                "shadowtls::native_tcp",
                                "--",
                                "--ignored",
                                "--exact",
                                "--nocapture",
                            ]
                            result = run_command(
                                argv,
                                cwd=CORE_DIR,
                                timeout=240,
                                env=dict(
                                    os.environ,
                                    VCORE_VLESS_INPUT=str(fixture),
                                    VCORE_SHADOWTLS_OBSERVATIONS=str(observations),
                                    VCORE_CASE_EVENTS=str(
                                        output / f"{identifier}-events.jsonl"
                                    ),
                                ),
                            )
                            (output / f"{identifier}.log").write_text(
                                redact(result.stdout.decode(errors="replace"))
                            )
                            observed = (
                                json.loads(observations.read_text())
                                if observations.is_file()
                                else None
                            )
                            passed = (
                                result.returncode == 0
                                and result.cleanup
                                and observed
                                == dict(
                                    tcp_bytes_each_direction=10 * 1024 * 1024,
                                    udp_packets=0,
                                    udp_sizes=[],
                                    stop_idle=True,
                                )
                            )
                            report["cases"].append(
                                dict(
                                    case_id=identifier,
                                    status="PASS" if passed else "FAIL",
                                    command=argv,
                                    exit_code=result.returncode,
                                    command_cleanup=result.cleanup,
                                    observations=observed,
                                )
                            )
                            print(
                                f"{identifier}: {'PASS' if passed else 'FAIL'}",
                                flush=True,
                            )
                            if not passed:
                                raise RuntimeError(
                                    "native ShadowTLS TCP validation failed"
                                )
                finally:
                    for role, directory in directories.items():
                        if (directory / "peer.log").is_file():
                            (output / f"{role}.log").write_text(
                                redact(
                                    (directory / "peer.log").read_text(errors="replace")
                                )
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
        raise RuntimeError("native ShadowTLS source or cleanup gate failed")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    run(parser.parse_args().output)
