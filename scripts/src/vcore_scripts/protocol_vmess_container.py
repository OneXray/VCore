"""N3 wire cases against official latest peers and entirely isolated origins."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_release import download_mihomo
from .native_release import PeerArtifact, download_native
from .protocol_containers import ContainerLab, command
from .protocol_evidence import read_events
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_streams import certificates
from .protocol_vmess import CASES, peer_config
from .protocol_vmess_public import CASES as PUBLIC_CASES
from .protocol_vmess_public import events_pass, node_config

ALL_CASES = CASES | PUBLIC_CASES


def run(output: Path, selected=None, *, preflight_only=False):
    selected = list(ALL_CASES) if selected is None else selected
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not set(selected) <= ALL_CASES.keys()
    ):
        raise ValueError("invalid N3 native selection")
    output.mkdir(parents=True, exist_ok=False)
    if preflight_only:
        # One listener/origin group per official implementation, not a traffic run.
        kinds = {ALL_CASES[case][0] for case in selected}
        selected = [
            next(case for case in selected if ALL_CASES[case][0] == kind)
            for kind in sorted(kinds)
        ]
    report = dict(
        stage="N3",
        scope="container-wire-and-public-consumer",
        source=source_identity(),
        status="NOT RUN",
        phase="preflight",
        cases=[],
        peers={},
        isolation={},
    )
    try:
        artifacts = {}
        for kind in sorted({ALL_CASES[case][0] for case in selected} | {"M"}):
            directory = output / "binaries" / kind
            if kind == "M":
                identity = {}
                binary = download_mihomo(
                    "linux-arm64", directory=directory, identity=identity
                )
                artifacts[kind] = PeerArtifact(binary, identity)
            else:
                artifacts[kind] = download_native(
                    kind, directory, "linux-arm64", defer_version=True
                )
            report["peers"][kind] = artifacts[kind].identity
        lab = ContainerLab(report["isolation"])
        report["phase"] = "build"
        built = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "vmess_native",
                "--test",
                "vmess_public",
                "--no-run",
            ],
            timeout=180,
        )
        (output / "build.log").write_text(redact(built.stdout.decode(errors="replace")))
        if built.returncode != 0 or not built.cleanup:
            raise RuntimeError("container wire build failed")
        # Reuse a peer only within one transport; every case gets fresh origin
        # controls/ports and sessions. One downloaded release snapshot per run.
        groups = {}
        for case in selected:
            kind, mode, encrypted, test = ALL_CASES[case]
            groups.setdefault((kind, mode, encrypted), []).append((case, test))
        for (kind, mode, encrypted), cases in groups.items():
            report["phase"] = "peer-start"
            with tempfile.TemporaryDirectory(
                prefix="private-", dir=output
            ) as temporary:
                root = Path(temporary)
                with contextlib.ExitStack() as stack:
                    origin_dir, server_dir = root / "origin", root / "server"
                    origin_dir.mkdir()
                    server_dir.mkdir()
                    shutil.copyfile(
                        Path(__file__).with_name("container_udp_origin.py"),
                        origin_dir / "origin.py",
                    )
                    artifact = artifacts[kind]
                    shutil.copy2(artifact.binary, server_dir / "peer")
                    tag = f"{mode}-{'tls' if encrypted else 'plain'}"
                    origin = lab.start(
                        stack,
                        origin_dir,
                        tag + "-origin",
                        [
                            "env",
                            "VCORE_ISOLATED_ORIGIN=1",
                            "python",
                            "-B",
                            "/data/fixture/origin.py",
                        ],
                    )
                    argv = (
                        [
                            "/data/fixture/peer",
                            "-d",
                            "/data",
                            "-f",
                            "/data/fixture/config.json",
                        ]
                        if kind == "M"
                        else [
                            "/data/fixture/peer",
                            "run",
                            "-c",
                            "/data/fixture/config.json",
                        ]
                    )
                    server = lab.start(stack, server_dir, tag + "-server", argv)
                    version = command(
                        "exec",
                        server.name,
                        "/data/fixture/peer",
                        "-v" if kind == "M" else "version",
                    ).strip()
                    digest = command(
                        "exec", server.name, "sha256sum", "/data/fixture/peer"
                    ).split()[0]
                    if not version or digest != artifact.identity["binary_sha256"]:
                        raise RuntimeError("container peer identity mismatch")
                    artifact.identity["version"] = version
                    # Non-leaf pin still exercises actual certificate name checks.
                    from .protocol_trojan import certificate_chain

                    cert, key, pin = (
                        certificate_chain(server_dir)
                        if encrypted
                        else certificates(server_dir)
                    )
                    config = peer_config(
                        kind,
                        mode,
                        encrypted,
                        23000,
                        Path("/data/fixture") / cert.name,
                        Path("/data/fixture") / key.name,
                    )
                    if kind == "M":
                        config["hosts"] = {"vcore-fixture.test": origin.ipv4}
                        config["listeners"][0]["listen"] = "::"
                    else:
                        config["dns"]["hosts"] = {"vcore-fixture.test": origin.ipv4}
                        config["inbounds"][0]["listen"] = "::"
                    (server_dir / "config.json").write_text(json.dumps(config))
                    upstream = None
                    node = node_config(mode, encrypted, server.ipv4, pin)
                    hop = None
                    if any(case in PUBLIC_CASES for case, _ in cases):
                        upstream_dir = root / "upstream"
                        upstream_dir.mkdir()
                        shutil.copy2(artifacts["M"].binary, upstream_dir / "peer")
                        upstream = lab.start(
                            stack,
                            upstream_dir,
                            tag + "-upstream",
                            [
                                "/data/fixture/peer",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ],
                        )
                        (upstream_dir / "config.json").write_text(
                            json.dumps(
                                {
                                    "socks-port": 23001,
                                    "allow-lan": True,
                                    "bind-address": "*",
                                    "log-level": "silent",
                                    "ipv6": True,
                                    "hosts": {"peer.fixture.test": server.ipv4},
                                    "rules": ["MATCH,DIRECT"],
                                }
                            )
                        )
                        hop = dict(
                            name="hop",
                            type="socks5",
                            server=upstream.ipv4,
                            port=23001,
                            udp=True,
                        )
                        upstream.release()
                        upstream.wait_tcp(23001)
                    fixture = root / "input.json"
                    fixture.write_text(
                        json.dumps(
                            dict(
                                isolation="containers",
                                origin_control=f"{origin.ipv4}:24000",
                                origin_ipv4=origin.ipv4,
                                origin_ipv6=origin.ipv6,
                                server_ipv6=server.ipv6,
                                data_dir=str(root / "data"),
                                node=node,
                                hop=hop,
                                peer_kind=kind,
                            )
                        )
                    )
                    origin.release()
                    server.release()
                    origin.wait_tcp(24000)
                    server.wait_tcp(23000)
                    report["phase"] = "execute"
                    for case, test in cases:
                        if preflight_only:
                            continue
                        print(case, flush=True)
                        record = dict(case_id=case, status="NOT RUN", peer_kind=kind)
                        report["cases"].append(record)
                        events = output / f"{case}-events.jsonl"
                        test_command = [
                            "cargo",
                            "test",
                            "--locked",
                            "--all-features",
                            "--test",
                            "vmess_public" if case in PUBLIC_CASES else "vmess_native",
                            test,
                            "--",
                            "--ignored",
                            "--exact",
                            "--nocapture",
                        ]
                        result = run_command(
                            test_command,
                            cwd=CORE_DIR,
                            timeout=240,
                            limit=4 * 1024 * 1024,
                            env=dict(
                                os.environ,
                                VCORE_VMESS_PEER=f"{server.ipv4}:23000",
                                VCORE_VMESS_TRANSPORT=json.dumps(
                                    dict(
                                        mode=mode,
                                        tls=encrypted,
                                        pin=pin,
                                        peer_kind=kind,
                                        udp_path_limit=15000,
                                    )
                                ),
                                VCORE_VMESS_ORIGIN_V4=origin.ipv4,
                                VCORE_VMESS_AB_INPUT=str(fixture),
                                VCORE_CASE_EVENTS=str(events),
                            ),
                        )
                        (output / f"{case}.log").write_text(
                            redact(result.stdout.decode(errors="replace"))
                        )
                        observed = read_events(events) if events.exists() else []
                        record.update(
                            command=test_command,
                            exit_code=result.returncode,
                            seconds=result.seconds,
                            command_cleanup=result.cleanup,
                            status="PASS"
                            if result.returncode == 0
                            and result.cleanup
                            and (
                                events_pass(observed, test)
                                if case in PUBLIC_CASES
                                else observed
                                == [
                                    dict(
                                        schema_version=1,
                                        suite="N3-WIRE",
                                        assertion=test,
                                        status=status,
                                    )
                                    for status in ("BEGIN", "PASS")
                                ]
                            )
                            else "FAIL",
                        )
                        server.ensure_alive()
                        origin.ensure_alive()
                        print(f"{case}: {record['status']}", flush=True)
                for case, _ in cases:
                    if preflight_only:
                        continue
                    next(item for item in report["cases"] if item["case_id"] == case)[
                        "cleanup"
                    ] = all(
                        peer.record["joined"]
                        for peer in [server, origin] + ([upstream] if upstream else [])
                    )
        report["status"] = (
            "READY"
            if preflight_only
            else "PASS"
            if (preflight_only or len(report["cases"]) == len(selected))
            and all(case["status"] == "PASS" for case in report["cases"])
            else "FAIL"
        )
    except KeyboardInterrupt:
        report.update(status="INTERRUPTED", reason="user interruption")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        report.update(
            status="BLOCKED" if report["phase"] == "preflight" else "FAIL",
            reason=str(error)
            if isinstance(error, RuntimeError)
            else type(error).__name__,
        )
    finally:
        report["cleanup"] = all(
            peer["joined"] for peer in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        if report["status"] in {"PASS", "READY"} and not (
            report["cleanup"] and report["source_unchanged"]
        ):
            report["status"] = "FAIL"
        (output / "vmess-results.json").write_text(json.dumps(report, indent=2) + "\n")
    return (
        0
        if report["status"] in {"PASS", "READY"}
        else (130 if report["status"] == "INTERRUPTED" else 1)
    )
