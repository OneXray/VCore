"""Container-only N3 UDP differential; not public-runtime or stage acceptance."""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_release import download_mihomo
from .protocol_containers import ContainerLab, command
from .protocol_fixtures import certificates
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_vmess import peer_config
from .protocol_vmess_udp_ab import options, warning_summary


def client_config(matrix, mode, encrypted, server, origin, client, pin):
    listeners, nodes, selected = [], [], []
    for index, option in enumerate(matrix):
        port = 25000 + index
        selected.append(dict(option, socks_port=port, socks_host=client))
        node = dict(
            name=f"edge-{index}",
            type="vmess",
            server=server,
            port=23000,
            uuid="07070707-0707-0707-0707-070707070707",
            alterId=0,
            cipher=option["cipher"],
            network=mode,
            tls=encrypted,
            udp=True,
        )
        node.update(
            {
                "global-padding": option["padding"],
                "authenticated-length": option["length"],
            }
        )
        if option["codec"] != "raw":
            node["packet-encoding"] = option["codec"]
        if encrypted:
            node.update(servername="localhost", fingerprint=pin)
        if mode == "ws":
            node["ws-opts"] = dict(path="/n3-ws", headers={"Host": "localhost"})
        if mode == "grpc":
            node["grpc-opts"] = {"grpc-service-name": "n3-grpc"}
        nodes.append(node)
        listeners.append(
            dict(
                name=f"fixture-{index}",
                type="socks",
                listen=client,
                port=port,
                udp=True,
                proxy=node["name"],
            )
        )
    return {
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "hosts": {"vcore-fixture.test": origin},
        "listeners": listeners,
        "proxies": nodes,
        "rules": ["MATCH,REJECT"],
    }, selected


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    matrix = options(args.codecs)
    sizes = args.sizes or [1, 64, 512, 1200]
    boundary = args.include_boundary or args.sizes is None
    report = dict(
        scope="container-matched-mihomo-vcore-udp-diagnostic",
        status="NOT RUN",
        phase="preflight",
        source=source_identity(),
        cases=[],
        isolation={},
        peer={},
        cleanup=False,
        rounds=args.rounds,
        packets_per_size=args.packets,
        sizes=sizes,
        include_boundary=boundary,
        boundary_policy="raw/XUDP: 15000; packetaddr: 15000 minus 7/19 address bytes",
        families=args.families,
        options=matrix,
        nat_reuse_probe=args.nat_reuse_probe,
        fixture_source_policy="distinct SOCKS UDP sockets retained until transport end",
        notes=[
            "Separate owned VMs: protocol server, official client ingress, UDP origin.",
            "Host runs VCore and test driver only; no published host/server ports.",
            "Same body flags, families, sizes, packet count; order alternates.",
            "Send, origin observation and reply each retain their 1s deadline.",
            "Origin now echoes autonomously and reports exact received bytes via TCP.",
            "Failed associations stop without retries; loopback protection unchanged.",
            "Virtual IPv6 and wire diagnostic do not prove device or N3 acceptance.",
        ],
    )
    try:
        binary = download_mihomo(
            "linux-arm64", directory=output / "binary", identity=report["peer"]
        )
        lab = ContainerLab(report["isolation"])
        report["phase"] = "build"
        build = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "vmess_native",
                "--no-run",
            ],
            cwd=CORE_DIR,
            timeout=180,
        )
        (output / "build.log").write_text(redact(build.stdout.decode(errors="replace")))
        if build.returncode != 0 or not build.cleanup:
            raise RuntimeError("diagnostic build failed")
        for mode, encrypted in itertools.product(args.modes, args.tls):
            name = f"{mode}-{'tls' if encrypted else 'plain'}"
            record = dict(name=name, status="NOT RUN")
            report["cases"].append(record)
            report["phase"] = "peer-start"
            print(f"UDP-CONTAINERS: {name}", flush=True)
            with tempfile.TemporaryDirectory(
                prefix="private-", dir=output
            ) as temporary:
                root = Path(temporary)
                with contextlib.ExitStack() as stack:
                    directories = {}
                    peers = {}
                    for role in ["origin", "server", "client"]:
                        directory = root / role
                        directory.mkdir()
                        directories[role] = directory
                        if role == "origin":
                            shutil.copyfile(
                                Path(__file__).with_name("container_udp_origin.py"),
                                directory / "origin.py",
                            )
                            argv = [
                                "env",
                                "VCORE_ISOLATED_ORIGIN=1",
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
                        peers[role] = lab.start(
                            stack, directory, f"{name}-{role}", argv
                        )
                    origin, server, client = (
                        peers[key] for key in ["origin", "server", "client"]
                    )
                    version = command(
                        "exec", server.name, "/data/fixture/mihomo", "-v"
                    ).strip()
                    digest = command(
                        "exec", server.name, "sha256sum", "/data/fixture/mihomo"
                    ).split()[0]
                    if digest != report["peer"]["binary_sha256"]:
                        raise RuntimeError(
                            "container peer identity differs from download"
                        )
                    report["peer"]["version"] = version
                    record["peer_version"] = version
                    record["origin_python"] = command(
                        "exec", origin.name, "python", "--version"
                    ).strip()
                    cert, key, pin = certificates(directories["server"])
                    config = peer_config(
                        "M",
                        mode,
                        encrypted,
                        23000,
                        Path("/data/fixture") / cert.name,
                        Path("/data/fixture") / key.name,
                    )
                    config["log-level"] = "warning"
                    config["hosts"] = {"vcore-fixture.test": origin.ipv4}
                    config["listeners"][0]["listen"] = server.ipv4
                    (directories["server"] / "config.json").write_text(
                        json.dumps(config)
                    )
                    config, selected = client_config(
                        matrix,
                        mode,
                        encrypted,
                        server.ipv4,
                        origin.ipv4,
                        client.ipv4,
                        pin,
                    )
                    (directories["client"] / "config.json").write_text(
                        json.dumps(config)
                    )
                    for peer in peers.values():
                        peer.release()
                    origin.wait_tcp(24000)
                    server.wait_tcp(23000)
                    for option in selected:
                        client.wait_tcp(option["socks_port"])
                    report["phase"] = "execute"
                    fixture = root / "input.json"
                    fixture.write_text(
                        json.dumps(
                            dict(
                                isolation="containers",
                                origin_control=f"{origin.ipv4}:24000",
                                origin_ipv4=origin.ipv4,
                                origin_ipv6=origin.ipv6,
                                options=selected,
                                rounds=args.rounds,
                                packets_per_size=args.packets,
                                sizes=sizes,
                                include_boundary=boundary,
                                families=args.families,
                            )
                        )
                    )
                    events = output / f"{name}.jsonl"
                    test_command = [
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        "vmess_native",
                        "udp_ab::socks_nat_source_reuse"
                        if args.nat_reuse_probe
                        else "udp_ab::matched_clients",
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ]
                    execution = run_command(
                        test_command,
                        cwd=CORE_DIR,
                        timeout=600,
                        limit=4 * 1024 * 1024,
                        env=dict(
                            os.environ,
                            VCORE_VMESS_PEER=f"{server.ipv4}:23000",
                            VCORE_VMESS_TRANSPORT=json.dumps(
                                dict(mode=mode, tls=encrypted, pin=pin)
                            ),
                            VCORE_VMESS_ORIGIN_V4=origin.ipv4,
                            VCORE_VMESS_AB_INPUT=str(fixture),
                            VCORE_VMESS_AB_EVENTS=str(events),
                            VCORE_VMESS_AB_PRIVATE=str(root),
                        ),
                    )
                    (output / f"{name}.log").write_text(
                        redact(execution.stdout.decode(errors="replace"))
                    )
                    observations = (
                        [json.loads(line) for line in events.read_text().splitlines()]
                        if events.exists()
                        else []
                    )
                    expected = (
                        3
                        if args.nat_reuse_probe
                        else args.rounds * len(matrix) * len(args.families) * 2
                    )
                    record.update(
                        command=test_command,
                        exit_code=execution.returncode,
                        seconds=execution.seconds,
                        command_cleanup=execution.cleanup,
                        expected_associations=expected,
                        observed_associations=len(observations),
                        failures=[
                            item for item in observations if item["status"] != "PASS"
                        ],
                        clients={
                            kind: dict(
                                associations=sum(
                                    item["client"] == kind for item in observations
                                ),
                                failed=sum(
                                    item["client"] == kind and item["status"] != "PASS"
                                    for item in observations
                                ),
                                completed_packets=sum(
                                    item["completed"]
                                    for item in observations
                                    if item["client"] == kind
                                ),
                            )
                            for kind in ["vcore", "mihomo"]
                        },
                    )
                    for peer in peers.values():
                        peer.ensure_alive()
                # Stop/delete VMs and join bounded log readers before inspection.
                for role in ["server", "client"]:
                    record[f"{role}_warnings"] = warning_summary(
                        directories[role] / "peer.log"
                    )
                record["cleanup"] = all(
                    peer.record["joined"] for peer in peers.values()
                )
                expected_outcome = (
                    [item["status"] for item in observations]
                    == ["PASS", "REPRODUCED", "PASS"]
                    if args.nat_reuse_probe
                    else not record["failures"]
                )
                record["status"] = (
                    ("REPRODUCED" if args.nat_reuse_probe else "PASS")
                    if (
                        execution.returncode == 0
                        and execution.cleanup
                        and record["cleanup"]
                        and len(observations) == expected
                        and expected_outcome
                        and all(
                            item.get("driver_joined", True) for item in observations
                        )
                    )
                    else "FAIL"
                )
                print(
                    json.dumps(
                        {key: record[key] for key in ["name", "status", "clients"]}
                    ),
                    flush=True,
                )
        expected_status = "REPRODUCED" if args.nat_reuse_probe else "PASS"
        report["status"] = (
            expected_status
            if report["cases"]
            and all(case["status"] == expected_status for case in report["cases"])
            else "FAIL"
        )
    except KeyboardInterrupt:
        report.update(status="INTERRUPTED", reason="user interruption")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        status = "BLOCKED" if report["phase"] == "preflight" else "FAIL"
        report.update(status=status, reason=type(error).__name__)
        print(f"UDP-CONTAINERS {status}: {type(error).__name__}", flush=True)
    finally:
        report["cleanup"] = all(
            peer["joined"] for peer in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        if report["status"] in {"PASS", "REPRODUCED"} and not (
            report["cleanup"] and report["source_unchanged"]
        ):
            report["status"] = "FAIL"
        (output / "udp-ab.json").write_text(json.dumps(report, indent=2) + "\n")
    return (
        0
        if report["status"] == "PASS"
        else (130 if report["status"] == "INTERRUPTED" else 1)
    )
