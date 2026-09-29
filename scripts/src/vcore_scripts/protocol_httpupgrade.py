"""Public HTTPUpgrade consumers against owned official release containers."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .native_release import download_native
from .protocol_completion_peers import CASES, peer_configuration
from .protocol_containers import ContainerLab, command, frozen_image
from .protocol_evidence import read_events
from .protocol_fixtures import certificates
from .protocol_hysteria2_catalog import assertions_pass
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command
from .protocol_security_acceptance import rust_command

CHECKS = ("tcp", "udp", "udp-domain", "early-data", "profiles", "negative", "close")


def selection(checks):
    rows = []
    for case in CASES:
        if case.protocol not in {"vmess", "trojan"}:
            continue
        if checks == "udp-domain" and case.protocol != "trojan":
            continue
        if checks == "profiles" and not case.tls:
            continue
        variants = (
            ("raw", "xudp", "packetaddr")
            if checks == "udp" and case.protocol == "vmess"
            else ("raw",)
            if checks == "udp"
            else ("domain",)
            if checks == "udp-domain"
            else ("ed1", "ed2048")
            if checks == "early-data"
            else ("chrome", "chrome120", "firefox", "safari")
            if checks == "profiles"
            else ("identity", "path") + (("certificate",) if case.tls else ())
            if checks == "negative"
            else ("",)
        )
        for variant in variants:
            consumer = (
                "udp"
                if checks.startswith("udp")
                else "echo_and_stop"
                if checks in {"early-data", "profiles"}
                else "rejected"
                if checks == "negative"
                else checks
            )
            rows.append(
                (
                    case.identifier + ("-" + variant if variant else ""),
                    case,
                    variant,
                    consumer,
                )
            )
    return rows


def configure(node, checks, variant):
    if checks == "udp" and node["type"] == "vmess":
        node["packet-encoding"] = "" if variant == "raw" else variant
    elif checks == "early-data":
        node["ws-opts"].update(
            {"max-early-data": int(variant[2:]), "path": "/protocol-upgrade?probe=once"}
        )
    elif checks == "profiles":
        node["client-fingerprint"] = variant
    elif checks == "negative":
        if variant == "identity":
            node["uuid" if node["type"] == "vmess" else "password"] = (
                "08080808-0808-0808-0808-080808080808"
            )
        elif variant == "certificate":
            node["fingerprint"] = "00" * 32
        elif variant == "path":
            node["ws-opts"]["path"] = "/wrong"


def families(node, kind):
    return (
        ["domain"]
        if kind == "XR"
        else ["ipv4", "ipv6"]
        if node["type"] == "trojan"
        else ["ipv4", "ipv6", "domain"]
    )


def expected_observation(consumer, node=None, kind="M"):
    if consumer == "echo_and_stop":
        return dict(authenticated_echo=True, live_stream_cancelled=True, stop_idle=True)
    if consumer == "rejected":
        return dict(origin_connected=False, received_business_bytes=0, stop_idle=True)
    if consumer == "tcp":
        return dict(
            families=["ipv4", "ipv6", "domain"],
            tcp_bytes_each_family_each_direction=10 * 1024 * 1024,
            server_first=True,
            client_first=True,
            stop_idle=True,
        )
    if consumer == "udp":
        vmess = node["type"] == "vmess"
        rows = []
        for family in families(node, kind):
            cap = (
                15000
                - (
                    (7 if family == "ipv4" else 19)
                    if node.get("packet-encoding") == "packetaddr"
                    else 0
                )
                if vmess
                else 8166
                if kind == "XR"
                else 8192
            )
            sizes = ([] if vmess or kind == "XR" else [0]) + [1, 64, 512, 1200, cap]
            rows.append(dict(family=family, sizes=sizes, packets=len(sizes) * 100))
        return dict(
            udp=rows,
            zero_no_delivery=vmess or kind == "XR",
            oversize_rejected=True,
            tcp_sibling=True,
            stop_idle=True,
        )
    raise ValueError("unknown HTTPUpgrade consumer")


def measure_close(lab, root, output, binary, origin, node, name):
    directory = root / (name + "-reference")
    directory.mkdir()
    shutil.copy2(binary, directory / "peer")
    reference = dict(node, name="reference")
    (directory / "config.json").write_text(
        json.dumps(
            {
                "socks-port": 23002,
                "allow-lan": True,
                "bind-address": "*",
                "ipv6": True,
                "log-level": "warning",
                "proxies": [reference],
                "rules": ["MATCH,reference"],
            }
        )
    )
    with contextlib.ExitStack() as stack:
        peer = lab.start(
            stack,
            directory,
            name + "-reference",
            ["/data/fixture/peer", "-d", "/data", "-f", "/data/fixture/config.json"],
        )
        peer.release()
        peer.wait_tcp(23002)
        measured = run_command(
            [
                "container",
                "exec",
                origin.name,
                "env",
                "VCORE_ISOLATED_ORIGIN=1",
                "python",
                "-B",
                "/data/fixture/close.py",
                peer.ipv4,
                origin.ipv4,
            ],
            timeout=30,
        )
        (output / (name + "-close-command.log")).write_text(
            redact(measured.stdout.decode(errors="replace"))
        )
        if measured.returncode or not measured.cleanup:
            raise RuntimeError("official HTTPUpgrade close comparison failed")
        value = json.loads(measured.stdout)
        if (
            set(value) != {"tail_hex", "terminated", "variant"}
            or value["terminated"] is not True
            or value["variant"] != "plain"
        ):
            raise RuntimeError("invalid official close observation")
    (output / (name + "-reference.log")).write_text(
        redact((directory / "peer.log").read_text(errors="replace"))
    )
    (output / (name + "-close-reference.json")).write_text(json.dumps(value) + "\n")
    return value


def events_pass(events, consumer):
    expected = {("HTTPUPGRADE-PUBLIC", consumer): 1}
    if consumer == "tcp":
        expected[("HTTPUPGRADE-BASE", "tcp_10mib_both_directions")] = 3
    return assertions_pass(events, expected)


def native_configuration(rows, certificate, origin):
    cert, key, _ = certificate
    return dict(
        log={"loglevel": "warning"},
        dns={"hosts": {"vcore-fixture.test": origin}},
        inbounds=[
            dict(
                listen="::",
                port=node["port"],
                protocol="trojan",
                settings={"clients": [{"password": node["password"]}]},
                streamSettings={
                    "network": "httpupgrade",
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["http/1.1"],
                        "certificates": [
                            {
                                "certificateFile": "/data/fixture/" + cert.name,
                                "keyFile": "/data/fixture/" + key.name,
                            }
                        ],
                    },
                    "httpupgradeSettings": {
                        "path": "/protocol-upgrade",
                        "host": "localhost",
                    },
                },
            )
            for _, node, _, _ in rows
        ],
        outbounds=[dict(protocol="freedom", settings={"domainStrategy": "UseIPv4"})],
    )


def run(output, *, checks="tcp", selected=None, supplied=None, image=None):
    if checks not in CHECKS:
        raise ValueError("unknown HTTPUpgrade check")
    kind = "XR" if checks == "udp-domain" else "M"
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError("HTTPUpgrade evidence must stay in target/interop/runs")
    cases = selection(checks)
    if selected is not None:
        if (
            not selected
            or len(set(selected)) != len(selected)
            or not set(selected) <= {c[0] for c in cases}
        ):
            raise ValueError("unknown or repeated HTTPUpgrade selection")
        cases = [c for c in cases if c[0] in selected]
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        source=source_identity(),
        status="NOT RUN",
        peer={},
        peer_kind=kind,
        isolation={},
        cases=[],
    )
    try:
        with (
            exclusive_run() if supplied is None else contextlib.nullcontext(),
            frozen_image(output / "image-pull.log")
            if image is None
            else contextlib.nullcontext(image) as image,
        ):
            report["container_image"] = image
            if supplied is None and kind == "M":
                binary = download_mihomo(
                    "linux-arm64", directory=output / "binary", identity=report["peer"]
                )
            elif supplied is None:
                artifact = download_native(
                    kind, output / "binary", "linux-arm64", defer_version=True
                )
                binary, report["peer"] = artifact.binary, artifact.identity
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
                raise RuntimeError("HTTPUpgrade consumer build failed")
            lab = ContainerLab(report["isolation"], mtu=1500)
            with tempfile.TemporaryDirectory(prefix="private-", dir=output) as tmp:
                root = Path(tmp)
                directories = {role: root / role for role in ("origin", "server")}
                for directory in directories.values():
                    directory.mkdir()
                certificate = certificates(directories["server"])
                shutil.copy2(binary, directories["server"] / "peer")
                shutil.copy2(
                    Path(__file__).with_name("container_udp_origin.py"),
                    directories["origin"] / "origin.py",
                )
                shutil.copy2(
                    Path(__file__).with_name("container_close_client.py"),
                    directories["origin"] / "close.py",
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
                                "python",
                                "-B",
                                "/data/fixture/origin.py",
                            ],
                        )
                        server = lab.start(
                            stack,
                            directories["server"],
                            "server",
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
                            ],
                        )
                        report["peer"]["version"] = command(
                            "exec",
                            server.name,
                            "/data/fixture/peer",
                            "-v" if kind == "M" else "version",
                        ).strip()
                        if (
                            command(
                                "exec", server.name, "sha256sum", "/data/fixture/peer"
                            ).split()[0]
                            != report["peer"]["binary_sha256"]
                        ):
                            raise RuntimeError("HTTPUpgrade peer identity mismatch")
                        rows = []
                        for i, (name, case, variant, consumer) in enumerate(cases):
                            node, listener = peer_configuration(
                                case,
                                server=server.ipv4,
                                cover="",
                                port=23000 + i,
                                certificate=certificate,
                            )
                            node["name"] = "peer"
                            listener["name"] = name
                            configure(node, checks, variant)
                            rows.append(
                                (
                                    name,
                                    node,
                                    listener,
                                    consumer,
                                )
                            )
                        (directories["server"] / "config.json").write_text(
                            json.dumps(
                                {
                                    "socks-port": 23999,
                                    "allow-lan": True,
                                    "bind-address": "*",
                                    "ipv6": True,
                                    "log-level": "warning",
                                    "hosts": {"vcore-fixture.test": origin.ipv4},
                                    "listeners": [r[2] for r in rows],
                                    "rules": ["MATCH,DIRECT"],
                                }
                                if kind == "M"
                                else native_configuration(
                                    rows, certificate, origin.ipv4
                                )
                            )
                        )
                        checked = run_command(
                            [
                                "container",
                                "exec",
                                server.name,
                                "/data/fixture/peer",
                                "-t",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ]
                            if kind == "M"
                            else [
                                "container",
                                "exec",
                                server.name,
                                "/data/fixture/peer",
                                "run",
                                "-test",
                                "-c",
                                "/data/fixture/config.json",
                            ],
                            timeout=30,
                        )
                        (output / "peer-config.log").write_text(
                            redact(checked.stdout.decode(errors="replace"))
                        )
                        if checked.returncode or not checked.cleanup:
                            raise RuntimeError("HTTPUpgrade peer configuration failed")
                        origin.release()
                        origin.wait_tcp(24000)
                        server.release()
                        server.wait_tcp(23999 if kind == "M" else rows[0][1]["port"])
                        for name, node, _, consumer in rows:
                            reference = (
                                measure_close(
                                    lab, root, output, binary, origin, node, name
                                )
                                if consumer == "close"
                                else None
                            )
                            fixture = root / "fixture.json"
                            fixture.write_text(
                                json.dumps(
                                    dict(
                                        isolation="containers",
                                        node=node,
                                        peer_kind=kind,
                                        families=families(node, kind),
                                        origin_ipv4=origin.ipv4,
                                        origin_ipv6=origin.ipv6,
                                        origin_control=f"{origin.ipv4}:24000",
                                        data_dir=str(root / "data"),
                                        close_reference=reference,
                                    )
                                )
                            )
                            observations = output / (name + "-observations.json")
                            events = output / (name + "-events.jsonl")
                            argv = rust_command(
                                "vless_public", "httpupgrade::" + consumer
                            )
                            result = run_command(
                                argv,
                                cwd=CORE_DIR,
                                timeout=240,
                                env=dict(
                                    os.environ,
                                    VCORE_VLESS_INPUT=str(fixture),
                                    VCORE_HTTPUPGRADE_OBSERVATIONS=str(observations),
                                    VCORE_PROTOCOL_STAGE="HTTPUPGRADE",
                                    VCORE_CASE_EVENTS=str(events),
                                ),
                            )
                            (output / (name + ".log")).write_text(
                                redact(result.stdout.decode(errors="replace"))
                            )
                            observed = (
                                json.loads(observations.read_text())
                                if observations.is_file()
                                else None
                            )
                            good = (
                                result.returncode == 0
                                and result.cleanup
                                and observed
                                == (
                                    dict(
                                        tail_hex=reference["tail_hex"],
                                        terminated=True,
                                        stop_idle=True,
                                    )
                                    if consumer == "close"
                                    else expected_observation(consumer, node, kind)
                                )
                                and events_pass(read_events(events), consumer)
                            )
                            report["cases"].append(
                                dict(
                                    case_id=name,
                                    command=argv,
                                    exit_code=result.returncode,
                                    command_cleanup=result.cleanup,
                                    observations=observed,
                                    status="PASS" if good else "FAIL",
                                )
                            )
                            print(name + (": PASS" if good else ": FAIL"), flush=True)
                            if not good:
                                raise RuntimeError("HTTPUpgrade consumer failed")
                finally:
                    for role, directory in directories.items():
                        if (directory / "peer.log").is_file():
                            (output / (role + ".log")).write_text(
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
        raise RuntimeError("HTTPUpgrade source or cleanup failed")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--case", action="append")
    parser.add_argument("--checks", choices=CHECKS, default="tcp")
    args = parser.parse_args()
    run(args.output, checks=args.checks, selected=args.case)
