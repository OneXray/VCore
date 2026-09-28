"""TUIC v5 public consumers against freshly downloaded, isolated Mihomo."""

from __future__ import annotations

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
from .protocol_fixtures import certificate_chain
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command
from .protocol_security_acceptance import rust_command


def expected_observation(consumer):
    if consumer == "udp_disabled":
        return dict(udp_packets=0, tcp_works=True, stop_idle=True)
    if consumer == "group":
        return dict(
            nested_select=True,
            pooled_path_retained=True,
            explicit_rebuild=True,
            reject_no_fallback=True,
            new_direct=True,
            node_measure=True,
            group_measure_rejected=True,
            rollback=True,
            stop_idle=True,
        )
    if consumer == "udp":
        return dict(
            udp_packets=2100,
            udp_sizes=[0, 1, 64, 512, 1200, 4096, 16384],
            families=["ipv4", "ipv6", "domain"],
            alternating_origins=True,
            tcp_sibling=True,
            stop_idle=True,
        )
    if consumer == "tcp":
        return dict(
            families=["ipv4", "ipv6", "domain"],
            tcp_bytes_each_family_each_direction=10 * 1024 * 1024,
            sibling_survives=True,
            stop_idle=True,
        )
    if consumer == "rejected":
        return dict(origin_connected=False, received_business_bytes=0, stop_idle=True)
    raise ValueError("unknown TUIC consumer")


def inputs(node, listener, checks):
    if checks == "negative":
        for index, (kind, mode) in enumerate(
            (kind, mode)
            for kind in ("udp-disabled", "socks5-tcp-only")
            for mode in ("native", "quic")
        ):
            client, peer = copy.deepcopy(node), copy.deepcopy(listener)
            client["udp-relay-mode"] = mode
            client["udp"] = kind != "udp-disabled"
            client["port"] = peer["port"] = 23000 + index
            peer["name"] = kind + "-" + mode
            yield (
                peer["name"],
                client,
                peer,
                ("udp_disabled" if kind == "udp-disabled" else "rejected"),
            )
        return
    if checks == "paths":
        for index, (upstream, mode) in enumerate(
            (upstream, mode)
            for upstream in ("socks5", "ss-uot", "anytls")
            for mode in ("native", "quic")
        ):
            client, peer = copy.deepcopy(node), copy.deepcopy(listener)
            client["udp-relay-mode"] = mode
            client["port"] = peer["port"] = 23000 + index
            peer["name"] = upstream + "-" + mode
            yield peer["name"], client, peer, "group"
        return
    if checks == "udp":
        for index, mode in enumerate(("native", "quic")):
            client, peer = copy.deepcopy(node), copy.deepcopy(listener)
            client["udp-relay-mode"] = mode
            client["port"] = peer["port"] = 23000 + index
            peer["name"] = "udp-" + mode
            yield peer["name"], client, peer, "udp"
        return
    names = (
        ("tcp-cubic", "tcp-new_reno", "tcp-bbr")
        if checks == "tcp"
        else (
            "alpn-default",
            "alpn-custom",
            "empty-password",
            "raw-password",
            "skip",
            "verify-name",
            "wrong-uuid",
            "wrong-password",
            "wrong-pin",
            "wrong-pin-skip",
            "untrusted",
            "wrong-name-skip",
            "wrong-alpn",
        )
    )
    for index, name in enumerate(names):
        client, peer = copy.deepcopy(node), copy.deepcopy(listener)
        client["udp"] = False
        client.pop("udp-relay-mode")
        client["port"] = peer["port"] = 23000 + index
        peer["name"] = name
        if name.startswith("tcp-"):
            client["congestion-controller"] = name.removeprefix("tcp-")
        elif name == "alpn-default":
            del client["alpn"]
        elif name == "alpn-custom":
            client["alpn"] = ["not-selected", "fixture-custom"]
            peer["alpn"] = ["fixture-custom"]
        elif name in {"empty-password", "raw-password"}:
            client["password"] = (
                "" if name == "empty-password" else " synthetic-原样\t\0 "
            )
            peer["users"] = {client["uuid"]: client["password"]}
        elif name == "skip":
            del client["fingerprint"]
            client["skip-cert-verify"] = True
        elif name == "verify-name":
            client["sni"] = "unrelated.invalid"
            client["name-cert-verify"] = "localhost"
        elif name == "wrong-uuid":
            client["uuid"] = "09090909-0909-0909-0909-090909090909"
        elif name == "wrong-password":
            client["password"] = "incorrect-synthetic-auth"
        elif name.startswith("wrong-pin"):
            client["fingerprint"] = "09" * 32
            client["skip-cert-verify"] = name.endswith("skip")
        elif name == "untrusted":
            del client["fingerprint"]
        elif name == "wrong-name-skip":
            client["name-cert-verify"] = "unrelated.invalid"
            client["skip-cert-verify"] = True
        elif name == "wrong-alpn":
            client["alpn"] = ["unrelated"]
        yield (
            name,
            client,
            peer,
            "rejected" if name.startswith("wrong-") or name == "untrusted" else "tcp",
        )


def upstream_pair(name, node, certificate, index):
    cert, key, pin = certificate
    base = dict(name="hop", server=node["server"], port=23100 + index, udp=True)
    listener = dict(name="hop-" + str(index), listen="::", port=base["port"])
    if name.startswith("socks5-"):
        return dict(base, type="socks5"), dict(listener, type="socks", udp=True)
    if name.startswith("ss-uot-"):
        keytext = "BwcHBwcHBwcHBwcHBwcHBw=="
        return dict(
            base,
            type="ss",
            cipher="2022-blake3-aes-128-gcm",
            password=keytext,
            **{"udp-over-tcp": True},
        ), dict(
            listener,
            type="shadowsocks",
            cipher="2022-blake3-aes-128-gcm",
            password=keytext,
            udp=False,
        )
    if name.startswith("anytls-"):
        password = "synthetic-hop"
        return dict(
            base, type="anytls", password=password, sni="localhost", fingerprint=pin
        ), dict(
            listener,
            type="anytls",
            users={"fixture": password},
            certificate="/data/fixture/" + cert.name,
            **{"private-key": "/data/fixture/" + key.name},
        )
    raise ValueError("unknown TUIC upstream")


def run(output, *, checks="tcp", selected=None, supplied=None, image=None):
    if checks not in {"tcp", "policy", "udp", "paths", "negative"}:
        raise ValueError("unknown TUIC check")
    output = output.resolve()
    if not output.is_relative_to((CORE_DIR / "target/interop/runs").resolve()):
        raise ValueError("TUIC evidence must stay in target/interop/runs")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        source=source_identity(), status="NOT RUN", peer={}, isolation={}, cases=[]
    )
    try:
        with (
            exclusive_run() if supplied is None else contextlib.nullcontext(),
            frozen_image(output / "image-pull.log")
            if image is None
            else contextlib.nullcontext(image) as image,
        ):
            report["container_image"] = image
            if supplied is None:
                binary = download_mihomo(
                    "linux-arm64", directory=output / "binary", identity=report["peer"]
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
                raise RuntimeError("TUIC consumer build failed")
            lab = ContainerLab(report["isolation"], mtu=1500)
            with tempfile.TemporaryDirectory(prefix="private-", dir=output) as tmp:
                root = Path(tmp)
                directories = {
                    role: root / role
                    for role in (
                        "origin",
                        "server",
                        *(["upstream"] if checks in {"paths", "negative"} else []),
                    )
                }
                for d in directories.values():
                    d.mkdir()
                cert = certificate_chain(directories["server"])
                shutil.copy2(binary, directories["server"] / "mihomo")
                if checks in {"paths", "negative"}:
                    for asset in (binary, *cert[:2]):
                        shutil.copy2(
                            asset,
                            directories["upstream"]
                            / ("mihomo" if asset == binary else asset.name),
                        )
                    shutil.copy2(
                        Path(__file__).with_name("container_restart_peer.py"),
                        directories["server"] / "restart.py",
                    )
                shutil.copy2(
                    Path(__file__).with_name("container_udp_origin.py"),
                    directories["origin"] / "origin.py",
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
                                *(
                                    [
                                        "env",
                                        "VCORE_ISOLATED_ORIGIN=1",
                                        "python",
                                        "-B",
                                        "/data/fixture/restart.py",
                                    ]
                                    if checks == "paths"
                                    else []
                                ),
                                "/data/fixture/mihomo",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ],
                        )
                        upstream = (
                            lab.start(
                                stack,
                                directories["upstream"],
                                "upstream",
                                [
                                    "/data/fixture/mihomo",
                                    "-d",
                                    "/data",
                                    "-f",
                                    "/data/fixture/config.json",
                                ],
                            )
                            if checks in {"paths", "negative"}
                            else None
                        )
                        report["peer"]["version"] = command(
                            "exec", server.name, "/data/fixture/mihomo", "-v"
                        ).strip()
                        if (
                            command(
                                "exec", server.name, "sha256sum", "/data/fixture/mihomo"
                            ).split()[0]
                            != report["peer"]["binary_sha256"]
                        ):
                            raise RuntimeError("TUIC peer binary identity mismatch")
                        case = next(
                            c for c in CASES if c.identifier == "tuic-v5-native"
                        )
                        node, listener = peer_configuration(
                            case,
                            server=server.ipv4,
                            cover="",
                            port=23000,
                            certificate=cert,
                        )
                        node["name"] = "peer"
                        rows = list(inputs(node, listener, checks))
                        if selected is not None:
                            if len(set(selected)) != len(selected) or not set(
                                selected
                            ) <= {r[0] for r in rows}:
                                raise ValueError("unknown or repeated TUIC case")
                            rows = [r for r in rows if r[0] in selected]
                        if not rows:
                            raise ValueError("empty TUIC selection")
                        upstreams = (
                            {
                                r[0]: upstream_pair(
                                    r[0], dict(r[1], server=upstream.ipv4), cert, i
                                )
                                for i, r in enumerate(rows)
                                if checks == "paths" or r[0].startswith("socks5-")
                            }
                            if checks in {"paths", "negative"}
                            else {}
                        )
                        if checks == "negative":
                            for client, peer in upstreams.values():
                                client["udp"] = peer["udp"] = False
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
                            )
                        )
                        if upstream is not None:
                            (directories["upstream"] / "config.json").write_text(
                                json.dumps(
                                    {
                                        "socks-port": 23999,
                                        "allow-lan": True,
                                        "bind-address": "*",
                                        "ipv6": True,
                                        "log-level": "warning",
                                        "listeners": [r[1] for r in upstreams.values()],
                                        "rules": ["MATCH,DIRECT"],
                                    }
                                )
                            )
                            if (
                                command(
                                    "exec",
                                    upstream.name,
                                    "sha256sum",
                                    "/data/fixture/mihomo",
                                ).split()[0]
                                != report["peer"]["binary_sha256"]
                                or command(
                                    "exec", upstream.name, "/data/fixture/mihomo", "-v"
                                ).strip()
                                != report["peer"]["version"]
                            ):
                                raise RuntimeError("TUIC upstream identity mismatch")
                            upstream.release()
                            upstream.wait_tcp(23999)
                        origin.release()
                        origin.wait_tcp(24000)
                        checked = run_command(
                            [
                                "container",
                                "exec",
                                server.name,
                                "/data/fixture/mihomo",
                                "-t",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ],
                            timeout=30,
                        )
                        (output / "peer-config.log").write_text(
                            redact(checked.stdout.decode(errors="replace"))
                        )
                        if checked.returncode or not checked.cleanup:
                            raise RuntimeError(
                                "TUIC isolated peer configuration rejected"
                            )
                        server.release()
                        server.wait_tcp(23999)
                        if checks == "paths":
                            server.wait_tcp(23998)
                        for name, node, _, consumer in rows:
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
                                        **(
                                            dict(upstream=upstreams[name][0])
                                            if name in upstreams
                                            else {}
                                        ),
                                        **(
                                            dict(restart_control=f"{server.ipv4}:23998")
                                            if checks == "paths"
                                            else {}
                                        ),
                                    )
                                )
                            )
                            observations = output / (name + "-observations.json")
                            events = output / (name + "-events.jsonl")
                            argv = rust_command("vless_public", "tuic::" + consumer)
                            result = run_command(
                                argv,
                                cwd=CORE_DIR,
                                timeout=240,
                                env=dict(
                                    os.environ,
                                    VCORE_VLESS_INPUT=str(fixture),
                                    VCORE_TUIC_OBSERVATIONS=str(observations),
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
                            from .protocol_evidence import read_events
                            from .protocol_hysteria2_catalog import assertions_pass

                            good = (
                                result.returncode == 0
                                and result.cleanup
                                and observed == expected_observation(consumer)
                                and assertions_pass(
                                    read_events(events), {("TUIC-PUBLIC", consumer): 1}
                                )
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
                                raise RuntimeError("TUIC public consumer failed")
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
        raise RuntimeError("TUIC source or cleanup failed")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--checks", choices=("tcp", "policy", "udp", "paths", "negative"), default="tcp"
    )
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    run(args.output, checks=args.checks, selected=args.case)
