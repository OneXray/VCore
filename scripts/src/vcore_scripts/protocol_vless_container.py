"""N4 wire cases against official latest peers and entirely isolated origins."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import ssl
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
from .protocol_vless_peers import configuration
from .protocol_vless_public import PUBLIC as PUBLIC_CASES
from .protocol_vless_public import WIRE as CASES
from .protocol_vless_public import events_pass
from .protocol_vless_security import client_identities
from .protocol_vmess import peer_config as legacy_peer
from .protocol_vmess_public import node_config as legacy_node

ALL_CASES = CASES | PUBLIC_CASES
CLOSE_TESTS = {
    "native_mihomo_close_alignment",
    "native_ws_reality_close_boundary",
    "native_vision_direct_close_alignment",
}
CLIENT_FINGERPRINTS = (
    "none",
    "chrome",
    "chrome120",
    "firefox",
    "firefox120",
    "safari",
    "safari16",
)


def close_reference(mode, node, config, certificate, private_key, pin):
    reference = dict(node, name="reference")
    if reference.get("network") == "ws":
        options = dict(reference.get("ws-opts", {}))
        if options.get("max-early-data", 0) > 0:
            # VCore defaults ED to this header; Mihomo's raw option defaults
            # to path ED. Explicit empty/custom values must stay unchanged.
            options.setdefault("early-data-header-name", "Sec-WebSocket-Protocol")
        reference["ws-opts"] = options
    scope = "same-mode"
    if mode.endswith("-reality") and reference.get("network") == "ws":
        # Mihomo's WS client never consumes RealityOpts. Its REALITY listener
        # does support WS, so preserve VCore's real peer and compare the WS
        # close layer with a separate TLS entrance. Never call this same-mode.
        baseline = json.loads(json.dumps(config["listeners"][0]))
        baseline.pop("reality-config")
        baseline.update(
            name="n4-ws-close-baseline",
            port=23003,
            certificate=str(certificate),
            **{"private-key": str(private_key)},
        )
        config["listeners"].append(baseline)
        reference.pop("reality-opts")
        reference.update(port=23003, fingerprint=pin)
        scope = "ws-standard-tls-baseline"
    elif mode.endswith("-reality") and reference.get("client-fingerprint") in (
        None,
        "",
        "none",
    ):
        reference["client-fingerprint"] = "chrome"
    elif (
        reference.get("jls-opts")
        and reference.get("network") == "grpc"
        and reference.get("client-fingerprint") in (None, "", "none")
    ):
        # Official Mihomo v1.19.31's gRPC ALPN reader does not recognize the
        # ordinary jls-tls ConnectionState type. uTLS JLS does work. Keep the
        # VCore node unchanged and label this different-profile close baseline.
        reference["client-fingerprint"] = "chrome"
        scope = "jls-grpc-chrome-baseline"
    return reference, scope


def run(
    output: Path,
    selected=None,
    *,
    preflight_only=False,
    client_fingerprint=None,
    encryption=None,
    jls=False,
):
    if client_fingerprint is not None and client_fingerprint not in CLIENT_FINGERPRINTS:
        raise ValueError("unsupported named client profile")
    public_cases = PUBLIC_CASES | (
        {
            "F5-ANYTLS": ("M", "anytls", True, "public_legacy_regression"),
            **{
                f"CF5-VMESS-{network.upper()}-TLS": (
                    "V2",
                    f"vmess-{network}",
                    True,
                    "public_legacy_tcp",
                )
                for network in ("http", "h2")
            },
        }
        if client_fingerprint
        else {}
    )
    all_cases = CASES | public_cases
    if encryption is not None:
        from .protocol_encryption import cases as encryption_profiles
        from .protocol_encryption_public import catalog

        if encryption not in encryption_profiles() or client_fingerprint is not None:
            raise ValueError("unsupported Encryption fixture")
        all_cases = catalog()
        public_cases = {
            key: value
            for key, value in all_cases.items()
            if not value[3].startswith("native_")
        }
    if jls:
        from .protocol_jls import catalog

        all_cases = catalog()
        public_cases = {
            key: value
            for key, value in all_cases.items()
            if not value[3].startswith("native_")
        }
    selected = list(all_cases) if selected is None else selected
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not set(selected) <= all_cases.keys()
    ):
        raise ValueError("invalid N4 native selection")
    if client_fingerprint and any(not all_cases[case][2] for case in selected):
        raise ValueError("named client profiles require TLS cases")
    output.mkdir(parents=True, exist_ok=False)
    if preflight_only:
        # One listener/origin group per official implementation, not a traffic run.
        kinds = {all_cases[case][0] for case in selected}
        selected = [
            next(case for case in selected if all_cases[case][0] == kind)
            for kind in sorted(kinds)
        ]
    report = dict(
        stage="N7.4-JLS"
        if jls
        else "N7.1"
        if encryption
        else "F5"
        if client_fingerprint
        else "N4",
        jls=jls,
        encryption_profile=encryption,
        client_fingerprint=client_fingerprint,
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
        for kind in sorted({all_cases[case][0] for case in selected} | {"M"}):
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
        lab = ContainerLab(report["isolation"], mtu=1500 if encryption or jls else 1280)
        report["phase"] = "build"
        built = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "vless_native",
                "--test",
                "vless_public",
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
            kind, mode, encrypted, test = all_cases[case]
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
                    shutil.copyfile(
                        Path(__file__).with_name("container_close_client.py"),
                        origin_dir / "close.py",
                    )
                    shutil.copyfile(
                        Path(__file__).with_name("container_tls_bio.py"),
                        origin_dir / "tls_bio.py",
                    )
                    artifact = artifacts[kind]
                    shutil.copy2(artifact.binary, server_dir / "peer")
                    tag = f"{mode}-{'tls' if encrypted else 'plain'}"
                    origin_cert, origin_key, origin_pin = certificates(origin_dir)
                    origin = lab.start(
                        stack,
                        origin_dir,
                        tag + "-origin",
                        [
                            "env",
                            "VCORE_ISOLATED_ORIGIN=1",
                            f"VCORE_ORIGIN_CERT=/data/fixture/{origin_cert.name}",
                            f"VCORE_ORIGIN_KEY=/data/fixture/{origin_key.name}",
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

                    def retain_logs(origin=origin, server=server, tag=tag):
                        for role, peer in (("origin", origin), ("server", server)):
                            if peer.log.exists():
                                (output / f"{tag}-{role}.log").write_text(
                                    redact(
                                        # Capture before cleanup: live log
                                        # following may buffer short messages.
                                        command("logs", peer.name)[-65536:]
                                    )
                                )

                    stack.callback(retain_logs)
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
                    identities = {}
                    if mode == "anytls":
                        node = dict(
                            name="peer",
                            type="anytls",
                            server=server.ipv4,
                            port=23000,
                            password="fixture",
                            sni="localhost",
                            udp=True,
                            fingerprint=pin,
                        )
                        config = {
                            "listeners": [
                                {
                                    "name": "anytls",
                                    "type": "anytls",
                                    "listen": "::",
                                    "port": 23000,
                                    "users": {"fixture": "fixture"},
                                    "certificate": f"/data/fixture/{cert.name}",
                                    "private-key": f"/data/fixture/{key.name}",
                                }
                            ],
                            "ipv6": True,
                            "log-level": "silent",
                            "hosts": {"vcore-fixture.test": origin.ipv4},
                            "rules": ["MATCH,DIRECT"],
                        }
                    elif mode.startswith(("vmess-", "trojan-")):
                        legacy_mode = mode.removeprefix("vmess-")
                        node = legacy_node(legacy_mode, True, server.ipv4, pin)
                        config = legacy_peer(
                            kind,
                            legacy_mode,
                            True,
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
                    else:
                        node, config = configuration(
                            mode.removesuffix("-h1") if jls else mode,
                            server.ipv4,
                            origin.ipv4,
                            Path("/data/fixture") / cert.name,
                            Path("/data/fixture") / key.name,
                        )
                        node["name"] = "peer"
                        if encrypted and not mode.endswith("-reality"):
                            node["fingerprint"] = pin
                        if mode.endswith("-mtls"):
                            identities = client_identities(server_dir)
                            node.update(identities["valid"])
                            config["listeners"][0].update(
                                {
                                    "client-auth-type": "require-and-verify",
                                    "client-auth-cert": "/data/fixture/root.pem",
                                }
                            )
                    if client_fingerprint:
                        node["client-fingerprint"] = client_fingerprint
                    extra_fixture = {}
                    if jls:
                        from .protocol_jls import configuration as jls_config

                        extra_fixture = jls_config(node, config, origin.ipv4, mode)
                    if encryption:
                        from .protocol_encryption_public import (
                            configuration as encrypted_config,
                        )

                        encrypted_config(encryption, node, config)
                        if mode == "vision-encryption":
                            node.pop("tls", None)
                            node.pop("servername", None)
                            for listener in config["listeners"]:
                                listener.pop("certificate", None)
                                listener.pop("private-key", None)
                                listener["allow-insecure"] = True
                    reference_node = None
                    reference_scope = None
                    if any(test in CLOSE_TESTS for _, test in cases):
                        reference_node, reference_scope = close_reference(
                            mode,
                            node,
                            config,
                            Path("/data/fixture") / cert.name,
                            Path("/data/fixture") / key.name,
                            pin,
                        )
                    (server_dir / "config.json").write_text(json.dumps(config))
                    upstream = None
                    hop = None
                    if any(case in public_cases for case, _ in cases):
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
                                vision_probe=mode.startswith("vision-"),
                                flow_reject_port=23004
                                if mode.startswith("vision-")
                                else None,
                                origin_pin=origin_pin,
                                origin_root_der=list(
                                    ssl.PEM_cert_to_DER_cert(origin_cert.read_text())
                                ),
                                identities=identities,
                                root_der=list(
                                    ssl.PEM_cert_to_DER_cert(
                                        (
                                            server_dir / "root.pem"
                                            if encrypted
                                            else cert
                                        ).read_text()
                                    )
                                ),
                                hop=hop,
                                peer_kind=kind,
                                **extra_fixture,
                            )
                        )
                    )
                    origin.release()
                    server.release()
                    origin.wait_tcp(24000)
                    if mode.endswith("-reality") or jls:
                        origin.wait_tcp(24001)
                    server.wait_tcp(23000)
                    comparison = None
                    if reference_node is not None:
                        comparison_dir = root / "comparison"
                        comparison_dir.mkdir()
                        shutil.copy2(artifacts["M"].binary, comparison_dir / "peer")
                        (comparison_dir / "config.json").write_text(
                            json.dumps(
                                {
                                    "socks-port": 23002,
                                    "allow-lan": True,
                                    "bind-address": "*",
                                    "log-level": "silent",
                                    "ipv6": True,
                                    "proxies": [reference_node],
                                    "rules": ["MATCH,reference"],
                                }
                            )
                        )
                        comparison = lab.start(
                            stack,
                            comparison_dir,
                            tag + "-comparison",
                            [
                                "/data/fixture/peer",
                                "-d",
                                "/data",
                                "-f",
                                "/data/fixture/config.json",
                            ],
                        )
                        comparison.release()
                        comparison.wait_tcp(23002)
                        observed_close = run_command(
                            [
                                "container",
                                "exec",
                                origin.name,
                                "env",
                                "VCORE_ISOLATED_ORIGIN=1",
                                "python",
                                "-B",
                                "/data/fixture/close.py",
                                comparison.ipv4,
                                origin.ipv4,
                            ],
                            timeout=30,
                        )
                        (output / f"{tag}-close-command.log").write_text(
                            redact(observed_close.stdout.decode(errors="replace"))
                        )
                        if observed_close.returncode or not observed_close.cleanup:
                            raise RuntimeError("official close comparison failed")
                        reference = json.loads(observed_close.stdout)
                        reference["scope"] = reference_scope
                        reference["client_fingerprint"] = reference_node.get(
                            "client-fingerprint"
                        )
                        reference["dut_client_fingerprint"] = node.get(
                            "client-fingerprint"
                        )
                        (output / f"{tag}-close-reference.json").write_text(
                            json.dumps(reference) + "\n"
                        )
                        data = json.loads(fixture.read_text())
                        data["close_reference"] = reference
                        if any(
                            test == "native_vision_direct_close_alignment"
                            for _, test in cases
                        ):
                            direct = run_command(
                                [
                                    "container",
                                    "exec",
                                    origin.name,
                                    "env",
                                    "VCORE_ISOLATED_ORIGIN=1",
                                    "python",
                                    "-B",
                                    "/data/fixture/close.py",
                                    comparison.ipv4,
                                    origin.ipv4,
                                    "vision-direct",
                                ],
                                timeout=30,
                            )
                            (output / f"{tag}-direct-close-command.log").write_text(
                                redact(direct.stdout.decode(errors="replace"))
                            )
                            if direct.returncode or not direct.cleanup:
                                raise RuntimeError(
                                    "official direct close comparison failed"
                                )
                            direct_reference = json.loads(direct.stdout)
                            direct_reference["scope"] = reference_scope
                            (output / f"{tag}-direct-close-reference.json").write_text(
                                json.dumps(direct_reference) + "\n"
                            )
                            data["direct_close_reference"] = direct_reference
                        fixture.write_text(json.dumps(data))
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
                            "vless_public" if case in public_cases else "vless_native",
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
                                VCORE_VLESS_PEER=f"{server.ipv4}:23000",
                                VCORE_VLESS_TRANSPORT=json.dumps(
                                    dict(
                                        mode=mode,
                                        tls=encrypted,
                                        pin=pin,
                                        peer_kind=kind,
                                        udp_path_limit=15000,
                                    )
                                ),
                                VCORE_VLESS_ORIGIN_V4=origin.ipv4,
                                VCORE_VLESS_INPUT=str(fixture),
                                VCORE_CASE_EVENTS=str(events),
                                VCORE_PROTOCOL_STAGE="N7"
                                if encryption or jls
                                else "N4",
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
                                events_pass(
                                    observed,
                                    test,
                                    mode,
                                    stage="N7" if encryption or jls else "N4",
                                )
                                if case in public_cases
                                else observed
                                == [
                                    dict(
                                        schema_version=1,
                                        suite="N7-WIRE"
                                        if encryption or jls
                                        else "N4-WIRE",
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
        (output / "vless-results.json").write_text(json.dumps(report, indent=2) + "\n")
    return (
        0
        if report["status"] in {"PASS", "READY"}
        else (130 if report["status"] == "INTERRUPTED" else 1)
    )


if __name__ == "__main__":
    import sys

    from .mihomo_isolation import exclusive_run

    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:] or None))
