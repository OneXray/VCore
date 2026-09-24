"""N5 VCore upload/download security against owned native handlers.

H1/H2 use one Mihomo listener with two ports. H3 uses the approved xcaddy
gateway (two bindings, one Xray h2c handler). Neither topology invents a decoder.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import shutil
import ssl
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .caddy_build import build_caddy
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .native_release import download_native
from .protocol_containers import ContainerLab, command, listing
from .protocol_evidence import read_events
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_trojan import certificate_chain
from .protocol_vless_security import client_identities
from .protocol_xhttp_fields import events_pass
from .protocol_xhttp_gateway import gateway_config, sanitized_gateway_log
from .protocol_xhttp_peers import CLIENT_ID, peer_config


def security_cases(base, identities, download_identity, server_ipv6):
    """Frozen cases, selected before observing results. No retry or skip-on-error."""
    for mode in ("packet-up", "stream-up", "stream-one"):
        node = copy.deepcopy(base)
        options = node["xhttp-opts"]
        options["mode"] = mode
        if mode == "packet-up":
            options["sc-min-posts-interval-ms"] = "1"
        yield f"{mode}-shared", node, False, None
        for identity in ("absent", "expired", "wrong-ca"):
            invalid = copy.deepcopy(node)
            invalid.update(identities[identity])
            if identity == "absent":
                del invalid["certificate"], invalid["private-key"]
            yield f"{mode}-shared-{identity}", invalid, True, identity
        if mode == "stream-one":
            continue
        options["download-settings"] = {}
        yield f"{mode}-inherit", copy.deepcopy(node), False, None
        download = options["download-settings"]
        download.update(download_identity)
        download.update(
            server=server_ipv6,
            port=23002,
            tls=True,
            servername="localhost",
            host="localhost",
            path="/n5/",
            headers={"X-Download": "fixture"},
            **{"reuse-settings": {}, "fingerprint": "", "name-cert-verify": ""},
        )
        yield f"{mode}-replace-dualstack-port", copy.deepcopy(node), False, None
        download["server"] = "peer.fixture.test"
        yield f"{mode}-download-domain", copy.deepcopy(node), False, None
        node["servername"] = "sni.fixture.test"
        node["name-cert-verify"] = "localhost"
        if base["alpn"] != ["h3"]:
            # One native handler accepts both ALPNs; the download has its own policy.
            download["alpn"] = ["http/1.1"] if base["alpn"] == ["h2"] else ["h2"]
            yield f"{mode}-name-clear-alpn", copy.deepcopy(node), False, None
        node["servername"] = "localhost"
        del node["name-cert-verify"]
        for leg in ("upload", "download"):
            for identity in ("absent", "expired", "wrong-ca"):
                invalid = copy.deepcopy(node)
                target = (
                    invalid
                    if leg == "upload"
                    else invalid["xhttp-opts"]["download-settings"]
                )
                target.update(identities[identity])
                if identity == "absent" and leg == "upload":
                    del target["certificate"], target["private-key"]
                yield f"{mode}-{leg}-{identity}", invalid, True, identity
        for key, value in (
            ("fingerprint", "00" * 32),
            ("name-cert-verify", "wrong.fixture.test"),
        ):
            invalid = copy.deepcopy(node)
            invalid["xhttp-opts"]["download-settings"][key] = value
            yield f"{mode}-download-wrong-{key}", invalid, True, None
        invalid = copy.deepcopy(node)
        invalid["skip-cert-verify"] = True
        invalid["xhttp-opts"]["download-settings"].update(
            {"skip-cert-verify": False, "servername": "wrong.fixture.test"}
        )
        yield f"{mode}-download-false-restores-verify", invalid, True, None


def run(output: Path, versions: list[str], *, supplied: dict | None = None):
    if (
        not versions
        or len(versions) != len(set(versions))
        or not set(versions) <= {"h1", "h2", "h3"}
    ):
        raise ValueError("select unique H1/H2/H3 security versions")
    if (
        not output.is_relative_to(CORE_DIR / "target/interop/runs")
        or output == CORE_DIR / "target/interop/runs"
    ):
        raise ValueError("security output must be a fresh target/interop/runs child")
    output.mkdir(exist_ok=False)
    report = dict(
        stage="N5",
        scope="security-development-only",
        source=source_identity(),
        status="NOT RUN",
        cases=[],
        peers={},
        isolation={},
    )
    try:
        artifacts = {}
        if supplied is not None:
            for kind in ({"M"} if any(v != "h3" for v in versions) else set()) | (
                {"XR", "Caddy"} if "h3" in versions else set()
            ):
                artifacts[kind], report["peers"][kind] = supplied[kind]
        elif any(v != "h3" for v in versions):
            identity = {}
            artifacts["M"] = download_mihomo(
                "linux-arm64", directory=output / "binaries/M", identity=identity
            )
            report["peers"]["M"] = identity
        if "h3" in versions and supplied is None:
            for kind, artifact in (
                ("Caddy", build_caddy(output / "binaries/Caddy")),
                (
                    "XR",
                    download_native(
                        "XR", output / "binaries/XR", "linux-arm64", defer_version=True
                    ),
                ),
            ):
                artifacts[kind] = artifact.binary
                report["peers"][kind] = artifact.identity
        lab = ContainerLab(report["isolation"], mtu=1500)
        build = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "xhttp_native",
                "--no-run",
            ],
            timeout=180,
        )
        (output / "build.log").write_text(redact(build.stdout.decode(errors="replace")))
        if build.returncode or not build.cleanup:
            raise RuntimeError("native security driver build failed")
        groups = [
            (version, negative)
            for version in versions
            for negative in ((False, True) if version == "h3" else (None,))
        ]
        for version, negative in groups:
            with (
                tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
                contextlib.ExitStack() as stack,
            ):
                root = Path(temporary)
                directories = {
                    role: root / role for role in ("origin", "server", "gateway")
                }
                for directory in directories.values():
                    directory.mkdir()
                origin_dir, server_dir, gateway_dir = directories.values()
                shutil.copyfile(
                    Path(__file__).with_name("container_udp_origin.py"),
                    origin_dir / "origin.py",
                )
                origin = lab.start(
                    stack,
                    origin_dir,
                    version + "-origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "python",
                        "-B",
                        "/data/fixture/origin.py",
                    ],
                )
                cert_dir = gateway_dir if version == "h3" else server_dir
                cert, key, pin = certificate_chain(cert_dir)
                identities = client_identities(cert_dir)
                identities["absent"] = {"certificate": "", "private-key": ""}
                second = root / "second"
                second.mkdir()
                for filename in ("root.pem", "root-key.pem"):
                    shutil.copyfile(cert_dir / filename, second / filename)
                download_identity = client_identities(second)["valid"]
                kind = "XR" if version == "h3" else "M"
                shutil.copy2(artifacts[kind], server_dir / "peer")
                config = peer_config(
                    kind, f"/data/fixture/{cert.name}", f"/data/fixture/{key.name}"
                )
                if kind == "M":
                    config["hosts"] = {"vcore-fixture.test": origin.ipv4}
                    config["listeners"][0].update(
                        {
                            "port": "23000,23002",
                            "client-auth-type": "require-and-verify",
                            "client-auth-cert": "/data/fixture/root.pem",
                        }
                    )
                else:
                    stream = config["inbounds"][0]["streamSettings"]
                    stream["security"] = "none"
                    del stream["tlsSettings"]
                    config["dns"] = {"hosts": {"vcore-fixture.test": origin.ipv4}}
                (server_dir / "config.json").write_text(json.dumps(config))
                server = lab.start(
                    stack,
                    server_dir,
                    version + "-server",
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
                peers = [(kind, server)]
                gateway = None
                edge = server
                if version == "h3":
                    shutil.copy2(artifacts["Caddy"], gateway_dir / "peer")
                    shutil.copyfile(
                        Path(__file__).with_name("container_quic_observer.py"),
                        gateway_dir / "observe.py",
                    )
                    gateway = lab.start(
                        stack,
                        gateway_dir,
                        version + "-gateway",
                        [
                            "env",
                            "XDG_CONFIG_HOME=/data/config",
                            "XDG_DATA_HOME=/data/share",
                            *(["QLOGDIR=/data/qlog"] if negative else []),
                            "/data/fixture/peer",
                            "run",
                            "--config",
                            "/data/fixture/config.json",
                        ],
                    )
                    conf = gateway_config(server.ipv4)
                    conf["apps"]["http"]["servers"]["fixture"]["listen"].append(
                        ":23002"
                    )
                    (gateway_dir / "config.json").write_text(json.dumps(conf))
                    peers.append(("Caddy", gateway))
                    edge = gateway
                for implementation, peer in peers:
                    identity = report["peers"][implementation]
                    actual = command(
                        "exec",
                        peer.name,
                        "/data/fixture/peer",
                        "-v" if implementation == "M" else "version",
                    ).strip()
                    digest = command(
                        "exec", peer.name, "sha256sum", "/data/fixture/peer"
                    ).split()[0]
                    if not actual or digest != identity["binary_sha256"]:
                        raise RuntimeError("native security binary identity mismatch")
                    identity["version"] = actual

                def preserve_logs(peers=peers, version=version, negative=negative):
                    for implementation, peer in peers:
                        text = command("logs", peer.name)[-65536:]
                        (
                            output / f"{version}-{negative}-{implementation}.log"
                        ).write_text(
                            sanitized_gateway_log(text)
                            if implementation == "Caddy"
                            else redact(text)
                        )

                stack.callback(preserve_logs)
                origin.release()
                server.release()
                if gateway:
                    gateway.release()
                origin.wait_tcp(24000)
                server.wait_tcp(23000)
                base = dict(
                    name="peer",
                    type="vless",
                    server=edge.ipv4,
                    port=23000,
                    uuid=CLIENT_ID,
                    udp=True,
                    tls=True,
                    servername="localhost",
                    fingerprint=pin,
                    alpn=["http/1.1" if version == "h1" else version],
                    network="xhttp",
                    **identities["valid"],
                    **{
                        "xhttp-opts": {
                            "path": "/n5",
                            "host": "localhost",
                            "headers": {"X-Upload": "fixture"},
                        }
                    },
                )
                selected = [
                    case
                    for case in security_cases(
                        base, identities, download_identity, edge.ipv6
                    )
                    if negative is None or case[2] == negative
                ]

                def trace_snapshot(gateway=gateway, negative=negative):
                    return (
                        json.loads(
                            command(
                                "exec",
                                gateway.name,
                                "python",
                                "-B",
                                "/data/fixture/observe.py",
                            )
                        )
                        if gateway and negative
                        else {}
                    )

                for name, node, reject, expected_identity in selected:
                    case_id = f"{version}-{name}"
                    print(case_id, flush=True)
                    fixture = root / "input.json"
                    fixture.write_text(
                        json.dumps(
                            dict(
                                isolation="containers",
                                node=node,
                                reject=reject,
                                server_ipv4=edge.ipv4,
                                origin_control=f"{origin.ipv4}:24000",
                                origin_ipv4=origin.ipv4,
                                origin_ipv6=origin.ipv6,
                                root_der=list(
                                    ssl.PEM_cert_to_DER_cert(
                                        (cert_dir / "root.pem").read_text()
                                    )
                                ),
                            )
                        )
                    )
                    events = output / f"{case_id}-events.jsonl"
                    assertion = "security::native_xhttp_security"
                    cmd = [
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        "xhttp_native",
                        assertion,
                        "--",
                        "--exact",
                        "--ignored",
                        "--nocapture",
                    ]
                    before = trace_snapshot()
                    result = run_command(
                        cmd,
                        timeout=140,
                        env=dict(
                            os.environ,
                            VCORE_XHTTP_INPUT=str(fixture),
                            VCORE_CASE_EVENTS=str(events),
                        ),
                    )
                    (output / f"{case_id}.log").write_text(
                        redact(result.stdout.decode(errors="replace"))
                    )
                    observation = read_events(events) if events.exists() else []
                    passed = (
                        result.returncode == 0
                        and result.cleanup
                        and events_pass(observation, assertion)
                    )
                    row = dict(
                        case_id=case_id,
                        status="PASS" if passed else "FAIL",
                        command=cmd,
                        exit_code=result.returncode,
                        seconds=result.seconds,
                        command_cleanup=result.cleanup,
                        topology="Caddy H3 -> one Xray h2c handler"
                        if gateway
                        else "one Mihomo handler, two ports",
                    )
                    if gateway and negative:
                        after = trace_snapshot()
                        # QUIC trace files contain only lifecycle records at this
                        # level; retain categories, never identities or packets.
                        evidence = [
                            event
                            for key, records in after.items()
                            if key not in before
                            for event in records
                        ]
                        row["certificate_errors"] = evidence
                        if expected_identity:
                            expected = {
                                "absent": "certificate_required",
                                "expired": "certificate_expired",
                                "wrong-ca": "unknown_ca",
                            }[expected_identity]
                            row["identity_enforced"] = any(
                                e["category"] == expected for e in evidence
                            )
                            if not row["identity_enforced"]:
                                row["status"] = "FAIL"
                    report["cases"].append(row)
                    print(case_id, row["status"], flush=True)
                    if row["status"] != "PASS":
                        raise RuntimeError("native security case failed")
                for _, peer in peers:
                    peer.ensure_alive()
        report["status"] = "PASS"
    except (OSError, ValueError, RuntimeError) as error:
        report.update(
            status="FAIL",
            reason=str(error)
            if isinstance(error, RuntimeError)
            else type(error).__name__,
        )
    finally:
        report["cleanup"] = all(
            p.get("joined") for p in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = report["source"] == source_identity()
        run_id = report["isolation"].get("run_id")
        report["owned_remaining"] = (
            [
                p["id"]
                for p in listing()
                if p["configuration"].get("labels", {}).get("vcore-run") == run_id
            ]
            if run_id
            else []
        )
        if (
            not report["cleanup"]
            or not report["source_unchanged"]
            or report["owned_remaining"]
        ):
            report["status"] = "FAIL"
        (output / "xhttp-security-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("versions", nargs="+", choices=("h1", "h2", "h3"))
    args = parser.parse_args()
    with exclusive_run():
        sys.exit(run(args.output.resolve(), args.versions))
