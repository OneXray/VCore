"""Isolated xcaddy H3/mTLS -> one native Xray XHTTP handler probe.

Native comparator evidence only: this never claims VCore N5 acceptance.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import select
import shutil
import socket
import struct
import tempfile
import time
from pathlib import Path

from .builds import CORE_DIR
from .caddy_build import build_caddy
from .container_close_client import exact
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .native_release import PeerArtifact, download_native
from .protocol_containers import ContainerLab, command, listing
from .protocol_fixtures import certificate_chain
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_vless_security import client_identities
from .protocol_xhttp_peers import client_config, exercise, peer_config, socks


def sanitized_gateway_log(text):
    """Keep native protocol evidence, not HTTP headers, identities or destinations."""
    entries = []
    events = {
        "aborting with incomplete response": "response_canceled",
        "strict SNI-Host enforcement": "strict_sni_host",
        "admin endpoint disabled": "admin_disabled",
        "unable to create folder for config autosave": "autosave_failed",
        "unable to get instance ID": "storage_id_failed",
    }
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            entries.append({"event": "non_json_log", "omitted": True})
            continue
        message = row.get("msg", "")
        entry = {
            "level": row.get("level"),
            "event": next(
                (name for pattern, name in events.items() if pattern in message),
                "other_native_event",
            ),
        }
        request = row.get("request", {})
        if request:
            entry.update(
                http_version=request.get("proto"),
                alpn=request.get("tls", {}).get("proto"),
                client_certificate_present=bool(
                    request.get("tls", {}).get("client_common_name")
                ),
            )
        entries.append(entry)
    return "".join(json.dumps(entry) + "\n" for entry in entries)


def gateway_config(upstream):
    address = ipaddress.ip_address(upstream)
    authority = f"[{address}]" if address.version == 6 else str(address)
    return {
        "admin": {"disabled": True},
        "storage": {"module": "file_system", "root": "/data/caddy"},
        "logging": {"logs": {"default": {"level": "WARN"}}},
        "apps": {
            "tls": {
                "certificates": {
                    "load_files": [
                        {
                            "certificate": "/data/fixture/cert.pem",
                            "key": "/data/fixture/key.pem",
                        }
                    ]
                }
            },
            "http": {
                "servers": {
                    "fixture": {
                        "listen": [":23000"],
                        "protocols": ["h3"],
                        "automatic_https": {"disable": True},
                        "tls_connection_policies": [
                            {
                                "client_authentication": {
                                    "mode": "require_and_verify",
                                    "ca": {
                                        "provider": "file",
                                        "pem_files": ["/data/fixture/root.pem"],
                                    },
                                }
                            }
                        ],
                        "routes": [
                            {
                                "handle": [
                                    {
                                        "handler": "reverse_proxy",
                                        "upstreams": [{"dial": f"{authority}:23000"}],
                                        "transport": {
                                            "protocol": "http",
                                            "versions": ["h2c"],
                                            "compression": False,
                                        },
                                    }
                                ]
                            }
                        ],
                    }
                }
            },
        },
    }


def cases(*, identities_only=False):
    for mode in ("packet-up", "stream-up", "stream-one"):
        for split in (False, True) if mode != "stream-one" else (False,):
            prefix = mode + ("-download" if split else "")
            checks = (
                ("echo",)
                if identities_only
                else ("echo", "bulk-server-first", "close", "udp")
            )
            for check in checks:
                yield dict(id=f"{prefix}-{check}", mode=mode, split=split, check=check)
            if split or identities_only:
                for leg in ("upload", "download") if split else ("shared",):
                    for identity in ("absent", "expired", "wrong-ca"):
                        yield dict(
                            id=f"{prefix}-{leg}-{identity}",
                            mode=mode,
                            split=split,
                            check="reject",
                            leg=leg,
                            identity=identity,
                        )


def native_config():
    config = peer_config("XR", "unused", "unused")
    stream = config["inbounds"][0]["streamSettings"]
    stream["security"] = "none"
    del stream["tlsSettings"]
    # This ONE handler owns the upload and download session table. Caddy does
    # not decode XHTTP or VLESS; h2c avoids H1 full-duplex/buffering differences.
    return config


def stream_check(proxy, port, origin, *, bulk):
    with socket.create_connection((origin, 24000), timeout=15) as control:
        control.sendall(b"\x0a" if bulk else b"\x0b")
        target = struct.unpack("!H", exact(control, 2))[0]
        stream, _ = socks(proxy, port, 1, origin, target)
        with stream:
            stream.settimeout(15)
            if exact(stream, 5) != b"hello":
                raise ValueError("missing native server-first data")
            size = 10 * 1024 * 1024 if bulk else 4
            payload = b"\x5a" * size if bulk else b"ping"
            stream.sendall(payload)
            observed = hashlib.sha256()
            remaining = size
            while remaining:
                data = exact(stream, min(65536, remaining))
                observed.update(data)
                remaining -= len(data)
            expected = hashlib.sha256(payload).hexdigest()
            if observed.hexdigest() != expected:
                raise ValueError("gateway data mismatch")
            if bulk and exact(stream, 7) != b"trailer":
                raise ValueError("missing complete native reply")
            stream.settimeout(5)
            started = time.monotonic()
            stream.shutdown(socket.SHUT_WR)
            tail = bytearray()
            try:
                while data := stream.recv(1024):
                    tail.extend(data)
                    if len(tail) > 1024:
                        raise ValueError("gateway close exceeded response bound")
            except ConnectionResetError:
                pass
            control.settimeout(5)
            if exact(control, 2) != b"AD":
                raise ValueError("native origin did not finish")
            return dict(
                bytes_each_way=size,
                sha256=expected,
                server_first=True,
                closed=True,
                close_seconds=round(time.monotonic() - started, 3),
                tail_after_upload_eof=len(tail),
                origin_finished=True,
            )


def rejected_identity(proxy, port, origin):
    with socket.create_connection((origin, 24000), timeout=5) as control:
        control.sendall(b"\x0c")
        target = struct.unpack("!H", exact(control, 2))[0]
        connected = False
        outcome = "closed"
        try:
            stream, _ = socks(proxy, port, 1, origin, target)
            with stream:
                stream.sendall(b"synthetic-probe")
                connected = exact(stream, 2) == b"ok"
        except TimeoutError:
            outcome = "timeout"  # Never infer rejection from a blackhole.
        except (OSError, ValueError):
            pass
        ready, _, _ = select.select([control], [], [], 0.3)
        return dict(
            rejected=not connected and not ready and outcome == "closed",
            data_exchanged=connected,
            origin_accepted=bool(ready),
            client_outcome=outcome,
            quiet_seconds=0.3,
        )


def run(output: Path, *, identities_only=False):
    output = output.resolve()
    if output.parent != (CORE_DIR / "target/interop/runs").resolve():
        raise ValueError("gateway output must be a fresh target/interop/runs child")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="N0-F",
        purpose="N5-xcaddy-H3-mTLS-prerequisite",
        vcore_acceptance=False,
        identities_only=identities_only,
        source=source_identity(),
        status="NOT RUN",
        phase="build",
        cases=[],
        peers={},
        isolation={},
        topology=(
            "Mihomo-H3-client -> Caddy-H3-mTLS -> one-Xray-h2c-XHTTP-handler -> origin"
        ),
    )
    try:
        built = build_caddy(output / "binaries/Caddy")
        report["phase"] = "download"
        identity = {}
        mihomo = PeerArtifact(
            download_mihomo(
                "linux-arm64",
                directory=output / "binaries/M",
                identity=identity,
            ),
            identity,
        )
        xray = download_native(
            "XR", output / "binaries/XR", "linux-arm64", defer_version=True
        )
        artifacts = {"Caddy": built, "M": mihomo, "XR": xray}
        report["peers"] = {
            kind: artifact.identity for kind, artifact in artifacts.items()
        }
        lab = ContainerLab(report["isolation"], mtu=1500)
        report["phase"] = "start"
        with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary:
            root = Path(temporary)
            directories = {
                role: root / role for role in ("origin", "gateway", "server", "client")
            }
            for directory in directories.values():
                directory.mkdir()
            origin_dir, gateway_dir, server_dir, client_dir = directories.values()
            shutil.copyfile(
                Path(__file__).with_name("container_udp_origin.py"),
                origin_dir / "origin.py",
            )
            shutil.copyfile(
                Path(__file__).with_name("container_quic_observer.py"),
                gateway_dir / "observe.py",
            )
            for role, artifact in (
                ("gateway", built),
                ("server", xray),
                ("client", mihomo),
            ):
                shutil.copyfile(artifact.binary, directories[role] / "peer")
                (directories[role] / "peer").chmod(0o755)
            _, _, pin = certificate_chain(gateway_dir)
            identities = client_identities(gateway_dir)
            identities["absent"] = {"certificate": "", "private-key": ""}
            second = root / "second-identity"
            second.mkdir()
            for name in ("root.pem", "root-key.pem"):
                shutil.copyfile(gateway_dir / name, second / name)
            download_identity = client_identities(second)["valid"]
            (server_dir / "config.json").write_text(json.dumps(native_config()))
            with contextlib.ExitStack() as stack:
                origin = lab.start(
                    stack,
                    origin_dir,
                    "n5-gateway-origin",
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
                    server_dir,
                    "n5-gateway-xray",
                    [
                        "/data/fixture/peer",
                        "run",
                        "-c",
                        "/data/fixture/config.json",
                    ],
                )
                (gateway_dir / "config.json").write_text(
                    json.dumps(gateway_config(server.ipv4))
                )
                gateway = lab.start(
                    stack,
                    gateway_dir,
                    "n5-gateway-caddy",
                    [
                        "env",
                        "XDG_CONFIG_HOME=/data/config",
                        "XDG_DATA_HOME=/data/share",
                        *(["QLOGDIR=/data/qlog"] if identities_only else []),
                        "/data/fixture/peer",
                        "run",
                        "--config",
                        "/data/fixture/config.json",
                    ],
                )
                selected = list(cases(identities_only=identities_only))
                config = dict(
                    ipv6=True,
                    **{"log-level": "warning"},
                    proxies=[],
                    listeners=[],
                    rules=["MATCH,REJECT"],
                )
                for index, case in enumerate(selected):
                    candidate = client_config(
                        gateway.ipv4, pin, "h3", case["mode"], download=case["split"]
                    )
                    node, listener = candidate["proxies"][0], candidate["listeners"][0]
                    node.update(identities["valid"])
                    node["xhttp-opts"]["host"] = "localhost"
                    if case["split"]:
                        node["xhttp-opts"]["download-settings"].update(
                            download_identity
                        )
                    if case["check"] == "reject":
                        target = (
                            node
                            if case["leg"] in ("upload", "shared")
                            else node["xhttp-opts"]["download-settings"]
                        )
                        target.update(identities[case["identity"]])
                    node["name"] = listener["name"] = listener["proxy"] = case["id"]
                    listener["port"] = 23100 + index
                    config["proxies"].append(node)
                    config["listeners"].append(listener)
                (client_dir / "config.json").write_text(json.dumps(config))
                client = lab.start(
                    stack,
                    client_dir,
                    "n5-gateway-mihomo",
                    [
                        "/data/fixture/peer",
                        "-d",
                        "/data",
                        "-f",
                        "/data/fixture/config.json",
                    ],
                )

                def preserve_logs():
                    # Snapshot before deletion, independent of log-follow buffering.
                    for role, peer in (
                        ("gateway", gateway),
                        ("server", server),
                        ("client", client),
                    ):
                        (output / f"{role}.log").write_text(
                            sanitized_gateway_log(command("logs", peer.name))
                            if role == "gateway"
                            else redact(command("logs", peer.name))
                        )

                stack.callback(preserve_logs)
                for kind, peer in (("Caddy", gateway), ("XR", server), ("M", client)):
                    version = command(
                        "exec",
                        peer.name,
                        "/data/fixture/peer",
                        "-v" if kind == "M" else "version",
                    ).strip()
                    digest = command(
                        "exec", peer.name, "sha256sum", "/data/fixture/peer"
                    ).split()[0]
                    if not version or digest != report["peers"][kind]["binary_sha256"]:
                        raise RuntimeError("container binary identity mismatch")
                    if kind == "Caddy" and not version.startswith(
                        report["peers"][kind]["release"] + " "
                    ):
                        raise RuntimeError(
                            "container Caddy version differs from latest source build"
                        )
                    report["peers"][kind]["version"] = version
                validation = run_command(
                    [
                        "container",
                        "exec",
                        gateway.name,
                        "env",
                        "XDG_CONFIG_HOME=/data/config",
                        "XDG_DATA_HOME=/data/share",
                        "/data/fixture/peer",
                        "validate",
                        "--config",
                        "/data/fixture/config.json",
                    ],
                    timeout=30,
                    limit=65536,
                )
                (output / "gateway-validation.log").write_text(
                    redact(validation.stdout.decode(errors="replace"))
                )
                if validation.returncode or not validation.cleanup:
                    raise RuntimeError("native Caddy configuration validation failed")
                for peer in (origin, server, gateway, client):
                    peer.release()
                origin.wait_tcp(24000)
                server.wait_tcp(23000)
                client.wait_tcp(23100)
                report["phase"] = "traffic"

                def trace_snapshot():
                    return json.loads(
                        command(
                            "exec",
                            gateway.name,
                            "python",
                            "-B",
                            "/data/fixture/observe.py",
                        )
                    )

                for index, case in enumerate(selected):
                    result = dict(case, status="FAIL")
                    before = trace_snapshot() if identities_only else {}
                    started = time.monotonic()
                    try:
                        check = case["check"]
                        args = (client.ipv4, 23100 + index, origin.ipv4)
                        observation = (
                            rejected_identity(*args)
                            if check == "reject"
                            else stream_check(*args, bulk=check == "bulk-server-first")
                            if check in ("bulk-server-first", "close")
                            else exercise(*args, udp=check == "udp")
                        )
                        result.update(observation, status="PASS")
                        if check == "reject" and not observation["rejected"]:
                            result.update(
                                status="FAIL",
                                failure_kind=(
                                    "TimeoutError"
                                    if observation["client_outcome"] == "timeout"
                                    else "OriginAccepted"
                                ),
                            )
                    except (OSError, ValueError) as error:
                        result["failure_kind"] = type(error).__name__
                    if identities_only:
                        after = trace_snapshot()
                        result["gateway_trace_files"] = len(after)
                        result["gateway_new_trace_files"] = len(
                            after.keys() - before.keys()
                        )
                        evidence = [
                            event
                            for key, events in after.items()
                            if key not in before
                            for event in events
                        ]
                        result["gateway_certificate_errors"] = evidence
                        if case["check"] == "reject":
                            expected = {
                                "absent": "certificate_required",
                                "expired": "certificate_expired",
                                "wrong-ca": "unknown_ca",
                            }[case["identity"]]
                            result["identity_enforced"] = any(
                                event["category"] == expected for event in evidence
                            ) and (
                                result.get("origin_accepted") is False
                                and result.get("data_exchanged") is False
                            )
                            if not result["identity_enforced"]:
                                result.update(status="FAIL", evidence_missing=True)
                    result["seconds"] = round(time.monotonic() - started, 3)
                    report["cases"].append(result)
                    print(case["id"], result["status"], flush=True)
                    (output / "result.json").write_text(
                        json.dumps(report, indent=2) + "\n"
                    )
                for peer in (origin, server, gateway, client):
                    peer.ensure_alive()
        report["status"] = (
            "PASS"
            if all(case["status"] == "PASS" for case in report["cases"])
            else "FAIL"
        )
        report["phase"] = "complete"
    except BaseException as error:
        report.update(status="FAIL", failure_kind=type(error).__name__)
        raise
    finally:
        report["source_unchanged"] = report["source"] == source_identity()
        report["cleanup"] = all(
            peer.get("joined") for peer in report["isolation"].get("peers", [])
        )
        run_id = report["isolation"].get("run_id")
        report["owned_remaining"] = (
            [
                item["id"]
                for item in listing()
                if item["configuration"].get("labels", {}).get("vcore-run") == run_id
            ]
            if run_id
            else []
        )
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return (
        0
        if report["status"] == "PASS"
        and report["source_unchanged"]
        and report["cleanup"]
        and not report["owned_remaining"]
        else 1
    )


def main(output, *, identities_only=False):
    with exclusive_run():
        return run(output, identities_only=identities_only)
