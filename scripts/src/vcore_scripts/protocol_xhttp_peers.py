"""N0-F native XHTTP/mux capability probes, not VCore N5 acceptance.

Official clients, servers and origins run in owned containers. The host only
drives SOCKS clients and observes the origin. Direct and layered native decoder
topologies have separate results; a layered pass never overwrites a direct fail.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import socket
import struct
import tempfile
import time
from pathlib import Path

from .builds import CORE_DIR
from .container_close_client import exact
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .native_release import PeerArtifact, download_native
from .protocol_containers import ContainerLab, command, listing
from .protocol_inputs import redact, source_identity
from .protocol_streams import certificates
from .protocol_trojan import certificate_chain
from .protocol_vless_security import client_identities

CLIENT_ID = "07070707-0707-0707-0707-070707070707"


def peer_config(kind, cert, key, *, decoder=None, plain=False):
    if kind == "M":
        listener = dict(
            name="xhttp",
            type="vless",
            listen="::",
            port=23000,
            users=[dict(uuid=CLIENT_ID)],
            **{"xhttp-config": dict(path="/n5", mode="auto")},
        )
        if plain:
            listener["allow-insecure"] = True
        else:
            listener.update(certificate=cert, **{"private-key": key})
        return dict(
            ipv6=True,
            **{"log-level": "warning"},
            listeners=[listener],
            rules=["MATCH,DIRECT"],
        )
    inbound = dict(
        listen="::",
        port=23000,
        protocol="vless",
        settings=dict(clients=[dict(id=CLIENT_ID)], decryption="none"),
        streamSettings=dict(
            network="xhttp",
            security="tls",
            tlsSettings=dict(
                alpn=["h3"], certificates=[dict(certificateFile=cert, keyFile=key)]
            ),
            xhttpSettings=dict(path="/n5", mode="auto"),
        ),
    )
    if decoder:
        # The same Xray XHTTP handler owns both legs. It forwards the resulting
        # byte stream to a real Mihomo VLESS decoder, without parsing its bytes.
        inbound.update(
            protocol="dokodemo-door",
            settings=dict(address=decoder, port=23001, network="tcp"),
        )
    return dict(
        log=dict(loglevel="warning"),
        inbounds=[inbound],
        outbounds=[dict(protocol="freedom")],
    )


def client_config(
    server, pin, version, mode, *, download=False, mux=None, codec="xudp", plain=False
):
    node = dict(
        name="probe",
        type="vless",
        server=server,
        port=23000,
        uuid=CLIENT_ID,
        tls=not plain,
        udp=True,
        network="xhttp",
        servername="localhost",
        alpn=["http/1.1" if version == "h1" else version],
        **{"packet-encoding": codec, "xhttp-opts": dict(path="/n5", mode=mode)},
    )
    if not plain:
        node["fingerprint"] = pin
    if download:
        node["xhttp-opts"]["download-settings"] = {}
    if mux:
        node["smux"] = dict(enabled=True, protocol=mux)
    return dict(
        ipv6=True,
        **{"log-level": "warning"},
        proxies=[node],
        listeners=[
            dict(
                name="consumer",
                type="socks",
                listen="::",
                port=23002,
                udp=True,
                proxy="probe",
            )
        ],
        rules=["MATCH,REJECT"],
    )


def identity_peer_config(kind, cert, key, ca):
    config = peer_config(kind, cert, key)
    if kind == "M":
        config["listeners"][0].update(
            {"client-auth-type": "require-and-verify", "client-auth-cert": ca}
        )
    else:
        # Xray's published verify usage adds RootCAs; it is NOT client auth.
        # This probe checks whether a client identity is actually enforced,
        # without inventing an unsupported client-auth option for that peer.
        tls = config["inbounds"][0]["streamSettings"]["tlsSettings"]
        tls["certificates"].append(dict(certificateFile=ca, usage="verify"))
    return config


def variants():
    for mode in ("packet-up", "stream-up", "stream-one"):
        yield dict(name=mode, mode=mode)
        if mode != "stream-one":
            yield dict(name=mode + "-download", mode=mode, download=True)
    yield dict(name="packetaddr", mode="packet-up", codec="packetaddr")
    for mux in ("h2mux", "smux", "yamux"):
        yield dict(name=mux, mode="packet-up", mux=mux)


def socks(proxy, port, command_id, target, target_port):
    connection = socket.create_connection((proxy, port), timeout=5)
    try:
        connection.sendall(b"\x05\x01\x00")
        if exact(connection, 2) != b"\x05\x00":
            raise ValueError("SOCKS greeting rejected")
        connection.sendall(
            bytes([5, command_id, 0, 1])
            + socket.inet_aton(target)
            + struct.pack("!H", target_port)
        )
        reply = exact(connection, 4)
        if reply[:3] != b"\x05\x00\x00" or reply[3] != 1:
            raise ValueError("SOCKS request rejected")
        address = socket.inet_ntoa(exact(connection, 4))
        relay_port = struct.unpack("!H", exact(connection, 2))[0]
        return connection, (proxy if address == "0.0.0.0" else address, relay_port)
    except BaseException:
        connection.close()
        raise


def exercise(proxy, port, origin, *, udp=False):
    """One small positive data probe; no retry, no full stage coverage claim."""
    payload = b"n5-native-decoder-probe" * 3
    with socket.create_connection((origin, 24000), timeout=5) as control:
        control.sendall(b"\x04" if udp else b"\x0d")
        target_port = struct.unpack("!H", exact(control, 2))[0]
        connection, relay = socks(
            proxy,
            port,
            3 if udp else 1,
            "0.0.0.0" if udp else origin,
            0 if udp else target_port,
        )
        with connection:
            if not udp:
                connection.sendall(payload)
                if (
                    exact(connection, len(payload)) != payload
                    or exact(control, 1) != b"A"
                ):
                    raise ValueError("native TCP mismatch")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                    datagram.settimeout(5)
                    datagram.bind(("0.0.0.0", 0))
                    address = (
                        b"\x01"
                        + socket.inet_aton(origin)
                        + struct.pack("!H", target_port)
                    )
                    datagram.sendto(b"\x00\x00\x00" + address + payload, relay)
                    reply, source = datagram.recvfrom(2048)
                    if source != relay or reply != b"\x00\x00\x00" + address + payload:
                        raise ValueError("native UDP mismatch")
                    observed = exact(control, 4)
                    length = struct.unpack("!H", observed[:2])[0]
                    if length != len(payload) or exact(control, length) != payload:
                        raise ValueError("native origin mismatch")
    return dict(bytes=len(payload), exact_echo=True, origin_observed=True)


def run(output: Path, *, identities_only=False):
    output = output.resolve()
    if output.parent != (CORE_DIR / "target/interop/runs").resolve():
        raise ValueError(
            "native probe output must be a fresh target/interop/runs child"
        )
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="N0-F",
        purpose="N5-H3-client-identity-prerequisite"
        if identities_only
        else "N5-native-prerequisites",
        vcore_acceptance=False,
        source=source_identity(),
        status="NOT RUN",
        cases=[],
        peers={},
        isolation={},
    )
    try:
        artifacts = {}
        for kind in ("M", "XR"):
            directory = output / "binaries" / kind
            if kind == "M":
                identity = {}
                artifacts[kind] = PeerArtifact(
                    download_mihomo(
                        "linux-arm64", directory=directory, identity=identity
                    ),
                    identity,
                )
            else:
                artifacts[kind] = download_native(
                    kind, directory, "linux-arm64", defer_version=True
                )
            report["peers"][kind] = artifacts[kind].identity
        # Go QUIC peers send 1280-byte Initial UDP payloads. A 1280-byte guest
        # L3 interface cannot carry those plus IP/UDP headers. This changes only
        # these disposable guests, never the shared network or host interface.
        lab = ContainerLab(report["isolation"], mtu=1500)
        with (
            tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
            contextlib.ExitStack() as stack,
        ):
            root = Path(temporary)
            origin_dir = root / "origin"
            origin_dir.mkdir()
            shutil.copyfile(
                Path(__file__).with_name("container_udp_origin.py"),
                origin_dir / "origin.py",
            )
            origin = lab.start(
                stack,
                origin_dir,
                "n5-origin",
                [
                    "env",
                    "VCORE_ISOLATED_ORIGIN=1",
                    "python",
                    "-B",
                    "/data/fixture/origin.py",
                ],
            )
            origin.release()
            origin.wait_tcp(24000)
            decoder_dir = root / "decoder"
            decoder_dir.mkdir()
            shutil.copy2(artifacts["M"].binary, decoder_dir / "peer")
            (decoder_dir / "config.json").write_text(
                json.dumps(
                    dict(
                        ipv6=True,
                        **{"log-level": "warning"},
                        listeners=[
                            dict(
                                name="decoder",
                                type="vless",
                                listen="::",
                                port=23001,
                                users=[dict(uuid=CLIENT_ID)],
                                **{"allow-insecure": True},
                            )
                        ],
                        rules=["MATCH,DIRECT"],
                    )
                )
            )
            decoder = lab.start(
                stack,
                decoder_dir,
                "n5-decoder",
                [
                    "/data/fixture/peer",
                    "-d",
                    "/data",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )
            decoder.release()
            decoder.wait_tcp(23001)
            groups = (
                ("M", "h1", True, False),
                ("M", "h2", True, False),
                ("M", "h1", False, False),
                ("M", "h2", False, False),
                ("XR", "h3", False, False),
                ("XR", "h3", False, True),
            )
            if identities_only:
                groups = (("M", "h2", False, False), ("XR", "h3", False, False))
            for kind, version, plain, layered in groups:
                security = "plain" if plain else "tls"
                topology = "layered" if layered else "direct"
                label = f"{kind}-{version}-{security}-{topology}"
                with contextlib.ExitStack() as group:
                    server_dir, client_dir = (
                        root / (label + "-server"),
                        root / (label + "-client"),
                    )
                    server_dir.mkdir()
                    client_dir.mkdir()

                    def preserve_logs(
                        server_dir=server_dir, client_dir=client_dir, label=label
                    ):
                        for role, directory in (
                            ("server", server_dir),
                            ("client", client_dir),
                        ):
                            log = directory / "peer.log"
                            if log.exists():
                                (output / f"{label}-{role}.log").write_text(
                                    redact(log.read_text(errors="replace"))
                                )

                    # Runs after peer stop/join, before temporary keys/configs
                    # are removed. No credentials or configs are copied out.
                    group.callback(preserve_logs)
                    shutil.copy2(artifacts[kind].binary, server_dir / "peer")
                    shutil.copy2(artifacts["M"].binary, client_dir / "peer")
                    cert, key, pin = (
                        certificate_chain(server_dir)
                        if identities_only
                        else certificates(server_dir)
                    )
                    config = peer_config(
                        kind,
                        "/data/fixture/" + cert.name,
                        "/data/fixture/" + key.name,
                        decoder=decoder.ipv4 if layered else None,
                        plain=plain,
                    )
                    identities = {}
                    if identities_only:
                        identities = client_identities(server_dir)
                        identities["absent"] = {"certificate": "", "private-key": ""}
                        config = identity_peer_config(
                            kind,
                            "/data/fixture/" + cert.name,
                            "/data/fixture/" + key.name,
                            "/data/fixture/root.pem",
                        )
                    (server_dir / "config.json").write_text(json.dumps(config))
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
                    server = lab.start(group, server_dir, label + "-server", argv)
                    version_text = command(
                        "exec",
                        server.name,
                        "/data/fixture/peer",
                        "-v" if kind == "M" else "version",
                    ).strip()
                    report["peers"][kind]["version"] = version_text
                    # One immutable client config gives every variant its own
                    # listener, node and pool; no API mutation or NAT-key reuse.
                    clients = dict(
                        ipv6=True,
                        **{"log-level": "warning"},
                        proxies=[],
                        listeners=[],
                        rules=["MATCH,REJECT"],
                    )
                    selected = list(variants())
                    if identities_only:
                        selected = [
                            dict(name=name, mode="packet-up", download=True)
                            for name in ("valid", "absent", "expired", "wrong-ca")
                        ]
                    for index, variant in enumerate(selected):
                        kwargs = {k: v for k, v in variant.items() if k != "name"}
                        client = client_config(
                            server.ipv4, pin, version, plain=plain, **kwargs
                        )
                        node, listener = client["proxies"][0], client["listeners"][0]
                        if identities_only:
                            node.update(identities["valid"])
                            node["xhttp-opts"]["download-settings"].update(
                                identities[variant["name"]]
                            )
                        node["name"] = listener["name"] = listener["proxy"] = variant[
                            "name"
                        ]
                        listener["port"] = 23100 + index
                        clients["proxies"].append(node)
                        clients["listeners"].append(listener)
                    (client_dir / "config.json").write_text(json.dumps(clients))
                    client = lab.start(
                        group,
                        client_dir,
                        label + "-client",
                        [
                            "/data/fixture/peer",
                            "-d",
                            "/data",
                            "-f",
                            "/data/fixture/config.json",
                        ],
                    )
                    server.release()
                    client.release()
                    if kind == "M":
                        server.wait_tcp(23000)
                    client.wait_tcp(23100)
                    for index, variant in enumerate(selected):
                        for udp in (False,) if identities_only else (False, True):
                            business = "udp" if udp else "tcp"
                            case = dict(
                                id=f"{label}-{variant['name']}-{business}",
                                topology="Xray-XHTTP-to-Mihomo-VLESS"
                                if layered
                                else "single-native-handler",
                                status="FAIL",
                            )
                            started = time.monotonic()
                            should_connect = (
                                not identities_only or variant["name"] == "valid"
                            )
                            case["expected_data_connected"] = should_connect
                            try:
                                case.update(
                                    exercise(
                                        client.ipv4, 23100 + index, origin.ipv4, udp=udp
                                    ),
                                    data_connected=True,
                                    status="PASS" if should_connect else "FAIL",
                                )
                                if not should_connect:
                                    case["failure_kind"] = "ClientIdentityNotEnforced"
                            except (OSError, ValueError) as error:
                                case["failure_kind"] = type(error).__name__
                                case["data_connected"] = False
                                # A rejected exchange alone is only a peer
                                # prerequisite observation, not an N5 negative
                                # gate proving zero business bytes/resources.
                                if not should_connect:
                                    case["status"] = "PASS"
                            case["seconds"] = round(time.monotonic() - started, 3)
                            report["cases"].append(case)
                            print(case["id"], case["status"], flush=True)
                            (output / "result.json").write_text(
                                json.dumps(report, indent=2) + "\n"
                            )
                    server.ensure_alive()
                    client.ensure_alive()
        report["status"] = (
            "PASS"
            if all(case["status"] == "PASS" for case in report["cases"])
            else "FAIL"
        )
    except BaseException as error:
        report["status"] = "FAIL"
        report["failure_kind"] = type(error).__name__
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
