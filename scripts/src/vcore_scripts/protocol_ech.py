"""N7 static ECH consumers against official latest isolated peers."""

from __future__ import annotations

import base64
import os
import shutil
import struct
import textwrap
from pathlib import Path

from .protocol_peers import run_command


def catalog():
    cases = {}

    def add(mode, suffix, test):
        cases[f"N7-ECH-{mode.upper()}-{suffix}"] = ("M", mode, True, test)

    modes = (
        "tcp-tls",
        "ws-tls",
        "upgrade-tls",
        "upgrade-fast-tls",
        "grpc-tls",
    ) + tuple(
        f"xhttp-{mode}{version}"
        for mode in (
            "stream-one",
            "stream-up",
            "packet-up",
            "stream-up-download",
            "packet-up-download",
        )
        for version in ("", "-h1")
    )
    for mode in modes:
        add(mode, "BASE", "public_base")
        add(mode, "CLOSE", "native_mihomo_close_alignment")
    for mode in (
        "tcp-tls",
        "ws-tls",
        "grpc-tls",
        "xhttp-stream-up-download",
        "xhttp-stream-up-download-h1",
    ):
        add(mode, "REJECT", "native_ech_fail_closed")
    for mode in modes:
        if "download" in mode:
            add(mode, "DOWNLOAD", "public_ech_download_identity")
    for mode in ("tcp-mtls", "ws-mtls", "grpc-mtls"):
        add(mode, "IDENTITY", "public_tls_identity_and_verification_name")
    for suffix, test in (
        ("GRAPH", "runtime::public_graph"),
        ("ENTRYPOINTS", "runtime::public_entrypoints"),
        ("IPV6", "runtime::public_ipv6_and_gates"),
        ("UDP-ISOLATION", "runtime::public_udp_isolation"),
    ):
        add("tcp-tls", suffix, test)
    for mode in ("grpc-tls", "xhttp-stream-up-download"):
        add(mode, "LIFE", "runtime::public_lifecycle")
        add(mode, "OWNED", "runtime::owned_resources")
    return cases


def material(directory: Path, key_id: int):
    """Generate synthetic keys with official OpenSSL, never implement crypto here."""
    openssl = next(
        (
            path
            for path in (
                os.environ.get("OPENSSL_BIN"),
                shutil.which("openssl3"),
                "/opt/homebrew/opt/openssl@3/bin/openssl",
                "/usr/local/opt/openssl@3/bin/openssl",
                shutil.which("openssl"),
            )
            if path and Path(path).is_file()
        ),
        None,
    )
    if openssl is None:
        raise RuntimeError("OpenSSL with X25519 support is required")
    private = directory / f"ech-{key_id}.der"
    generated = run_command(
        [
            openssl,
            "genpkey",
            "-algorithm",
            "X25519",
            "-outform",
            "DER",
            "-out",
            str(private),
        ],
        timeout=15,
    )
    public = run_command(
        [
            openssl,
            "pkey",
            "-inform",
            "DER",
            "-in",
            str(private),
            "-pubout",
            "-outform",
            "DER",
        ],
        timeout=15,
    )
    if any(item.returncode or not item.cleanup for item in (generated, public)):
        raise RuntimeError("synthetic ECH material generation failed")
    secret = private.read_bytes()
    if len(secret) != 48 or len(public.stdout) != 44:
        raise RuntimeError("unexpected synthetic X25519 DER encoding")
    name = b"public.invalid"
    contents = bytes([key_id]) + struct.pack("!HH", 32, 32) + public.stdout[-32:]
    contents += struct.pack("!HHHBB", 4, 1, 1, 0, len(name)) + name + b"\0\0"
    config = struct.pack("!HH", 0xFE0D, len(contents)) + contents
    key_set = (
        struct.pack("!H", 32) + secret[-32:] + struct.pack("!H", len(config)) + config
    )
    return base64.b64encode(struct.pack("!H", len(config)) + config).decode(), key_set


def configuration(node, peer, directory, mode, *, kind="M"):
    primary, first_key = material(directory, 7)
    download, second_key = material(directory, 9)
    encoded = base64.b64encode(first_key + second_key).decode()
    pem = (
        "-----BEGIN ECH KEYS-----\n"
        + "\n".join(textwrap.wrap(encoded, 64))
        + "\n-----END ECH KEYS-----\n"
    )
    (directory / "ech-keys.pem").write_text(pem)
    node["ech-opts"] = dict(enable=True, config=primary)
    if mode.endswith("-h1"):
        node["alpn"] = ["http/1.1"]
    if kind == "M":
        for listener in peer["listeners"]:
            listener["ech-key"] = "/data/fixture/ech-keys.pem"
    elif kind == "XR":
        for inbound in peer["inbounds"]:
            inbound["streamSettings"]["tlsSettings"]["echServerKeys"] = encoded
    else:
        raise ValueError("unsupported static ECH peer")
    return dict(ech_download_config=download)


def wrong_key(options):
    wire = bytearray(base64.b64decode(options["config"], validate=True))
    wire[11:43] = bytes([7]) * 32
    return dict(enable=True, config=base64.b64encode(wire).decode())


def legacy_gateway_command():
    # Xray's dokodemo-door marks its inbound splice-capable even with TLS.
    # Its default freedom response path then bypasses the TLS writer. Use
    # the upstream runtime switch only for this synthetic TLS gateway.
    return [
        "env",
        "XRAY_BUF_SPLICE=disable",
        "/data/fixture/peer",
        "run",
        "-c",
        "/data/fixture/config.json",
    ]


def legacy_gateway_config(upstream, tls_options):
    """Official Xray TLS ingress, no custom protocol server or V2Ray patches."""
    return dict(
        log={"loglevel": "warning"},
        inbounds=[
            dict(
                listen="::",
                port=23000,
                protocol="dokodemo-door",
                settings=dict(address=upstream, port=23000, network="tcp"),
                streamSettings=dict(
                    network="tcp", security="tls", tlsSettings=tls_options
                ),
            )
        ],
        outbounds=[dict(protocol="freedom")],
    )


def field_variants():
    cases = {}
    for version in ("h1", "h2", "h3"):
        for action in ("reject-main", "reject-download", "replace", "clear"):
            cases[f"{version}-ech-{action}"] = (
                {
                    "mode": "stream-up",
                    "download-settings": {},
                    "_ech_action": action,
                    "_reject": action.startswith("reject-"),
                },
                version,
            )
    return cases


if __name__ == "__main__":
    import argparse

    from .mihomo_isolation import exclusive_run
    from .protocol_vless_container import CLIENT_FINGERPRINTS, run

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", nargs="*")
    parser.add_argument("--client-fingerprint", choices=CLIENT_FINGERPRINTS)
    args = parser.parse_args()
    with exclusive_run():
        raise SystemExit(
            run(
                args.output.resolve(),
                args.cases or None,
                ech=True,
                client_fingerprint=args.client_fingerprint,
            )
        )
