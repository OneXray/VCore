"""Shared synthetic certificates and peer configuration; never starts a listener."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .protocol_peers import run_command


def certificates(directory: Path):
    cert, key = directory / "cert.pem", directory / "key.pem"
    generated = run_command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        timeout=20,
        limit=65536,
    )
    der = run_command(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        timeout=10,
        limit=65536,
    )
    if (
        generated.returncode != 0
        or der.returncode != 0
        or not generated.cleanup
        or not der.cleanup
    ):
        raise RuntimeError("synthetic certificate generation failed")
    return cert, key, hashlib.sha256(der.stdout).hexdigest()


def certificate_chain(directory):
    """Owned synthetic CA + leaf; root pin still verifies the leaf name."""
    root = directory / "root.pem"
    root_key = directory / "root-key.pem"
    key = directory / "key.pem"
    csr = directory / "leaf.csr"
    cert = directory / "cert.pem"
    extensions = directory / "extensions.cnf"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
    )
    commands = [
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=trojan-root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            str(root_key),
            "-out",
            str(root),
        ],
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(csr),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(root),
            "-CAkey",
            str(root_key),
            "-set_serial",
            "2",
            "-days",
            "2",
            "-extfile",
            str(extensions),
            "-out",
            str(cert),
        ],
        ["openssl", "x509", "-in", str(root), "-outform", "DER"],
    ]
    for command in commands:
        result = run_command(command, timeout=20, limit=65536)
        if result.returncode or not result.cleanup:
            raise RuntimeError("synthetic chain generation failed")
    cert.write_bytes(cert.read_bytes() + root.read_bytes())
    return cert, key, hashlib.sha256(result.stdout).hexdigest()


def trojan_peer_config(kind, mode, port, password, cert, key):
    host = "::1" if mode.endswith("-ipv6") else "127.0.0.1"
    mode = mode.removesuffix("-ipv6").removesuffix("-ca")
    if kind == "M":
        listener = {
            "name": "trojan",
            "type": "trojan",
            "listen": host,
            "port": port,
            "users": [{"username": "fixture", "password": password}],
            "certificate": str(cert),
            "private-key": str(key),
        }
        if mode.startswith("ws"):
            listener["ws-path"] = "cover.example/trojan-ws"
        if mode.startswith("grpc"):
            listener["grpc-service-name"] = "trojan-grpc"
        if mode == "ws-alpn":
            listener["grpc-service-name"] = "unrelated-service"
        return {
            "mode": "rule",
            "log-level": "silent",
            "ipv6": True,
            "hosts": {"vcore-fixture.test": "127.0.0.1"},
            "listeners": [listener],
            "rules": ["MATCH,DIRECT"],
        }
    stream = {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]
        },
    }
    if mode.startswith("ws"):
        stream.update(network="ws", wsSettings={"path": "/trojan-ws/"})
        stream["tlsSettings"]["alpn"] = ["http/1.1"]
        if kind == "V2":
            stream["wsSettings"].update(
                maxEarlyData=2048,
                earlyDataHeaderName="x-vcore-ed" if mode == "ws-header" else "",
            )
    if mode == "grpc":
        stream.update(network="grpc", grpcSettings={"serviceName": "trojan-grpc"})
        stream["tlsSettings"]["alpn"] = ["h2"]
    return {
        "log": {"loglevel": "none"},
        "dns": {"hosts": {"vcore-fixture.test": "127.0.0.1"}},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "trojan",
                "settings": {"clients": [{"password": password}]},
                "streamSettings": stream,
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}],
    }
