"""VMESS wire gate; all peers and origins run in isolated containers."""

from __future__ import annotations

import sys
from pathlib import Path

from .mihomo_isolation import exclusive_run

CASES = {
    "VMESS-M-IDENTITY": ("M", "tcp", False, "native_identity_time_replay_rejection")
}
CASES["VMESS-M-RAW-UDP"] = ("M", "tcp", False, "native_raw_udp_boundaries")
CASES["VMESS-M-ENCODED-UDP"] = ("M", "tcp", False, "native_encoded_udp_boundaries")
for _mode in ("tcp", "ws", "grpc", "http", "h2"):
    for _tls in (False, True):
        _kind = "V2" if _mode in {"http", "h2"} else "M"
        CASES[f"VMESS-{_kind}-{_mode.upper()}-{'TLS' if _tls else 'PLAIN'}"] = (
            _kind,
            _mode,
            _tls,
            "native_cipher_matrix",
        )
        CASES[f"VMESS-{_kind}-{_mode.upper()}-{'TLS' if _tls else 'PLAIN'}-CLOSE"] = (
            _kind,
            _mode,
            _tls,
            "native_mihomo_close_alignment",
        )
        if _mode != "tcp" or _tls:
            for _encoding in ("raw", "encoded"):
                CASES[
                    f"VMESS-{_kind}-{_mode.upper()}-{'TLS' if _tls else 'PLAIN'}"
                    f"-{_encoding.upper()}-UDP"
                ] = (
                    _kind,
                    _mode,
                    _tls,
                    f"native_{_encoding}_udp_boundaries",
                )


def udp_path_limit():
    # Both packet sender and origin are now Linux VM services.
    return 15000


def peer_config(kind, mode, encrypted, port, cert, key):
    if mode.startswith("trojan-"):
        config = peer_config(
            kind, mode.removeprefix("trojan-"), encrypted, port, cert, key
        )
        config["listeners"][0].update(
            type="trojan",
            users=[dict(username="fixture", password="synthetic-regression-only")],
        )
        return config
    variant = mode
    mode = mode.split("-")[0]
    identity = "07070707-0707-0707-0707-070707070707"
    if kind == "M":
        listener = dict(
            name="vmess",
            type="vmess",
            listen="127.0.0.1",
            port=port,
            users=[dict(username="fixture", uuid=identity, alterId=0)],
        )
        if encrypted:
            listener.update(certificate=str(cert), **{"private-key": str(key)})
        if mode == "ws":
            listener["ws-path"] = "/vmess-ws"
        if mode == "grpc":
            listener["grpc-service-name"] = "vmess-grpc"
        if variant == "ws-alpn":
            listener["grpc-service-name"] = "vmess-alpn"
        return {
            "mode": "rule",
            "log-level": "silent",
            "ipv6": True,
            "hosts": {"vcore-fixture.test": "127.0.0.1"},
            "listeners": [listener],
            "rules": ["MATCH,DIRECT"],
        }
    stream = dict(network="tcp", security="tls" if encrypted else "none")
    if mode == "http":
        stream["tcpSettings"] = {
            "header": {"type": "http", "request": {"path": ["/vmess-http"]}}
        }
    elif mode == "h2":
        stream.update(
            network="http", httpSettings=dict(host=["localhost"], path="/vmess-h2")
        )
    elif mode == "ws":
        stream.update(
            network="ws",
            wsSettings={
                "path": "/vmess-ws/",
                "maxEarlyData": 2048,
                "earlyDataHeaderName": "X-Vcore-Ed" if variant == "ws-header" else "",
            },
        )
    if encrypted:
        stream["tlsSettings"] = {
            "alpn": ["h2"] if mode == "h2" else ["http/1.1"],
            "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}],
        }
    return {
        "log": {"loglevel": "none"},
        "dns": {"hosts": {"vcore-fixture.test": "127.0.0.1"}},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vmess",
                "settings": {"clients": [{"id": identity, "alterId": 0}]},
                "streamSettings": stream,
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}],
    }


def run(output: Path, selected=None):
    from .protocol_vmess_container import run as run_container

    return run_container(output, selected)


if __name__ == "__main__":
    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:] or None))
