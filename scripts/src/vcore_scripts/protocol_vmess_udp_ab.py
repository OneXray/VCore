"""Container-only matched UDP diagnostic, not N3 stage acceptance."""

from __future__ import annotations

import argparse
import itertools
import re
import sys
from pathlib import Path

from .mihomo_isolation import exclusive_run


def options(codecs):
    return [
        dict(codec=codec, cipher=cipher, padding=padding, length=length)
        for codec, cipher, padding, length in itertools.product(
            codecs,
            ["none", "auto", "aes-128-gcm", "chacha20-poly1305"],
            [False, True],
            [False, True],
        )
        if cipher != "none" or not (padding or length)
    ]


def warning_summary(path):
    lines = path.read_text(errors="replace").splitlines()
    loopbacks = []
    for line in lines:
        if "reject loopback connection" in line:
            endpoints = re.findall(
                r"(?:\[[0-9a-fA-F:]+\]|(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+):(\d+)\b",
                line,
            )
            loopbacks.append(dict(ports=[int(port) for port in endpoints]))
    return dict(lines=len(lines), loopback_rejections=loopbacks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=["tcp", "ws", "grpc"],
        default=["tcp", "ws", "grpc"],
    )
    parser.add_argument(
        "--tls", nargs="+", choices=["plain", "tls"], default=["plain", "tls"]
    )
    parser.add_argument(
        "--codecs",
        nargs="+",
        choices=["raw", "xudp", "packetaddr"],
        default=["raw", "xudp", "packetaddr"],
    )
    parser.add_argument(
        "--families",
        nargs="+",
        choices=["ipv4", "ipv6", "domain"],
        default=["ipv4", "ipv6", "domain"],
    )
    parser.add_argument("--rounds", type=int, choices=range(1, 21), default=2)
    parser.add_argument("--packets", type=int, choices=range(1, 101), default=100)
    parser.add_argument("--sizes", nargs="+", type=int)
    parser.add_argument("--include-boundary", action="store_true")
    parser.add_argument("--collision-probe", action="store_true")
    parser.add_argument("--socket-probe", action="store_true")
    parser.add_argument("--nat-reuse-probe", action="store_true")
    args = parser.parse_args()
    if args.collision_probe or args.socket_probe:
        parser.error("BLOCKED: archived host-server probes require container migration")
    if args.sizes and any(size < 1 or size > 15000 for size in args.sizes):
        parser.error("sizes must be between 1 and the 15000-byte fixture budget")
    args.tls = [value == "tls" for value in args.tls]
    if args.nat_reuse_probe:
        args.modes, args.tls, args.codecs = ["tcp"], [False], ["raw", "xudp"]
        args.rounds, args.packets, args.sizes, args.families = 1, 1, [1], ["ipv4"]
        args.include_boundary = False
    from .protocol_vmess_udp_container import run as container_run

    with exclusive_run():
        return container_run(args)


if __name__ == "__main__":
    sys.exit(main())
