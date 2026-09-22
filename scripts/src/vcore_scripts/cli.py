from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .builds import build_android, build_apple, build_windows
from .checks import check_c_header, check_tls_dependencies
from .mihomo import run_mihomo_interop
from .mihomo_release import SUPPORTED_TARGETS, download_mihomo
from .tun2socks import run_demo


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vcore-scripts",
        description="Build and validate VCore platform artifacts.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="build platform artifacts")
    platforms = build.add_subparsers(dest="platform", required=True)
    platforms.add_parser("apple", help="build LibVCore.xcframework on macOS")
    platforms.add_parser("android", help="build Android libvcore.so artifacts")
    platforms.add_parser("windows", help="build packaged Windows artifacts")

    download = commands.add_parser("download", help="download official test peers")
    downloads = download.add_subparsers(dest="download", required=True)
    peer = downloads.add_parser("mihomo", help="download the latest stable mihomo")
    peer.add_argument(
        "--target", choices=SUPPORTED_TARGETS, help="default: host platform"
    )

    check = commands.add_parser("check", help="run repository checks")
    checks = check.add_subparsers(dest="check", required=True)
    checks.add_parser("c-header", help="compile vcore.h as C and C++")
    checks.add_parser("tls-dependencies", help="validate the locked TLS graph")
    mihomo = checks.add_parser(
        "mihomo-interop", help="run local protocol interoperability against mihomo"
    )
    mihomo.add_argument(
        "--container",
        action="store_true",
        help="download Linux ARM64 peers for Apple Container as well as native peers",
    )
    mihomo.add_argument(
        "--extended",
        action="store_true",
        help="include repeated cross-protocol two-hop gates",
    )
    mihomo.add_argument(
        "--soak-seconds",
        type=int,
        default=0,
        help="requires --extended; full soak acceptance needs 1800 wall-clock seconds",
    )

    demo = commands.add_parser("demo", help="run opt-in interoperability demos")
    demos = demo.add_subparsers(dest="demo", required=True)
    tun2socks = demos.add_parser(
        "windows-tun2socks", help="run VCore TUN through an external Xray SOCKS inbound"
    )
    tun2socks.add_argument("config", type=Path)
    tun2socks.add_argument("--xray-source", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            if args.platform == "apple":
                build_apple()
            elif args.platform == "android":
                build_android()
            else:
                build_windows()
        elif args.command == "download":
            download_mihomo(args.target)
        elif args.command == "check":
            if args.check == "c-header":
                check_c_header()
            elif args.check == "mihomo-interop":
                run_mihomo_interop(
                    extended=args.extended,
                    soak_seconds=args.soak_seconds,
                    container=args.container,
                )
            else:
                check_tls_dependencies()
        else:
            run_demo(args.config, xray_source=args.xray_source)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vcore-scripts: {error}", file=sys.stderr)
        return 1
    return 0
