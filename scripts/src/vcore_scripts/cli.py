from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .builds import build_android, build_apple, build_windows
from .checks import check_c_header, check_tls_dependencies
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
    windows = platforms.add_parser("windows", help="build packaged Windows artifacts")
    windows.add_argument("--architecture", choices=("arm64", "x64"), default="arm64")

    check = commands.add_parser("check", help="run repository checks")
    checks = check.add_subparsers(dest="check", required=True)
    checks.add_parser("c-header", help="compile vcore.h as C and C++")
    checks.add_parser("tls-dependencies", help="validate the locked TLS graph")

    demo = commands.add_parser("demo", help="run opt-in interoperability demos")
    demos = demo.add_subparsers(dest="demo", required=True)
    tun2socks = demos.add_parser(
        "windows-tun2socks", help="run VCore TUN through an external Xray SOCKS inbound"
    )
    tun2socks.add_argument("config", nargs="?", type=Path)
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
                build_windows(args.architecture)
        elif args.command == "check":
            if args.check == "c-header":
                check_c_header()
            else:
                check_tls_dependencies()
        else:
            run_demo(args.config)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vcore-scripts: {error}", file=sys.stderr)
        return 1
    return 0
