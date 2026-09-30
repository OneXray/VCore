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
    for name, description in (
        ("apple", "build LibVCore.xcframework on macOS"),
        ("android", "build Android libvcore.so artifacts"),
        ("windows", "build packaged Windows artifacts"),
    ):
        command = platforms.add_parser(name, help=description)
        command.add_argument(
            "--delivery",
            action="store_true",
            help="record production artifact identity",
        )

    check = commands.add_parser("check", help="run repository checks")
    checks = check.add_subparsers(dest="check", required=True)
    core = checks.add_parser(
        "core", help="run memory-only tests or feature/build checks"
    )
    core.add_argument(
        "--profile", choices=("debug", "release", "features"), default="debug"
    )
    core.add_argument("--list", dest="list_only", action="store_true")
    checks.add_parser("c-header", help="compile vcore.h as C and C++")
    checks.add_parser("tls-dependencies", help="validate the locked TLS graph")
    delivery = checks.add_parser(
        "platform-artifacts", help="verify production artifact evidence, not devices"
    )
    delivery.add_argument("--manifest", type=Path, action="append", required=True)
    delivery.add_argument("--source-dir", type=Path)
    delivery.add_argument(
        "--complete",
        action="store_true",
        help="require every production platform group",
    )
    abi = checks.add_parser("platform-abi", help="link/load native production artifact")
    abi.add_argument("--manifest", type=Path, required=True)

    demo = commands.add_parser("demo", help="run opt-in platform demos")
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
            if args.delivery:
                from .platform_delivery import build_delivery

                build_delivery(args.platform)
            elif args.platform == "apple":
                build_apple()
            elif args.platform == "android":
                build_android()
            else:
                build_windows()
        elif args.command == "check":
            if args.check == "core":
                from .core_checks import run

                run(args.profile, list_only=args.list_only)
            elif args.check == "c-header":
                check_c_header()
            elif args.check == "platform-artifacts":
                from .platform_delivery import check_delivery

                check_delivery(
                    args.manifest, source_dir=args.source_dir, complete=args.complete
                )
            elif args.check == "platform-abi":
                from .platform_delivery import check_abi

                check_abi(args.manifest.resolve())
            else:
                check_tls_dependencies()
        else:
            run_demo(args.config, xray_source=args.xray_source)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vcore-scripts: {error}", file=sys.stderr)
        return 1
    return 0
