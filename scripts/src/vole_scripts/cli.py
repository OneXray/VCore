from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence

from .builds import build_android, build_apple, build_cli, build_linux, build_windows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vole-scripts",
        description="Build Vole platform artifacts.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="build platform artifacts")
    platforms = build.add_subparsers(dest="platform", required=True)
    for name, description in (
        ("apple", "build LibVole.xcframework on macOS"),
        ("android", "build Android libvole.so artifacts"),
        ("windows", "build Windows native artifacts"),
        ("linux", "build native Linux FFI artifacts"),
    ):
        command = platforms.add_parser(name, help=description)
        command.add_argument(
            "--delivery",
            action="store_true",
            help="record production artifact identity",
        )

        if name == "windows":
            command.add_argument("--backend", choices=("wintun", "uwp"), default="uwp")
    command = platforms.add_parser("cli", help="build the foreground executable")
    command.add_argument("--target", help="Rust target triple (default: native host)")
    command.add_argument("--profile", choices=("debug", "release"), default="release")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.platform == "cli":
            build_cli(args.target, args.profile)
        elif args.delivery:
            from .platform_delivery import build_delivery

            if args.platform == "windows":
                build_delivery(args.platform, backend=args.backend)
            else:
                build_delivery(args.platform)
        elif args.platform == "apple":
            build_apple()
        elif args.platform == "android":
            build_android()
        elif args.platform == "windows":
            build_windows(args.backend)
        else:
            build_linux()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vole-scripts: {error}", file=sys.stderr)
        return 1
    return 0
