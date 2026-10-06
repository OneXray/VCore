from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence

from .builds import build_android, build_apple, build_windows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vcore-scripts",
        description="Build VCore platform artifacts.",
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

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.delivery:
            from .platform_delivery import build_delivery

            build_delivery(args.platform)
        elif args.platform == "apple":
            build_apple()
        elif args.platform == "android":
            build_android()
        else:
            build_windows()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vcore-scripts: {error}", file=sys.stderr)
        return 1
    return 0
