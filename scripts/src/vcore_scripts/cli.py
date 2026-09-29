from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .builds import build_android, build_apple, build_windows
from .checks import check_c_header, check_tls_dependencies
from .mihomo_release import SUPPORTED_TARGETS, download_mihomo
from .protocol_catalogs import CATALOG_DIR, SUITES, check_protocol_catalogs
from .protocol_evidence import check_run
from .protocol_harness import run_protocol_interop
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

    download = commands.add_parser("download", help="download official test peers")
    downloads = download.add_subparsers(dest="download", required=True)
    peer = downloads.add_parser("mihomo", help="download the latest stable mihomo")
    peer.add_argument(
        "--target", choices=SUPPORTED_TARGETS, help="default: host platform"
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
    apple = checks.add_parser(
        "apple-runtime", help="run native Apple simulator with isolated origins"
    )
    apple.add_argument("--platform", choices=("tvos", "ios"), default="tvos")
    apple.add_argument(
        "--manifest", type=Path, help="validate a clean production artifact identity"
    )
    reality = checks.add_parser(
        "reality-hybrid",
        help="verify isolated hybrid REALITY, not the complete security suite",
    )
    reality.add_argument("--run-dir", type=Path, required=True)
    reality.add_argument("--case", dest="identifiers", action="append")
    xhttp = checks.add_parser(
        "xhttp-peers",
        help="probe isolated native XHTTP peer capabilities, not suite acceptance",
    )
    xhttp.add_argument("--run-dir", type=Path, required=True)
    xhttp.add_argument(
        "--identities-only",
        action="store_true",
        help="probe real download-leg client-identity enforcement only",
    )
    peers = checks.add_parser(
        "protocol-peers",
        help="verify isolated official peer capabilities, not VCore acceptance",
    )
    peers.add_argument("--run-dir", type=Path, required=True)
    peers.add_argument("--case", dest="identifiers", action="append")
    gateway = checks.add_parser(
        "xhttp-gateway",
        help="build xcaddy and test isolated H3/mTLS native topology",
    )
    gateway.add_argument("--run-dir", type=Path, required=True)
    gateway.add_argument(
        "--identities-only",
        action="store_true",
        help="small identity probes with native QUIC certificate-error observation",
    )
    coverage = checks.add_parser(
        "protocol-coverage", help="validate executable catalogs or persisted evidence"
    )
    coverage_modes = coverage.add_mutually_exclusive_group(required=True)
    coverage_modes.add_argument(
        "--catalog-only",
        action="store_true",
        help="check declarations only, not implementation or behavior acceptance",
    )
    coverage_modes.add_argument(
        "--run-dir", type=Path, help="validate a complete persisted suite run"
    )
    suites = [name.lower() for name in SUITES]
    coverage.add_argument("--suite", choices=suites, default="foundations")
    coverage.add_argument(
        "--manifest",
        type=Path,
        help="explicit frozen executable manifest for evidence checks",
    )
    protocol = checks.add_parser(
        "protocol-interop", help="run a protocol or integration capability suite"
    )
    protocol.add_argument(
        "--suite", choices=suites, required=True, help="capability suite to run"
    )
    protocol.add_argument("--case", dest="identifiers", action="append")
    protocol.add_argument(
        "--protocol",
        choices=[
            "foundation",
            "legacy",
            "trojan",
            "vmess",
            "vless",
            "hysteria2",
            "tuic",
        ],
    )
    modes = protocol.add_mutually_exclusive_group()
    modes.add_argument("--list", dest="list_only", action="store_true")
    modes.add_argument("--preflight", dest="preflight_only", action="store_true")
    protocol.add_argument(
        "--run-dir", type=Path, help="fresh child directory of target/interop/runs"
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
            if args.delivery:
                from .platform_delivery import build_delivery

                build_delivery(args.platform)
            elif args.platform == "apple":
                build_apple()
            elif args.platform == "android":
                build_android()
            else:
                build_windows()
        elif args.command == "download":
            download_mihomo(args.target)
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
            elif args.check == "apple-runtime":
                from .apple_runtime import run

                run(args.platform, args.manifest)
            elif args.check == "xhttp-peers":
                from .protocol_xhttp_peers import main as xhttp_peers

                return xhttp_peers(args.run_dir, identities_only=args.identities_only)
            elif args.check == "protocol-peers":
                from .protocol_completion_peers import run

                run(args.run_dir, identifiers=args.identifiers)
            elif args.check == "xhttp-gateway":
                from .protocol_xhttp_gateway import main as xhttp_gateway

                return xhttp_gateway(args.run_dir, identities_only=args.identities_only)
            elif args.check == "protocol-coverage":
                if args.catalog_only:
                    check_protocol_catalogs(CATALOG_DIR)
                else:
                    check_run(
                        args.run_dir.resolve(),
                        args.suite.upper(),
                        args.manifest,
                    )
            elif args.check == "protocol-interop":
                run_protocol_interop(
                    stage=args.suite.upper(),
                    identifiers=args.identifiers,
                    protocol=args.protocol,
                    list_only=args.list_only,
                    preflight_only=args.preflight_only,
                    run_dir=args.run_dir,
                )
            elif args.check == "reality-hybrid":
                from .protocol_reality_hybrid import main as run_reality_hybrid

                return run_reality_hybrid(args.run_dir, args.identifiers)
            else:
                check_tls_dependencies()
        else:
            run_demo(args.config, xray_source=args.xray_source)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vcore-scripts: {error}", file=sys.stderr)
        return 1
    return 0
