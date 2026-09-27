from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .builds import build_android, build_apple, build_windows
from .checks import check_c_header, check_tls_dependencies
from .mihomo_release import SUPPORTED_TARGETS, download_mihomo
from .protocol_catalogs import CATALOG_DIR, check_protocol_catalogs
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
    reality = checks.add_parser(
        "reality-hybrid",
        help="run isolated N7.2 S03/D16 checks, not complete N7 acceptance",
    )
    reality.add_argument("--run-dir", type=Path, required=True)
    reality.add_argument("--case", dest="identifiers", action="append")
    xhttp = checks.add_parser(
        "xhttp-peers",
        help="probe isolated native N5 peer capabilities, not stage acceptance",
    )
    xhttp.add_argument("--run-dir", type=Path, required=True)
    xhttp.add_argument(
        "--identities-only",
        action="store_true",
        help="probe real download-leg client-identity enforcement only",
    )
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
        "--run-dir", type=Path, help="validate a complete persisted stage run"
    )
    suites = {
        "foundations": "N1",
        "trojan": "N2",
        "vmess": "N3",
        "vless": "N4",
        "xhttp": "N5",
        "hysteria2": "N6",
        "security": "N7",
        "integration": "N9",
    }
    stages = list(suites.values())
    coverage_selection = coverage.add_mutually_exclusive_group()
    coverage_selection.add_argument("--suite", choices=suites, default=None)
    coverage_selection.add_argument("--stage", choices=stages, help=argparse.SUPPRESS)
    coverage.set_defaults(suites=suites)
    coverage.add_argument(
        "--manifest",
        type=Path,
        help="explicit frozen executable manifest for evidence checks",
    )
    protocol = checks.add_parser(
        "protocol-interop", help="run structured stage foundations and native peers"
    )
    selection = protocol.add_mutually_exclusive_group(required=True)
    selection.add_argument("--suite", choices=suites, help="capability suite to run")
    selection.add_argument("--stage", choices=stages, help=argparse.SUPPRESS)
    protocol.set_defaults(suites=suites)
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
            elif args.check == "xhttp-peers":
                from .protocol_xhttp_peers import main as xhttp_peers

                return xhttp_peers(args.run_dir, identities_only=args.identities_only)
            elif args.check == "xhttp-gateway":
                from .protocol_xhttp_gateway import main as xhttp_gateway

                return xhttp_gateway(args.run_dir, identities_only=args.identities_only)
            elif args.check == "protocol-coverage":
                if args.catalog_only:
                    check_protocol_catalogs(CATALOG_DIR)
                else:
                    check_run(
                        args.run_dir.resolve(),
                        args.suites[args.suite] if args.suite else (args.stage or "N1"),
                        args.manifest,
                    )
            elif args.check == "protocol-interop":
                run_protocol_interop(
                    stage=args.suites[args.suite] if args.suite else args.stage,
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
