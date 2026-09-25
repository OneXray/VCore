"""Named-profile VCore integration, reusing the owned container wire harness."""

import argparse
import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from .mihomo_isolation import exclusive_run
from .protocol_inputs import same_source, source_identity
from .protocol_vless_container import CLIENT_FINGERPRINTS, run

SELECTED_TIMEOUT_SECONDS = 3600

CASES = [
    "F5-ANYTLS",
    *[
        f"N4-REGRESSION-{protocol}-{network}"
        for protocol in ("TROJAN", "VMESS")
        for network in ("TCP", "WS", "GRPC")
    ],
    *[
        f"N4-{mode}-BASE"
        for mode in (
            "TCP-TLS",
            "WS-TLS",
            "WS-ED-1-TLS",
            "WS-ED-2048-TLS",
            "WS-HEADER-TLS",
            "WS-PATH-TLS",
            "UPGRADE-TLS",
            "UPGRADE-FAST-TLS",
            "HTTP-TLS",
            "H2-TLS",
            "GRPC-TLS",
            "TCP-REALITY",
            "WS-REALITY",
            "UPGRADE-REALITY",
            "UPGRADE-FAST-REALITY",
            "GRPC-REALITY",
            "XHTTP-STREAM-ONE",
            "XHTTP-STREAM-UP",
            "XHTTP-PACKET-UP",
            "XHTTP-STREAM-ONE-REALITY",
            "XHTTP-STREAM-UP-DOWNLOAD-REALITY",
            "VISION-TLS",
            "VISION-REALITY",
        )
    ],
    "N4-VISION-TLS-INNER-TLS",
    "CF5-VMESS-HTTP-TLS",
    "CF5-VMESS-H2-TLS",
    "N4-VISION-REALITY-INNER-TLS",
    "N4-TCP-REALITY-NEG",
    "N4-TCP-TLS-NEG",
    "N4-GRPC-MTLS-IDENTITY",
    "N4-WS-ALPN-TLS-NEG",
    "N4-TCP-TLS-CLOSE",
    "N4-TCP-REALITY-CLOSE",
    "N4-GRPC-REALITY-CLOSE",
    "N4-VISION-REALITY-CLOSE",
    "N4-GRPC-TLS-LIFE",
    "N4-GRPC-TLS-OWNED",
    "N4-VISION-REALITY-LIFE",
    "N4-VISION-REALITY-OWNED",
]


def run_selected(output, profile):
    from .builds import CORE_DIR
    from .protocol_xhttp_fields import run as run_xhttp
    from .protocol_xhttp_fields import selected_profile_variants

    if (
        profile not in CLIENT_FINGERPRINTS
        or output.parent != CORE_DIR / "target/interop/runs"
    ):
        raise ValueError("use a supported profile and fresh target/interop/runs child")
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = dict(
        stage="CF5",
        scope="selected-transports",
        profile=profile,
        source=source_identity(),
        status="NOT RUN",
        parts=[],
        started_utc=datetime.now(UTC).isoformat(),
        timeout_seconds=SELECTED_TIMEOUT_SECONDS,
    )
    try:
        for phase in ("transports", "xhttp"):
            if phase == "transports":
                result = run(output / phase, CASES, client_fingerprint=profile)
                path = output / phase / "vless-results.json"
            else:
                selected = [
                    f"{version}-{mode}-headers"
                    for version in ("h1", "h2")
                    for mode in ("stream-one", "stream-up", "packet-up")
                ]
                selected.extend(selected_profile_variants(profile))
                jobs = {
                    name: [
                        dict(
                            case_id=f"CF5-{profile}-{name}",
                            test="security::native_xhttp_security"
                            if name.endswith("reject-pin")
                            else "public_base",
                        )
                    ]
                    for name in selected
                }
                result = run_xhttp(
                    output / phase, selected, jobs=jobs, client_fingerprint=profile
                )
                path = output / phase / "xhttp-fields-results.json"
            part = json.loads(path.read_text())
            report["parts"].append(
                dict(
                    phase=phase,
                    report=str(path.relative_to(output)),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    status=part["status"],
                    cleanup=part["cleanup"],
                    source_unchanged=part["source_unchanged"],
                    cases=len(part["cases"]),
                )
            )
            if result:
                raise RuntimeError(f"{phase} gate failed")
        report["status"] = "PASS"
    except (OSError, ValueError, RuntimeError) as error:
        report.update(status="FAIL", reason=str(error))
    finally:
        report["finished_utc"] = datetime.now(UTC).isoformat()
        report["seconds"] = round(time.monotonic() - started, 3)
        report["source_after"] = source_identity()
        # Staging an already captured untracked file changes the diagnostic
        # Git patch, not the exhaustive path/content source-tree digest.
        report["source_unchanged"] = same_source(
            report["source"], report["source_after"]
        )
        if not report["source_unchanged"]:
            report["status"] = "FAIL"
        if report["seconds"] > SELECTED_TIMEOUT_SECONDS:
            report.update(
                status="FAIL", reason="selected transport suite deadline exceeded"
            )
        (output / "fingerprint-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return 0 if report["status"] == "PASS" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", nargs="*")
    parser.add_argument(
        "--client-fingerprint", choices=CLIENT_FINGERPRINTS, default="chrome120"
    )
    args = parser.parse_args(argv)
    with exclusive_run():
        if not args.cases:
            return run_selected(args.output.resolve(), args.client_fingerprint)
        return run(
            args.output.resolve(),
            args.cases or CASES,
            client_fingerprint=args.client_fingerprint,
        )


if __name__ == "__main__":
    sys.exit(main())
