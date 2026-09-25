"""Named-profile VCore integration, reusing the owned container wire harness."""

import argparse
import sys
from pathlib import Path

from .mihomo_isolation import exclusive_run
from .protocol_vless_container import run

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
            "GRPC-TLS",
            "TCP-REALITY",
            "WS-REALITY",
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", nargs="*")
    # Grow this only with verified VCore support, not reference-client names.
    parser.add_argument(
        "--client-fingerprint", choices=("chrome120",), default="chrome120"
    )
    args = parser.parse_args(argv)
    with exclusive_run():
        return run(
            args.output.resolve(),
            args.cases or CASES,
            client_fingerprint=args.client_fingerprint,
        )


if __name__ == "__main__":
    sys.exit(main())
