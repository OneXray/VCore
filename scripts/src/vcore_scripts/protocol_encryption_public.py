"""Public Encryption consumers using the existing isolated VLESS lab."""

from __future__ import annotations

import json
from pathlib import Path

from .builds import CORE_DIR
from .protocol_encryption import cases, encode


def configuration(profile, node, peer):
    style, rtt, key = cases()[profile]
    vectors = json.loads(
        (CORE_DIR / "tests/protocols/encryption-crypto.json").read_text()
    )
    pairs = {
        "x25519": (encode(vectors["x25519_public"]), encode(vectors["x25519_private"])),
        "mlkem": (encode(vectors["mlkem_public"]), encode(vectors["mlkem_seed"])),
    }
    pairs["mixed"] = tuple(
        ".".join((pairs["x25519"][i], pairs["mlkem"][i], pairs["x25519"][i]))
        for i in (0, 1)
    )
    # Nontrivial fragments/gaps exercise early-data continuation, not merely
    # the smallest one-flight padding used by the wire/replay lab.
    padding = "100-35-35.100-1-1.100-47-47"
    node["encryption"] = f"mlkem768x25519plus.{style}.{rtt}.{pairs[key][0]}.{padding}"
    for listener in peer["listeners"]:
        listener["decryption"] = (
            f"mlkem768x25519plus.{style}.600s.{pairs[key][1]}.{padding}"
        )


def catalog():
    required = {}
    modes = (
        "tcp",
        "tcp-tls",
        "tcp-reality",
        "ws",
        "ws-tls",
        "ws-ed-1",
        "ws-ed-2048",
        "upgrade",
        "upgrade-fast",
        "grpc",
        "grpc-tls",
        "xhttp-stream-one",
        "xhttp-stream-up",
        "xhttp-packet-up",
        "xhttp-stream-up-download",
        "xhttp-packet-up-download",
    )
    for mode in modes:
        tls = mode.endswith(("-tls", "-reality")) or mode.startswith("xhttp-")
        for suffix, test in (
            ("BASE", "public_base"),
            ("CLOSE", "native_mihomo_close_alignment"),
        ):
            required[f"SECURITY-E-{mode.upper()}-{suffix}"] = ("M", mode, tls, test)
    for mode in ("tcp-tls", "grpc-tls"):
        for suffix, test in (
            ("GRAPH", "runtime::public_graph"),
            ("IPV6", "runtime::public_ipv6_and_gates"),
            ("ENTRYPOINTS", "runtime::public_entrypoints"),
            ("LIFE", "runtime::public_lifecycle"),
            ("OWNED", "runtime::owned_resources"),
            ("UDP-ISOLATION", "runtime::public_udp_isolation"),
        ):
            required[f"SECURITY-E-{mode.upper()}-{suffix}"] = ("M", mode, True, test)
    for mode in ("vision-encryption", "vision-tls", "vision-reality"):
        for suffix, test in (
            ("BASE", "public_base"),
            ("INNER-TLS", "native_vision_inner_tls"),
            ("UDP", "native_vision_xudp"),
            ("CLOSE", "native_mihomo_close_alignment"),
            ("DIRECT-CLOSE", "native_vision_direct_close_alignment"),
        ):
            required[f"SECURITY-E-{mode.upper()}-{suffix}"] = (
                "M",
                mode,
                mode != "vision-encryption",
                test,
            )
    return required


if __name__ == "__main__":
    import argparse

    from .mihomo_isolation import exclusive_run
    from .protocol_vless_container import run

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("profile", choices=cases())
    parser.add_argument("cases", nargs="*")
    args = parser.parse_args()
    with exclusive_run():
        raise SystemExit(
            run(args.output.resolve(), args.cases or None, encryption=args.profile)
        )
