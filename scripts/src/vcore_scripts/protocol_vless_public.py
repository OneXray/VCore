"""Frozen VLESS native/public consumer requirements; no result-derived catalog."""

from .protocol_evidence import idle_resources
from .protocol_vless_peers import MODES, peer_kind
from .protocol_vmess_public import pairs

PUBLIC = {}
WIRE = {}


def add(mode, suffix, test, *, wire=False):
    kind = peer_kind(mode)
    encrypted = mode.endswith(("-tls", "-reality", "-mtls")) or mode.startswith(
        ("xhttp-", "vision-")
    )
    (WIRE if wire else PUBLIC)[f"VLESS-{mode.upper()}-{suffix}"] = (
        kind,
        mode,
        encrypted,
        test,
    )


for mode in MODES:
    add(mode, "BASE", "public_base")
add("ws-alpn-tls", "NEG", "public_alpn_rejection")
for mode in ("tcp", "ws", "grpc", "http", "h2"):
    for suffix in ("", "-tls"):
        add(mode + suffix, "NEG", "public_negative")
    for suffix, test in (
        ("GRAPH", "runtime::public_graph"),
        ("IPV6", "runtime::public_ipv6_and_gates"),
        ("ENTRYPOINTS", "runtime::public_entrypoints"),
    ):
        add(mode + "-tls", suffix, test)
for mode in (
    "upgrade-tls",
    "upgrade-fast-tls",
    "upgrade-reality",
    "upgrade-fast-reality",
    "tcp-reality",
    "ws-reality",
    "grpc-reality",
    "vision-tls",
    "vision-reality",
    "xhttp-stream-one",
    "xhttp-stream-up",
    "xhttp-packet-up",
):
    add(mode, "NEG", "public_negative")
for mode in ("tcp-tls", "grpc-tls", "vision-tls", "vision-reality"):
    add(mode, "LIFE", "runtime::public_lifecycle")
    add(mode, "OWNED", "runtime::owned_resources")
for mode in ("tcp-tls", "grpc-tls", "vision-tls"):
    add(mode, "UDP-ISOLATION", "runtime::public_udp_isolation")
for mode in ("vision-tls", "vision-reality"):
    add(mode, "INNER-TLS", "native_vision_inner_tls", wire=True)
    add(mode, "GRAPH", "runtime::public_graph")
    add(mode, "ENTRYPOINTS", "runtime::public_entrypoints")
    add(mode, "IPV6", "runtime::public_ipv6_and_gates")
for mode in ("tcp", "grpc-tls", "http", "h2-tls"):
    add(mode, "UDP-BOUNDARIES", "native_three_udp_encodings", wire=True)
for mode in ("tcp-mtls", "ws-mtls", "grpc-mtls"):
    add(mode, "IDENTITY", "public_tls_identity_and_verification_name")
add(
    "grpc-tls",
    "POOL-SELECTION",
    "runtime::grpc_pool_keeps_physical_selection_until_new_transport",
)
for protocol in ("vmess", "trojan"):
    for network in ("tcp", "ws", "grpc"):
        PUBLIC[f"VLESS-REGRESSION-{protocol.upper()}-{network.upper()}"] = (
            "M",
            f"{protocol}-{network}",
            True,
            "public_legacy_regression",
        )
for mode in (
    "tcp",
    "tcp-tls",
    "tcp-reality",
    "ws-reality",
    "grpc-reality",
    "ws",
    "ws-tls",
    "grpc",
    "grpc-tls",
    "http",
    "http-tls",
    "h2",
    "h2-tls",
    "upgrade-fast-tls",
    "upgrade-reality",
    "upgrade-fast-reality",
    "vision-tls",
    "vision-reality",
    "xhttp-stream-one",
    "xhttp-stream-up",
    "xhttp-packet-up",
):
    add(
        mode,
        "CLOSE",
        "native_ws_reality_close_boundary"
        if mode in {"ws-reality", "upgrade-reality", "upgrade-fast-reality"}
        else "native_mihomo_close_alignment",
        wire=True,
    )
add("grpc-tls", "POOL-COUNTS", "native_grpc_pool_thresholds", wire=True)
CASES = WIRE | PUBLIC


def events_pass(events, test, mode, *, stage="VLESS"):
    main = [event for event in events if event.get("suite") == f"{stage}-PUBLIC"]
    if len(main) != 2 or not pairs(main, f"{stage}-PUBLIC", test, 1):
        return False
    if any(
        event.get("schema_version") != 1 or event.get("status") not in {"BEGIN", "PASS"}
        for event in events
    ):
        return False
    if test == "public_base" and not (
        pairs(events, f"{stage}-BASE", "tcp_10mib_both_directions", 3)
        and pairs(
            events,
            f"{stage}-BASE",
            "udp_each_codec_and_family",
            1 if mode.startswith("vision-") else 3,
        )
    ):
        return False
    if test in {"runtime::public_lifecycle", "runtime::owned_resources"}:
        suite = (
            f"{stage}-LIFE" if test.endswith("public_lifecycle") else f"{stage}-OWNED"
        )
        if not pairs(events, suite, "stop_and_remain_quiet", 20):
            return False
        for event in [
            e for e in events if e.get("suite") == suite and e["status"] == "PASS"
        ]:
            if event.get("seconds", 0) < 5:
                return False
            if suite == f"{stage}-OWNED":
                points = event.get("checkpoints", [])
                phases = {p["phase"]: p["resources"] for p in points}
                if (
                    len(points) != 3
                    or set(phases) != {"baseline", "after-stop", "quiet"}
                    or not all(idle_resources(r) for r in phases.values())
                    or phases["after-stop"] != phases["quiet"]
                    or not idle_resources(event.get("resources"))
                ):
                    return False
    return True
