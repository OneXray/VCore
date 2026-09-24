"""Frozen N5 cases. Independent tuning is pairwise; coupled modes remain explicit."""

from __future__ import annotations

import hashlib

from .protocol_vless_acceptance import OBSERVATIONS as PREVIOUS
from .protocol_vmess_acceptance import SCRIPT_ASSERTIONS
from .protocol_xhttp_fields import native_kind, variants

UNIT_TESTS = {
    "xhttp_config": [
        "xhttp_fields_reject_wrong_types_null_and_every_range_boundary_before_io",
        "empty_http_authority_falls_back_to_each_legs_authentication_name",
        "download_security_changes_do_not_silently_discard_inherited_certificate_policy",
        "h3_requires_exclusive_alpn_and_standard_tls_on_each_leg",
        "custom_headers_inherit_replace_clear_and_do_not_leak_values",
        "conflicting_request_fields_are_rejected_on_both_legs_before_io",
        "http_version_selects_h1_only_for_its_single_alpn_and_supports_plaintext",
        "download_certificate_policy_inherits_and_explicit_false_or_empty_clears",
        "download_mtls_identity_is_inherited_or_replaced_and_cleared_as_a_pair",
        "download_reality_object_replaces_inherits_or_clears_without_merging_keys",
        "reuse_object_presence_and_download_whole_object_replacement_are_preserved",
    ],
    "sing_mux_config": [
        "sing_mux_accepts_three_protocols_and_rejects_invalid_or_ignored_options"
    ],
    "xhttp_requests": [
        "packet_up_coalesces_small_writes_and_flushes_without_more_caller_io",
        "packet_up_backpressures_bounded_batches_and_stop_cancels_the_timer",
        "first_vless_read_never_acknowledges_or_replays_a_concurrent_packet_write",
        "response_codes_follow_mihomo_streaming_and_packet_rules",
        "streaming_content_type_can_be_disabled_without_disabling_padding",
        "custom_semantic_headers_are_allowed_when_no_generated_field_overwrites_them",
        "padding_uses_the_configured_http_location_and_encoding",
        "packet_metadata_and_upload_methods_are_sent_in_each_supported_location",
        "packet_upload_can_move_payload_into_bounded_header_or_cookie_chunks",
        "http1_stream_one_is_chunked_duplex_and_shutdown_closes_both_directions",
        "http1_packet_up_shares_a_session_across_two_connections",
        "http1_response_body_can_arrive_after_the_response_headers",
        "custom_request_headers_reach_the_http_peer_without_changing_body",
    ],
    "xhttp_reuse": [
        "enabled_reuse_shares_physical_h2_without_one_close_killing_its_sibling",
        "reuse_thresholds_expand_and_retire_without_closing_active_sessions",
        "expired_transport_is_not_assigned_again_while_old_session_stays_live",
        "pooled_packet_posts_do_not_each_consume_a_transport_lease",
        "h2_keepalive_uses_default_explicit_and_disabled_idle_periods",
        "download_uses_its_own_reuse_counters_and_keeps_shared_sessions_alive",
        "h1_packet_upload_reuses_its_idle_connection_but_reopens_the_cancelled_get",
        "stopping_during_handshake_prevents_late_driver_admission",
        "stop_wakes_a_handshake_even_when_the_peer_never_responds",
    ],
    "sing_mux": [
        "yamux_replacing_dropped_streams_at_capacity_keeps_the_sibling_alive",
        "sing_mux_scheduling_uses_the_selected_branch_not_a_global_stream_quota",
        "h2mux_sends_idle_ping_and_retires_a_peer_that_never_acknowledges",
        "only_tcp_preserves_all_three_vless_udp_wire_commands",
        "h2mux_reuses_physical_vless_and_cancels_only_one_logical_stream",
        "yamux_reuses_physical_vless_and_cancels_only_one_logical_stream",
        "smux_reuses_physical_vless_and_cancels_only_one_logical_stream",
        "sing_mux_udp_preserves_addresses_and_cancellation_safe_partial_frames",
    ],
    "xhttp_budget": [
        "h3_rejects_incapable_or_small_budget_upstreams_before_any_datagram"
    ],
}

DRIVER_TESTS = ["malformed_smux_headers_close_the_owned_driver_before_reading_a_body"]

FIELD_IDS = {
    *(f"X{i:02}" for i in range(1, 30)),
    *(f"D{i:02}" for i in range(1, 16)),
    *(f"D{i:02}" for i in range(27, 33)),
    *(f"M{i:02}" for i in range(1, 8)),
}
OBSERVATIONS = {
    "N5-CFG": UNIT_TESTS["xhttp_config"] + UNIT_TESTS["sing_mux_config"],
    "N5-UNIT": sum(
        (
            UNIT_TESTS[n]
            for n in ("xhttp_requests", "xhttp_reuse", "sing_mux", "xhttp_budget")
        ),
        [],
    )
    + DRIVER_TESTS,
    "N5-REGRESSION": PREVIOUS["N4-REGRESSION"]
    + PREVIOUS["N4-CODEC"]
    + PREVIOUS["N4-TRANSPORT"]
    + PREVIOUS["N4-VISION"],
}
OBSERVATIONS["N5-RELEASE"] = OBSERVATIONS["N5-CFG"] + OBSERVATIONS["N5-UNIT"]
GATES = {
    "N5-CFG",
    "N5-UNIT",
    "N5-REGRESSION",
    "N5-RELEASE",
    "N5-QUALITY",
    "N5-FEATURES",
    "N5-SCRIPTS",
}
SECURITY = {f"N5-SECURITY-{v.upper()}": v for v in ("h1", "h2", "h3")}
NATIVE = {}
VERSIONS = ("h1", "h2", "h1c", "h2c", "h1r", "h2r", "h3")
ALL_VARIANTS = variants()


def add(variant, suffix, test):
    if variant not in ALL_VARIANTS:
        raise ValueError("missing frozen N5 variant")
    # Case-sensitive table names need distinct stable identifiers.
    digest = hashlib.sha256(variant.encode()).hexdigest()[:8].upper()
    identifier = f"N5-{variant.upper()}-{suffix}-{digest}"
    if identifier in NATIVE:
        raise ValueError("duplicate N5 requirement")
    NATIVE[identifier] = (variant, test)


for version in VERSIONS:
    for mode in ("stream-one", "stream-up", "packet-up"):
        variant = f"{version}-{mode}-headers"
        add(variant, "BASE", "public_base")
        add(variant, "CLOSE", "close::native_mihomo_xhttp_close")
    for mode in ("stream-up", "packet-up"):
        variant = f"{version}-{mode}-split-reuse"
        add(variant, "BASE", "public_base")
        add(variant, "CLOSE", "close::native_mihomo_xhttp_close")
    for suffix in ("auto", "auto-download"):
        add(f"{version}-{suffix}", "AUTO", "native_xhttp_request_fields")
    if version.endswith("r"):
        for suffix in (
            "download-reality-replacement",
            "reject-download-short-id",
            "reject-download-public-key",
        ):
            add(
                f"{version}-{suffix}",
                "SECURITY",
                "security::native_xhttp_security"
                if suffix.startswith("reject")
                else "native_xhttp_request_fields",
            )

# Every finite request enum is consumed on H1, H2 and H3. Security is orthogonal
# here; every plain/TLS/REALITY + mode + download branch has a public BASE above.
for version in ("h1", "h2", "h3"):
    for name, (options, v) in ALL_VARIANTS.items():
        if v != version or "_mux" in options or "_keepalive" in options:
            continue
        suffix = name.removeprefix(version + "-")
        if suffix.startswith(
            ("padding-", "metadata-", "payload-", "session-", "post-", "reject-")
        ) or suffix in (
            "stream-up-no-grpc",
            "stream-one-no-grpc",
            "body-auto",
        ):
            add(
                name,
                "FIELDS",
                "security::native_xhttp_security"
                if options.get("_reject")
                else "native_xhttp_request_fields",
            )
add(
    "h3-keepalive",
    "KEEPALIVE",
    "keepalive::native_h3_keepalive_observes_each_leg_and_stop",
)

# All three wire protocols and both only-tcp branches for every outer transport.
# Padding parity alternates between branches; H2 additionally expands all padding
# values. Padding and the outer framing are independent, tested separately above.
for outer in (
    *VERSIONS,
    *(
        f"outer-{m}"
        for m in (
            "tcp",
            "tcp-tls",
            "tcp-reality",
            "ws",
            "ws-tls",
            "ws-reality",
            "grpc",
            "grpc-tls",
            "grpc-reality",
            "http",
            "http-tls",
            "h2",
            "h2-tls",
            "ws-header",
            "ws-header-tls",
            "ws-path",
            "ws-path-tls",
        )
    ),
):
    for index, protocol in enumerate(("h2mux", "smux", "yamux")):
        for only in (False, True):
            paddings = (
                (False, True) if outer == "h2" else ((index + int(only)) % 2 == 0,)
            )
            for padding in paddings:
                variant = (
                    f"{outer}-mux-{protocol}-{'padded' if padding else 'plain'}"
                    + ("-only-tcp" if only else "")
                )
                add(variant, "BASE", "public_base")

for version in ("h1", "h2", "h3"):
    for protocol in ("h2mux", "smux", "yamux"):
        add(
            f"{version}-mux-{protocol}-padding-required",
            "REJECT",
            "security::native_xhttp_security",
        )

REPRESENTATIVES = (
    "h1-packet-up-split-reuse",
    "h2-stream-up-split-reuse",
    "h3-packet-up-split-reuse",
    "h2-mux-h2mux-padded",
    "h2-mux-smux-padded",
    "h2-mux-yamux-padded",
)
for variant in REPRESENTATIVES:
    for suffix, test in (
        ("GRAPH", "runtime::public_graph"),
        ("IPV6", "runtime::public_ipv6_and_gates"),
        ("ENTRYPOINTS", "runtime::public_entrypoints"),
        ("LIFE", "runtime::public_lifecycle"),
        ("ISOLATION", "runtime::public_udp_isolation"),
        ("OWNED", "lifecycle::native_xhttp_owned_resources"),
        ("NEG", "public_negative"),
    ):
        add(variant, suffix, test)
for variant in (
    "h1-packet-up-reuse",
    "h2-stream-up-reuse",
    "h3-packet-up-reuse",
    "h2-mux-h2mux-padded",
    "h2-mux-smux-padded",
    "h2-mux-yamux-padded",
):
    add(
        variant,
        "POOL-SELECTION",
        "runtime::grpc_pool_keeps_physical_selection_until_new_transport",
    )

X_NAMES = (
    "path",
    "host",
    "mode",
    "headers",
    "no-grpc-header",
    "x-padding-bytes",
    "x-padding-obfs-mode",
    "x-padding-key",
    "x-padding-header",
    "x-padding-placement",
    "x-padding-method",
    "uplink-http-method",
    "session-placement",
    "session-key",
    "session-table",
    "session-length",
    "seq-placement",
    "seq-key",
    "uplink-data-placement",
    "uplink-data-key",
    "uplink-chunk-size",
    "sc-max-each-post-bytes",
    "sc-min-posts-interval-ms",
)
REUSE_ROWS = {
    *(f"X{i:02}" for i in range(24, 30)),
    *(f"D{i:02}" for i in range(27, 33)),
}


def rows(identifier):
    if identifier in {"N5-CFG", "N5-UNIT"}:
        return sorted(FIELD_IDS)
    if identifier in GATES:
        return []
    if identifier in SECURITY:
        return [f"D{i:02}" for i in range(1, 14)]
    variant, test = NATIVE[identifier]
    options, version = ALL_VARIANTS[variant]
    if version.startswith("outer-"):
        return [f"M{i:02}" for i in range(1, 8)]
    result = {"X01", "X02", "X03", "X06"}
    result |= {f"X{i:02}" for i, name in enumerate(X_NAMES, 1) if name in options}
    if "download-settings" in options:
        result |= {"D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08"}
        if version.endswith("r"):
            result |= {"D14", "D15"}
    if "reuse-settings" in options or "reuse" in variant:
        result |= REUSE_ROWS
    if "_mux" in options:
        result |= {f"M{i:02}" for i in range(1, 8)}
    if options.get("_keepalive"):
        result |= {"X29", "D32"}
    return sorted(result)


def definitions():
    result = []
    for identifier in sorted(GATES | set(SECURITY) | set(NATIVE)):
        variant, test = NATIVE.get(
            identifier, (SECURITY.get(identifier, "memory-or-build"), identifier)
        )
        options, version = ALL_VARIANTS.get(variant, ({}, variant))
        native = identifier not in GATES
        kind = native_kind(version) if native else "unit"
        if identifier in SECURITY:
            kind = "XR" if version == "h3" else "M"
        encrypted = not version.endswith("c") and (
            not version.startswith("outer-") or version.endswith(("-tls", "-reality"))
        )
        gap = (
            {
                "reason": "Xray H3 forwards to the official Mihomo VLESS decoder "
                "for packetaddr/sing-mux. mTLS uses the approved unmodified "
                "xcaddy/Caddy gateway to one Xray handler.",
                "source": "https://github.com/XTLS/Xray-core/tree/v26.3.27/transport/internet/splithttp",
            }
            if kind == "XR"
            else {
                "reason": "Official V2Ray supplies HTTP/H2/custom-ED framing; "
                "sing-mux is decoded by official Mihomo, not V2Ray CommandMux.",
                "source": "https://github.com/MetaCubeX/mihomo/blob/v1.19.31/listener/inbound/vless.go",
            }
            if kind == "V2"
            else None
        )
        result.append(
            dict(
                case_id=identifier,
                stage="N5",
                substage="N5.4"
                if version == "h3"
                else "N5.3"
                if "_mux" in options
                else "N5.2"
                if identifier in SECURITY or "download-settings" in options
                else "N5.1"
                if native
                else "N5.5",
                required=True,
                row_ids=rows(identifier),
                protocol="vless",
                network=variant,
                security="tls-or-reality" if encrypted else "plain",
                udp_codec="raw/xudp/packetaddr/sing-mux",
                field_values=dict(
                    scope="protocol-consumer", variant=variant, **options
                ),
                outer_family="IPv4/IPv6",
                inner_family="IPv4/IPv6/domain",
                target_type="isolated synthetic origin"
                if native
                else "memory-only/build",
                upstream_graph="direct/concrete/nested-select"
                if "graph" in test
                else "per-assertion",
                peer_kind=kind,
                peer_config=dict(variant=variant, test=test),
                gap_source=gap,
                expected_observation=OBSERVATIONS.get(
                    identifier,
                    SCRIPT_ASSERTIONS if identifier == "N5-SCRIPTS" else [test],
                ),
                required_evidence=["structured-assertions", "command", "cleanup"]
                + (["official-peer-identity", "isolated-origins"] if native else []),
                prerequisites=[
                    "owned-host-only-container-network",
                    "official-latest-peer",
                ]
                if native
                else ["rust-toolchain"],
                runner="native-xhttp"
                if identifier in NATIVE
                else "xhttp-security"
                if identifier in SECURITY
                else "xhttp-gate",
                timeout_seconds=3600
                if identifier in GATES or identifier in SECURITY
                else 300,
            )
        )
    return result
