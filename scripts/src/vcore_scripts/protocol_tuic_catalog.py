"""TUIC v5 required groups and independently enumerated wire consumers."""

from .protocol_shadowtls_catalog import commands as shared_commands

LOCAL = {"MEMORY", "FEATURES", "QUALITY", "PLATFORMS", "SHARED-QUIC"}
HY2 = ("TCP", "UDP", "SECURITY", "OWNED", "DEADLINE")
GATES = {
    "MEMORY": "datagrams",
    "FEATURES": "configuration",
    "QUALITY": "regression",
    "PLATFORMS": "regression",
    "SHARED-QUIC": "regression",
    **{
        "MIHOMO-" + name: "interop"
        for name in ("TCP", "POLICY", "UDP", "PATHS", "NEGATIVE")
    },
    **{"HYSTERIA2-" + name: "regression" for name in HY2},
    "XHTTP-H3": "regression",
}
CFG_EVENTS = {("TUIC-CFG", n): 1 for n in ("identity", "redaction", "udp", "bounds")}
MEMORY_EVENTS = CFG_EVENTS | {
    ("TUIC-UNIT", n): 1
    for n in (
        "tcp_owner",
        "credit_deadline",
        "path_requirements",
        "handshake_stop",
        "udp_wire",
        "unused_association",
        "session_retirement",
        "partial_control_expiry",
        "udp_credit_cancel",
        "protect_fail_closed",
        "heartbeat_full_queue_stop",
        "receive_windows",
        "send_buffers",
        "reassembly_order",
        "reassembly_limits",
        "delivery_limits",
    )
}


def definitions():
    return [
        dict(
            case_id="TUIC-" + name,
            stage="TUIC",
            substage="TUIC." + category,
            required=True,
            row_ids=[],
            protocol="tuic",
            network="quic",
            security="tls13",
            udp_codec="native/quic",
            field_values={},
            outer_family="IPv4",
            inner_family="IPv4/IPv6/domain",
            target_type="memory-only/build" if name in LOCAL else "isolated origin",
            upstream_graph="controlled-datagrams/optional-nested-select",
            peer_kind="unit" if name in LOCAL else "M",
            peer_config={"group": name},
            gap_source=None,
            expected_observation=["TUIC-" + name],
            required_evidence=["command", "structured-assertions", "cleanup"]
            + ([] if name in LOCAL else ["peer-identity", "isolated-origins"]),
            prerequisites=["rust-toolchain"]
            if name in LOCAL
            else ["owned-host-only-container-network", "official-latest-peer"],
            runner="tuic-gate",
            timeout_seconds=3600,
        )
        for name, category in GATES.items()
    ]


def wire_cases(name):
    if name == "MIHOMO-TCP":
        return [("tcp-" + n, "tcp") for n in ("cubic", "new_reno", "bbr")]
    if name == "MIHOMO-POLICY":
        return [
            (n, "tcp" if i < 6 else "rejected")
            for i, n in enumerate(
                (
                    "alpn-default",
                    "alpn-custom",
                    "empty-password",
                    "raw-password",
                    "skip",
                    "verify-name",
                    "wrong-uuid",
                    "wrong-password",
                    "wrong-pin",
                    "wrong-pin-skip",
                    "untrusted",
                    "wrong-name-skip",
                    "wrong-alpn",
                )
            )
        ]
    if name == "MIHOMO-UDP":
        return [("udp-" + mode, "udp") for mode in ("native", "quic")]
    if name == "MIHOMO-PATHS":
        return [
            (hop + "-" + mode, "group")
            for hop in ("socks5", "ss-uot", "anytls")
            for mode in ("native", "quic")
        ]
    if name == "MIHOMO-NEGATIVE":
        return [
            (
                kind + "-" + mode,
                "udp_disabled" if kind == "udp-disabled" else "rejected",
            )
            for kind in ("udp-disabled", "socks5-tcp-only")
            for mode in ("native", "quic")
        ]
    raise ValueError("unknown TUIC wire group")


def commands(name):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if name == "MEMORY":
        return [
            cargo + ["--test", "tuic_config", "--test", "tuic_memory"],
            cargo + ["--lib", "outbound::tuic::"],
        ]
    if name == "FEATURES":
        return [
            ["cargo", "check", "--locked", "--no-default-features"]
            + (["--features", f] if f else [])
            for f in ("", "outbound-tuic", "quic-transport")
        ] + [
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "interop-test",
                "--test",
                "tuic_config",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "outbound-tuic,interop-test",
                "--test",
                "tuic_config",
                "--test",
                "tuic_memory",
            ],
            ["cargo", "test", "--locked", "--test", "feature_foundations"],
            cargo + ["--all-targets", "--no-run"],
        ]
    if name == "SHARED-QUIC":
        return [
            cargo
            + [
                "--test",
                "hysteria2_paths",
                "--test",
                "hysteria2_packet_ids",
                "--test",
                "xhttp_h3_shutdown",
                "--test",
                "limit_foundations",
            ],
            cargo
            + [
                "--test",
                "quic_datagram_foundations",
                "pending_send_is_not_restarted_and_stop_cancels_without_waiting_for_writable",
                "--",
                "--exact",
            ],
            cargo + ["--lib", "outbound::hysteria2::"],
            cargo + ["--lib", "security::tls::tests::"],
        ]
    return shared_commands(name) if name in {"QUALITY", "PLATFORMS"} else []
