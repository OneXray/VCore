"""SS UoT v2 gates, reconstructed from existing runner evidence conventions."""

from .protocol_completion_peers import CASES
from .protocol_shadowtls_catalog import commands as shared_commands

UOT_CASES = tuple(c for c in CASES if c.uot)
GATES = {
    "MEMORY": "datagrams",
    "FEATURES": "configuration",
    "QUALITY": "regression",
    "PLATFORMS": "regression",
    "MIHOMO-DIRECT": "interop",
    "MIHOMO-SOCKS5": "interop",
    "MIHOMO-GROUPS": "interop",
    "MIHOMO-NEGATIVE": "interop",
    "NATIVE-UNSUPPORTED": "interop",
    "ANYTLS": "regression",
    "BARE-SS": "regression",
}
LOCAL = {"MEMORY", "FEATURES", "QUALITY", "PLATFORMS"}
MEMORY_EVENTS = {
    ("UOT-CFG", "strict_v2"): 1,
    **{
        ("UOT-SS", n): 1
        for n in (
            "first_packet",
            "never_sent",
            "deadline",
            "cancel_write",
            "budget_read_cancel",
            "dns",
            "stop_full_queue",
        )
    },
}


def definitions():
    return [
        dict(
            case_id="UOT-" + name,
            stage="UOT",
            substage="UOT." + category,
            required=True,
            row_ids=[],
            protocol="ss",
            network="tcp",
            security="ss2022/optional-v3",
            udp_codec="uot-v2",
            field_values={},
            outer_family="IPv4",
            inner_family="IPv4/IPv6/domain",
            target_type="memory-only/build" if name in LOCAL else "isolated origin",
            upstream_graph="controlled-stream/optional-socks5-or-select",
            peer_kind="unit"
            if name in LOCAL
            else "SS"
            if name == "NATIVE-UNSUPPORTED"
            else "M",
            peer_config={"group": name},
            gap_source=None,
            expected_observation=["UOT-" + name],
            required_evidence=["command", "structured-assertions", "cleanup"]
            + ([] if name in LOCAL else ["peer-identity", "isolated-origins"]),
            prerequisites=["rust-toolchain"]
            if name in LOCAL
            else ["owned-host-only-container-network", "official-latest-peer"],
            runner="uot-gate",
            timeout_seconds=3600,
        )
        for name, category in GATES.items()
    ]


def wire_cases(name):
    if name in {"MIHOMO-DIRECT", "MIHOMO-SOCKS5", "MIHOMO-GROUPS"}:
        return [
            (c.identifier, "group" if name == "MIHOMO-GROUPS" else "data")
            for c in UOT_CASES
        ]
    if name == "NATIVE-UNSUPPORTED":
        return [
            (c.identifier + "-unsupported", "rejected")
            for c in UOT_CASES
            if not c.shadow_tls
        ]
    if name == "MIHOMO-NEGATIVE":
        return [
            (c.identifier + "-" + failure, "rejected")
            for c in UOT_CASES
            for failure in (("key", "identity") if c.shadow_tls else ("key",))
        ]
    raise ValueError("unknown UoT wire group")


def commands(name):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if name == "MEMORY":
        return [
            cargo
            + [
                arg
                for target in (
                    "uot_config",
                    "shadowsocks_uot",
                    "shadowsocks_backpressure",
                )
                for arg in ("--test", target)
            ],
            cargo + ["--lib", "outbound::uot::"],
            cargo + ["--lib", "outbound::anytls::"],
        ]
    if name == "FEATURES":
        return [
            ["cargo", "check", "--locked", "--no-default-features"]
            + (["--features", feature] if feature else [])
            for feature in (
                "",
                "outbound-shadowsocks",
                "outbound-anytls",
                "outbound-shadowsocks,shadow-tls-v3",
            )
        ] + [
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "interop-test",
                "--test",
                "uot_config",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "outbound-shadowsocks,interop-test",
                "--test",
                "uot_config",
                "--test",
                "shadowsocks_uot",
            ],
            ["cargo", "test", "--locked", "--test", "feature_foundations"],
            cargo + ["--all-targets", "--no-run"],
        ]
    return shared_commands(name) if name in {"QUALITY", "PLATFORMS"} else []
