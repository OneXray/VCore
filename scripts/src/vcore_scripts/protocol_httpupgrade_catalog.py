"""Independent required HTTPUpgrade consumers and regression selection."""

from .protocol_shadowtls_catalog import commands as shared_commands

LOCAL = {"MEMORY", "FEATURES", "QUALITY", "PLATFORMS"}
WIRE = ("TCP", "UDP", "UDP-DOMAIN", "EARLY-DATA", "PROFILES", "NEGATIVE", "CLOSE")
GATES = ("MEMORY", "FEATURES", "QUALITY", "PLATFORMS", *WIRE, "VLESS", "VMESS")
BASES = tuple(
    f"{protocol}-upgrade-{security}-{mode}"
    for protocol, security in (("vmess", "plain"), ("vmess", "tls"), ("trojan", "tls"))
    for mode in ("normal", "fast")
)
UNIT = (
    "config_dispatch",
    "config_bounds",
    "early_data",
    "invalid_response",
    "deadline_cancel",
    "expired_deadline",
)
REGRESSION = {
    "VLESS": [
        "VLESS-" + mode + "-BASE"
        for mode in (
            "WS",
            "WS-TLS",
            "UPGRADE",
            "UPGRADE-FAST",
            "UPGRADE-TLS",
            "UPGRADE-FAST-TLS",
        )
    ]
    + [
        "VLESS-REGRESSION-" + protocol + "-" + network
        for protocol in ("VMESS", "TROJAN")
        for network in ("TCP", "WS", "GRPC")
    ],
    "VMESS": ["VMESS-PUBLIC-" + mode + "-TLS-BASE" for mode in ("HTTP", "H2")],
}


def wire_cases(name):
    rows = []
    for base in BASES:
        if name == "UDP-DOMAIN" and not base.startswith("trojan"):
            continue
        if name == "PROFILES" and "-plain-" in base:
            continue
        variants = {
            "TCP": ("",),
            "CLOSE": ("",),
            "UDP": ("raw", "xudp", "packetaddr")
            if base.startswith("vmess")
            else ("raw",),
            "UDP-DOMAIN": ("domain",),
            "EARLY-DATA": ("ed1", "ed2048"),
            "PROFILES": ("chrome", "chrome120", "firefox", "safari"),
            "NEGATIVE": ("identity", "path")
            + (("certificate",) if "-tls-" in base else ()),
        }[name]
        consumer = {
            "TCP": "tcp",
            "CLOSE": "close",
            "UDP": "udp",
            "UDP-DOMAIN": "udp",
            "EARLY-DATA": "echo_and_stop",
            "PROFILES": "echo_and_stop",
            "NEGATIVE": "rejected",
        }[name]
        rows += [(base + ("-" + v if v else ""), consumer) for v in variants]
    return rows


def definitions():
    return [
        dict(
            case_id="HTTPUPGRADE-" + name,
            stage="HTTPUPGRADE",
            substage="HTTPUPGRADE."
            + (
                "configuration"
                if name == "FEATURES"
                else "stream"
                if name == "MEMORY"
                else "interop"
                if name in WIRE
                else "regression"
            ),
            required=True,
            row_ids=[],
            protocol="vmess/trojan",
            network="httpupgrade",
            security="plain/tls",
            udp_codec="raw/xudp/packetaddr/trojan",
            field_values={},
            outer_family="IPv4",
            inner_family="IPv4/IPv6/domain",
            target_type="memory-only/build" if name in LOCAL else "isolated origin",
            upstream_graph="existing connector",
            peer_kind="unit"
            if name in LOCAL
            else "XR"
            if name == "UDP-DOMAIN"
            else "V2"
            if name == "VMESS"
            else "M",
            peer_config={"group": name},
            gap_source=None,
            expected_observation=["HTTPUPGRADE-" + name],
            required_evidence=["command", "structured-assertions", "cleanup"]
            + ([] if name in LOCAL else ["peer-identity", "isolated-origins"]),
            prerequisites=["rust-toolchain"]
            if name in LOCAL
            else ["owned-host-only-container-network", "official-latest-peer"],
            runner="httpupgrade-gate",
            timeout_seconds=3600,
        )
        for name in GATES
    ]


def commands(name):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if name == "MEMORY":
        return [
            cargo
            + [
                arg
                for t in (
                    "httpupgrade_config",
                    "httpupgrade_memory",
                    "vmess_lifecycle",
                    "vmess_config",
                    "trojan",
                    "trojan_config",
                    "vless_config",
                    "vless_lifecycle",
                    "stream_foundations",
                    "stream_shutdown",
                )
                for arg in ("--test", t)
            ]
        ]
    if name == "FEATURES":
        return (
            [
                ["cargo", "check", "--locked", "--no-default-features"]
                + (["--features", f] if f else [])
                for f in ("", "stream-transport", "outbound-vmess", "outbound-trojan")
            ]
            + [
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--no-default-features",
                    "--features",
                    f + ",interop-test",
                    "--test",
                    "httpupgrade_config",
                    "--test",
                    "httpupgrade_memory",
                ]
                for f in ("outbound-vmess", "outbound-trojan")
            ]
            + [
                ["cargo", "test", "--locked", "--test", "feature_foundations"],
                cargo + ["--all-targets", "--no-run"],
            ]
        )
    return shared_commands(name) if name in {"QUALITY", "PLATFORMS"} else []
