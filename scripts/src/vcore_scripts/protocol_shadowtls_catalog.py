"""Frozen ShadowTLS v3 acceptance groups, not a duplicate field matrix."""

from __future__ import annotations

import sys

from .protocol_completion_peers import CASES

SS_CASES = tuple(c.identifier for c in CASES if c.shadow_tls and not c.uot)
FAULTS = (
    "fragment",
    "hrr-wire",
    "cover-mac",
    "business-mac",
    "business-truncated",
    "stall",
    "native-udp-disabled",
)
GATES = {
    "MEMORY": "stream",
    "FEATURES": "configuration",
    "QUALITY": "regression",
    "PLATFORMS": "regression",
    "FINGERPRINT": "regression",
    "MIHOMO-DATA": "interop",
    "MIHOMO-POLICY": "interop",
    "MIHOMO-FAULT": "interop",
    "NATIVE": "interop",
    "SHARED": "regression",
    "BARE-SS": "regression",
}
LOCAL = {"MEMORY", "FEATURES", "QUALITY", "PLATFORMS", "FINGERPRINT"}
SHARED = {
    **{
        p: dict(
            client_fingerprint=p,
            selected=[
                "VLESS-TCP-TLS-BASE",
                "VLESS-TCP-TLS-NEG",
                "VLESS-TCP-REALITY-BASE",
                "VLESS-TCP-REALITY-NEG",
                "FINGERPRINT-ANYTLS",
            ],
        )
        for p in ("none", "chrome")
    },
    "jls": dict(
        jls=True,
        client_fingerprint="chrome",
        selected=["SECURITY-JLS-TCP-BASE", "SECURITY-JLS-TCP-AUTH"],
    ),
}
MEMORY_EVENTS = {
    **{("SHADOWTLS-CFG", n): 1 for n in ("policy", "reject", "feature")},
    **{("SHADOWTLS-STREAM", n): 1 for n in ("cancelled_hello", "invalid_record")},
    **{
        ("SHADOWTLS-UNIT", n): 1
        for n in (
            "native_signature",
            "native_finished",
            "stream_io",
            "read_cancel",
            "close_deadline",
        )
    },
}


def definitions():
    return [
        dict(
            case_id="SHADOWTLS-" + name,
            stage="SHADOWTLS",
            substage="SHADOWTLS." + category,
            required=True,
            row_ids=[],
            protocol="ss",
            network="tcp/native-udp",
            security="shadowtls-v3",
            udp_codec="ss2022",
            field_values={},
            outer_family="IPv4",
            inner_family="IPv4/IPv6/domain",
            target_type="memory-only/build" if name in LOCAL else "isolated origin",
            upstream_graph="existing-controlled-connector",
            peer_kind="unit" if name in LOCAL else "SS" if name == "NATIVE" else "M",
            peer_config={"group": name},
            gap_source=None,
            expected_observation=["SHADOWTLS-" + name],
            required_evidence=["command", "structured-assertions", "cleanup"]
            + ([] if name in LOCAL else ["peer-identity", "isolated-origins"]),
            prerequisites=["rust-toolchain"]
            if name in LOCAL
            else ["owned-host-only-container-network", "official-latest-peer"],
            runner="shadowtls-gate",
            timeout_seconds=3600,
        )
        for name, category in GATES.items()
    ]


def commands(name):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if name == "MEMORY":
        return [
            cargo
            + [
                arg
                for target in (
                    "shadowtls_config",
                    "shadowtls_stream",
                    "shadowsocks_backpressure",
                    "jls_config",
                    "reality_config",
                )
                for arg in ("--test", target)
            ],
            cargo + ["--lib", "security::shadow_tls_tests::"],
            cargo + ["--lib", "security::tls::tests::"],
        ]
    if name == "FEATURES":
        return [
            [
                "cargo",
                "check",
                "--locked",
                "--no-default-features",
                "--features",
                features,
            ]
            for features in (
                "outbound-shadowsocks",
                "shadow-tls-v3",
                "outbound-shadowsocks,shadow-tls-v3",
            )
        ] + [
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "outbound-shadowsocks,interop-test",
                "--test",
                "shadowtls_config",
            ],
            ["cargo", "test", "--locked", "--test", "feature_foundations"],
            cargo + ["--all-targets", "--no-run"],
        ]
    if name == "QUALITY":
        return [
            ["cargo", "fmt", "--all", "--", "--check"],
            [
                "cargo",
                "clippy",
                "--locked",
                "--all-features",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests"],
            ["ruff", "check", "scripts"],
            ["ruff", "format", "--check", "scripts"],
            ["git", "diff", "--check"],
        ]
    if name == "PLATFORMS":
        return [["vcore-scripts", "build", target] for target in ("apple", "android")]
    if name == "FINGERPRINT":
        return [
            [
                sys.executable,
                "-m",
                "vcore_scripts.protocol_fingerprint_shape",
                "{output}/fingerprint",
            ]
        ]
    return []
