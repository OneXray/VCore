"""Explicit memory-only/build commands; never run historical host-server suites."""

from __future__ import annotations

import sys

from .builds import DEFAULT_FEATURES
from .protocol_hysteria2_acceptance import commands as n6_commands
from .protocol_n7_acceptance import commands as n7_commands

FEATURE_TEST = (
    "runtime::tests::n9_feature_admission_is_explicit_without_opening_sockets"
)
FEATURES = [
    "outbound-" + p
    for p in (
        "socks5",
        "anytls",
        "shadowsocks",
        "trojan",
        "vmess",
        "vless",
        "hysteria2",
    )
]


def commands(identifier):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if identifier in {"N9-DEBUG", "N9-RELEASE"}:
        selected = (
            n7_commands("N7-CFG")
            + n6_commands("N6-REGRESSION")
            + n6_commands("N6-UNIT")
            + n6_commands("N6-CFG")
            + [
                cargo + ["--test", "shadowsocks_backpressure"],
                cargo + ["--test", "hysteria2_packet_ids"],
                cargo + ["--lib", "outbound::shadowsocks::tests::official_tcp_"],
                cargo + ["--lib", "outbound::anytls::"],
                cargo + ["--lib", FEATURE_TEST, "--", "--exact"],
            ]
        )
        return (
            [argv[:2] + ["--release"] + argv[2:] for argv in selected]
            if identifier == "N9-RELEASE"
            else selected
        )
    if identifier == "N9-QUALITY":
        return n6_commands("N6-QUALITY") + [
            [
                "sh",
                "-n",
                "tests/run_xray_interop.sh",
                "tests/run_anytls_interop.sh",
                "tests/run_mihomo_interop.sh",
            ],
            ["vcore-scripts", "check", "protocol-coverage", "--catalog-only"],
            ["vcore-scripts", "build", "apple"],
            ["vcore-scripts", "build", "android"],
        ]
    if identifier == "N9-FEATURES":
        return (
            [
                ["cargo", "check", "--locked", "--no-default-features", "--lib"]
                + (["--features", f] if f else [])
                for f in [
                    "",
                    *FEATURES,
                    "stream-transport",
                    "quic-transport",
                    "tun",
                    "ffi",
                ]
            ]
            + [
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--no-default-features",
                    "--features",
                    f,
                    "--lib",
                    FEATURE_TEST,
                    "--",
                    "--exact",
                ]
                for f in FEATURES
            ]
            + [
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--no-default-features",
                    "--test",
                    "feature_foundations",
                    "--test",
                    "hysteria2_config",
                ],
                ["cargo", "check", "--locked", "--lib"],
                cargo + ["--all-targets", "--no-run"],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--release",
                    "--no-default-features",
                    "--features",
                    DEFAULT_FEATURES,
                    "--lib",
                ],
            ]
        )
    if identifier == "N9-SCRIPTS":
        return [
            [
                sys.executable,
                "-m",
                "vcore_scripts.protocol_script_tests",
                "{output}/script-tests.json",
            ]
        ]
    return []


def passed(identifier, records, events, script=None):
    from .protocol_hysteria2_catalog import CFG, UNIT, assertions_pass
    from .protocol_n7_units import TESTS
    from .protocol_n9_catalog import PROTOCOLS

    good = bool(records) and all(
        type(r.get("exit_code")) is int
        and r["exit_code"] == 0
        and r.get("cleanup") is True
        for r in records
    )
    if identifier in {"N9-DEBUG", "N9-RELEASE"}:
        expected = {
            ("N7-CONFIG-TLS", name): 1 for names in TESTS.values() for name in names
        }
        expected.update({("N6-CFG", name): 1 for name in CFG})
        expected.update({("N6-UNIT", name): 1 for name in UNIT})
        expected.update({("N9-FEATURE", name): 1 for name in PROTOCOLS})
        expected[("N9-ADAPTER", "growing_caller_buffer")] = 1
        expected[("N9-ADAPTER", "server_first_buffered_upstream")] = 1
        expected[("N9-ADAPTER", "hysteria2_fragment_id_reuse")] = 1
        selected = [
            e
            for e in events
            if e.get("suite")
            in {"N7-CONFIG-TLS", "N6-CFG", "N6-UNIT", "N9-FEATURE", "N9-ADAPTER"}
        ]
        good &= assertions_pass(selected, expected) and all(
            e.get("status") in {"BEGIN", "PASS"} for e in events
        )
    if identifier == "N9-FEATURES":
        good &= assertions_pass(
            [e for e in events if e.get("suite") == "N9-FEATURE"],
            {("N9-FEATURE", p): 7 for p in PROTOCOLS},
        )
    if identifier == "N9-SCRIPTS":
        rows = (script or {}).get("cases", [])
        names = [r.get("test") for r in rows]
        required = {
            "test_protocol_n9.N9AcceptanceTest." + name
            for name in (
                "test_n9_consumer_results_keep_the_manifest_scope",
                "test_pair_evidence_requires_each_real_path_and_original_assertions",
                "test_list_contains_all_ordered_pairs_and_remaining_gates",
                "test_pressure_evidence_is_recomputed_not_inferred",
                "test_native_source_identity_and_cleanup_are_required",
            )
        }
        good &= (
            bool(rows)
            and len(names) == len(set(names)) == (script or {}).get("tests_run")
            and required <= set(names)
            and all(r.get("status") == "PASS" for r in rows)
        )
    return bool(good)
