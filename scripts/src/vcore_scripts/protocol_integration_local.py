"""Explicit memory-only/build commands; never run historical host-server suites."""

from __future__ import annotations

import sys

from .core_checks import commands as core_commands
from .protocol_hysteria2_acceptance import commands as hysteria2_commands


def commands(identifier):
    if identifier in {
        "INTEGRATION-DEBUG",
        "INTEGRATION-RELEASE",
        "INTEGRATION-FEATURES",
    }:
        return core_commands(identifier.removeprefix("INTEGRATION-").lower())
    if identifier == "INTEGRATION-QUALITY":
        # Behavioral integration also runs with the approved local boring fork.
        # Strict release-source audit remains a separate mandatory PR/delivery gate.
        return [
            row
            for row in hysteria2_commands("HYSTERIA2-QUALITY")
            if row != ["vcore-scripts", "check", "tls-dependencies"]
        ] + [
            ["vcore-scripts", "check", "protocol-coverage", "--catalog-only"],
            ["vcore-scripts", "build", "apple"],
            ["vcore-scripts", "build", "android"],
        ]
    if identifier == "INTEGRATION-SCRIPTS":
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
    from .protocol_integration_catalog import PROTOCOLS
    from .protocol_security_units import TESTS

    good = bool(records) and all(
        type(r.get("exit_code")) is int
        and r["exit_code"] == 0
        and r.get("cleanup") is True
        for r in records
    )
    if identifier in {"INTEGRATION-DEBUG", "INTEGRATION-RELEASE"}:
        expected = {
            ("SECURITY-CONFIG-TLS", name): 1
            for names in TESTS.values()
            for name in names
        }
        expected.update({("HYSTERIA2-CFG", name): 1 for name in CFG})
        expected.update({("HYSTERIA2-UNIT", name): 1 for name in UNIT})
        expected.update({("INTEGRATION-FEATURE", name): 1 for name in PROTOCOLS})
        expected[("INTEGRATION-ADAPTER", "growing_caller_buffer")] = 1
        expected[("INTEGRATION-ADAPTER", "server_first_buffered_upstream")] = 1
        expected[("INTEGRATION-ADAPTER", "hysteria2_fragment_id_reuse")] = 1
        selected = [
            e
            for e in events
            if e.get("suite")
            in {
                "SECURITY-CONFIG-TLS",
                "HYSTERIA2-CFG",
                "HYSTERIA2-UNIT",
                "INTEGRATION-FEATURE",
                "INTEGRATION-ADAPTER",
            }
        ]
        good &= assertions_pass(selected, expected) and all(
            e.get("status") in {"BEGIN", "PASS"} for e in events
        )
    if identifier == "INTEGRATION-FEATURES":
        good &= assertions_pass(
            [e for e in events if e.get("suite") == "INTEGRATION-FEATURE"],
            {("INTEGRATION-FEATURE", p): 8 for p in PROTOCOLS},
        )
    if identifier == "INTEGRATION-SCRIPTS":
        rows = (script or {}).get("cases", [])
        names = [r.get("test") for r in rows]
        required = {
            "test_protocol_integration.IntegrationAcceptanceTest." + name
            for name in (
                "test_integration_consumer_results_keep_the_manifest_scope",
                "test_pair_evidence_requires_each_real_path_and_original_assertions",
                "test_list_contains_all_ordered_pairs_and_remaining_gates",
                "test_pressure_evidence_is_recomputed_not_inferred",
                "test_native_source_identity_and_cleanup_are_required",
                "test_integration_quality_separates_release_source_policy",
            )
        }
        good &= (
            bool(rows)
            and len(names) == len(set(names)) == (script or {}).get("tests_run")
            and required <= set(names)
            and all(r.get("status") == "PASS" for r in rows)
        )
    return bool(good)
