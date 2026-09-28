import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import load_manifest, validate_results
from vcore_scripts.protocol_inputs import redact
from vcore_scripts.protocol_security_acceptance import rust_command
from vcore_scripts.protocol_shadowtls_acceptance import (
    expected_observation,
    fault_pass,
    local_pass,
    result,
    wire_pass,
)
from vcore_scripts.protocol_shadowtls_catalog import SS_CASES, commands, definitions


class ShadowTlsAcceptanceTest(unittest.TestCase):
    def test_local_command_identity_uses_the_same_redaction_as_the_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            for index, argv in enumerate(commands("QUALITY")):
                name = f"SHADOWTLS-QUALITY-{index}"
                (root / (name + ".log")).write_text("")
                records.append(
                    dict(
                        name=name,
                        command=[redact(v) for v in argv],
                        exit_code=0,
                        cleanup=True,
                        log=name + ".log",
                    )
                )
            self.assertTrue(local_pass("QUALITY", root, {"commands": records}))
            records[0]["command"] = ["true"]
            self.assertFalse(local_pass("QUALITY", root, {"commands": records}))

    def test_wire_proof_requires_all_algorithms_raw_events_and_actual_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = []
            for name in SS_CASES:
                observed = expected_observation("native_tcp", True)
                (root / (name + "-observations.json")).write_text(json.dumps(observed))
                (root / (name + "-events.jsonl")).write_text(
                    "".join(
                        json.dumps(
                            dict(
                                schema_version=1,
                                suite="SHADOWTLS",
                                assertion="native_tcp",
                                status=status,
                            )
                        )
                        + "\n"
                        for status in ("BEGIN", "PASS")
                    )
                )
                rows.append(
                    dict(
                        case_id=name,
                        command=rust_command("vless_public", "shadowtls::native_tcp"),
                        exit_code=0,
                        command_cleanup=True,
                        observations=observed,
                    )
                )
            self.assertTrue(wire_pass("NATIVE", root, {"cases": rows}))
            self.assertFalse(wire_pass("NATIVE", root, {"cases": rows[:-1]}))
            observed = dict(rows[0]["observations"], tcp_bytes_each_direction=0)
            rows[0]["observations"] = observed
            (root / (SS_CASES[0] + "-observations.json")).write_text(
                json.dumps(observed)
            )
            self.assertFalse(wire_pass("NATIVE", root, {"cases": rows}))

    def test_suite_is_registered_and_cannot_accept_a_partial_or_forged_result(self):
        cases = definitions()
        self.assertEqual(
            cases, [c for c in load_manifest() if c["stage"] == "SHADOWTLS"]
        )
        self.assertEqual(len(cases), 11)
        records = []
        for case in cases:
            record = result(case, True, True)
            self.assertEqual(record["scope"], "protocol-consumer")
            records.append(record)
        validate_results(cases, records)
        with self.assertRaises(ValueError):
            validate_results(cases, records[:-1])
        forged = copy.deepcopy(records)
        forged[0]["assertions"] = {}
        with self.assertRaises(ValueError):
            validate_results(cases, forged)

    def test_fault_proof_requires_actual_injection_hrr_or_closed_handshakes(self):
        for label, field in [
            ("fragment", "split_record"),
            ("hrr-wire", "hrr_seen"),
            ("business-mac", "injected"),
            ("cover-mac", "injected"),
        ]:
            self.assertFalse(fault_pass(label, [], []))
            self.assertTrue(fault_pass(label, [{field: True}], []))
            self.assertFalse(
                fault_pass(label, [{field: True, "upload_join_failed": True}], [])
            )
        events = [{"hello_seen": True}, {"client_closed": True}] * 2
        self.assertTrue(fault_pass("stall", events, []))
        self.assertFalse(fault_pass("stall", events[:-1], []))
        self.assertFalse(fault_pass("stall", events, [{"version": "TLSv1.3"}]))

    def test_no_implicit_uot_and_authentication_evidence_are_distinct_from_bulk(self):
        self.assertEqual(expected_observation("data", True)["udp_packets"], 500)
        self.assertEqual(expected_observation("native_tcp", True)["udp_packets"], 0)
        self.assertFalse(expected_observation("policy", False)["origin_connected"])
        self.assertEqual(expected_observation("corrupt", True)["delivered_bytes"], 0)
        self.assertFalse(
            expected_observation("native_udp_disabled", True)["udp_delivered"]
        )
        with self.assertRaises(ValueError):
            expected_observation("unknown", True)
