import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import load_manifest, validate_results
from vcore_scripts.protocol_security_acceptance import result, rust_command
from vcore_scripts.protocol_uot import expected_observation
from vcore_scripts.protocol_uot_acceptance import wire_pass
from vcore_scripts.protocol_uot_catalog import definitions, wire_cases


class UotAcceptanceTest(unittest.TestCase):
    def test_registered_groups_use_real_result_keys_and_require_every_group(self):
        cases = definitions()
        self.assertEqual(cases, [c for c in load_manifest() if c["stage"] == "UOT"])
        self.assertEqual(len(cases), 11)
        results = [result(c, True, True) for c in cases]
        validate_results(cases, results)
        with self.assertRaises(ValueError):
            validate_results(cases, results[:-1])
        forged = copy.deepcopy(results)
        forged[0]["assertions"] = {}
        with self.assertRaises(ValueError):
            validate_results(cases, forged)

    def test_all_six_combinations_need_raw_packets_events_and_no_native_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rows = []
            for identifier, consumer in wire_cases("MIHOMO-DIRECT"):
                observation = expected_observation(consumer)
                (root / (identifier + "-observations.json")).write_text(
                    json.dumps(observation)
                )
                (root / (identifier + "-events.jsonl")).write_text(
                    "".join(
                        json.dumps(
                            dict(
                                schema_version=1,
                                suite="UOT-PUBLIC",
                                assertion=consumer,
                                status=status,
                            )
                        )
                        + "\n"
                        for status in ("BEGIN", "PASS")
                    )
                )
                rows.append(
                    dict(
                        case_id=identifier,
                        command=rust_command("vless_public", "uot::" + consumer),
                        exit_code=0,
                        command_cleanup=True,
                        observations=observation,
                        listener_native_udp=False,
                    )
                )
            report = dict(cases=rows, tcp_only_upstream=False)
            self.assertEqual(len(rows), 6)
            self.assertTrue(wire_pass("MIHOMO-DIRECT", root, report))
            self.assertFalse(wire_pass("MIHOMO-SOCKS5", root, report))
            self.assertFalse(
                wire_pass("MIHOMO-DIRECT", root, dict(report, cases=rows[:-1]))
            )
            rows[0]["listener_native_udp"] = True
            self.assertFalse(wire_pass("MIHOMO-DIRECT", root, report))
            rows[0]["listener_native_udp"] = False
            rows[0]["observations"]["native_udp_packets"] = 1
            self.assertFalse(wire_pass("MIHOMO-DIRECT", root, report))

    def test_negative_and_group_cases_are_not_counted_as_data(self):
        self.assertEqual(len(wire_cases("MIHOMO-NEGATIVE")), 9)
        self.assertEqual(len(wire_cases("NATIVE-UNSUPPORTED")), 3)
        self.assertTrue(all(test == "group" for _, test in wire_cases("MIHOMO-GROUPS")))
        self.assertEqual(expected_observation("rejected")["origin_packets"], 0)
        self.assertEqual(expected_observation("data")["udp_sizes"][-1], 16384)
        with self.assertRaises(ValueError):
            expected_observation("unsupported")
