from __future__ import annotations

import copy
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from vcore_scripts.builds import CORE_DIR, DEFAULT_FEATURES
from vcore_scripts.protocol_evidence import load_manifest, select_cases
from vcore_scripts.protocol_trojan import CASES, native_events_pass
from vcore_scripts.protocol_trojan_acceptance import fields_report, native_results


class TrojanEvidenceTest(unittest.TestCase):
    def test_removed_or_downgraded_required_case_is_rejected(self):
        original = load_manifest()
        index = next(i for i, case in enumerate(original) if case["stage"] == "TROJAN")
        for downgrade in (True, False):
            cases = copy.deepcopy(original)
            if downgrade:
                cases[index]["required"] = False
            else:
                cases.pop(index)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "cases.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "executable-case-manifest",
                            "cases": cases,
                        }
                    )
                )
                with self.assertRaises(ValueError):
                    load_manifest(path)

    def test_native_summary_cannot_hide_missing_events_or_unjoined_processes(self):
        case = next(
            case for case in load_manifest() if case["case_id"] == "TROJAN-M-TCP"
        )
        record = {
            "case_id": case["case_id"],
            "status": "PASS",
            "mode": "tcp",
            "exit_code": 0,
            "command_cleanup": True,
            "cleanup": {"joined": True},
        }
        report = {"source_unchanged": True, "cases": [record]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(native_results([case], report, root)[0]["status"], "FAIL")
            events = [
                {
                    "suite": "TROJAN-NATIVE",
                    "assertion": "public_trojan_native_base",
                    "schema_version": 1,
                    "status": status,
                }
                for status in ("BEGIN", "PASS")
            ]
            (root / (case["case_id"] + "-events.jsonl")).write_text(
                "".join(json.dumps(event) + "\n" for event in events)
            )
            self.assertEqual(native_results([case], report, root)[0]["status"], "PASS")
            for update in [
                {"exit_code": 124},
                {"command_cleanup": False},
                {"cleanup": {"joined": False}},
                {"status": "BLOCKED"},
            ]:
                invalid = copy.deepcopy(report)
                invalid["cases"][0].update(update)
                self.assertEqual(
                    native_results([case], invalid, root)[0]["status"], "FAIL"
                )
            report["source_unchanged"] = False
            self.assertEqual(native_results([case], report, root)[0]["status"], "FAIL")
            report["cases"].append(record)
            with self.assertRaises(ValueError):
                native_results([case], report, root)

    def test_partial_case_selection_never_signs_off_fields(self):
        case = next(case for case in load_manifest() if case["case_id"] == "TROJAN-CFG")
        result = fields_report([case], [{"case_id": case["case_id"], "status": "PASS"}])
        self.assertEqual(len(result["fields"]), 18)
        self.assertTrue(all(field["status"] == "NOT RUN" for field in result["fields"]))

    def test_default_and_packaged_builds_enable_trojan(self):
        features = tomllib.loads((CORE_DIR / "Cargo.toml").read_text())["features"]
        self.assertIn("outbound-trojan", features["default"])
        self.assertIn("outbound-trojan", features["tun"])
        self.assertIn("outbound-trojan", DEFAULT_FEATURES.split(","))

    def test_every_native_case_is_required_and_mapped_to_fields(self):
        cases = select_cases(load_manifest(), stage="TROJAN")
        native = {
            case["case_id"]: case for case in cases if case["runner"] == "native-trojan"
        }
        self.assertEqual(set(native), set(CASES))
        for identifier, (kind, mode, test) in CASES.items():
            self.assertEqual(native[identifier]["peer_kind"], kind)
            self.assertEqual(
                native[identifier]["peer_config"], {"mode": mode, "test": test}
            )
            self.assertTrue(native[identifier]["row_ids"])
            if kind != "M":
                self.assertTrue(native[identifier]["gap_source"])

    def test_zero_tests_partial_duplicate_wrong_or_failed_events_fail(self):
        test = "public_trojan_native_base"
        events = [
            {
                "suite": "TROJAN-NATIVE",
                "assertion": test,
                "schema_version": 1,
                "status": status,
            }
            for status in ("BEGIN", "PASS")
        ]
        self.assertTrue(native_events_pass(events, test))
        for invalid in [[], events[:1], events + events, events[::-1]]:
            self.assertFalse(native_events_pass(invalid, test))
        for update in [
            {"status": "FAIL"},
            {"assertion": "other"},
            {"schema_version": 2},
        ]:
            invalid = copy.deepcopy(events)
            invalid[1].update(update)
            self.assertFalse(native_events_pass(invalid, test))

    def test_lifecycle_requires_twenty_full_quiet_cycles(self):
        test = "runtime::public_trojan_native_lifecycle"
        events = [
            {
                "suite": "TROJAN-NATIVE",
                "assertion": test,
                "schema_version": 1,
                "status": status,
            }
            for status in ("BEGIN", "PASS")
        ]
        cycles = [
            {
                "suite": "TROJAN-LIFE-CYCLE",
                "assertion": "stop_and_remain_quiet",
                "schema_version": 1,
                "status": status,
                "seconds": 5.1 if status == "PASS" else 0,
            }
            for _ in range(20)
            for status in ("BEGIN", "PASS")
        ]
        self.assertTrue(native_events_pass(events + cycles, test))
        self.assertFalse(native_events_pass(events + cycles[:-2], test))
        cycles[-1]["seconds"] = 4.9
        self.assertFalse(native_events_pass(events + cycles, test))
