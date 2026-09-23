from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import (
    load_manifest,
    rust_results,
    select_cases,
    validate_results,
)


class ProtocolEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.cases = select_cases(load_manifest(), stage="N1")
        self.results = [
            {
                "case_id": case["case_id"],
                "status": "PASS",
                "scope": "foundation-only",
                "assertions": dict.fromkeys(case["expected_observation"], True),
                "evidence": list(case["required_evidence"]),
                "cleanup": True,
                "command_exit_code": 0,
                "row_ids": case["row_ids"],
                "peer_kind": case["peer_kind"],
            }
            for case in self.cases
        ]

    def test_complete_results_are_accepted_as_foundation_not_protocol_field_signoff(
        self,
    ):
        validate_results(self.cases, self.results)

    def test_missing_duplicate_unknown_and_empty_required_cases_fail(self):
        for results in [
            self.results[:-1],
            self.results + [self.results[0]],
            self.results + [{"case_id": "unknown"}],
        ]:
            with self.subTest(results=len(results)), self.assertRaises(ValueError):
                validate_results(self.cases, results)
        with self.assertRaises(ValueError):
            validate_results([], [])
        with self.assertRaises(ValueError):
            select_cases(load_manifest(), stage="N8")

    def test_failure_blocked_not_run_timeout_and_cleanup_never_become_pass(self):
        for update in [
            {"status": status} for status in ["FAIL", "BLOCKED", "NOT RUN"]
        ] + [{"cleanup": False}, {"command_exit_code": 124}]:
            results = copy.deepcopy(self.results)
            results[0].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate_results(self.cases, results)

    def test_cfg_only_incomplete_or_false_assertions_are_not_behavior_evidence(self):
        for update in [
            {"evidence": ["CFG"]},
            {"assertions": {}},
            {"assertions": {key: False for key in self.results[0]["assertions"]}},
            {"row_ids": ["T08"]},
        ]:
            results = copy.deepcopy(self.results)
            results[0].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate_results(self.cases, results)

    def test_manifest_rejects_duplicate_ids_and_unknown_rows(self):
        manifest = load_manifest()
        for mutation in ["duplicate", "unknown-row"]:
            data = {
                "schema_version": 1,
                "kind": "executable-case-manifest",
                "cases": copy.deepcopy(manifest),
            }
            if mutation == "duplicate":
                data["cases"].append(data["cases"][0])
            else:
                data["cases"][0]["row_ids"] = ["not-a-field"]
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "cases.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    load_manifest(path)

    def test_resource_claims_require_idle_structured_snapshots(self):
        case = next(case for case in self.cases if case["case_id"] == "N1-RESOURCES")
        events = [
            {
                "schema_version": 1,
                "suite": case["case_id"],
                "assertion": name,
                "status": status,
            }
            for name in case["expected_observation"]
            for status in ["BEGIN", "PASS"]
        ]
        self.assertEqual(rust_results(case, events, 0)["status"], "FAIL")

    def test_malformed_or_unknown_assertions_never_become_pass(self):
        case = self.cases[0]
        events = [
            {
                "schema_version": 1,
                "suite": case["case_id"],
                "assertion": name,
                "status": status,
            }
            for name in case["expected_observation"]
            for status in ["BEGIN", "PASS"]
        ]
        self.assertEqual(rust_results(case, events, 0)["status"], "PASS")
        events[0]["schema_version"] = 99
        self.assertEqual(rust_results(case, events, 0)["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
