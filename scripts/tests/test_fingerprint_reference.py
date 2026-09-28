"""Offline checks of the selected-profile reference driver interface."""

import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.builds import CORE_DIR
from vcore_scripts.protocol_fingerprint_reference import (
    check_reference_report,
    reference_cases,
    run_reference,
)


class FingerprintReferenceTest(unittest.TestCase):
    def test_partial_or_unclean_reference_is_not_a_completed_baseline(self):
        for changed in (
            {"selection": "partial"},
            {"cleanup": False},
            {"source_unchanged": False},
        ):
            report = dict(
                scope="selected-v1",
                status="CAPTURED",
                selection="full",
                cleanup=True,
                source_unchanged=True,
                cases=[],
            )
            report.update(changed)
            with self.assertRaises(ValueError):
                check_reference_report(report)

    def test_invalid_selection_has_no_filesystem_or_network_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            for cases in (
                [],
                ["missing"],
                ["FINGERPRINT-REFERENCE-chrome-tcp-16-0"] * 2,
            ):
                with self.assertRaises(ValueError):
                    run_reference(output, cases)
                self.assertFalse(output.exists())

    def test_catalog_covers_selected_names_contexts_and_successive_connections(self):
        cases = reference_cases()
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        self.assertEqual(
            {case["profile"] for case in cases},
            {
                "none",
                "chrome",
                "chrome120",
                "firefox",
                "firefox120",
                "safari",
                "safari16",
            },
        )
        for profile in ("chrome", "chrome120", "firefox", "safari"):
            selected = [c for c in cases if c["profile"] == profile]
            self.assertEqual(
                {c["context"] for c in selected},
                {"tcp", "ws", "grpc", "reality", "tls12", "tls13"},
            )
            self.assertEqual({c["attempt"] for c in selected}, {0, 1})
        self.assertEqual({c["sni_length"] for c in cases}, {16, 80})
        catalog = {case["id"]: case for case in cases}
        samples = json.loads(
            (CORE_DIR / "tests/fingerprints/mihomo-selected-v1.json").read_text()
        )["samples"]
        for sample in samples:
            with self.subTest(sample=sample["case_id"]):
                case = catalog[sample["case_id"]]
                for field in ("profile", "context", "template"):
                    self.assertEqual(sample[field], case[field])


if __name__ == "__main__":
    unittest.main()
