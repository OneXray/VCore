"""Fail-closed N5 coverage and fixture checks; no host listeners."""

import copy
import unittest

from vcore_scripts.protocol_xhttp_acceptance import (
    FIELD_IDS,
    NATIVE,
    OBSERVATIONS,
    definitions,
    gate_result,
    native_results,
)
from vcore_scripts.protocol_xhttp_fields import events_pass, public_events_pass


def pair(suite, assertion):
    return [
        dict(schema_version=1, suite=suite, assertion=assertion, status=s)
        for s in ("BEGIN", "PASS")
    ]


class XhttpAcceptanceTest(unittest.TestCase):
    def test_frozen_catalog_has_all_rows_modes_and_mux_wires(self):
        cases = definitions()
        self.assertEqual(len(FIELD_IDS), 57)
        self.assertEqual(len(cases), len({c["case_id"] for c in cases}))
        self.assertEqual(FIELD_IDS, set().union(*(set(c["row_ids"]) for c in cases)))
        for version in ("h1", "h2", "h1c", "h2c", "h1r", "h2r", "h3"):
            for mode in ("stream-one", "stream-up", "packet-up"):
                self.assertTrue(
                    any(
                        v == f"{version}-{mode}-headers" and test == "public_base"
                        for v, test in NATIVE.values()
                    )
                )
            for protocol in ("h2mux", "smux", "yamux"):
                self.assertTrue(
                    any(
                        v.startswith(f"{version}-mux-{protocol}-")
                        and test == "public_base"
                        for v, test in NATIVE.values()
                    )
                )
        for version in ("h1r", "h2r"):
            for field in ("public-key", "short-id"):
                self.assertIn(
                    (
                        f"{version}-reject-download-{field}",
                        "security::native_xhttp_security",
                    ),
                    NATIVE.values(),
                )

    def test_unknown_duplicate_wrong_suite_and_partial_events_fail(self):
        observed = pair("N5-XHTTP", "native_xhttp_request_fields")
        self.assertTrue(events_pass(observed, "native_xhttp_request_fields"))
        for bad in (
            [],
            observed[:1],
            observed * 2,
            observed + pair("extra", "unknown"),
        ):
            self.assertFalse(events_pass(bad, "native_xhttp_request_fields"))
        public = pair("N5-PUBLIC", "runtime::public_graph")
        self.assertTrue(public_events_pass(public, "runtime::public_graph"))
        self.assertFalse(
            public_events_pass(
                public + pair("N5-BASE", "unknown"), "runtime::public_graph"
            )
        )
        bad = copy.deepcopy(public)
        bad[1]["schema_version"] = 2
        self.assertFalse(public_events_pass(bad, "runtime::public_graph"))

    def test_unit_gate_requires_every_frozen_assertion_and_successful_command(self):
        case = next(c for c in definitions() if c["case_id"] == "N5-CFG")
        events = sum((pair("N5-UNIT", name) for name in OBSERVATIONS["N5-CFG"]), [])
        records = [dict(exit_code=0, cleanup=True)]
        self.assertEqual(gate_result(case, records, events)["status"], "PASS")
        for bad in ([], events[:-1], events + events[:2]):
            self.assertEqual(gate_result(case, records, bad)["status"], "FAIL")
        self.assertEqual(
            gate_result(case, [dict(exit_code=1, cleanup=True)], events)["status"],
            "FAIL",
        )

    def test_native_missing_and_duplicate_records_are_not_success(self):
        case = next(c for c in definitions() if c["case_id"] in NATIVE)
        for records in ([], [dict(case_id=case["case_id"])] * 2):
            with self.assertRaises(ValueError):
                native_results([case], dict(cases=records), None)
        self.assertEqual(
            native_results([case], dict(cases=[]), None, allow_partial=True), []
        )
        for records in ([dict(case_id="unknown")], [dict(case_id=case["case_id"])] * 2):
            with self.assertRaises(ValueError):
                native_results([case], dict(cases=records), None, allow_partial=True)


if __name__ == "__main__":
    unittest.main()
