import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import load_manifest, validate_results
from vcore_scripts.protocol_httpupgrade import expected_observation, selection
from vcore_scripts.protocol_httpupgrade_acceptance import wire_pass
from vcore_scripts.protocol_httpupgrade_catalog import WIRE, definitions, wire_cases
from vcore_scripts.protocol_security_acceptance import result, rust_command


class HttpUpgradeAcceptanceTest(unittest.TestCase):
    def test_required_groups_are_registered_and_cannot_be_omitted(self):
        cases = definitions()
        self.assertEqual(len(cases), 13)
        self.assertEqual(
            cases, [c for c in load_manifest() if c["stage"] == "HTTPUPGRADE"]
        )
        rows = [result(c, True, True) for c in cases]
        validate_results(cases, rows)
        with self.assertRaises(ValueError):
            validate_results(cases, rows[:-1])
        rows[0]["assertions"] = {}
        with self.assertRaises(ValueError):
            validate_results(cases, rows)

    def test_runner_matches_independent_six_mode_wire_matrix(self):
        counts = [6, 14, 2, 12, 16, 16, 6]
        for name, count in zip(WIRE, counts, strict=True):
            self.assertEqual(len(wire_cases(name)), count)
            self.assertEqual(
                [(r[0], r[3]) for r in selection(name.lower())], wire_cases(name)
            )

    def test_raw_evidence_rejects_missing_cases_forged_bytes_and_wrong_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in WIRE:
                rows = []
                for identifier, consumer in wire_cases(name):
                    node = dict(
                        type="vmess" if identifier.startswith("vmess") else "trojan"
                    )
                    node["packet-encoding"] = identifier.rsplit("-", 1)[-1]
                    if consumer == "close":
                        reference = dict(tail_hex="", terminated=True, variant="plain")
                        for suffix in ("-close-reference.json", "-close-command.log"):
                            (root / (identifier + suffix)).write_text(
                                json.dumps(reference)
                            )
                        observed = dict(tail_hex="", terminated=True, stop_idle=True)
                    else:
                        observed = expected_observation(
                            consumer, node, "XR" if name == "UDP-DOMAIN" else "M"
                        )
                    (root / (identifier + "-observations.json")).write_text(
                        json.dumps(observed)
                    )
                    events = []
                    for suite, assertion in [("HTTPUPGRADE-PUBLIC", consumer)] + (
                        [("HTTPUPGRADE-BASE", "tcp_10mib_both_directions")] * 3
                        if consumer == "tcp"
                        else []
                    ):
                        events += [
                            dict(
                                schema_version=1,
                                suite=suite,
                                assertion=assertion,
                                status=s,
                            )
                            for s in ("BEGIN", "PASS")
                        ]
                    (root / (identifier + "-events.jsonl")).write_text(
                        "".join(json.dumps(e) + "\n" for e in events)
                    )
                    rows.append(
                        dict(
                            case_id=identifier,
                            command=rust_command(
                                "vless_public", "httpupgrade::" + consumer
                            ),
                            exit_code=0,
                            command_cleanup=True,
                            observations=observed,
                        )
                    )
                report = dict(cases=rows)
                self.assertTrue(wire_pass(name, root, report))
                self.assertFalse(wire_pass(name, root, dict(cases=rows[:-1])))
                for key, value in (
                    ("exit_code", True),
                    ("command_cleanup", False),
                    ("observations", {}),
                    ("command", []),
                ):
                    broken = copy.deepcopy(report)
                    broken["cases"][0][key] = value
                    self.assertFalse(wire_pass(name, root, broken))


if __name__ == "__main__":
    unittest.main()
