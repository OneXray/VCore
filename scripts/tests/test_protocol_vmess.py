"""Offline evidence validation: no protocol listener or origin is launched."""

from __future__ import annotations

import copy
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from vcore_scripts.builds import CORE_DIR, DEFAULT_FEATURES
from vcore_scripts.protocol_evidence import RESOURCE_KINDS, load_manifest
from vcore_scripts.protocol_vmess_acceptance import (
    FIELD_IDS,
    NATIVE,
    OBSERVATIONS,
    REQUIRED_IDS,
    definitions,
    fields_report,
    gate_result,
    native_results,
)
from vcore_scripts.protocol_vmess_public import events_pass


def pair(suite, name):
    return [
        dict(schema_version=1, suite=suite, assertion=name, status=status)
        for status in ("BEGIN", "PASS")
    ]


class VmessEvidenceTest(unittest.TestCase):
    def test_archived_host_diagnostics_fail_before_any_output_or_peer(self):
        from vcore_scripts.protocol_vmess_close import run as close
        from vcore_scripts.protocol_vmess_udp_diagnostic import run as udp

        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "must-not-exist"
            for run in (close, udp):
                with self.assertRaisesRegex(RuntimeError, "BLOCKED"):
                    run(output)
                self.assertFalse(output.exists())

    def test_required_manifest_cannot_drop_or_downgrade_behavior(self):
        original = load_manifest()
        index = next(i for i, case in enumerate(original) if case["stage"] == "N3")
        for mutation in ("drop", "required", "observation", "row"):
            cases = copy.deepcopy(original)
            if mutation == "drop":
                cases.pop(index)
            elif mutation == "required":
                cases[index]["required"] = False
            elif mutation == "observation":
                cases[index]["expected_observation"] = ["always-green"]
            else:
                cases[index]["row_ids"] = ["VM01"]
            with tempfile.TemporaryDirectory() as root:
                path = Path(root) / "cases.json"
                path.write_text(
                    json.dumps(
                        dict(
                            schema_version=1,
                            kind="executable-case-manifest",
                            cases=cases,
                        )
                    )
                )
                with self.assertRaises(ValueError):
                    load_manifest(path)

    def test_fields_require_complete_native_and_public_evidence(self):
        cases = definitions()
        self.assertEqual({c["case_id"] for c in cases}, REQUIRED_IDS)
        self.assertEqual(
            {c["case_id"] for c in cases if c["runner"] == "native-vmess"}, set(NATIVE)
        )
        results = [dict(case_id=c["case_id"], status="PASS") for c in cases]
        fields = fields_report(cases, results)["fields"]
        self.assertEqual({f["row_id"] for f in fields}, FIELD_IDS)
        self.assertTrue(all(f["status"] == "PASS" for f in fields))
        for bad in (
            results[:-1],
            results[:-1] + [dict(case_id=results[-1]["case_id"], status="NOT RUN")],
        ):
            self.assertTrue(
                all(
                    f["status"] == "NOT RUN"
                    for f in fields_report(cases, bad)["fields"]
                )
            )
        features = tomllib.loads((CORE_DIR / "Cargo.toml").read_text())["features"]
        for enabled in (
            features["default"],
            features["tun"],
            DEFAULT_FEATURES.split(","),
        ):
            self.assertIn("outbound-vmess", enabled)

    def test_zero_partial_duplicate_failed_or_unjoined_rust_gate_is_not_pass(self):
        cases = {c["case_id"]: c for c in definitions()}
        for identifier, names in OBSERVATIONS.items():
            case = cases[identifier]
            events = [e for name in names for e in pair(identifier, name)]
            commands = [dict(exit_code=0, cleanup=True)]
            self.assertEqual(gate_result(case, commands, events)["status"], "PASS")
            for bad in (
                [],
                events[:-1],
                events + events[:1],
                events[:-1] + [events[-1] | {"status": "FAIL"}],
            ):
                self.assertEqual(gate_result(case, commands, bad)["status"], "FAIL")
            for record in (
                dict(exit_code=124, cleanup=True),
                dict(exit_code=0, cleanup=False),
            ):
                self.assertEqual(gate_result(case, [record], events)["status"], "FAIL")

    def test_native_summary_cannot_hide_absent_events_changed_source_or_cleanup(self):
        case = next(c for c in definitions() if c["case_id"] == "N3-M-IDENTITY")
        test = case["peer_config"]["test"]
        record = dict(
            case_id=case["case_id"],
            status="PASS",
            exit_code=0,
            command_cleanup=True,
            cleanup=True,
            peer_kind="M",
            command=[
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "vmess_native",
                test,
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
            ],
        )
        report = dict(cases=[record], source_unchanged=True, cleanup=True)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            self.assertEqual(native_results([case], report, path)[0]["status"], "FAIL")
            (path / (case["case_id"] + "-events.jsonl")).write_text(
                "".join(json.dumps(e) + "\n" for e in pair("N3-WIRE", test))
            )
            self.assertEqual(native_results([case], report, path)[0]["status"], "PASS")
            for key in ("cleanup", "source_unchanged"):
                self.assertEqual(
                    native_results([case], report | {key: False}, path)[0]["status"],
                    "FAIL",
                )
            for change in (
                dict(exit_code=124),
                dict(command_cleanup=False),
                dict(cleanup=False),
                dict(command=[]),
                dict(peer_kind="V2"),
            ):
                self.assertEqual(
                    native_results([case], report | {"cases": [record | change]}, path)[
                        0
                    ]["status"],
                    "FAIL",
                )
            with self.assertRaises(ValueError):
                native_results([case], report | {"cases": [record, record]}, path)

    def test_public_base_requires_every_family_codec_and_body_option(self):
        test = "public_base"
        events = pair("N3-PUBLIC", test)
        self.assertFalse(events_pass(events, test))
        for name in ("tcp_10mib_both_directions", "udp_each_codec_and_family"):
            events += [e for _ in range(3) for e in pair("N3-BASE", name)]
        self.assertTrue(events_pass(events, test))
        self.assertFalse(events_pass(events[:-2], test))
        self.assertFalse(events_pass(events + events[-2:], test))
        body = pair("N3-PUBLIC", "public_body_options") + [
            e for _ in range(14) for e in pair("N3-BODY", "config_controls_aead_body")
        ]
        self.assertTrue(events_pass(body, "public_body_options"))
        self.assertFalse(events_pass(body[:-2], "public_body_options"))

    def test_owned_resources_need_twenty_idle_stop_and_quiet_cycles(self):
        snapshot = dict(
            counts=[
                dict(kind=kind, current=0, peak=1) for kind in sorted(RESOURCE_KINDS)
            ]
        )
        test = "runtime::owned_resources"
        events = pair("N3-PUBLIC", test)
        for _ in range(20):
            cycle = pair("N3-OWNED", "stop_and_remain_quiet")
            cycle[-1].update(
                seconds=5,
                resources=snapshot,
                checkpoints=[
                    dict(phase=phase, resources=snapshot)
                    for phase in ("baseline", "after-stop", "quiet")
                ],
            )
            events += cycle
        self.assertTrue(events_pass(events, test))
        for change in (
            {"seconds": 4.9},
            {"checkpoints": []},
            {"resources": {}},
            {"status": "FAIL"},
        ):
            self.assertFalse(events_pass(events[:-1] + [events[-1] | change], test))
        self.assertFalse(events_pass(events[:-2], test))
        busy = copy.deepcopy(events)
        busy[-1]["resources"]["counts"][0]["current"] = 1
        self.assertFalse(events_pass(busy, test))


if __name__ == "__main__":
    unittest.main()
