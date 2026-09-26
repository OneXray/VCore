"""Offline evidence validation: no protocol listener or origin is launched."""

from __future__ import annotations

import copy
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vcore_scripts.builds import CORE_DIR, DEFAULT_FEATURES
from vcore_scripts.protocol_evidence import RESOURCE_KINDS, load_manifest
from vcore_scripts.protocol_vless_acceptance import (
    FIELD_IDS,
    NATIVE,
    OBSERVATIONS,
    REQUIRED_IDS,
    definitions,
    execute,
    fields_report,
    gate_result,
    native_results,
    required_command_names,
)
from vcore_scripts.protocol_vless_container import close_reference, run
from vcore_scripts.protocol_vless_peers import configuration
from vcore_scripts.protocol_vless_public import events_pass


def pair(suite, name):
    return [
        dict(schema_version=1, suite=suite, assertion=name, status=status)
        for status in ("BEGIN", "PASS")
    ]


class VlessEvidenceTest(unittest.TestCase):
    def test_fingerprint_runner_rejects_unknown_profile_or_plaintext_before_io(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            for profile, cases in [
                ("chrome133", ["N4-TCP-TLS-BASE"]),
                ("chrome120", ["N4-TCP-BASE"]),
            ]:
                with self.assertRaises(ValueError):
                    run(output, cases, client_fingerprint=profile)
                self.assertFalse(output.exists())

    def test_every_planned_n4_transport_security_class_has_a_native_consumer(self):
        catalog = json.loads(
            (CORE_DIR / "tests/protocols/combinations.json").read_text()
        )
        aliases = {"ws-custom-ed": "ws-header", "ws-path-ed": "ws-path"}
        suffixes = {"plain": "", "tls": "-tls", "reality-classic": "-reality"}
        for family in catalog["combinations"]:
            if (
                "N4" not in family["stages"]
                or "vless" not in family["protocols"]
                or family["classification"] == "rejected-by-contract"
            ):
                continue
            if family["id"].startswith("VL-VISION-"):
                modes = [family["id"].removeprefix("VL-").lower()]
            elif family["id"] == "VL-TLS-IDENTITY":
                modes = [network + "-mtls" for network in family["networks"]]
            else:
                networks = (
                    ["upgrade", "upgrade-fast"]
                    if family["id"] == "VL-WS-HTTPUPGRADE"
                    else [
                        aliases.get(network, network) for network in family["networks"]
                    ]
                )
                modes = [
                    network + suffixes[security]
                    for network in networks
                    for security in family["security_modes"]
                ]
            for mode in modes:
                self.assertIn(
                    f"N4-{mode.upper()}-BASE", REQUIRED_IDS, (family["id"], mode)
                )

    def test_official_ws_reference_preserves_vcore_default_and_explicit_ed_locations(
        self,
    ):
        for specified in (None, "", "X-Synthetic-ED"):
            options = {"max-early-data": 1, "v2ray-http-upgrade-fast-open": True}
            if specified is not None:
                options["early-data-header-name"] = specified
            node = {"network": "ws", "ws-opts": options}
            reference, scope = close_reference(
                "upgrade-fast-tls", node, {}, Path("cert"), Path("key"), "pin"
            )
            self.assertEqual(scope, "same-mode")
            self.assertEqual(
                reference["ws-opts"]["early-data-header-name"],
                "Sec-WebSocket-Protocol" if specified is None else specified,
            )
            self.assertEqual(
                "early-data-header-name" in node["ws-opts"], specified is not None
            )

    def test_vision_flow_rejection_uses_plain_user_without_mutating_valid_peer(self):
        for mode in ("vision-tls", "vision-reality"):
            node, config = configuration(
                mode, "server", "origin", Path("cert"), Path("key")
            )
            self.assertEqual(node["flow"], "xtls-rprx-vision")
            valid, plain = config["listeners"]
            self.assertEqual(valid["users"][0]["flow"], "xtls-rprx-vision")
            self.assertEqual(plain["users"][0]["flow"], "")
            self.assertEqual((valid["port"], plain["port"]), (23000, 23004))
            self.assertEqual(valid.get("reality-config"), plain.get("reality-config"))
            self.assertEqual(valid.get("certificate"), plain.get("certificate"))

    def test_ws_reality_close_reference_is_explicitly_layered_not_same_mode(self):
        node = {
            "network": "ws",
            "tls": True,
            "port": 23000,
            "reality-opts": {"public-key": "synthetic"},
        }
        config = {
            "listeners": [{"port": 23000, "reality-config": {"dest": "synthetic"}}]
        }
        reference, scope = close_reference(
            "ws-reality", node, config, Path("cert"), Path("key"), "pin"
        )
        self.assertEqual(scope, "ws-standard-tls-baseline")
        self.assertIn("reality-opts", node)
        self.assertNotIn("reality-opts", reference)
        self.assertEqual(reference["port"], 23003)
        self.assertIn("reality-config", config["listeners"][0])
        self.assertNotIn("reality-config", config["listeners"][1])
        case = next(c for c in definitions() if c["case_id"] == "N4-WS-REALITY-CLOSE")
        self.assertEqual(case["field_values"]["close_reference"], scope)
        self.assertIn("not a same-combination", case["gap_source"]["reason"])

    def test_jls_grpc_close_reference_labels_the_official_alpn_type_gap(self):
        for profile in (None, "", "none", "chrome", "chrome120", "firefox", "safari"):
            node = {
                "network": "grpc",
                "tls": True,
                "jls-opts": {"username": "synthetic", "password": "synthetic"},
            }
            if profile is not None:
                node["client-fingerprint"] = profile
            original = copy.deepcopy(node)
            reference, scope = close_reference(
                "grpc-tls", node, {}, Path("cert"), Path("key"), "pin"
            )
            baseline = profile in (None, "", "none")
            self.assertEqual(
                scope, "jls-grpc-chrome-baseline" if baseline else "same-mode"
            )
            self.assertEqual(
                reference["client-fingerprint"], "chrome" if baseline else profile
            )
            self.assertEqual(reference["jls-opts"], node["jls-opts"])
            self.assertEqual(node, original)

        for node in ({"network": "grpc"}, {"network": "tcp", "jls-opts": {}}):
            reference, scope = close_reference(
                "tcp-tls", node, {}, Path("cert"), Path("key"), "pin"
            )
            self.assertEqual(scope, "same-mode")
            self.assertNotIn("client-fingerprint", reference)

    def test_reality_close_reference_keeps_explicit_browser_profiles(self):
        for profile in (None, "none", "chrome120", "firefox", "safari"):
            node = {"network": "grpc"}
            if profile is not None:
                node["client-fingerprint"] = profile
            reference, scope = close_reference(
                "grpc-reality", node, {}, Path("cert"), Path("key"), "pin"
            )
            self.assertEqual(scope, "same-mode")
            self.assertEqual(
                reference["client-fingerprint"],
                "chrome" if profile in (None, "none") else profile,
            )

    def test_safari_ech_close_reference_labels_the_official_client_gap(self):
        for profile in ("safari", "safari16", "chrome", "firefox", "none"):
            for enabled in (False, True):
                node = {
                    "network": "grpc",
                    "tls": True,
                    "client-fingerprint": profile,
                    "ech-opts": {"enable": enabled, "config": "synthetic"},
                }
                original = copy.deepcopy(node)
                reference, scope = close_reference(
                    "grpc-tls", node, {}, Path("cert"), Path("key"), "pin"
                )
                baseline = enabled and profile in ("safari", "safari16")
                self.assertEqual(
                    scope, "ech-safari-chrome-baseline" if baseline else "same-mode"
                )
                self.assertEqual(
                    reference["client-fingerprint"], "chrome" if baseline else profile
                )
                self.assertEqual(reference["ech-opts"], node["ech-opts"])
                self.assertEqual(node, original)

    def test_independent_features_match_the_executed_command_set(self):
        case = next(c for c in definitions() if c["case_id"] == "N4-FEATURES")
        with (
            tempfile.TemporaryDirectory() as root,
            patch(
                "vcore_scripts.protocol_harness._command",
                return_value=SimpleNamespace(returncode=0, cleanup=True),
            ) as command,
        ):
            execute([case], {"commands": []}, Path(root), {})
        actual = {call.args[2] for call in command.call_args_list}
        expected = {
            name
            for name in required_command_names()
            if name.startswith("feature-") or name == "production-build"
        }
        self.assertEqual(actual, expected)

    def test_required_manifest_cannot_drop_or_downgrade_behavior(self):
        original = load_manifest()
        index = next(i for i, case in enumerate(original) if case["stage"] == "N4")
        for mutation in ("drop", "required", "observation", "row"):
            cases = copy.deepcopy(original)
            if mutation == "drop":
                cases.pop(index)
            elif mutation == "required":
                cases[index]["required"] = False
            elif mutation == "observation":
                cases[index]["expected_observation"] = ["always-green"]
            else:
                cases[index]["row_ids"] = ["VL01"]
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
            {c["case_id"] for c in cases if c["runner"] == "native-vless"}, set(NATIVE)
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
            self.assertIn("outbound-vless", enabled)

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
        case = next(
            c for c in definitions() if c["case_id"] == "N4-VISION-TLS-INNER-TLS"
        )
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
                "vless_native",
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
                "".join(json.dumps(e) + "\n" for e in pair("N4-WIRE", test))
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
        events = pair("N4-PUBLIC", test)
        self.assertFalse(events_pass(events, test, "tcp"))
        for name in ("tcp_10mib_both_directions", "udp_each_codec_and_family"):
            events += [e for _ in range(3) for e in pair("N4-BASE", name)]
        self.assertTrue(events_pass(events, test, "tcp"))
        self.assertFalse(events_pass(events[:-2], test, "tcp"))
        self.assertFalse(events_pass(events + events[-2:], test, "tcp"))
        n7 = [
            dict(event, suite=event["suite"].replace("N4-", "N7-")) for event in events
        ]
        self.assertTrue(events_pass(n7, test, "tcp", stage="N7"))
        self.assertFalse(events_pass(n7[:-2], test, "tcp", stage="N7"))
        self.assertFalse(events_pass(n7, test, "tcp"))
        vision = (
            pair("N4-PUBLIC", test)
            + [
                e
                for _ in range(3)
                for e in pair("N4-BASE", "tcp_10mib_both_directions")
            ]
            + pair("N4-BASE", "udp_each_codec_and_family")
        )
        self.assertTrue(events_pass(vision, test, "vision-tls"))
        self.assertFalse(events_pass(vision, test, "tcp"))

    def test_owned_resources_need_twenty_idle_stop_and_quiet_cycles(self):
        snapshot = dict(
            counts=[
                dict(kind=kind, current=0, peak=1) for kind in sorted(RESOURCE_KINDS)
            ]
        )
        test = "runtime::owned_resources"
        events = pair("N4-PUBLIC", test)
        for _ in range(20):
            cycle = pair("N4-OWNED", "stop_and_remain_quiet")
            cycle[-1].update(
                seconds=5,
                resources=snapshot,
                checkpoints=[
                    dict(phase=phase, resources=snapshot)
                    for phase in ("baseline", "after-stop", "quiet")
                ],
            )
            events += cycle
        self.assertTrue(events_pass(events, test, "tcp"))
        for change in (
            {"seconds": 4.9},
            {"checkpoints": []},
            {"resources": {}},
            {"status": "FAIL"},
        ):
            self.assertFalse(
                events_pass(events[:-1] + [events[-1] | change], test, "tcp")
            )
        self.assertFalse(events_pass(events[:-2], test, "tcp"))
        busy = copy.deepcopy(events)
        busy[-1]["resources"]["counts"][0]["current"] = 1
        self.assertFalse(events_pass(busy, test, "tcp"))


if __name__ == "__main__":
    unittest.main()
