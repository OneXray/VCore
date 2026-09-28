from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import load_manifest
from vcore_scripts.protocol_security_acceptance import (
    gate_result,
    native_envelope,
    rust_command,
    vless_pass,
)
from vcore_scripts.protocol_security_catalog import FIELDS, definitions, groups


class SecurityAcceptanceTest(unittest.TestCase):
    def test_legacy_ech_gateway_keeps_response_inside_tls(self):
        from vcore_scripts.protocol_ech import legacy_gateway_command

        self.assertEqual(
            legacy_gateway_command(),
            [
                "env",
                "XRAY_BUF_SPLICE=disable",
                "/data/fixture/peer",
                "run",
                "-c",
                "/data/fixture/config.json",
            ],
        )

    def test_frozen_scope_and_compositions(self):
        cases = definitions()
        self.assertEqual(
            [c for c in load_manifest() if c["stage"] == "SECURITY"], cases
        )
        self.assertEqual(len(cases), 43)
        self.assertEqual(set().union(*(set(c["row_ids"]) for c in cases)), FIELDS)
        self.assertEqual(len(FIELDS), 11)
        catalog = groups()
        self.assertEqual(len(catalog["SECURITY-ECH-STANDARD"]["selected"]), 50)
        for profile in ("chrome", "chrome120", "firefox", "safari"):
            self.assertEqual(
                catalog["SECURITY-ECH-" + profile.upper()]["client_fingerprint"],
                profile,
            )
        for security in ("ECH", "JLS", "HYBRID"):
            self.assertEqual(
                sum(k.startswith(f"SECURITY-{security}-ENCRYPTION-") for k in catalog),
                6,
            )
        self.assertFalse(
            any("shadow" in str(c).lower() or "restls" in str(c).lower() for c in cases)
        )

    def fixture(self, directory):
        name, test = "SECURITY-ECH-TCP-TLS-REJECT", "native_ech_fail_closed"
        group = dict(runner="vless", selected=[name], ech=True)
        report = dict(
            status="PASS",
            cleanup=True,
            source_unchanged=True,
            source=dict(
                parent_commit="7" * 40,
                source_tree_sha256="a" * 64,
                dirty_patch_sha256="b" * 64,
                lock_sha256="c" * 64,
            ),
            ech=True,
            jls=False,
            encryption_profile=None,
            client_fingerprint=None,
            cases=[
                dict(
                    case_id=name,
                    command=rust_command("vless_native", test),
                    exit_code=0,
                    cleanup=True,
                    command_cleanup=True,
                    status="PASS",
                    peer_kind="M",
                )
            ],
            isolation=dict(
                network_mode="hostOnly",
                host_servers=False,
                guest_mtu=1500,
                image_digest="sha256:" + "d" * 64,
                peers=[dict(started=True, joined=True)],
            ),
            peers={
                "M": dict(
                    version="synthetic test metadata",
                    binary_sha256="a" * 64,
                    archive_sha256="b" * 64,
                    source_url="https://github.com/MetaCubeX/mihomo/releases/latest/download/fixture",
                )
            },
        )
        path = directory / (name + "-events.jsonl")
        events = [
            dict(schema_version=1, suite="SECURITY-WIRE", assertion=test, status=s)
            for s in ("BEGIN", "PASS")
        ]
        path.write_text("".join(json.dumps(e) + "\n" for e in events))
        return group, report, path, events

    def test_native_missing_duplicate_wrong_events_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            group, report, path, events = self.fixture(directory)
            self.assertTrue(vless_pass(group, report, directory))
            for samples in ([], report["cases"] * 2):
                invalid = dict(report, cases=samples)
                self.assertFalse(vless_pass(group, invalid, directory))
            for samples in (
                events[:1],
                events * 2,
                [dict(e, suite="VLESS-WIRE") for e in events],
                [dict(e, status="PASS") for e in events],
            ):
                path.write_text("".join(json.dumps(e) + "\n" for e in samples))
                self.assertFalse(vless_pass(group, report, directory))

    def test_source_cleanup_and_identity_are_not_inferred(self):
        with tempfile.TemporaryDirectory() as temp:
            _, report, _, _ = self.fixture(Path(temp))
            self.assertTrue(native_envelope(report, report["peers"], report["source"]))
            self.assertTrue(native_envelope(report, image_digest="sha256:" + "d" * 64))
            self.assertFalse(native_envelope(report, image_digest="sha256:" + "e" * 64))
            for field in ("cleanup", "source_unchanged"):
                self.assertFalse(native_envelope(dict(report, **{field: False})))
            self.assertFalse(native_envelope(report, {}, report["source"]))
            self.assertFalse(native_envelope(report, report["peers"], {}))
            for mutate in (
                lambda r: r["isolation"].update(host_servers=True),
                lambda r: r["isolation"].update(peers=[]),
                lambda r: r["isolation"]["peers"][0].update(joined=False),
                lambda r: r["peers"]["M"].update(binary_sha256=""),
            ):
                invalid = copy.deepcopy(report)
                mutate(invalid)
                self.assertFalse(native_envelope(invalid))

    def test_close_reference_cannot_hide_a_different_official_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            group, report, _, _ = self.fixture(directory)
            name, test = "SECURITY-ECH-GRPC-TLS-CLOSE", "native_mihomo_close_alignment"
            group.update(selected=[name], client_fingerprint="safari")
            report.update(client_fingerprint="safari")
            report["cases"][0].update(
                case_id=name, command=rust_command("vless_native", test)
            )
            (directory / (name + "-events.jsonl")).write_text(
                "".join(
                    json.dumps(
                        dict(
                            schema_version=1,
                            suite="SECURITY-WIRE",
                            assertion=test,
                            status=s,
                        )
                    )
                    + "\n"
                    for s in ("BEGIN", "PASS")
                )
            )
            path = directory / "grpc-tls-tls-close-reference.json"
            self.assertFalse(vless_pass(group, report, directory))
            valid = dict(
                scope="ech-safari-chrome-baseline",
                client_fingerprint="chrome",
                dut_client_fingerprint="safari",
                terminated=True,
                tail_hex="",
            )
            path.write_text(json.dumps(valid))
            self.assertTrue(vless_pass(group, report, directory))
            for field, value in (
                ("scope", "same-mode"),
                ("client_fingerprint", "safari"),
                ("dut_client_fingerprint", "chrome"),
                ("terminated", False),
            ):
                path.write_text(json.dumps(dict(valid, **{field: value})))
                self.assertFalse(vless_pass(group, report, directory))

    def test_empty_gate_and_missing_script_proof_fail(self):
        cases = {c["case_id"]: c for c in definitions()}
        for name in ("SECURITY-CFG", "SECURITY-RELEASE", "SECURITY-SCRIPTS"):
            self.assertEqual(gate_result(cases[name], [], [])["status"], "FAIL")
        record = [dict(exit_code=0, cleanup=True)]
        self.assertEqual(
            gate_result(cases["SECURITY-CFG"], record, [])["status"], "FAIL"
        )
        self.assertEqual(
            gate_result(cases["SECURITY-SCRIPTS"], record, [], {})["status"], "FAIL"
        )
