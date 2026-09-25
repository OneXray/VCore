"""Offline guardrails for selected-profile coverage and explicit differences."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.builds import CORE_DIR
from vcore_scripts.protocol_fingerprint import CASES
from vcore_scripts.protocol_fingerprint_reference import _reference_shape
from vcore_scripts.protocol_fingerprint_shape import (
    check_captures,
    check_warm_captures,
    expected_shape,
)
from vcore_scripts.protocol_inputs import same_source
from vcore_scripts.protocol_xhttp_fields import (
    run,
    selected_gateway_config,
    selected_profile_variants,
)
from vcore_scripts.tls_client_hello import validate_capture


class SelectedFingerprintGatesTest(unittest.TestCase):
    def test_staging_metadata_is_not_a_source_change(self):
        source = dict(
            parent_commit="parent",
            source_tree_sha256="tree",
            lock_sha256="lock",
            dirty_patch_sha256="unstaged",
        )
        self.assertTrue(same_source(source, dict(source, dirty_patch_sha256="staged")))
        for field in ("parent_commit", "source_tree_sha256", "lock_sha256"):
            self.assertFalse(same_source(source, dict(source, **{field: "changed"})))

    def test_partial_wire_and_warm_matrices_never_pass(self):
        for check in (check_captures, check_warm_captures):
            with self.assertRaises(ValueError):
                check([])

    def test_reality_does_not_inherit_standard_tls13_template_pruning(self):
        samples = json.loads(
            (CORE_DIR / "tests/fingerprints/mihomo-selected-v1.json").read_text()
        )["samples"]
        sample = next(
            s
            for s in samples
            if s["profile"] == "firefox" and s["context"] == "reality"
        )
        shape = expected_shape(sample, "reality")
        self.assertEqual(shape["ciphers"], validate_capture(sample)["ciphers"])
        self.assertEqual(len(shape["ciphers"]), 17)
        hello = copy.deepcopy(validate_capture(sample))
        psk = dict(type=41, bytes=50, identities=[7], binders=[32])
        hello["extensions"].append(psk)
        hello["bytes"] += 54
        case = dict(template="Firefox120", sni="fingerprint.test", context="reality")
        with self.assertRaises(ValueError):
            _reference_shape(hello, case)
        self.assertEqual(
            _reference_shape(hello, case, allow_psk=True)["extensions"][-1], psk
        )
        hello["extensions"].insert(0, hello["extensions"].pop())
        with self.assertRaises(ValueError):
            _reference_shape(hello, case, allow_psk=True)

    def test_transport_catalog_includes_existing_native_and_upgrade_paths(self):
        for name in (
            "N4-UPGRADE-TLS-BASE",
            "N4-UPGRADE-FAST-TLS-BASE",
            "N4-H2-TLS-BASE",
            "N4-HTTP-TLS-BASE",
            "N4-WS-ED-2048-TLS-BASE",
            "CF5-VMESS-H2-TLS",
            "CF5-VMESS-HTTP-TLS",
        ):
            self.assertIn(name, CASES)
        self.assertEqual(len(CASES), len(set(CASES)))

    def test_download_crossings_are_explicit_and_h3_requires_clear(self):
        cases = selected_profile_variants("chrome")

        def get(suffix):
            return cases[f"h2-selected-download-{suffix}"][0]["download-settings"]

        self.assertNotIn("client-fingerprint", get("inherit"))
        self.assertEqual(get("different")["client-fingerprint"], "firefox")
        self.assertEqual(get("clear")["client-fingerprint"], "none")
        h3 = cases["h3-selected-download-clear"][0]
        self.assertEqual(h3["_main_alpn"], "h2")
        self.assertEqual(h3["download-settings"]["client-fingerprint"], "none")
        parent = CORE_DIR / "target/interop/runs"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            output = Path(directory) / "not-created"
            for profile, selection in [
                ("chrome133", ["h2-auto"]),
                ("chrome", ["h3-auto"]),
                ("chrome", ["h2c-auto"]),
                ("none", ["h2c-auto"]),
            ]:
                with self.assertRaises(ValueError):
                    run(output, selection, client_fingerprint=profile)
                self.assertFalse(output.exists())

    def test_split_h2_h3_uses_a_gateway_with_one_native_handler(self):
        fixture = selected_gateway_config("192.0.2.1")["apps"]["http"]["servers"][
            "fixture"
        ]
        self.assertEqual(fixture["protocols"], ["h2", "h3"])
        handler = fixture["routes"][0]["handle"][0]
        self.assertEqual(handler["upstreams"], [{"dial": "192.0.2.1:23000"}])
        self.assertEqual(handler["transport"]["versions"], ["h2c"])
        self.assertEqual(
            fixture["tls_connection_policies"][0]["client_authentication"]["mode"],
            "require_and_verify",
        )
