from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import chdir, redirect_stderr, redirect_stdout
from pathlib import Path

from vcore_scripts import cli

CATALOGS = Path(__file__).resolve().parents[2] / "tests" / "protocols"


class ProtocolCatalogTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vcore-catalog-test-")
        self.addCleanup(temporary.cleanup)
        self.catalogs = Path(temporary.name)
        for name in ("fields", "combinations"):
            shutil.copy2(CATALOGS / f"{name}.json", self.catalogs)

    def run_check(self, *options):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                code = cli.main(
                    [
                        "check",
                        "protocol-coverage",
                        "--catalog-dir",
                        str(self.catalogs),
                        *options,
                    ]
                )
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), errors.getvalue()

    def edit_catalog(self, name, change):
        for original in ("fields", "combinations"):
            shutil.copy2(CATALOGS / f"{original}.json", self.catalogs)
        data = json.loads((CATALOGS / f"{name}.json").read_text())
        change(data)
        (self.catalogs / f"{name}.json").write_text(json.dumps(data))

    def test_valid_declarations_are_not_behavior_acceptance(self):
        code, output, errors = self.run_check("--catalog-only")
        self.assertEqual(code, 0, errors)
        report = json.loads(output)
        self.assertEqual(report["status"], "VALID")
        self.assertEqual(report["behavior_status"], "NOT RUN")
        self.assertEqual(report["fields"], 145)
        self.assertEqual(report["combination_families"], 69)
        self.assertEqual(errors, "")

    def test_field_catalog_cannot_drop_duplicate_or_replace_a_stable_id(self):
        def remove(data):
            data["fields"].pop()
            data["field_count"] = 144

        def duplicate(data):
            data["fields"][-1]["id"] = "C01"

        def replace(data):
            data["fields"][-1]["id"] = "C99"

        for change in (remove, duplicate, replace):
            with self.subTest(change=change.__name__):
                self.edit_catalog("fields", change)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("field IDs", errors)

    def test_combination_catalog_retains_every_stable_family(self):
        def remove(data):
            data["combinations"].pop()

        def duplicate(data):
            data["combinations"][-1]["id"] = "TR-TCP"

        def replace(data):
            data["combinations"][-1]["id"] = "UNDECLARED-FAMILY"

        for change in (remove, duplicate, replace):
            with self.subTest(change=change.__name__):
                self.edit_catalog("combinations", change)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("combination IDs", errors)

    def test_declarations_cannot_embed_fabricated_passes(self):
        for name in ("fields", "combinations"):
            for location in ("catalog", "row"):
                with self.subTest(name=name, location=location):

                    def change(data, location=location, name=name):
                        if location == "catalog":
                            data["status"] = "PASS"
                        else:
                            data[name][0]["behavior_status"] = "PASS"

                    self.edit_catalog(name, change)
                    code, output, errors = self.run_check("--catalog-only")
                    self.assertEqual(code, 1)
                    self.assertEqual(output, "")
                    self.assertIn("declarations must remain NOT RUN", errors)

    def test_unknown_or_empty_cross_catalog_references_are_rejected(self):
        for name, key, value in (
            ("fields", "sources", ["missing-source"]),
            ("fields", "default_peer", "unknown-peer"),
            ("fields", "peer_override_rules", ["missing-rule"]),
            ("combinations", "row_ids", ["C99"]),
            ("combinations", "row_ids", []),
            ("combinations", "sources", ["missing-source"]),
            ("combinations", "peers", ["unknown-peer"]),
        ):
            with self.subTest(name=name, key=key, value=value):
                self.edit_catalog(
                    name,
                    lambda data, name=name, key=key, value=value: data[name][
                        0
                    ].__setitem__(key, value),
                )
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("reference", errors)

    def test_native_gaps_and_rejections_cannot_lose_their_contracts(self):
        for family, key, value in (
            ("TR-TCP", "classification", "optional-skip"),
            ("REJECT-VISION-TRANSPORT", "rejection_phase", ""),
            ("REJECT-VISION-TRANSPORT", "rejection_phase", "after-send"),
            ("REJECT-VISION-TRANSPORT", "when", ""),
            ("VM-V2-XUDP", "blocked_on", ""),
        ):
            with self.subTest(family=family, key=key, value=value):

                def change(data, family=family, key=key, value=value):
                    row = next(r for r in data["combinations"] if r["id"] == family)
                    row[key] = value

                self.edit_catalog("combinations", change)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("classification contract", errors)

    def test_invalid_schema_and_duplicate_json_keys_fail_without_echoing_input(self):
        original = (CATALOGS / "fields.json").read_text()
        bad_json = [
            "[]",
            '{"private-synthetic-marker":',
            original.replace('"schema_version": 1', '"schema_version": 2'),
            original.replace('"schema_version": 1', '"schema_version": true'),
            original.replace(
                '"field_count": 145',
                '"private-synthetic-marker": 1, "private-synthetic-marker": 2, '
                '"field_count": 145',
            ),
        ]
        for number, payload in enumerate(bad_json):
            with self.subTest(number=number):
                (self.catalogs / "fields.json").write_text(payload)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertNotIn("private-synthetic-marker", errors)
                self.assertNotIn("Traceback", errors)

    def test_missing_or_malformed_rows_are_diagnostics_not_exceptions(self):
        for name in ("fields", "combinations"):
            for replacement in (None, {}, [None], [{"id": []}], [{"id": "C01"}]):
                with self.subTest(name=name, replacement=replacement):
                    self.edit_catalog(
                        name,
                        lambda data, name=name, replacement=replacement: (
                            data.__setitem__(name, replacement)
                        ),
                    )
                    code, output, errors = self.run_check("--catalog-only")
                    self.assertEqual(code, 1)
                    self.assertEqual(output, "")
                    self.assertNotIn("Traceback", errors)

    def test_rows_require_applicability_owners_and_observable_contracts(self):
        for name, key, value in (
            ("fields", "protocols", []),
            ("fields", "protocols", ["future-unknown-protocol"]),
            ("fields", "path", ""),
            ("fields", "contract", " "),
            ("fields", "required_observation", ""),
            ("fields", "work_packages", ["N99.1"]),
            ("fields", "responsible_stages", ["N2"]),
            ("combinations", "protocols", ["wireguard"]),
            ("combinations", "stages", []),
            ("combinations", "required_observation", ""),
        ):
            with self.subTest(name=name, key=key):
                self.edit_catalog(
                    name,
                    lambda data, name=name, key=key, value=value: data[name][
                        0
                    ].__setitem__(key, value),
                )
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("protocol catalog", errors)

    def test_sources_reject_external_paths_credentials_and_invalid_values(self):
        for value in (
            "../references/mihomo/probe.go",
            "/private-synthetic-marker/secret",
            "file:///private-synthetic-marker",
            "https://host.test/?token=secret",
            "https://synthetic:private-synthetic-marker@host.test/source",
            "",
            None,
            [],
        ):
            with self.subTest(value=value):

                def change(data, value=value):
                    data["sources"][next(iter(data["sources"]))] = value

                self.edit_catalog("fields", change)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertNotIn("private-synthetic-marker", errors)
                self.assertIn("source reference", errors)

    def test_scope_peer_and_override_registries_cannot_be_inconsistent(self):
        def bad_scope(data):
            data["scope"] = ["trojan"]

        def bad_peer(data):
            data["peers"]["M"] = None

        def missing_rules(data):
            data.pop("peer_override_rules")

        def malformed_rules(data):
            data["peer_override_rules"] = None

        def duplicate_rule(data):
            data["peer_override_rules"].append(data["peer_override_rules"][0])

        def bad_rule_peer(data):
            data["peer_override_rules"][0]["peer"] = "unknown-peer"

        def bad_rule_source(data):
            data["peer_override_rules"][0]["sources"] = ["missing-source"]

        for change in (
            bad_scope,
            bad_peer,
            missing_rules,
            malformed_rules,
            duplicate_rule,
            bad_rule_peer,
            bad_rule_source,
        ):
            with self.subTest(change=change.__name__):
                self.edit_catalog("fields", change)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("protocol catalog", errors)
                self.assertNotIn("Traceback", errors)

    def test_mode_families_cannot_drop_or_empty_required_dimensions(self):
        for key in ("networks", "security_modes", "udp_codecs", "business", "peers"):
            for mode in ("missing", "empty", "wrong-type"):
                with self.subTest(key=key, mode=mode):

                    def change(data, key=key, mode=mode):
                        row = data["combinations"][0]
                        if mode == "missing":
                            row.pop(key)
                        else:
                            row[key] = [] if mode == "empty" else "tcp"

                    self.edit_catalog("combinations", change)
                    code, output, errors = self.run_check("--catalog-only")
                    self.assertEqual(code, 1)
                    self.assertEqual(output, "")
                    self.assertIn("protocol catalog", errors)

    def test_upstream_declaration_keeps_all_64_ordered_pairs(self):
        for key, value in (
            ("ordered_pairs", 63),
            ("ordered_pairs", 64.0),
            ("existing_protocols", ["socks5", "anytls"]),
            ("existing_protocols", [None, {}, "socks5"]),
            ("protocols", ["trojan"]),
        ):
            with self.subTest(key=key):

                def change(data, key=key, value=value):
                    row = next(
                        r for r in data["combinations"] if r["id"] == "ALL-UPSTREAMS"
                    )
                    row[key] = value

                self.edit_catalog("combinations", change)
                code, output, errors = self.run_check("--catalog-only")
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("upstream", errors)

    def test_catalog_mode_must_be_explicit_not_implied_acceptance(self):
        code, output, errors = self.run_check()
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("--catalog-only", errors)

    def test_default_catalog_location_is_independent_of_working_directory(self):
        output = io.StringIO()
        with chdir(self.catalogs), redirect_stdout(output):
            code = cli.main(["check", "protocol-coverage", "--catalog-only"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["fields"], 145)
