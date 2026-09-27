"""Offline checks of the supported validation entrypoint, not milestone counts."""

import contextlib
import io
import unittest

from vcore_scripts import cli
from vcore_scripts.core_checks import commands, validate_execution
from vcore_scripts.protocol_catalogs import check_protocol_catalogs
from vcore_scripts.protocol_evidence import check_limit_references, load_manifest


class CoreChecksTest(unittest.TestCase):
    def test_catalog_validity_does_not_claim_executed_behavior(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            check_protocol_catalogs()
        self.assertIn('"behavior_status": "NOT RUN"', output.getvalue())
        check_limit_references(load_manifest())

    def test_profiles_select_tests_without_running_all_target_servers(self):
        for profile in ("debug", "release", "features"):
            selected = commands(profile)
            self.assertTrue(selected)
            for command in selected:
                if command[:2] == ["cargo", "test"]:
                    self.assertTrue(
                        "--all-targets" not in command or "--no-run" in command
                    )
                    self.assertNotIn("--ignored", command)
            if profile != "features":
                self.assertTrue(
                    all(
                        ("--release" in command) == (profile == "release")
                        for command in selected
                    )
                )
        with self.assertRaises(ValueError):
            commands("missing")

    def test_empty_partial_failed_or_unjoined_execution_fails(self):
        command = ["cargo", "test", "--test", "one", "--test", "two"]
        ok = "test result: ok. 2 passed; 0 failed; 0 ignored;"
        validate_execution(command, ok + "\n" + ok, 0, True)
        for output, code, cleanup in (
            ("", 0, True),
            (ok, 0, True),
            (ok + "\ntest result: ok. 0 passed; 0 failed; 3 ignored;", 0, True),
            (ok + "\n" + ok, 1, True),
            (ok + "\n" + ok, 0, False),
        ):
            with (
                self.subTest(output=output, code=code, cleanup=cleanup),
                self.assertRaises(RuntimeError),
            ):
                validate_execution(command, output, code, cleanup)

    def test_list_mode_is_read_only_and_capability_names_resolve(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["check", "core", "--list"]), 0)
            self.assertEqual(
                cli.main(
                    ["check", "protocol-interop", "--suite", "integration", "--list"]
                ),
                0,
            )
        self.assertIn("shadowsocks_backpressure", output.getvalue())
        self.assertIn("N9-PAIR-SS-SS", output.getvalue())


if __name__ == "__main__":
    unittest.main()
