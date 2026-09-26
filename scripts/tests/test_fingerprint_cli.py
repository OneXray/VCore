"""Profile CLI help/listing never acquires a network or starts a test peer."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vcore_scripts.mihomo_isolation import exclusive_run
from vcore_scripts.protocol_fingerprint import main


class FingerprintCliTest(unittest.TestCase):
    def test_help_exposes_explicit_profile_selection_without_running(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as error:
            main(["--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertIn("--client-fingerprint", output.getvalue())
        for name in (
            "none",
            "chrome",
            "chrome120",
            "firefox",
            "firefox120",
            "safari",
            "safari16",
        ):
            self.assertIn(name, output.getvalue())

    def test_option_between_output_and_cases_reaches_pre_io_selection_check(self):
        for name in (
            "none",
            "chrome",
            "chrome120",
            "firefox",
            "firefox120",
            "safari",
            "safari16",
        ):
            # This argument-only test can run inside a locked native suite.
            # Exercise the real lock on its own temporary filesystem boundary.
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch(
                    "vcore_scripts.protocol_fingerprint.exclusive_run",
                    lambda: exclusive_run(Path(temporary) / "cli.lock"),
                ),
                self.assertRaisesRegex(ValueError, "invalid N4 native selection"),
            ):
                main(["unused-output", "--client-fingerprint", name, "missing"])


if __name__ == "__main__":
    unittest.main()
