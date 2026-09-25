"""Profile CLI help/listing never acquires a network or starts a test peer."""

import contextlib
import io
import unittest

from vcore_scripts.protocol_fingerprint import main


class FingerprintCliTest(unittest.TestCase):
    def test_help_exposes_explicit_profile_selection_without_running(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as error:
            main(["--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertIn("--client-fingerprint", output.getvalue())
        self.assertIn("chrome120", output.getvalue())

    def test_option_between_output_and_cases_reaches_pre_io_selection_check(self):
        with self.assertRaisesRegex(ValueError, "invalid N4 native selection"):
            main(["unused-output", "--client-fingerprint", "chrome120", "missing"])


if __name__ == "__main__":
    unittest.main()
