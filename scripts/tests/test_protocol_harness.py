from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vcore_scripts import cli, protocol_harness, protocol_preflight
from vcore_scripts.native_release import PeerArtifact
from vcore_scripts.protocol_inputs import redact


class ProtocolHarnessTest(unittest.TestCase):
    def test_cli_freezes_list_case_protocol_and_preflight_selection(self):
        with patch("vcore_scripts.cli.run_protocol_interop") as run:
            self.assertEqual(
                cli.main(
                    [
                        "check",
                        "protocol-interop",
                        "--stage",
                        "N1",
                        "--case",
                        "N1-QUIC",
                        "--protocol",
                        "foundation",
                        "--list",
                    ]
                ),
                0,
            )
            self.assertEqual(run.call_args.kwargs["identifiers"], ["N1-QUIC"])
            self.assertTrue(run.call_args.kwargs["list_only"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(
                ["check", "protocol-interop", "--stage", "N1", "--list", "--preflight"]
            )

    def test_coverage_requires_explicit_catalog_or_result_mode(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["check", "protocol-coverage"])
        with patch("vcore_scripts.cli.check_run") as check:
            self.assertEqual(
                cli.main(
                    [
                        "check",
                        "protocol-coverage",
                        "--stage",
                        "N1",
                        "--run-dir",
                        "target/interop/runs/fixture",
                    ]
                ),
                0,
            )
            self.assertEqual(check.call_args.args[1], "N1")

    def test_redaction_removes_paths_uuid_authorization_and_private_key(self):
        output = redact(
            "/Users/example/private/input password=secret "
            "Authorization: Bearer secret-token\n"
            "12345678-1234-1234-1234-123456789abc "
            "-----BEGIN PRIVATE KEY-----secret-material-----END PRIVATE KEY-----"
        )
        for secret in [
            "secret",
            "Bearer-token",
            "secret-token",
            "12345678",
            "/Users/example",
            "secret-material",
        ]:
            self.assertNotIn(secret, output)

    def test_peer_preflight_failure_does_not_prevent_other_peer_capabilities(self):
        with tempfile.TemporaryDirectory() as temporary:

            def download(kind, directory):
                if kind == "H":
                    raise RuntimeError("private-marker")
                return PeerArtifact(
                    Path(temporary) / kind, {"version": "fixture", "kind": kind}
                )

            with patch.object(
                protocol_preflight, "download_native", side_effect=download
            ):
                artifacts, records = protocol_preflight.preflight(
                    Path(temporary), {"H", "XR", "V2"}
                )
            self.assertEqual(set(artifacts), {"XR", "V2"})
            self.assertEqual(
                {record["kind"]: record["status"] for record in records},
                {"H": "BLOCKED", "V2": "READY", "XR": "READY"},
            )
            self.assertNotIn("private-marker", json.dumps(records))

    def test_sigint_still_writes_incomplete_report_without_promoting_not_run(self):
        identity = {
            "source_tree_sha256": "0" * 64,
            "lock_sha256": "1" * 64,
            "dirty_patch_sha256": "2" * 64,
            "parent_commit": "3" * 40,
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            contextlib.ExitStack() as stack,
        ):
            root = Path(temporary)
            stack.enter_context(patch.object(protocol_harness, "CORE_DIR", root))
            stack.enter_context(
                patch.object(
                    protocol_harness,
                    "run_identity",
                    return_value=identity
                    | {
                        "stage": "N1",
                        "mode": "execute",
                        "suite_timeout_seconds": 30,
                        "commands": [],
                    },
                )
            )
            stack.enter_context(
                patch.object(protocol_harness, "source_identity", return_value=identity)
            )
            stack.enter_context(
                patch.object(
                    protocol_harness,
                    "exclusive_run",
                    side_effect=contextlib.nullcontext,
                )
            )
            stack.enter_context(
                patch.object(protocol_harness, "check_protocol_catalogs")
            )
            stack.enter_context(
                patch.object(
                    protocol_harness, "_execute", side_effect=KeyboardInterrupt
                )
            )
            output = root / "target/interop/runs/fixture"
            with (
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaises(RuntimeError),
            ):
                protocol_harness.run_protocol_interop(
                    stage="N1", identifiers=["N1-QUIC"], run_dir=output
                )
            self.assertEqual(
                json.loads((output / "cases.json").read_text())[0]["status"], "NOT RUN"
            )
            self.assertFalse(json.loads((output / "run.json").read_text())["cleanup"])
            self.assertTrue((output / "resources.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
