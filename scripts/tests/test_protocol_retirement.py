from __future__ import annotations

import io
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from vcore_scripts import cli
from vcore_scripts.protocol_catalogs import FIELD_IDS, PEERS, PROTOCOLS, STAGES
from vcore_scripts.protocol_preflight import preflight


class ProtocolRetirementTest(unittest.TestCase):
    def test_wireguard_is_not_a_feature_protocol_peer_or_field_target(self):
        root = Path(__file__).resolve().parents[2]
        features = tomllib.loads((root / "Cargo.toml").read_text())["features"]
        self.assertNotIn("outbound-wireguard", features)
        self.assertNotIn("wireguard", PROTOCOLS)
        self.assertNotIn("W", PEERS)
        self.assertNotIn("N8", STAGES)
        self.assertFalse(any(identifier.startswith("WG") for identifier in FIELD_IDS))

    def test_retired_cli_selections_fail_before_any_harness_work(self):
        for arguments in (
            ["protocol-interop", "--stage", "N8", "--list"],
            ["protocol-coverage", "--stage", "N8", "--catalog-only"],
            ["protocol-interop", "--stage", "N7", "--protocol", "wireguard", "--list"],
        ):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(["check", *arguments])
                self.assertEqual(error.exception.code, 2)

    def test_retired_peer_preflight_cannot_download_or_create_a_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "not-created"
            with (
                patch("vcore_scripts.protocol_preflight.run_command") as command,
                patch("vcore_scripts.protocol_preflight.download_native") as download,
            ):
                with self.assertRaisesRegex(ValueError, "unsupported native peer"):
                    preflight(directory, {"M", "W"}, container=True)
                command.assert_not_called()
                download.assert_not_called()
            self.assertFalse(directory.exists())
