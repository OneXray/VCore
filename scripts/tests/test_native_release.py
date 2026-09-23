from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch

from vcore_scripts import native_release


class Response(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/fixture"


class NativeReleaseTest(unittest.TestCase):
    def test_failed_download_never_uses_old_binary_or_leaks_network_details(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.URLError("synthetic-private-marker"),
            ),
        ):
            binary = Path(directory) / "v2ray"
            binary.write_bytes(b"older executable")
            with self.assertRaises(RuntimeError) as caught:
                native_release.download_native("V2", Path(directory), "darwin-arm64")
            self.assertNotIn("synthetic-private-marker", str(caught.exception))
            self.assertEqual(binary.read_bytes(), b"older executable")
            self.assertEqual(list(Path(directory).iterdir()), [binary])

    def test_v2ray_uses_latest_binary_and_records_content_identity(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("v2ray", b"fixture-executable")
            bundle.writestr("geoip.dat", b"unused")
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "urllib.request.urlopen", return_value=Response(archive.getvalue())
            ) as request,
            patch("vcore_scripts.native_release.run_command") as run,
        ):
            run.return_value.stdout = b"V2Ray 5.53.0 fixture\n"
            run.return_value.returncode = 0
            run.return_value.cleanup = True
            peer = native_release.download_native("V2", Path(directory), "darwin-arm64")
            self.assertEqual(
                request.call_args.args[0].full_url,
                "https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-macos-arm64-v8a.zip",
            )
            self.assertEqual(peer.binary.read_bytes(), b"fixture-executable")
            self.assertEqual(
                peer.identity["binary_sha256"],
                hashlib.sha256(b"fixture-executable").hexdigest(),
            )
            self.assertEqual(
                peer.identity["archive_sha256"],
                hashlib.sha256(archive.getvalue()).hexdigest(),
            )
            self.assertEqual(peer.identity["version"], "V2Ray 5.53.0 fixture")
            self.assertFalse((Path(directory) / "geoip.dat").exists())


if __name__ == "__main__":
    unittest.main()
