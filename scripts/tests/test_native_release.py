from __future__ import annotations

import hashlib
import io
import tarfile
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
    def test_shadowtls_uses_latest_unmodified_binary_with_deferred_guest_version(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "urllib.request.urlopen", return_value=Response(b"official-st-binary")
            ) as request,
            patch("vcore_scripts.native_release.run_command") as run,
        ):
            peer = native_release.download_native(
                "ST", Path(directory), "linux-arm64", defer_version=True
            )
            self.assertEqual(
                request.call_args.args[0].full_url,
                "https://github.com/ihciah/shadow-tls/releases/latest/download/shadow-tls-aarch64-unknown-linux-musl",
            )
            self.assertEqual(peer.binary.name, "shadow-tls")
            self.assertEqual(peer.binary.read_bytes(), b"official-st-binary")
            self.assertEqual(
                peer.identity["binary_sha256"],
                hashlib.sha256(b"official-st-binary").hexdigest(),
            )
            self.assertIsNone(peer.identity["version"])
            run.assert_not_called()

    def test_ss_tar_is_bounded_named_only_and_rejects_links(self):
        def archive(unsafe=False):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:xz") as bundle:
                entry = tarfile.TarInfo("ssserver")
                entry.size = 7
                bundle.addfile(entry, io.BytesIO(b"fixture"))
                entry = tarfile.TarInfo("sslocal")
                if unsafe:
                    entry.type, entry.linkname = tarfile.SYMTYPE, "/tmp/forbidden"
                bundle.addfile(entry)
            return data.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            path, binary = Path(directory) / "peer.tar.xz", Path(directory) / "ssserver"
            path.write_bytes(archive())
            self.assertEqual(
                native_release._extract_tar(path, binary, "ssserver"),
                hashlib.sha256(b"fixture").hexdigest(),
            )
            self.assertEqual(binary.read_bytes(), b"fixture")
            path.write_bytes(archive(True))
            with self.assertRaises(RuntimeError):
                native_release._extract_tar(path, binary, "ssserver")

    def test_foreign_binary_version_is_deferred_to_its_container(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("v2ray", b"linux-fixture")
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("urllib.request.urlopen", return_value=Response(archive.getvalue())),
            patch("vcore_scripts.native_release.run_command") as run,
        ):
            peer = native_release.download_native(
                "V2", Path(directory), "linux-arm64", defer_version=True
            )
            run.assert_not_called()
            self.assertIsNone(peer.identity["version"])
            self.assertEqual(peer.binary.read_bytes(), b"linux-fixture")

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
