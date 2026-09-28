from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import stat
import tempfile
import unittest
import urllib.error
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vcore_scripts import mihomo_release

LATEST_VERSION_URL = (
    "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
)
RELEASE_BASE = "https://github.com/MetaCubeX/mihomo/releases/download"
TARGET_ASSET_PREFIXES = {
    "darwin-arm64": "mihomo-darwin-arm64",
    "darwin-amd64": "mihomo-darwin-amd64",
    "linux-arm64": "mihomo-linux-arm64",
    "linux-amd64": "mihomo-linux-amd64-v1",
    "windows-arm64": "mihomo-windows-arm64",
    "windows-amd64": "mihomo-windows-amd64-v1",
}


class Response(io.BytesIO):
    def __init__(self, contents: bytes, url: str):
        super().__init__(contents)
        self.url = url

    def geturl(self):
        return self.url

    def read(self, size=-1):
        if size <= 0:
            raise AssertionError("Network responses must be read in bounded chunks")
        return super().read(size)

    def read1(self, size=-1):
        return self.read(size)


def zip_contents(entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents in entries:
            archive.writestr(name, contents)
    return output.getvalue()


def archive_fixture(target="darwin-arm64", contents=b"fixture executable\n"):
    if target.startswith("windows-"):
        return zip_contents([("mihomo.exe", contents)])
    return gzip.compress(contents, mtime=0)


def asset_name(target, tag):
    suffix = "zip" if target.startswith("windows-") else "gz"
    return f"{TARGET_ASSET_PREFIXES[target]}-{tag}.{suffix}"


class MihomoReleaseTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory) / "core"
        self.enterContext(patch.object(mihomo_release, "CORE_DIR", self.root))
        self.urlopen = self.enterContext(
            patch(
                "urllib.request.urlopen",
                side_effect=AssertionError("Unexpected network request"),
            )
        )
        self.output = self.enterContext(redirect_stdout(io.StringIO()))

    def binary_path(self, target="darwin-arm64", tag="v1.19.31"):
        return (
            self.root
            / "target"
            / "interop"
            / "mihomo"
            / tag
            / target
            / ("mihomo.exe" if target.startswith("windows-") else "mihomo")
        )

    def archive_url(self, target="darwin-arm64", tag="v1.19.31"):
        return f"{RELEASE_BASE}/{tag}/{asset_name(target, tag)}"

    def asset_response(self, archive, target="darwin-arm64", tag="v1.19.31"):
        return Response(archive, self.archive_url(target, tag))

    def version_response(self, tag="v1.19.31"):
        return Response(f"{tag}\n".encode(), LATEST_VERSION_URL)

    def provide_archive(self, archive, target="darwin-arm64", tag="v1.19.31"):
        self.urlopen.side_effect = None
        self.urlopen.return_value = self.asset_response(archive, target, tag)

    def assert_download_rejected(self, archive, target="darwin-arm64"):
        self.provide_archive(archive, target)
        with self.assertRaises(RuntimeError):
            mihomo_release.download_mihomo(target, release="v1.19.31")
        binary = self.binary_path(target)
        self.assertFalse(binary.exists())
        self.assertFalse(any(binary.parent.glob(".download-*")))

    def test_target_mapping_is_pure_and_supports_host_aliases(self):
        self.assertEqual(
            set(mihomo_release.SUPPORTED_TARGETS), set(TARGET_ASSET_PREFIXES)
        )
        for system in ("Darwin", "Linux", "Windows"):
            for machine, architecture in (
                ("arm64", "arm64"),
                ("aarch64", "arm64"),
                ("amd64", "amd64"),
                ("x86_64", "amd64"),
                ("AMD64", "amd64"),
            ):
                with (
                    self.subTest(system=system, machine=machine),
                    patch.object(
                        mihomo_release.platform, "system", return_value=system
                    ),
                    patch.object(
                        mihomo_release.platform, "machine", return_value=machine
                    ),
                ):
                    self.assertEqual(
                        mihomo_release._target(None), f"{system.lower()}-{architecture}"
                    )
        for target in TARGET_ASSET_PREFIXES:
            self.assertEqual(mihomo_release._target(target), target)
        self.urlopen.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_unsupported_target_fails_before_network_or_filesystem_changes(self):
        for target in ("freebsd-amd64", "linux-386", "../../outside"):
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                mihomo_release.download_mihomo(target)
        for system, machine in (("FreeBSD", "amd64"), ("Linux", "riscv64")):
            with (
                self.subTest(system=system, machine=machine),
                patch.object(mihomo_release.platform, "system", return_value=system),
                patch.object(mihomo_release.platform, "machine", return_value=machine),
                self.assertRaises(RuntimeError),
            ):
                mihomo_release.download_mihomo()
        self.urlopen.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_downloads_expected_gzip_and_zip_asset_for_each_target(self):
        payload = b"offline executable fixture\x00\xff"
        for target in TARGET_ASSET_PREFIXES:
            with self.subTest(target=target):
                archive = archive_fixture(target, payload)
                self.provide_archive(archive, target)
                binary = mihomo_release.download_mihomo(target, release="v1.19.31")
                self.assertEqual(binary, self.binary_path(target))
                self.assertEqual(binary.read_bytes(), payload)
                self.assertEqual(list(binary.parent.iterdir()), [binary])
                request = self.urlopen.call_args.args[0]
                self.assertEqual(request.full_url, self.archive_url(target))
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(self.urlopen.call_args.kwargs["timeout"], 30)
                if not target.startswith("windows-"):
                    self.assertTrue(binary.stat().st_mode & stat.S_IXUSR)
                report = self.output.getvalue()
                for value in (
                    "v1.19.31",
                    asset_name(target, "v1.19.31"),
                    self.archive_url(target),
                    hashlib.sha256(archive).hexdigest(),
                    hashlib.sha256(payload).hexdigest(),
                    str(binary),
                ):
                    self.assertIn(value, report)

    def test_latest_release_gets_version_text_on_every_call(self):
        self.urlopen.side_effect = [
            Response(b" v1.19.31\r\n", LATEST_VERSION_URL),
            self.version_response("v1.19.32"),
        ]
        self.assertEqual(mihomo_release.latest_release(), "v1.19.31")
        self.assertEqual(mihomo_release.latest_release(), "v1.19.32")
        self.assertEqual(self.urlopen.call_count, 2)
        for call in self.urlopen.call_args_list:
            self.assertEqual(call.args[0].full_url, LATEST_VERSION_URL)
            self.assertEqual(call.args[0].get_method(), "GET")
            self.assertEqual(call.kwargs["timeout"], 30)
        self.assertFalse(self.root.exists())

    def test_latest_version_change_downloads_into_new_version_directory(self):
        old_archive = archive_fixture(contents=b"old")
        new_archive = archive_fixture(contents=b"new")
        self.urlopen.side_effect = [
            self.version_response("v1.19.31"),
            self.asset_response(old_archive, tag="v1.19.31"),
            self.version_response("v1.19.32"),
            self.asset_response(new_archive, tag="v1.19.32"),
        ]
        old_binary = mihomo_release.download_mihomo("darwin-arm64")
        new_binary = mihomo_release.download_mihomo("darwin-arm64")
        self.assertNotEqual(old_binary, new_binary)
        self.assertEqual(old_binary.read_bytes(), b"old")
        self.assertEqual(new_binary.read_bytes(), b"new")
        self.assertEqual(new_binary, self.binary_path(tag="v1.19.32"))
        self.assertEqual(
            [call.args[0].full_url for call in self.urlopen.call_args_list],
            [
                LATEST_VERSION_URL,
                self.archive_url(tag="v1.19.31"),
                LATEST_VERSION_URL,
                self.archive_url(tag="v1.19.32"),
            ],
        )

    def test_same_release_is_downloaded_again_even_when_binary_exists(self):
        self.urlopen.side_effect = [
            self.asset_response(archive_fixture(contents=b"first download")),
            self.asset_response(archive_fixture(contents=b"second download")),
        ]
        first = mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
        self.assertEqual(first.read_bytes(), b"first download")
        second = mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
        self.assertEqual(first, second)
        self.assertEqual(second.read_bytes(), b"second download")
        self.assertEqual(self.urlopen.call_count, 2)

    def test_version_lookup_failure_does_not_return_existing_binary(self):
        binary = self.binary_path()
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"previous valid binary")
        self.urlopen.side_effect = urllib.error.URLError("offline fixture")
        with self.assertRaises(RuntimeError):
            mihomo_release.download_mihomo("darwin-arm64")
        self.urlopen.assert_called_once()
        self.assertEqual(self.urlopen.call_args.args[0].full_url, LATEST_VERSION_URL)
        self.assertEqual(binary.read_bytes(), b"previous valid binary")

    def test_latest_release_rejects_invalid_utf8_unsafe_or_oversized_versions(self):
        for contents in (
            b"\xff",
            b"",
            b"   \n",
            b"../outside",
            b"v1/other",
            b"v1\\other",
            b".",
            b"v1\nv2",
            b'{"tag_name":"v1.19.31"}',
            b"v" * 129,
        ):
            self.urlopen.side_effect = None
            self.urlopen.return_value = Response(contents, LATEST_VERSION_URL)
            with self.subTest(contents=contents), self.assertRaises(RuntimeError):
                mihomo_release.latest_release()
        self.urlopen.return_value = self.version_response()
        with (
            patch.object(mihomo_release, "MAX_VERSION_BYTES", 4),
            self.assertRaises(RuntimeError),
        ):
            mihomo_release.latest_release()
        self.assertFalse(self.root.exists())

    def test_explicit_unsafe_release_fails_before_network_or_filesystem_changes(self):
        for tag in ("../outside", "v1/other", "v1\\other", ".", "", "v" * 129):
            with self.subTest(tag=tag), self.assertRaises(RuntimeError):
                mihomo_release.download_mihomo("darwin-arm64", release=tag)
        self.urlopen.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_network_or_archive_failure_preserves_existing_binary(self):
        binary = self.binary_path()
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"previous valid binary")
        for failure in ("network", "archive"):
            if failure == "network":
                self.urlopen.side_effect = urllib.error.URLError("offline fixture")
            else:
                self.provide_archive(b"invalid gzip")
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
            self.assertEqual(binary.read_bytes(), b"previous valid binary")
            self.assertEqual(list(binary.parent.iterdir()), [binary])

    def test_corrupt_gzip_or_zip_never_installs_binary(self):
        for target in ("darwin-arm64", "windows-amd64"):
            with self.subTest(target=target):
                self.assert_download_rejected(b"not an archive", target)

    def test_gzip_crc_failure_after_payload_read_preserves_existing_binary(self):
        binary = self.binary_path()
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"previous valid binary")
        archive = bytearray(archive_fixture(contents=b"new binary" * 10000))
        archive[-8] ^= 0xFF
        self.provide_archive(bytes(archive))
        decoded_sizes = []
        read1 = gzip.GzipFile.read1

        def record_decoded_chunk(source, size=-1):
            chunk = read1(source, size)
            decoded_sizes.append(len(chunk))
            return chunk

        with (
            patch.object(gzip.GzipFile, "read1", record_decoded_chunk),
            self.assertRaises(RuntimeError),
        ):
            mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
        self.assertGreater(sum(decoded_sizes), 0)
        self.assertEqual(binary.read_bytes(), b"previous valid binary")
        self.assertEqual(list(binary.parent.iterdir()), [binary])

    def test_archive_download_is_bounded(self):
        archive = archive_fixture()
        with patch.object(mihomo_release, "MAX_ARCHIVE_BYTES", len(archive) - 1):
            self.assert_download_rejected(archive)

    def test_gzip_and_zip_decompressed_binary_sizes_are_bounded(self):
        for target in ("darwin-arm64", "windows-amd64"):
            archive = archive_fixture(target, b"A" * 4096)
            with (
                self.subTest(target=target),
                patch.object(mihomo_release, "MAX_BINARY_BYTES", 128),
            ):
                self.assert_download_rejected(archive, target)

    def test_interrupted_http_stream_is_reported_without_installing_binary(self):
        for version in (True, False):
            response = (
                self.version_response()
                if version
                else self.asset_response(archive_fixture())
            )
            self.urlopen.side_effect = None
            self.urlopen.return_value = response
            with (
                self.subTest(version=version),
                patch.object(
                    response,
                    "read1",
                    side_effect=http.client.IncompleteRead(b"partial", 100),
                ),
                self.assertRaises(RuntimeError),
            ):
                if version:
                    mihomo_release.latest_release()
                else:
                    mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
            binary = self.binary_path()
            self.assertFalse(binary.exists())
            self.assertFalse(any(binary.parent.glob(".download-*")))

    def test_http_redirect_downgrade_is_rejected(self):
        for version in (True, False):
            self.urlopen.side_effect = None
            self.urlopen.return_value = Response(
                b"v1.19.31" if version else archive_fixture(),
                "http://example.com/download",
            )
            with self.subTest(version=version), self.assertRaises(RuntimeError):
                if version:
                    mihomo_release.latest_release()
                else:
                    mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
            self.assertFalse(self.binary_path().exists())

    def test_interrupted_binary_publication_preserves_previous_binary(self):
        binary = self.binary_path()
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"previous valid binary")
        self.provide_archive(archive_fixture(contents=b"new binary"))
        with (
            patch.object(
                mihomo_release.os, "replace", side_effect=OSError("publication failure")
            ),
            self.assertRaises(RuntimeError),
        ):
            mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31")
        self.assertEqual(binary.read_bytes(), b"previous valid binary")
        self.assertEqual(list(binary.parent.iterdir()), [binary])
        self.provide_archive(archive_fixture(contents=b"new binary"))
        self.assertEqual(
            mihomo_release.download_mihomo("darwin-arm64", release="v1.19.31"), binary
        )
        self.assertEqual(binary.read_bytes(), b"new binary")

    def test_zip_rejects_traversal_and_non_regular_executables(self):
        symlink = zipfile.ZipInfo("mihomo.exe")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for name in ("../mihomo.exe", "/mihomo.exe", "..\\mihomo.exe", symlink):
            archive = zip_contents([(name, b"outside")])
            with self.subTest(name=str(name)):
                self.assert_download_rejected(archive, "windows-amd64")
        self.assertFalse((self.root.parent / "mihomo.exe").exists())

    def test_zip_rejects_missing_or_multiple_executables(self):
        for entries in (
            [("readme.txt", b"no executable")],
            [("mihomo.exe", b"first"), ("other.exe", b"second")],
        ):
            archive = zip_contents(entries)
            with self.subTest(entries=entries):
                self.assert_download_rejected(archive, "windows-amd64")


if __name__ == "__main__":
    unittest.main()
