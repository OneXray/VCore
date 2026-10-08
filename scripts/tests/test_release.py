"""Exercise real archives with native compilation replaced by fixture files."""

import gzip
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds, release

INFO = {"version": "1.2.3", "commit": "a" * 40}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.enterContext(patch.object(builds, "CORE_DIR", self.root))
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        self.enterContext(patch.object(release, "release_info", return_value=INFO))

    def write(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(path.name.encode())
        return path

    def test_cli_packages_a_single_binary(self):
        for target in builds.CLI_TARGETS:
            binary = self.write(
                "build/vole.exe" if "windows" in target else "build/vole"
            )
            with (
                self.subTest(target=target),
                patch.object(builds, "native_target", return_value=target),
                patch.object(builds, "build_cli", return_value=binary),
                patch.object(release, "_smoke"),
            ):
                archive = release.build_cli(target, None, Path("dist/cli"))
            if archive.suffix == ".zip":
                with zipfile.ZipFile(archive) as stream:
                    self.assertEqual(stream.namelist(), ["vole.exe"])
                    content = stream.read("vole.exe")
            else:
                with gzip.open(archive) as stream:
                    content = stream.read()
            self.assertEqual(content, binary.read_bytes())
            self.assertEqual(list(archive.parent.iterdir()), [archive])

    def test_ffi_packages_platform_libraries_headers_and_uwp_hosts(self):
        files = {
            "apple": {"LibVole.xcframework/Info.plist"}
            | {
                f"LibVole.xcframework/{part}/{name}"
                for part in (
                    "ios-arm64",
                    "ios-arm64-simulator",
                    "macos-arm64_x86_64",
                    "tvos-arm64",
                    "tvos-arm64-simulator",
                )
                for name in ("libvole.a", "Headers/vole.h", "Headers/module.modulemap")
            },
            "android": {
                f"{abi}/{name}"
                for abi in ("arm64-v8a", "x86_64")
                for name in ("libvole.so", "libc++_shared.so")
            }
            | {"include/vole.h"},
            "linux": {"libvole.so", "libvole.a", "include/vole.h"},
            "windows": {"vole.dll", "vole.dll.lib", "include/vole.h"},
        }
        self.write("include/vole.h")
        for key, targets in release.FFI_TARGETS.items():
            platform = key.split("-")[0]
            backend = key.split("-")[1] if platform == "windows" else None
            target = targets[0] if platform in {"linux", "windows"} else None
            expected = files[platform].copy()
            if backend == "uwp":
                expected |= {
                    "include/vole_windows_uwp.h",
                    "vole-windows-vpn-host.exe",
                    "vole-windows-session-host.exe",
                }
            built = self.root / "build" / key
            for name in expected | {"wintun.dll", "old-output"}:
                self.write(built / name)
            with (
                self.subTest(key=key),
                patch.object(builds, "native_target", return_value=target),
                patch.object(builds, "build_" + platform, return_value=built),
            ):
                archive = release.build_ffi(
                    platform,
                    target,
                    backend,
                    None,
                    Path("dist/package"),
                )
            if archive.suffix == ".zip":
                with zipfile.ZipFile(archive) as stream:
                    contents = {name: stream.read(name) for name in stream.namelist()}
            else:
                with tarfile.open(archive) as stream:
                    contents = {
                        member.name: stream.extractfile(member).read()
                        for member in stream.getmembers()
                    }
            self.assertEqual(set(contents), expected)
            for name, data in contents.items():
                self.assertEqual(data, Path(name).name.encode())

    def test_assembly_requires_all_fourteen_archives(self):
        incoming = self.root / "dist/incoming"
        for index, name in enumerate(sorted(release.ASSETS)):
            self.write(incoming / str(index) / name)
        output = self.root / "dist/ready/assets"
        notes = output.parent / "notes.md"
        paths = release.assemble_release(None, incoming, output, notes)
        self.assertEqual(len(paths), 14)
        self.assertEqual({p.name for p in output.iterdir()}, release.ASSETS)
        self.assertIn("/tree/" + INFO["commit"], notes.read_text())
        next(incoming.glob("*/*")).unlink()
        with self.assertRaisesRegex(ValueError, "fourteen"):
            release.assemble_release(None, incoming, output, notes)
        self.assertEqual(len(list(output.iterdir())), 14)

    def test_apple_assembly_consumes_independently_built_targets(self):
        incoming = self.root / "dist/apple-targets"

        def compile(target):
            library = self.write(Path("native") / target / "libvole.a")
            library.write_bytes(target.encode())
            return library

        with patch.object(
            builds, "build_apple_target", side_effect=compile
        ) as compiler:
            for target in builds.APPLE_TARGETS:
                library = release.build_apple_target(target, None, incoming / target)
                self.assertEqual(library.read_bytes(), target.encode())
            self.assertEqual(compiler.call_count, 6)

        built = self.root / "dist/apple"
        for name in release.ffi_files("apple", None):
            self.write(built / name)
        with patch.object(builds, "assemble_apple", return_value=built) as assemble:
            archive = release.assemble_apple(incoming, Path("dist/release/ffi-apple"))
            assemble.assert_called_once_with(
                {
                    target: incoming / target / "libvole.a"
                    for target in builds.APPLE_TARGETS
                }
            )
        self.assertEqual(archive.name, "vole-ffi-apple.tar.gz")
        with tarfile.open(archive) as stream:
            self.assertEqual(set(stream.getnames()), release.ffi_files("apple", None))
