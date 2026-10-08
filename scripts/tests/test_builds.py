"""Check platform outputs around the external compiler boundary."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds


class BuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("vole.h", "vole_windows_uwp.h", "module.modulemap"):
            self.write(
                Path("include") / name,
                (builds.CORE_DIR / "include" / name).read_bytes(),
            )
        self.enterContext(patch.object(builds, "CORE_DIR", self.root))
        self.enterContext(
            patch.dict(os.environ, {"CARGO_TARGET_DIR": "cache"}, clear=True)
        )
        self.commands = []
        self.enterContext(patch.object(builds, "_run", side_effect=self.compile))

    def write(self, relative, data=b"library"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def compile(self, command, *, env):
        self.commands.append((command, env))
        if command[:2] == ["xcrun", "lipo"]:
            Path(command[-1]).write_bytes(b"universal library")
        elif command[:2] == ["cargo", "build"]:
            target = command[command.index("--target") + 1]
            for name in (
                "vole.exe",
                "vole.dll",
                "vole.dll.lib",
                "vole-windows-vpn-host.exe",
                "vole-windows-session-host.exe",
                "libvole.so",
                "libvole.a",
            ):
                self.write(f"cache/{target}/release/{name}")

    def test_windows_cli_and_ffi_select_their_backends(self):
        with (
            patch.object(builds.platform, "system", return_value="Windows"),
            patch.object(builds, "_windows_architecture", return_value="arm64"),
            patch.object(
                builds, "_windows_msvc_environment", return_value=dict(os.environ)
            ),
        ):
            binary = builds.build_cli()
            self.assertEqual(binary.read_bytes(), b"library")
            cli_command = self.commands[-1][0]
            self.assertEqual(
                cli_command[cli_command.index("--features") + 1], "cli,windows-wintun"
            )
            wintun = builds.build_windows("wintun")
            uwp = builds.build_windows("uwp")
        self.assertEqual(
            {
                p.relative_to(wintun).as_posix()
                for p in wintun.rglob("*")
                if p.is_file()
            },
            {"vole.dll", "vole.dll.lib", "include/vole.h"},
        )
        self.assertEqual(
            {p.relative_to(uwp).as_posix() for p in uwp.rglob("*") if p.is_file()},
            {
                "vole.dll",
                "vole.dll.lib",
                "include/vole.h",
                "include/vole_windows_uwp.h",
                "vole-windows-vpn-host.exe",
                "vole-windows-session-host.exe",
            },
        )
        for output in (wintun, uwp):
            for header in (output / "include").iterdir():
                self.assertEqual(
                    header.read_bytes(),
                    (self.root / "include" / header.name).read_bytes(),
                )
        for (command, _), backend in zip(
            self.commands[1:], ("wintun", "uwp"), strict=True
        ):
            self.assertEqual(
                command[command.index("--features") + 1], f"ffi,windows-{backend}"
            )
            self.assertEqual("--bins" in command, backend == "uwp")

    def test_android_uses_matching_api_and_cpp_runtime(self):
        toolchain = self.root / "ndk/toolchain"
        for target, abi in (
            ("aarch64-linux-android", "arm64-v8a"),
            ("x86_64-linux-android", "x86_64"),
        ):
            for name in (target + "28-clang", target + "28-clang++", "llvm-ar"):
                self.write(toolchain / "bin" / name)
            self.write(
                toolchain / "sysroot/usr/lib" / target / "libc++_shared.so",
                abi.encode(),
            )
        with (
            patch.object(builds.platform, "system", return_value="Linux"),
            patch.object(builds, "_android_toolchain", return_value=toolchain),
            patch.dict(
                os.environ,
                {"ANDROID_NDK_HOME": str(self.root / "ndk"), "VOLE_ANDROID_API": "28"},
            ),
        ):
            output = builds.build_android()
        for command, env in self.commands:
            target = command[command.index("--target") + 1]
            abi = env["VOLE_CMAKE_ANDROID_ABI"]
            self.assertEqual(
                env[f"BINDGEN_EXTRA_CLANG_ARGS_{target}"], f"--target={target}28"
            )
            self.assertEqual(env["VOLE_CMAKE_ANDROID_API"], "28")
            self.assertEqual((output / abi / "libvole.so").read_bytes(), b"library")
            self.assertEqual(
                (output / abi / "libc++_shared.so").read_bytes(), abi.encode()
            )

    def test_apple_build_stages_five_slices_from_six_targets(self):
        with patch.object(builds.platform, "system", return_value="Darwin"):
            builds.build_apple()
        work = self.root / "cache/vole-apple"
        self.assertEqual(
            {p.name for p in work.iterdir()},
            {
                "include",
                "ios-device",
                "ios-simulator",
                "macos",
                "tvos-device",
                "tvos-simulator",
            },
        )
        self.assertEqual((work / "macos/libvole.a").read_bytes(), b"universal library")
        self.assertEqual((work / "ios-simulator/libvole.a").read_bytes(), b"library")
        self.assertEqual(
            {p.name for p in (work / "include").iterdir()},
            {"vole.h", "module.modulemap"},
        )
        self.assertEqual(
            sum(command[:2] == ["cargo", "build"] for command, _ in self.commands), 6
        )
        self.assertEqual(
            self.commands[-1][0][:2], ["xcodebuild", "-create-xcframework"]
        )

    def test_ndk_selection_uses_latest_installed_stable_revision(self):
        for version in ("30.2.9", "30.2.10", "30.10.1", "30.99.1-beta1"):
            folder = version.removesuffix("-beta1")
            self.write(
                f"sdk/ndk/{folder}/source.properties",
                f"Pkg.Revision = {version}\n".encode(),
            )
        with patch.dict(os.environ, {"ANDROID_HOME": str(self.root / "sdk")}):
            self.assertEqual(builds._android_ndk_home(), self.root / "sdk/ndk/30.10.1")
