from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shlex
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from vole_scripts import builds, cli
from vole_scripts.builds import EXPECTED_IDENTITY, _android_target, _require_identity


def _windows_pe(machine: int) -> bytes:
    contents = bytearray(512)
    contents[:2] = b"MZ"
    contents[0x3C:0x40] = (0x80).to_bytes(4, "little")
    contents[0x80:0x84] = b"PE\0\0"
    contents[0x84:0x86] = machine.to_bytes(2, "little")
    contents[0x100 : 0x100 + len(EXPECTED_IDENTITY)] = EXPECTED_IDENTITY
    return bytes(contents)


class ScriptTest(unittest.TestCase):
    def test_platform_builds_explicitly_include_all_client_protocols(self):
        manifest = tomllib.loads((builds.CORE_DIR / "Cargo.toml").read_text())
        features = set(builds.DEFAULT_FEATURES.split(","))
        self.assertEqual(
            features, set(manifest["features"]["default"]) | {"ffi", "tun"}
        )
        self.assertNotIn("interop-test", features)
        self.assertNotIn("benchmark-geodata-http", features)

    def test_windows_backend_dependencies_and_host_bins_are_explicit(self):
        manifest = tomllib.loads((builds.CORE_DIR / "Cargo.toml").read_text())
        features = manifest["features"]
        self.assertEqual(features["ffi"], ["invoke"])
        self.assertEqual(features["cli"], ["invoke"])
        self.assertIn("dep:tun-rs", features["windows-wintun"])
        self.assertNotIn("dep:tun-rs", features["tun"])
        self.assertNotIn("dep:tun-rs", features["windows-uwp"])
        self.assertFalse(
            set(features["invoke"]) & {"windows-uwp", "windows-wintun", "ffi"}
        )
        windows = manifest["target"]["cfg(windows)"]["dependencies"]
        self.assertTrue(windows["tun-rs"]["optional"])
        self.assertEqual(windows["tun-rs"]["features"], ["interruptible"])
        for binary in manifest["bin"]:
            if binary["name"].startswith("vole-windows-"):
                self.assertEqual(binary["required-features"], ["ffi", "windows-uwp"])

    def test_platform_cargo_build_rejects_test_features_before_spawn(self):
        for features in (
            "ffi,benchmark-geodata-http",
            "ffi interop-test",
            "ffi vole/benchmark-geodata-http",
        ):
            with self.subTest(features=features), patch.object(builds, "_run") as run:
                with self.assertRaisesRegex(RuntimeError, "test-only"):
                    builds._cargo_build("fixture-target", ["--release"], features, {})
                run.assert_not_called()
        self.assertEqual(
            builds._production_features(builds.DEFAULT_FEATURES),
            builds.DEFAULT_FEATURES,
        )

    def test_cargo_target_directory_uses_cargo_environment_and_checkout_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for environment, expected in (
                ({}, root / "target"),
                ({"CARGO_TARGET_DIR": ""}, root / "target"),
                ({"CARGO_TARGET_DIR": str(root / "cache")}, root / "cache"),
                ({"CARGO_TARGET_DIR": "cache"}, root / "cache"),
            ):
                with (
                    self.subTest(environment=environment),
                    patch.object(builds, "CORE_DIR", root),
                    patch.dict(builds.os.environ, environment, clear=True),
                ):
                    self.assertEqual(builds._cargo_target_dir(), expected)
                    self.assertEqual(builds._cargo_target_dir(environment), expected)

    def test_cli_only_dispatches_platform_builds(self):
        for platform_name in ("apple", "android", "windows"):
            with (
                self.subTest(platform=platform_name),
                patch(f"vole_scripts.cli.build_{platform_name}") as build,
            ):
                self.assertEqual(cli.main(["build", platform_name]), 0)
                build.assert_called_once_with()
            with (
                self.subTest(platform=platform_name, delivery=True),
                patch("vole_scripts.platform_delivery.build_delivery") as delivery,
            ):
                self.assertEqual(cli.main(["build", platform_name, "--delivery"]), 0)
                delivery.assert_called_once_with(platform_name)

    def test_cli_rejects_removed_validation_and_demo_commands_before_building(self):
        for arguments in (
            ["check", "core"],
            ["check", "protocol-interop"],
            ["check", "platform-artifacts"],
            ["check", "platform-abi"],
            ["demo", "windows-tun2socks"],
            ["build", "linux"],
        ):
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(io.StringIO()),
                patch("subprocess.Popen") as spawn,
            ):
                with self.assertRaises(SystemExit) as error:
                    cli.main(arguments)
                self.assertEqual(error.exception.code, 2)
                spawn.assert_not_called()

    def test_cli_dispatches_windows_build_without_architecture(self):
        with patch("vole_scripts.cli.build_windows") as build:
            self.assertEqual(cli.main(["build", "windows"]), 0)
        build.assert_called_once_with()

    def test_windows_architecture_uses_native_processor_registry(self):
        key = object()
        for native, expected in (("AMD64", "x64"), ("ARM64", "arm64")):
            with self.subTest(native=native):
                registry = SimpleNamespace(
                    HKEY_LOCAL_MACHINE=object(),
                    OpenKey=MagicMock(),
                    QueryValueEx=MagicMock(return_value=(native, None)),
                )
                registry.OpenKey.return_value.__enter__.return_value = key
                with patch.dict("sys.modules", {"winreg": registry}):
                    self.assertEqual(builds._windows_architecture(), expected)
                registry.QueryValueEx.assert_called_once_with(
                    key, "PROCESSOR_ARCHITECTURE"
                )

    def test_windows_example_uses_one_application_with_isolated_hosts(self):
        root = ET.parse(
            builds.CORE_DIR / "example/windows-uwp/AppxManifest.xml.in"
        ).getroot()
        foundation = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
        desktop = "http://schemas.microsoft.com/appx/manifest/desktop/windows10"
        uap10 = "http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
        applications = root.findall(
            f"{{{foundation}}}Applications/{{{foundation}}}Application"
        )

        self.assertEqual(len(applications), 1)
        self.assertFalse(
            any("AppListEntry" in element.attrib for element in root.iter())
        )
        extensions = applications[0].find(f"{{{foundation}}}Extensions")
        full_trust = extensions.find(
            f"{{{desktop}}}Extension[@Category='windows.fullTrustProcess']"
        )
        provider = extensions.find(
            f"{{{foundation}}}Extension[@Category='windows.backgroundTasks']"
        )
        self.assertEqual(
            full_trust.attrib["Executable"], "vole-windows-session-host.exe"
        )
        self.assertEqual(provider.attrib["Executable"], "vole-windows-vpn-host.exe")
        self.assertEqual(provider.attrib[f"{{{uap10}}}RuntimeBehavior"], "windowsApp")
        self.assertEqual(provider.attrib[f"{{{uap10}}}TrustLevel"], "appContainer")

    def test_android_target_mapping_is_strict(self):
        self.assertEqual(
            _android_target("aarch64-linux-android", "24"),
            ("arm64-v8a", "aarch64-linux-android24-clang", "AARCH64_LINUX_ANDROID"),
        )
        with self.assertRaisesRegex(RuntimeError, "unsupported Android Rust target"):
            _android_target("mips-linux-android", "24")

    def test_android_build_packages_the_matching_ndk_cpp_runtime(self):
        for configured, api, bindgen_overrides, expected_extra in (
            (False, "24", {}, []),
            (True, "28", {"BINDGEN_EXTRA_CLANG_ARGS": "-DGLOBAL=1"}, ["-DGLOBAL=1"]),
            (
                False,
                "28",
                {
                    "BINDGEN_EXTRA_CLANG_ARGS": "-DGLOBAL=1",
                    "BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android": "-DARM64=1",
                },
                ["-DARM64=1"],
            ),
            (
                True,
                "24",
                {
                    "BINDGEN_EXTRA_CLANG_ARGS": "-DGLOBAL=1",
                    "BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android": "-DLOWER=1",
                    "BINDGEN_EXTRA_CLANG_ARGS_aarch64-linux-android": (
                        '-I"fixture include"'
                    ),
                },
                ["-Ifixture include"],
            ),
            (
                False,
                "24",
                {
                    "BINDGEN_EXTRA_CLANG_ARGS": "-DGLOBAL=1",
                    "BINDGEN_EXTRA_CLANG_ARGS_aarch64-linux-android": "",
                },
                [],
            ),
        ):
            with (
                self.subTest(configured=configured, api=api, bindgen=bindgen_overrides),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                target_dir = root / ("cache" if configured else "target")
                toolchain = root / "ndk/toolchain"
                (toolchain / "bin").mkdir(parents=True)
                (toolchain / "bin/llvm-ar").touch()
                targets = ("aarch64-linux-android", "x86_64-linux-android")
                for target in targets:
                    abi, clang, _ = _android_target(target, api)
                    (toolchain / "bin" / clang).touch()
                    (toolchain / "bin" / (clang + "++")).touch()
                    runtime = (
                        toolchain / "sysroot/usr/lib" / target / "libc++_shared.so"
                    )
                    runtime.parent.mkdir(parents=True)
                    runtime.write_bytes(abi.encode())
                    artifact = target_dir / target / "release/libvole.so"
                    artifact.parent.mkdir(parents=True)
                    artifact.write_bytes(EXPECTED_IDENTITY)
                with (
                    patch.dict(
                        builds.os.environ,
                        {
                            "ANDROID_NDK_HOME": str(root / "ndk"),
                            "VOLE_ANDROID_API": api,
                        }
                        | bindgen_overrides
                        | ({"CARGO_TARGET_DIR": str(target_dir)} if configured else {}),
                        clear=True,
                    ),
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(builds, "_android_toolchain", return_value=toolchain),
                    patch.object(builds, "_require_targets"),
                    patch.object(builds, "_cargo_build") as cargo,
                ):
                    builds.build_android()
                self.assertEqual(cargo.call_count, 2)
                for invocation, target in zip(
                    cargo.call_args_list, targets, strict=True
                ):
                    abi, clang, _ = _android_target(target, api)
                    env = invocation.args[3]
                    self.assertEqual(env["VOLE_CMAKE_ANDROID_ABI"], abi)
                    self.assertEqual(env["VOLE_CMAKE_ANDROID_API"], api)
                    extra = (
                        expected_extra
                        if target == "aarch64-linux-android"
                        else shlex.split(
                            bindgen_overrides.get("BINDGEN_EXTRA_CLANG_ARGS", "")
                        )
                    )
                    self.assertEqual(
                        shlex.split(env[f"BINDGEN_EXTRA_CLANG_ARGS_{target}"]),
                        [f"--target={clang.removesuffix('-clang')}", *extra],
                    )
                    self.assertEqual(
                        env[f"CMAKE_TOOLCHAIN_FILE_{target.replace('-', '_')}"],
                        str(root / "scripts/cmake/android.toolchain.cmake"),
                    )
                    self.assertEqual(
                        env[f"CXX_{target.replace('-', '_')}"],
                        str(toolchain / "bin" / (clang + "++")),
                    )
                    output = root / "dist/android" / abi
                    self.assertEqual(
                        (output / "libvole.so").read_bytes(), EXPECTED_IDENTITY
                    )
                    self.assertEqual(
                        (output / "libc++_shared.so").read_bytes(), abi.encode()
                    )

    def test_artifact_identity_check_reads_binary_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "libvole.a"
            artifact.write_bytes(b"prefix\0" + EXPECTED_IDENTITY + b"\0suffix")
            _require_identity(artifact, "test")
            artifact.write_bytes(b"wrong")
            with self.assertRaisesRegex(RuntimeError, "incompatible Rust identity"):
                _require_identity(artifact, "test")

    def test_native_windows_wintun_check_preserves_packaged_delivery_outputs(self):
        for architecture, target in (
            ("x64", "x86_64-pc-windows-msvc"),
            ("arm64", "aarch64-pc-windows-msvc"),
        ):
            with (
                self.subTest(architecture=architecture),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                output = root / "dist/windows" / architecture
                output.mkdir(parents=True)
                files = {
                    name: name.encode()
                    for name in (
                        "vole.dll",
                        "vole-windows-artifacts.json",
                        "vole-delivery.json",
                    )
                }
                for name, data in files.items():
                    (output / name).write_bytes(data)
                env = {"VOLE_NATIVE_CHECK": architecture}
                with (
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(builds, "os", SimpleNamespace(name="nt")),
                    patch.object(
                        builds, "_windows_architecture", return_value=architecture
                    ),
                    patch.object(
                        builds, "_windows_msvc_environment", return_value=env
                    ) as native,
                    patch.object(builds, "_run") as run,
                ):
                    builds.check_windows_wintun_cli()
                    native.assert_called_once_with(architecture)
                    run.assert_called_once_with(
                        [
                            "cargo",
                            "check",
                            "--locked",
                            "--release",
                            "--target",
                            target,
                            "--no-default-features",
                            "--features",
                            "cli,windows-wintun",
                            "--lib",
                            "--bin",
                            "vole",
                        ],
                        env=env,
                    )
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in output.iterdir()},
                        files,
                    )

    def test_wintun_check_rejects_non_windows_before_toolchain_or_compiler(self):
        with (
            patch.object(builds, "os", SimpleNamespace(name="posix")),
            patch.object(builds, "_windows_msvc_environment") as native,
            patch.object(builds, "_run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "on Windows"):
                builds.check_windows_wintun_cli()
            native.assert_not_called()
            run.assert_not_called()

    def test_windows_release_build_uses_production_features_and_checks_identity(self):
        for configured in (False, True):
            with (
                self.subTest(configured=configured),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                target_dir = root / ("cache" if configured else "target")
                release = target_dir / "aarch64-pc-windows-msvc/release"
                release.mkdir(parents=True)
                artifacts = (
                    "vole.dll",
                    "vole-windows-vpn-host.exe",
                    "vole-windows-session-host.exe",
                )
                for name in artifacts:
                    (release / name).write_bytes(_windows_pe(0xAA64))

                with (
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(
                        builds,
                        "os",
                        SimpleNamespace(name="nt", environ={}, fspath=os.fspath),
                    ),
                    patch.object(builds, "_windows_architecture", return_value="arm64"),
                    patch.object(
                        builds,
                        "_windows_msvc_environment",
                        return_value={"CARGO_TARGET_DIR": str(target_dir)}
                        if configured
                        else {},
                    ),
                    patch.object(builds, "_run") as run,
                ):
                    builds.build_windows()
                    self.assertEqual(
                        run.call_args_list[1].args[0],
                        [
                            "cargo",
                            "build",
                            "--locked",
                            "--release",
                            "--target",
                            "aarch64-pc-windows-msvc",
                            "--no-default-features",
                            "--features",
                            builds.WINDOWS_FEATURES,
                            "--lib",
                            "--bins",
                        ],
                    )
                    manifest = json.loads(
                        (
                            root / "dist/windows/arm64/vole-windows-artifacts.json"
                        ).read_text()
                    )
                    expected_digest = hashlib.sha256(_windows_pe(0xAA64)).hexdigest()
                    self.assertEqual(
                        manifest,
                        {
                            "architecture": "arm64",
                            "artifacts": {
                                "vole-windows-session-host.exe": expected_digest,
                                "vole-windows-vpn-host.exe": expected_digest,
                                "vole.dll": expected_digest,
                            },
                            "buildIdentity": EXPECTED_IDENTITY.decode("ascii"),
                            "formatVersion": 1,
                            "windowsPackageIntegrationRevision": 3,
                        },
                    )

                    provider = release / "vole-windows-vpn-host.exe"
                    provider.write_bytes(_windows_pe(0x8664))
                    with self.assertRaisesRegex(RuntimeError, "wrong architecture"):
                        builds.build_windows()
                    self.assertFalse(
                        (
                            root / "dist/windows/arm64/vole-windows-artifacts.json"
                        ).exists()
                    )

                    provider.write_bytes(_windows_pe(0xAA64))
                    dll = bytearray(_windows_pe(0xAA64))
                    dll[0x100 : 0x100 + len(EXPECTED_IDENTITY)] = bytes(
                        len(EXPECTED_IDENTITY)
                    )
                    (release / "vole.dll").write_bytes(dll)
                    with self.assertRaisesRegex(
                        RuntimeError, "incompatible Rust identity"
                    ):
                        builds.build_windows()


if __name__ == "__main__":
    unittest.main()
