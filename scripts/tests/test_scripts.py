from __future__ import annotations

import contextlib
import io
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


def _archive(*members: tuple[str, bytes]) -> bytes:
    contents = b"!<arch>\n"
    for name, payload in members:
        contents += (
            name.encode().ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"644".ljust(8)
            + str(len(payload)).encode().ljust(10)
            + b"`\n"
            + payload
            + (b"\n" if len(payload) % 2 else b"")
        )
    return contents


def _windows_import(machine: int) -> bytes:
    return _archive(
        ("/", b"symbol table"),
        ("dll.obj/", machine.to_bytes(2, "little") + bytes(18)),
        (
            "function.obj/",
            b"\x00\x00\xff\xff\x00\x00" + machine.to_bytes(2, "little") + bytes(12),
        ),
    )


def _linux_elf(machine: int, kind: int = 3) -> bytes:
    return (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + kind.to_bytes(2, "little")
        + machine.to_bytes(2, "little")
        + bytes(44)
        + EXPECTED_IDENTITY
    )


class ScriptTest(unittest.TestCase):
    def test_build_identity_uses_the_package_version(self):
        manifest = tomllib.loads((builds.CORE_DIR / "Cargo.toml").read_text())
        self.assertEqual(
            EXPECTED_IDENTITY.decode(),
            "Vole;engine=rust;coreVersion=" + manifest["package"]["version"],
        )

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
        for platform_name in ("apple", "android", "windows", "linux"):
            with (
                self.subTest(platform=platform_name),
                patch(f"vole_scripts.cli.build_{platform_name}") as build,
            ):
                self.assertEqual(cli.main(["build", platform_name]), 0)
                if platform_name == "windows":
                    build.assert_called_once_with("uwp")
                else:
                    build.assert_called_once_with()

    def test_cli_rejects_removed_validation_and_demo_commands_before_building(self):
        for arguments in (
            ["check", "core"],
            ["check", "protocol-interop"],
            ["check", "platform-artifacts"],
            ["check", "platform-abi"],
            ["demo", "windows-tun2socks"],
            ["build", "linux", "--delivery"],
            ["build", "windows", "--backend", "wintun", "--delivery"],
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
        build.assert_called_once_with("uwp")

    def test_cli_dispatches_targets_profiles_and_ffi_windows_backends(self):
        with patch("vole_scripts.cli.build_cli") as build:
            self.assertEqual(cli.main(["build", "cli"]), 0)
            build.assert_called_once_with(None, "release")
        with patch("vole_scripts.cli.build_cli") as build:
            self.assertEqual(
                cli.main(
                    [
                        "build",
                        "cli",
                        "--target",
                        "aarch64-pc-windows-msvc",
                        "--profile",
                        "debug",
                    ]
                ),
                0,
            )
            build.assert_called_once_with("aarch64-pc-windows-msvc", "debug")
        with patch("vole_scripts.cli.build_windows") as build:
            self.assertEqual(cli.main(["build", "windows", "--backend", "wintun"]), 0)
            build.assert_called_once_with("wintun")

    def test_cli_backend_option_is_rejected_before_building(self):
        for target in (
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ):
            for backend in ("wintun", "uwp"):
                with (
                    self.subTest(target=target, backend=backend),
                    contextlib.redirect_stderr(io.StringIO()),
                    patch("vole_scripts.cli.build_cli") as build,
                    patch("subprocess.Popen") as spawn,
                    self.assertRaises(SystemExit) as error,
                ):
                    cli.main(
                        [
                            "build",
                            "cli",
                            "--target",
                            target,
                            "--windows-backend",
                            backend,
                        ]
                    )
                self.assertEqual(error.exception.code, 2)
                build.assert_not_called()
                spawn.assert_not_called()

    def test_cli_features_fix_windows_to_wintun(self):
        for target, (system, _) in builds.CLI_TARGETS.items():
            with self.subTest(target=target):
                self.assertEqual(
                    builds.cli_features(target),
                    "cli,windows-wintun" if system == "Windows" else "cli",
                )
        with self.assertRaises(TypeError):
            builds.cli_features("x86_64-pc-windows-msvc", "uwp")
        with patch.object(builds, "_run") as run, self.assertRaises(TypeError):
            builds.build_cli(windows_backend="uwp")
        run.assert_not_called()

    def test_cli_target_and_profile_rejections_precede_compilation(self):
        for target, profile, system in (
            ("unknown-target", "release", "Linux"),
            ("x86_64-unknown-linux-gnu", "other", "Linux"),
            ("x86_64-unknown-linux-gnu", "release", "Darwin"),
        ):
            with (
                self.subTest(target=target, profile=profile, system=system),
                patch.object(builds.platform, "system", return_value=system),
                patch.object(builds, "_require_targets") as require,
                patch.object(builds, "_windows_msvc_environment") as msvc,
                patch.object(builds, "_run") as run,
                self.assertRaises((ValueError, RuntimeError)),
            ):
                builds.build_cli(target, profile)
            require.assert_not_called()
            msvc.assert_not_called()
            run.assert_not_called()

    def test_cli_builds_verify_native_artifacts_and_forward_environment(self):
        for target, (system, architecture) in builds.CLI_TARGETS.items():
            for profile in ("debug", "release"):
                with (
                    self.subTest(target=target, profile=profile),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    cache = root / "cache"
                    artifact = (
                        cache
                        / target
                        / profile
                        / ("vole.exe" if system == "Windows" else "vole")
                    )
                    artifact.parent.mkdir(parents=True)
                    contents = (
                        _windows_pe(0x8664 if architecture == "x64" else 0xAA64)
                        if system == "Windows"
                        else _linux_elf(62 if architecture == "x64" else 183)
                        if system == "Linux"
                        else EXPECTED_IDENTITY
                    )
                    artifact.write_bytes(contents)
                    environment = {
                        "CARGO_TARGET_DIR": str(cache),
                        "VOLE_RELEASE_NOTICES": "fixture notices",
                    }
                    with (
                        patch.dict(
                            os.environ, {"VOLE_BUILD_PROFILE": "debug"}, clear=True
                        ),
                        patch.object(builds, "CORE_DIR", root),
                        patch.object(builds.platform, "system", return_value=system),
                        patch.object(builds, "native_target", return_value=target),
                        patch.object(builds, "_require_targets") as require,
                        patch.object(
                            builds,
                            "_windows_msvc_environment",
                            return_value={"NATIVE_MSVC": "yes"},
                        ) as msvc,
                        patch.object(builds, "check_apple_binary") as apple,
                        patch.object(builds, "_run") as run,
                        contextlib.redirect_stdout(io.StringIO()) as output,
                    ):
                        self.assertEqual(
                            builds.build_cli(profile=profile, env=environment), artifact
                        )
                        require.assert_called_once_with([target])
                        command = run.call_args.args[0]
                        self.assertIn("--locked", command)
                        self.assertEqual("--release" in command, profile == "release")
                        self.assertEqual(
                            command[command.index("--features") + 1],
                            "cli,windows-wintun" if system == "Windows" else "cli",
                        )
                        self.assertEqual(command[-2:], ["--bin", "vole"])
                        self.assertEqual(
                            run.call_args.kwargs["env"]["VOLE_RELEASE_NOTICES"],
                            "fixture notices",
                        )
                        self.assertNotIn("VOLE_RELEASE_NOTICES", os.environ)
                        self.assertEqual(output.getvalue().strip(), str(artifact))
                        if system == "Windows":
                            msvc.assert_called_once_with(architecture)
                        else:
                            msvc.assert_not_called()
                        if system == "Darwin":
                            self.assertEqual(
                                apple.call_args.args[1:],
                                (
                                    "macos",
                                    None,
                                    {"x86_64" if architecture == "x64" else "arm64"},
                                    "10.15" if architecture == "x64" else "11.0",
                                ),
                            )
                        else:
                            apple.assert_not_called()

    def test_native_target_maps_supported_os_and_machine_aliases(self):
        for system, machine, architecture, target in (
            ("Linux", "amd64", "x64", "x86_64-unknown-linux-gnu"),
            ("Linux", "aarch64", "arm64", "aarch64-unknown-linux-gnu"),
            ("Darwin", "x86_64", "x64", "x86_64-apple-darwin"),
            ("Darwin", "arm64", "arm64", "aarch64-apple-darwin"),
            ("Windows", "AMD64", "arm64", "aarch64-pc-windows-msvc"),
        ):
            with (
                self.subTest(system=system, machine=machine),
                patch.object(builds.platform, "system", return_value=system),
                patch.object(builds.platform, "machine", return_value=machine),
                patch.object(
                    builds, "_windows_architecture", return_value=architecture
                ),
            ):
                self.assertEqual(builds.native_target(), target)

    def test_linux_build_stages_both_libraries_and_header_without_other_output_mutation(
        self,
    ):
        for architecture, target, machine in (
            ("x64", "x86_64-unknown-linux-gnu", 62),
            ("arm64", "aarch64-unknown-linux-gnu", 183),
        ):
            with (
                self.subTest(architecture=architecture),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                release = root / "target" / target / "release"
                release.mkdir(parents=True)
                shared = _linux_elf(machine)
                static = _archive(
                    ("/", b"symbols"), ("vole.o/", _linux_elf(machine, 1))
                )
                (release / "libvole.so").write_bytes(shared)
                (release / "libvole.a").write_bytes(static)
                (root / "include").mkdir()
                (root / "include/vole.h").write_bytes(b"fixture C header")
                stale = root / "dist/linux" / architecture / "stale"
                stale.parent.mkdir(parents=True)
                stale.write_bytes(b"stale")
                keep = root / "dist/windows/keep"
                keep.parent.mkdir(parents=True)
                keep.write_bytes(b"keep")
                with (
                    patch.dict(os.environ, {}, clear=True),
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(builds.platform, "system", return_value="Linux"),
                    patch.object(builds, "native_target", return_value=target),
                    patch.object(builds, "_require_targets") as require,
                    patch.object(builds, "_run") as run,
                ):
                    output = builds.build_linux(env={"VOLE_RELEASE_NOTICES": "fixture"})
                    require.assert_called_once_with([target])
                    command = run.call_args.args[0]
                    self.assertEqual(
                        command[-3:], ["--features", builds.DEFAULT_FEATURES, "--lib"]
                    )
                    self.assertIn("--locked", command)
                    self.assertIn("--release", command)
                    self.assertEqual(
                        run.call_args.kwargs["env"]["VOLE_RELEASE_NOTICES"], "fixture"
                    )
                self.assertEqual(output, stale.parent)
                self.assertFalse(stale.exists())
                self.assertEqual((output / "libvole.so").read_bytes(), shared)
                self.assertEqual((output / "libvole.a").read_bytes(), static)
                self.assertEqual(
                    (output / "include/vole.h").read_bytes(), b"fixture C header"
                )
                self.assertEqual(keep.read_bytes(), b"keep")

    def test_archive_architecture_readers_reject_missing_truncated_and_wrong_objects(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            static = root / "libvole.a"
            imported = root / "vole.dll.lib"
            for architecture, machine in (("x64", 62), ("arm64", 183)):
                static.write_bytes(
                    _archive(
                        ("/", b"symbols"), ("#1/5", b"a.o__" + _linux_elf(machine, 1))
                    )
                )
                builds._require_linux_architecture(static, architecture)
                imported.write_bytes(
                    _windows_import(0x8664 if architecture == "x64" else 0xAA64)
                )
                builds._require_windows_import_library(imported, architecture)
            for contents in (
                b"!<arch>\n",
                b"not an archive",
                _archive(("/", b"symbols")),
                _archive(("vole.o/", _linux_elf(183, 1))),
                _archive(("vole.o/", _linux_elf(62, 3))),
                _archive(("vole.o/", _linux_elf(62, 1)))[:-1],
            ):
                static.write_bytes(contents)
                with (
                    self.subTest(contents=contents[:20]),
                    self.assertRaises(RuntimeError),
                ):
                    builds._require_linux_architecture(static, "x64")
            for contents in (
                b"!<arch>\n",
                _windows_import(0xAA64),
                _windows_import(0x8664)[:-1],
                _archive(("bad.o/", b"tiny")),
            ):
                imported.write_bytes(contents)
                with (
                    self.subTest(contents=contents[:20]),
                    self.assertRaises(RuntimeError),
                ):
                    builds._require_windows_import_library(imported, "x64")

    def test_windows_wintun_and_uwp_builds_have_isolated_complete_artifact_sets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "target/x86_64-pc-windows-msvc/release"
            release.mkdir(parents=True)
            for name in (
                "vole.dll",
                "vole-windows-vpn-host.exe",
                "vole-windows-session-host.exe",
            ):
                (release / name).write_bytes(_windows_pe(0x8664))
            (release / "vole.dll.lib").write_bytes(_windows_import(0x8664))
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(
                    builds,
                    "os",
                    SimpleNamespace(name="nt", environ={}, fspath=os.fspath),
                ),
                patch.object(builds, "_windows_architecture", return_value="x64"),
                patch.object(builds, "_windows_msvc_environment", return_value={}),
                patch.object(builds, "_run") as run,
            ):
                uwp = builds.build_windows()
                before = {file.name: file.read_bytes() for file in uwp.iterdir()}
                wintun = builds.build_windows(
                    "wintun", env={"VOLE_RELEASE_NOTICES": "fixture"}
                )
                self.assertEqual(
                    {file.name: file.read_bytes() for file in uwp.iterdir()}, before
                )
                self.assertNotIn("--bins", run.call_args.args[0])
                self.assertEqual(
                    run.call_args.kwargs["env"]["VOLE_RELEASE_NOTICES"], "fixture"
                )
                self.assertEqual(
                    run.call_args.args[0][-3:],
                    ["--features", builds.windows_features("wintun"), "--lib"],
                )
            self.assertEqual(wintun, root / "dist/windows/x64/wintun")
            self.assertEqual(
                set(file.name for file in wintun.iterdir()),
                {"vole.dll", "vole.dll.lib"},
            )

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
                    patch.object(
                        builds,
                        "os",
                        SimpleNamespace(
                            name="posix", environ=os.environ, fspath=os.fspath
                        ),
                    ),
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
                (release / "vole.dll.lib").write_bytes(_windows_import(0xAA64))

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
                    self.assertEqual(
                        {p.name for p in (root / "dist/windows/arm64/uwp").iterdir()},
                        {
                            "vole.dll",
                            "vole.dll.lib",
                            "vole-windows-vpn-host.exe",
                            "vole-windows-session-host.exe",
                        },
                    )

                    provider = release / "vole-windows-vpn-host.exe"
                    provider.write_bytes(_windows_pe(0x8664))
                    with self.assertRaisesRegex(RuntimeError, "wrong architecture"):
                        builds.build_windows()
                    self.assertEqual(
                        list((root / "dist/windows/arm64/uwp").iterdir()), []
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
