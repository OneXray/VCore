"""Offline regressions for Apple artifact identity; no simulator or network."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds


class ApplePlatformTest(unittest.TestCase):
    def test_apple_build_reads_and_stages_the_configured_cargo_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout, target = root / "core", root / "cargo-output"
            targets = (
                "aarch64-apple-ios",
                "aarch64-apple-ios-sim",
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "aarch64-apple-tvos",
                "aarch64-apple-tvos-sim",
            )
            for triple in targets:
                library = target / triple / "release/libvole.a"
                library.parent.mkdir(parents=True)
                library.write_bytes(builds.EXPECTED_IDENTITY + triple.encode())

            def run(command, **_):
                if command[:2] == ["xcrun", "lipo"]:
                    Path(command[-1]).write_bytes(builds.EXPECTED_IDENTITY)

            with (
                patch.object(builds, "CORE_DIR", checkout),
                patch.dict(
                    builds.os.environ,
                    {
                        "CARGO_TARGET_DIR": str(target),
                        "VOLE_APPLE_DIST_DIR": str(root / "package"),
                    },
                    clear=True,
                ),
                patch.object(builds.platform, "system", return_value="Darwin"),
                patch.object(builds, "_require_targets") as require,
                patch.object(builds, "_cargo_build") as cargo,
                patch.object(builds, "_run", side_effect=run) as commands,
                patch.object(builds, "check_apple_binary") as check,
            ):
                builds.build_apple()
            require.assert_called_once_with(list(targets))
            self.assertEqual(
                [invocation.args[0] for invocation in cargo.call_args_list],
                list(targets),
            )
            self.assertEqual(
                (target / "vole-apple/ios-simulator/libvole.a").read_bytes(),
                builds.EXPECTED_IDENTITY + b"aarch64-apple-ios-sim",
            )
            lipo = [
                invocation.args[0]
                for invocation in commands.call_args_list
                if invocation.args[0][:2] == ["xcrun", "lipo"]
            ]
            self.assertEqual(
                lipo,
                [
                    [
                        "xcrun",
                        "lipo",
                        "-create",
                        target / "aarch64-apple-darwin/release/libvole.a",
                        target / "x86_64-apple-darwin/release/libvole.a",
                        "-output",
                        target / "vole-apple/macos/libvole.a",
                    ]
                ],
            )
            self.assertEqual(check.call_count, 5)
            self.assertEqual(
                check.call_args_list[1].args[1:],
                ("ios", "simulator", {"arm64"}, "13.0"),
            )
            self.assertEqual(
                check.call_args_list[2].args[1:],
                ("macos", None, {"arm64", "x86_64"}, "10.15"),
            )
            for invocation in check.call_args_list:
                self.assertTrue(invocation.args[0].is_relative_to(target))
            self.assertFalse((checkout / "target").exists())

    def test_all_native_archive_members_have_the_right_platform_and_floor(self):
        first = (
            "lib.a(rust.o):\nLoad command 0\n cmd LC_BUILD_VERSION\n"
            " platform 3\n minos 17.0\n"
        )
        second = (
            "lib.a(crypto.o):\nLoad command 0\n cmd LC_VERSION_MIN_TVOS\n"
            " version 10.0\n"
        )
        self.assertEqual(
            builds._check_apple_load_commands(
                first + second, "tvos", None, "arm64", "17.0"
            ),
            2,
        )
        for bad in (
            first + second.replace("TVOS", "IPHONEOS"),
            first.replace("platform 3", "platform 2") + second,
            first.replace("minos 17.0", "minos 18.0") + second,
            first + "lib.a(unmarked.o):\nLoad command 0\n cmd LC_SEGMENT_64\n",
            first + second + second.replace("version 10.0", "version corrupt"),
            "",
        ):
            with self.subTest(output=bad), self.assertRaises(ValueError):
                builds._check_apple_load_commands(bad, "tvos", None, "arm64", "17.0")
        simulator = first.replace("platform 3", "platform 8")
        self.assertEqual(
            builds._check_apple_load_commands(
                simulator, "tvos", "simulator", "arm64", "17.0"
            ),
            1,
        )
        with self.assertRaises(ValueError):
            builds._check_apple_load_commands(
                first, "tvos", "simulator", "arm64", "17.0"
            )

    def test_ios_simulator_binary_rejects_intel_architectures(self):
        for architectures in ("x86_64", "arm64 x86_64"):
            with (
                self.subTest(architectures=architectures),
                patch.object(
                    builds.subprocess, "check_output", return_value=architectures
                ) as inspect,
                self.assertRaisesRegex(ValueError, "architecture"),
            ):
                builds.check_apple_binary(
                    Path("ios-simulator/libvole.a"),
                    "ios",
                    "simulator",
                    {"arm64"},
                    "13.0",
                )
            self.assertEqual(inspect.call_count, 1)

    def test_retained_architecture_floors_do_not_raise_product_minimums(self):
        for system, variant, architecture, platform, version, product in (
            ("ios", None, "arm64", 2, "13.0", "13.0"),
            ("ios", "simulator", "arm64", 7, "14.0", "13.0"),
            ("macos", None, "arm64", 1, "11.0", "10.15"),
            ("macos", None, "x86_64", 1, "10.15", "10.15"),
        ):
            output = (
                "lib.a(std.o):\nLoad command 0\n cmd LC_BUILD_VERSION\n"
                f" platform {platform}\n minos {version}\n"
            )
            self.assertEqual(
                builds._check_apple_load_commands(
                    output, system, variant, architecture, product
                ),
                1,
            )
        with (
            patch.dict(os.environ, {"VOLE_TVOS_DEPLOYMENT_TARGET": "16.0"}),
            self.assertRaisesRegex(ValueError, "17.0"),
        ):
            builds.tvos_deployment_target()


if __name__ == "__main__":
    unittest.main()
