"""Offline regressions for Apple artifact identity; no simulator or network."""

import copy
import hashlib
import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vcore_scripts import apple_runtime, builds, platform_delivery


class ApplePlatformTest(unittest.TestCase):
    def test_owned_simulator_cleanup_covers_partial_creation_and_runtime_failure(self):
        for failure in (None, "create", "boot", "body"):
            with self.subTest(failure=failure):
                owner = "vcore-platform-" + "a" * 32
                devices = [{"name": "user-device", "udid": "other", "state": "Booted"}]
                runtime = {
                    "identifier": "com.apple.CoreSimulator.SimRuntime.tvOS-27-0",
                    "isAvailable": True,
                    "version": "27.0",
                    "buildversion": "fixture",
                    "supportedDeviceTypes": [
                        {"productFamily": "Apple TV", "identifier": "compatible-tv"}
                    ],
                }
                record = {}

                def simctl(
                    *args,
                    runtime=runtime,
                    devices=devices,
                    owner=owner,
                    failure=failure,
                    **_,
                ):
                    if args[:2] == ("list", "runtimes"):
                        return json.dumps({"runtimes": [runtime]})
                    if args[:2] == ("list", "devices"):
                        return json.dumps({"devices": {"fixture": devices}})
                    if args[0] == "create":
                        self.assertEqual(args[1:3], (owner, "compatible-tv"))
                        devices.append(
                            {"name": owner, "udid": "owned", "state": "Shutdown"}
                        )
                    else:
                        self.assertEqual(args[1], "owned")
                    if args[0] == failure:
                        raise RuntimeError("injected")
                    if args[0] == "boot":
                        devices[-1]["state"] = "Booted"
                    elif args[0] == "shutdown":
                        devices[-1]["state"] = "Shutdown"
                    elif args[0] == "delete":
                        devices.pop()
                    return "owned"

                with (
                    patch.object(apple_runtime, "_simctl", side_effect=simctl),
                    patch.object(
                        apple_runtime.uuid,
                        "uuid4",
                        return_value=SimpleNamespace(hex="a" * 32),
                    ),
                ):
                    try:
                        with apple_runtime.simulator(
                            "tvos", record, minimum="17.0"
                        ) as identifier:
                            self.assertEqual(identifier, "owned")
                            if failure == "body":
                                raise RuntimeError("injected")
                    except RuntimeError as error:
                        self.assertIsNotNone(failure)
                        self.assertEqual(str(error), "injected")
                    else:
                        self.assertIsNone(failure)
                self.assertTrue(record["cleaned"])
                self.assertEqual(
                    devices,
                    [{"name": "user-device", "udid": "other", "state": "Booted"}],
                )

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

    def test_existing_arm64_architecture_floors_do_not_raise_product_minimums(self):
        for system, variant, platform, version, product in (
            ("ios", "simulator", 7, "14.0", "13.0"),
            ("macos", None, 1, "11.0", "10.15"),
        ):
            output = (
                "lib.a(std.o):\nLoad command 0\n cmd LC_BUILD_VERSION\n"
                f" platform {platform}\n minos {version}\n"
            )
            self.assertEqual(
                builds._check_apple_load_commands(
                    output, system, variant, "arm64", product
                ),
                1,
            )
        with (
            patch.dict(os.environ, {"VCORE_TVOS_DEPLOYMENT_TARGET": "16.0"}),
            self.assertRaisesRegex(ValueError, "17.0"),
        ):
            builds.tvos_deployment_target()

    def test_five_slice_manifest_rejects_missing_tvos_or_mislabelled_ios(self):
        slices = {
            "ios-arm64": ("ios", None, ["arm64"]),
            "ios-arm64_x86_64-simulator": ("ios", "simulator", ["arm64", "x86_64"]),
            "macos-arm64_x86_64": ("macos", None, ["arm64", "x86_64"]),
            "tvos-arm64": ("tvos", None, ["arm64"]),
            "tvos-arm64-simulator": ("tvos", "simulator", ["arm64"]),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            framework = root / "LibVCore.xcframework"
            libraries = []
            for identifier, (platform, variant, architectures) in slices.items():
                folder = framework / identifier
                (folder / "Headers").mkdir(parents=True)
                (folder / "libvcore.a").write_bytes(builds.EXPECTED_IDENTITY)
                (folder / "Headers/vcore.h").write_text("header fixture")
                (folder / "Headers/module.modulemap").write_text("module fixture")
                library = dict(
                    LibraryIdentifier=identifier,
                    SupportedPlatform=platform,
                    SupportedArchitectures=architectures,
                    LibraryPath="libvcore.a",
                    HeadersPath="Headers",
                )
                if variant:
                    library["SupportedPlatformVariant"] = variant
                libraries.append(library)
            manifest = root / "vcore-delivery.json"

            def write(rows):
                (framework / "Info.plist").write_bytes(
                    plistlib.dumps({"AvailableLibraries": rows})
                )
                record = dict(
                    formatVersion=1,
                    profile="release",
                    group="apple",
                    source={"fixture": True},
                    features=builds.DEFAULT_FEATURES.split(","),
                    buildIdentity=builds.EXPECTED_IDENTITY.decode(),
                    toolchain={
                        key: "fixture"
                        for key in (
                            "rustc",
                            "cargo",
                            "xcode",
                            "iphoneos",
                            "iphonesimulator",
                            "macosx",
                            "appletvos",
                            "appletvsimulator",
                        )
                    },
                )
                record["toolchain"].update(
                    iosDeploymentTarget="13.0",
                    macosDeploymentTarget="10.15",
                    tvosDeploymentTarget="17.0",
                )
                record["artifacts"] = [
                    dict(
                        path=p.relative_to(root).as_posix(),
                        size=p.stat().st_size,
                        sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                    )
                    for p in sorted(framework.rglob("*"))
                    if p.is_file()
                ]
                manifest.write_text(json.dumps(record))

            with (
                patch.object(
                    platform_delivery, "_source", return_value={"fixture": True}
                ),
                patch.object(builds, "check_apple_binary") as check,
            ):
                write(libraries)
                platform_delivery.check_delivery([manifest])
                self.assertEqual(check.call_count, 5)
                self.assertEqual(
                    check.call_args.args[1:], ("tvos", "simulator", {"arm64"}, "17.0")
                )
                for mutation in ("missing", "platform", "variant", "architecture"):
                    rows = copy.deepcopy(libraries)
                    if mutation == "missing":
                        rows.pop()
                    elif mutation == "platform":
                        rows[-1]["SupportedPlatform"] = "ios"
                    elif mutation == "variant":
                        del rows[-1]["SupportedPlatformVariant"]
                    else:
                        rows[-1]["SupportedArchitectures"] = ["x86_64"]
                    write(rows)
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        platform_delivery.check_delivery([manifest])


if __name__ == "__main__":
    unittest.main()
