import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds


class AndroidPlatformTest(unittest.TestCase):
    def test_android_ndk_major_uses_numeric_stable_revisions_and_honors_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            installed = root / "sdk/ndk"
            for version, revision in (
                ("30.2.9", "30.2.9"),
                ("30.2.10", "30.2.10"),
                ("30.10.1", "30.10.1"),
                ("31.1.1", "31.1.1"),
                ("30.99.99", "30.99.99-beta1"),
                ("30.99.99-beta1", "30.99.99"),
                ("30.88.1", "30.88.2"),
                ("30.77.1", None),
                ("32.1.1", "32.1.1-rc1"),
            ):
                ndk = installed / version
                ndk.mkdir(parents=True)
                if revision:
                    (ndk / "source.properties").write_text(
                        f"Pkg.Desc = Android NDK\nPkg.Revision = {revision}\n"
                    )
            for overrides, expected in (
                ({}, installed / "30.10.1"),
                ({"VOLE_ANDROID_NDK_VERSION": "30"}, installed / "30.10.1"),
                ({"VOLE_ANDROID_NDK_VERSION": "31"}, installed / "31.1.1"),
                ({"VOLE_ANDROID_NDK_VERSION": "30.2.9"}, installed / "30.2.9"),
                (
                    {
                        "ANDROID_NDK_HOME": str(root / "explicit-ndk"),
                        "VOLE_ANDROID_NDK_VERSION": "32",
                    },
                    root / "explicit-ndk",
                ),
            ):
                with (
                    self.subTest(overrides=overrides),
                    patch.dict(
                        os.environ,
                        {"ANDROID_HOME": str(root / "sdk")} | overrides,
                        clear=True,
                    ),
                    patch.object(
                        Path,
                        "home",
                        side_effect=RuntimeError("Could not determine home directory"),
                    ) as home,
                ):
                    self.assertEqual(builds._android_ndk_home(), expected)
                    home.assert_not_called()
            with (
                patch.dict(
                    os.environ,
                    {
                        "ANDROID_HOME": str(root / "sdk"),
                        "VOLE_ANDROID_NDK_VERSION": "32",
                    },
                    clear=True,
                ),
                patch.object(
                    Path,
                    "home",
                    side_effect=RuntimeError("Could not determine home directory"),
                ),
                self.assertRaisesRegex(RuntimeError, "stable Android NDK.*32"),
            ):
                builds._android_ndk_home()

    def test_android_ndk_default_sdk_uses_home_only_without_sdk_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ndk = root / "Library/Android/sdk/ndk/30.1.1"
            ndk.mkdir(parents=True)
            (ndk / "source.properties").write_text("Pkg.Revision = 30.1.1\n")
            for sdk_environment in ({}, {"ANDROID_HOME": ""}):
                with (
                    self.subTest(environment=sdk_environment),
                    patch.dict(os.environ, sdk_environment, clear=True),
                    patch.object(Path, "home", return_value=root) as home,
                ):
                    self.assertEqual(builds._android_ndk_home(), ndk)
                    home.assert_called_once_with()
