from __future__ import annotations

import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from vcore_scripts import builds, cli
from vcore_scripts.builds import EXPECTED_IDENTITY, _android_target, _require_identity
from vcore_scripts.checks import (
    CRATES_IO_SOURCES,
    RUSTLS_GIT_SOURCE_PREFIX,
    _tls_dependency_errors,
)
from vcore_scripts.tun2socks import derive_xray_config


def _windows_pe(machine: int) -> bytes:
    contents = bytearray(512)
    contents[:2] = b"MZ"
    contents[0x3C:0x40] = (0x80).to_bytes(4, "little")
    contents[0x80:0x84] = b"PE\0\0"
    contents[0x84:0x86] = machine.to_bytes(2, "little")
    contents[0x100 : 0x100 + len(EXPECTED_IDENTITY)] = EXPECTED_IDENTITY
    return bytes(contents)


class ScriptTest(unittest.TestCase):
    def test_cli_dispatches_windows_build_without_architecture(self):
        with patch("vcore_scripts.cli.build_windows") as build:
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
            full_trust.attrib["Executable"], "vcore-windows-session-host.exe"
        )
        self.assertEqual(provider.attrib["Executable"], "vcore-windows-vpn-host.exe")
        self.assertEqual(provider.attrib[f"{{{uap10}}}RuntimeBehavior"], "windowsApp")
        self.assertEqual(provider.attrib[f"{{{uap10}}}TrustLevel"], "appContainer")

    def test_android_target_mapping_is_strict(self):
        self.assertEqual(
            _android_target("aarch64-linux-android", "24"),
            ("arm64-v8a", "aarch64-linux-android24-clang", "AARCH64_LINUX_ANDROID"),
        )
        with self.assertRaisesRegex(RuntimeError, "unsupported Android Rust target"):
            _android_target("mips-linux-android", "24")

    def test_artifact_identity_check_reads_binary_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "libvcore.a"
            artifact.write_bytes(b"prefix\0" + EXPECTED_IDENTITY + b"\0suffix")
            _require_identity(artifact, "test")
            artifact.write_bytes(b"wrong")
            with self.assertRaisesRegex(RuntimeError, "incompatible Rust identity"):
                _require_identity(artifact, "test")

    def test_windows_release_build_uses_production_features_and_checks_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "target/aarch64-pc-windows-msvc/release"
            release.mkdir(parents=True)
            artifacts = (
                "vcore.dll",
                "vcore-windows-vpn-host.exe",
                "vcore-windows-session-host.exe",
            )
            for name in artifacts:
                (release / name).write_bytes(_windows_pe(0xAA64))

            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(builds, "os", SimpleNamespace(name="nt")),
                patch.object(builds, "_windows_architecture", return_value="arm64"),
                patch.object(builds, "_windows_msvc_environment", return_value={}),
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
                        "ffi",
                        "--lib",
                        "--bins",
                    ],
                )
                manifest = json.loads(
                    (
                        root / "dist/windows/arm64/vcore-windows-artifacts.json"
                    ).read_text()
                )
                expected_digest = (
                    "93dd534a99e69369e9dc435101dce44d5b0be4fb43c82abec500e1bb4fb88444"
                )
                self.assertEqual(
                    manifest,
                    {
                        "architecture": "arm64",
                        "artifacts": {
                            "vcore-windows-session-host.exe": expected_digest,
                            "vcore-windows-vpn-host.exe": expected_digest,
                            "vcore.dll": expected_digest,
                        },
                        "buildIdentity": EXPECTED_IDENTITY.decode("ascii"),
                        "formatVersion": 1,
                        "windowsPackageIntegrationRevision": 2,
                    },
                )

                provider = release / "vcore-windows-vpn-host.exe"
                provider.write_bytes(_windows_pe(0x8664))
                with self.assertRaisesRegex(RuntimeError, "wrong architecture"):
                    builds.build_windows()
                self.assertFalse(
                    (root / "dist/windows/arm64/vcore-windows-artifacts.json").exists()
                )

                provider.write_bytes(_windows_pe(0xAA64))
                dll = bytearray(_windows_pe(0xAA64))
                dll[0x100 : 0x100 + len(EXPECTED_IDENTITY)] = bytes(
                    len(EXPECTED_IDENTITY)
                )
                (release / "vcore.dll").write_bytes(dll)
                with self.assertRaisesRegex(RuntimeError, "incompatible Rust identity"):
                    builds.build_windows()

    def test_tls_metadata_accepts_the_locked_graph(self):
        registry = next(iter(CRATES_IO_SOURCES))
        metadata = {
            "packages": [
                {
                    "id": "rustls-id",
                    "name": "rustls",
                    "version": "0.23.43",
                    "source": RUSTLS_GIT_SOURCE_PREFIX + "a" * 40,
                },
                {
                    "id": "tokio-rustls-id",
                    "name": "tokio-rustls",
                    "version": "0.26.4",
                    "source": registry,
                },
                {
                    "id": "ring-id",
                    "name": "ring",
                    "version": "0.17.14",
                    "source": registry,
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "rustls-id",
                        "features": ["reality", "ring", "std", "tls12"],
                    }
                ]
            },
        }
        self.assertEqual(_tls_dependency_errors(metadata), [])

        metadata["packages"].append(
            {
                "id": "aws-id",
                "name": "aws-lc-rs",
                "version": "1.0.0",
                "source": registry,
            }
        )
        self.assertTrue(
            any(
                "AWS-LC package is forbidden" in error
                for error in _tls_dependency_errors(metadata)
            )
        )

        metadata["packages"][0]["source"] = None
        self.assertTrue(
            any(
                "vcore/reality-0.23 GitHub branch" in error
                for error in _tls_dependency_errors(metadata)
            )
        )

    def test_tun2socks_config_moves_direct_sockopt(self):
        source = {
            "inbounds": [
                {
                    "tag": "proxy",
                    "protocol": "socks",
                    "listen": "0.0.0.0",
                    "port": 1080,
                    "settings": {"udp": False},
                }
            ],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {}},
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {},
                    "sockopt": {"interface": "Ethernet"},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            config, inbound_tag, direct_tag = derive_xray_config(path, Path(directory))
        self.assertEqual((inbound_tag, direct_tag), ("proxy", "direct"))
        direct = next(item for item in config["outbounds"] if item["tag"] == "direct")
        self.assertNotIn("sockopt", direct)
        self.assertEqual(direct["streamSettings"]["sockopt"], {"interface": "Ethernet"})
        self.assertTrue(config["inbounds"][0]["settings"]["udp"])


if __name__ == "__main__":
    unittest.main()
