from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from vcore_scripts import builds, cli
from vcore_scripts.builds import EXPECTED_IDENTITY, _android_target, _require_identity
from vcore_scripts.checks import (
    BORING_GIT_SOURCE,
    BORING_REVISION,
    CRATES_IO_SOURCES,
    _shadowsocks_aws_lc_errors,
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
    def test_platform_builds_explicitly_include_all_client_protocols(self):
        manifest = tomllib.loads((builds.CORE_DIR / "Cargo.toml").read_text())
        features = set(builds.DEFAULT_FEATURES.split(","))
        self.assertEqual(
            features, set(manifest["features"]["default"]) | {"ffi", "tun"}
        )
        self.assertNotIn("interop-test", features)

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

    def test_legacy_demo_requires_explicit_config_and_source(self):
        with patch("vcore_scripts.cli.run_demo") as run:
            self.assertEqual(
                cli.main(
                    [
                        "demo",
                        "windows-tun2socks",
                        "fixture.json",
                        "--xray-source",
                        "fixture-xray",
                    ]
                ),
                0,
            )
        run.assert_called_once_with(
            Path("fixture.json"), xray_source=Path("fixture-xray")
        )

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

    def test_android_build_packages_the_matching_ndk_cpp_runtime(self):
        for configured in (False, True):
            with (
                self.subTest(configured=configured),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                target_dir = root / ("cache" if configured else "target")
                toolchain = root / "ndk/toolchain"
                (toolchain / "bin").mkdir(parents=True)
                (toolchain / "bin/llvm-ar").touch()
                targets = ("aarch64-linux-android", "x86_64-linux-android")
                for target in targets:
                    abi, clang, _ = _android_target(target, "24")
                    (toolchain / "bin" / clang).touch()
                    (toolchain / "bin" / (clang + "++")).touch()
                    runtime = (
                        toolchain / "sysroot/usr/lib" / target / "libc++_shared.so"
                    )
                    runtime.parent.mkdir(parents=True)
                    runtime.write_bytes(abi.encode())
                    artifact = target_dir / target / "release/libvcore.so"
                    artifact.parent.mkdir(parents=True)
                    artifact.write_bytes(EXPECTED_IDENTITY)
                with (
                    patch.dict(
                        builds.os.environ,
                        {"ANDROID_NDK_HOME": str(root / "ndk")}
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
                    abi, clang, _ = _android_target(target, "24")
                    env = invocation.args[3]
                    self.assertEqual(env["VCORE_CMAKE_ANDROID_ABI"], abi)
                    self.assertEqual(env["VCORE_CMAKE_ANDROID_API"], "24")
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
                        (output / "libvcore.so").read_bytes(), EXPECTED_IDENTITY
                    )
                    self.assertEqual(
                        (output / "libc++_shared.so").read_bytes(), abi.encode()
                    )

    def test_artifact_identity_check_reads_binary_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "libvcore.a"
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
                            builds.DEFAULT_FEATURES,
                            "--lib",
                            "--bins",
                        ],
                    )
                    manifest = json.loads(
                        (
                            root / "dist/windows/arm64/vcore-windows-artifacts.json"
                        ).read_text()
                    )
                    expected_digest = hashlib.sha256(_windows_pe(0xAA64)).hexdigest()
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
                            "windowsPackageIntegrationRevision": 3,
                        },
                    )

                    provider = release / "vcore-windows-vpn-host.exe"
                    provider.write_bytes(_windows_pe(0x8664))
                    with self.assertRaisesRegex(RuntimeError, "wrong architecture"):
                        builds.build_windows()
                    self.assertFalse(
                        (
                            root / "dist/windows/arm64/vcore-windows-artifacts.json"
                        ).exists()
                    )

                    provider.write_bytes(_windows_pe(0xAA64))
                    dll = bytearray(_windows_pe(0xAA64))
                    dll[0x100 : 0x100 + len(EXPECTED_IDENTITY)] = bytes(
                        len(EXPECTED_IDENTITY)
                    )
                    (release / "vcore.dll").write_bytes(dll)
                    with self.assertRaisesRegex(
                        RuntimeError, "incompatible Rust identity"
                    ):
                        builds.build_windows()

    def test_tls_metadata_accepts_the_locked_graph(self):
        registry = next(iter(CRATES_IO_SOURCES))
        metadata = {
            "packages": [
                {
                    "id": "rustls-id",
                    "name": "rustls",
                    "version": "0.23.45",
                    "source": registry,
                },
                {
                    "id": "tokio-rustls-id",
                    "name": "tokio-rustls",
                    "version": "0.26.5",
                    "source": registry,
                },
                {
                    "id": "ring-id",
                    "name": "ring",
                    "version": "0.17.14",
                    "source": registry,
                },
                *[
                    dict(id=name, name=name, version="5.2.0", source=BORING_GIT_SOURCE)
                    for name in ("boring", "boring-sys", "tokio-boring")
                ],
                dict(id="hpke", name="hpke", version="0.14.1", source=registry),
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "rustls-id",
                        "features": ["ring", "std", "tls12"],
                        "deps": [],
                    },
                    {
                        "id": "boring",
                        "features": [
                            "reality",
                            "client-fingerprint",
                            "shadow-tls-v3",
                            "jls",
                        ],
                        "deps": [{"pkg": "boring-sys"}],
                    },
                    {
                        "id": "boring-sys",
                        "features": ["reality", "shadow-tls-v3", "jls"],
                    },
                    {
                        "id": "tokio-boring",
                        "features": [],
                        "deps": [{"pkg": "boring"}, {"pkg": "boring-sys"}],
                    },
                    {
                        "id": "hpke",
                        "features": ["alloc", "aes", "chacha", "x25519", "hkdfsha2"],
                    },
                ]
            },
        }
        self.assertEqual(_tls_dependency_errors(metadata), [])

        for invalid_source in (None, BORING_GIT_SOURCE):
            invalid = copy.deepcopy(metadata)
            invalid["packages"][-1]["source"] = invalid_source
            self.assertTrue(_tls_dependency_errors(invalid))
        for feature in ("alloc", "aes", "chacha", "x25519"):
            invalid = copy.deepcopy(metadata)
            invalid["resolve"]["nodes"][-1]["features"].remove(feature)
            self.assertTrue(_tls_dependency_errors(invalid))

        for index, old_version in [(0, "0.23.43"), (1, "0.26.4"), (3, "5.1.0")]:
            with self.subTest(outdated_version=old_version):
                outdated = copy.deepcopy(metadata)
                outdated["packages"][index]["version"] = old_version
                self.assertTrue(_tls_dependency_errors(outdated))

        for source in [
            None,
            registry,
            BORING_GIT_SOURCE.rsplit("#", 1)[0] + "#" + "f" * 40,
            BORING_GIT_SOURCE.replace("?branch=release", "?branch=main"),
            BORING_GIT_SOURCE.replace("?branch=release", f"?rev={BORING_REVISION}"),
            BORING_GIT_SOURCE.replace("OneXray/boring", "example/boring"),
        ]:
            for index in (3, 4, 5):
                with self.subTest(boring_source=source, package=index):
                    invalid = copy.deepcopy(metadata)
                    invalid["packages"][index]["source"] = source
                    self.assertTrue(_tls_dependency_errors(invalid))

        for required in ["reality", "client-fingerprint", "shadow-tls-v3", "jls"]:
            with self.subTest(boring_feature=required):
                invalid = copy.deepcopy(metadata)
                invalid["resolve"]["nodes"][1]["features"].remove(required)
                self.assertTrue(_tls_dependency_errors(invalid))

        for missing in ["edge", "node", "package"]:
            with self.subTest(boring_missing=missing):
                invalid = copy.deepcopy(metadata)
                if missing == "edge":
                    invalid["resolve"]["nodes"][1]["deps"] = []
                elif missing == "node":
                    invalid["resolve"]["nodes"].pop()
                else:
                    invalid["packages"].pop()
                self.assertTrue(_tls_dependency_errors(invalid))

        for forbidden in ["reality", "aws_lc_rs", "fips"]:
            invalid = copy.deepcopy(metadata)
            invalid["resolve"]["nodes"][0]["features"].append(forbidden)
            self.assertTrue(_tls_dependency_errors(invalid))

        for forbidden in ("fips", "restls"):
            for index in (1, 2, 3):
                with self.subTest(native_feature=forbidden, node=index):
                    invalid = copy.deepcopy(metadata)
                    invalid["resolve"]["nodes"][index]["features"].append(forbidden)
                    self.assertTrue(_tls_dependency_errors(invalid))

        for source in CRATES_IO_SOURCES:
            with self.subTest(rustls_registry=source):
                official = copy.deepcopy(metadata)
                official["packages"][0]["source"] = source
                self.assertEqual(_tls_dependency_errors(official), [])

        for source in (
            None,
            "git+https://example.invalid/rustls?branch=custom#" + "a" * 40,
            "git+https://github.com/rustls/rustls#" + "a" * 40,
            "registry+https://example.invalid/index",
        ):
            with self.subTest(rustls_source=source):
                invalid = copy.deepcopy(metadata)
                invalid["packages"][0]["source"] = source
                self.assertTrue(
                    any(
                        "rustls must come from crates.io" in error
                        for error in _tls_dependency_errors(invalid)
                    )
                )

        duplicate = copy.deepcopy(metadata)
        duplicate["packages"].append(
            dict(
                id="second-rustls",
                name="rustls",
                version="0.23.45",
                source="git+https://github.com/rustls/rustls#" + "a" * 40,
            )
        )
        self.assertTrue(_tls_dependency_errors(duplicate))

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
                "rustls must come from crates.io" in error
                for error in _tls_dependency_errors(metadata)
            )
        )

    def test_aws_lc_exception_is_restricted_to_official_shadowsocks_chain(self):
        registry = next(iter(CRATES_IO_SOURCES))
        names = ["shadowsocks", "shadowsocks-crypto", "aws-lc-rs", "aws-lc-sys"]
        metadata = {
            "packages": [
                {"id": name, "name": name, "version": version, "source": source}
                for name, version, source in zip(
                    names,
                    ["1.25.0", "0.8.0", "1.18.1", "0.45.0"],
                    [registry] * 4,
                    strict=True,
                )
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": name,
                        "features": features,
                        "deps": [{"pkg": names[i + 1]}] if i < 3 else [],
                    }
                    for i, (name, features) in enumerate(
                        zip(
                            names,
                            [["aead-cipher-2022"], ["v2", "aws-lc"], [], []],
                            strict=True,
                        )
                    )
                ]
            },
        }
        self.assertEqual(_shadowsocks_aws_lc_errors(metadata), [])
        for source in CRATES_IO_SOURCES:
            with self.subTest(shadowsocks_registry=source):
                official = copy.deepcopy(metadata)
                official["packages"][0]["source"] = source
                self.assertEqual(_shadowsocks_aws_lc_errors(official), [])
        for source in (
            "git+https://github.com/shadowsocks/shadowsocks-rust.git?rev="
            "ab388c7466d21f979430e33cc9ef10e22fb05955#"
            "ab388c7466d21f979430e33cc9ef10e22fb05955",
            "registry+https://example.invalid/index",
        ):
            with self.subTest(shadowsocks_source=source):
                invalid = copy.deepcopy(metadata)
                invalid["packages"][0]["source"] = source
                self.assertTrue(_shadowsocks_aws_lc_errors(invalid))
        for index, feature in [(0, "aead-cipher-2022-extra"), (1, "v2-extra")]:
            invalid = copy.deepcopy(metadata)
            invalid["resolve"]["nodes"][index]["features"].append(feature)
            self.assertTrue(_shadowsocks_aws_lc_errors(invalid))
        for target in names[1:]:
            with self.subTest(extra_consumer=target):
                invalid = copy.deepcopy(metadata)
                invalid["resolve"]["nodes"].append(
                    {"id": "another-consumer", "deps": [{"pkg": target}]}
                )
                self.assertTrue(_shadowsocks_aws_lc_errors(invalid))
        for index in range(4):
            with self.subTest(unofficial_source=names[index]):
                invalid = copy.deepcopy(metadata)
                invalid["packages"][index]["source"] = None
                self.assertTrue(_shadowsocks_aws_lc_errors(invalid))
            with self.subTest(missing_node=names[index]):
                invalid = copy.deepcopy(metadata)
                del invalid["resolve"]["nodes"][index]
                self.assertTrue(_shadowsocks_aws_lc_errors(invalid))
        invalid = copy.deepcopy(metadata)
        invalid["packages"].append({"id": "fips", "name": "aws-lc-fips-sys"})
        self.assertTrue(_shadowsocks_aws_lc_errors(invalid))

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
