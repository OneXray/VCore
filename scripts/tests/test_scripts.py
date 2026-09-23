from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from vcore_scripts import builds, cli, mihomo
from vcore_scripts.builds import EXPECTED_IDENTITY, _android_target, _require_identity
from vcore_scripts.checks import (
    CRATES_IO_SOURCES,
    SHADOWSOCKS_GIT_SOURCE,
    _shadowsocks_aws_lc_errors,
    _tls_dependency_errors,
)
from vcore_scripts.mihomo_container import (
    NETWORK,
    ContainerPeer,
    ContainerPeers,
    host_ipv6,
)
from vcore_scripts.mihomo_isolation import exclusive_run
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

    def test_mihomo_check_dispatches(self):
        with patch("vcore_scripts.cli.run_mihomo_interop") as run:
            self.assertEqual(cli.main(["check", "mihomo-interop"]), 0)
        run.assert_called_once_with(extended=False, soak_seconds=0, container=False)

    def test_mihomo_native_and_container_share_one_latest_release(self):
        release = "v9.8.7"
        native, linux = Path("native-mihomo"), Path("linux-mihomo")
        with (
            patch.object(mihomo, "latest_release", return_value=release) as latest,
            patch.object(
                mihomo, "download_mihomo", side_effect=[native, linux]
            ) as fetch,
            patch.object(mihomo, "exclusive_run", nullcontext),
            patch.object(mihomo, "_run_mihomo_interop") as run,
        ):
            mihomo.run_mihomo_interop(container=True)
        latest.assert_called_once_with()
        self.assertEqual(
            fetch.call_args_list,
            [call(release=release), call("linux-arm64", release=release)],
        )
        run.assert_called_once_with(
            native, extended=False, soak_seconds=0, container_binary=linux
        )

    def test_mihomo_lookup_failure_does_not_run_a_stale_peer(self):
        with (
            patch.object(mihomo, "latest_release", side_effect=RuntimeError("offline")),
            patch.object(mihomo, "download_mihomo") as fetch,
            patch.object(mihomo, "exclusive_run", nullcontext),
            patch.object(mihomo, "_run_mihomo_interop") as run,
            self.assertRaisesRegex(RuntimeError, "offline"),
        ):
            mihomo.run_mihomo_interop()
        fetch.assert_not_called()
        run.assert_not_called()

    def test_download_cli_dispatches_host_and_container_target(self):
        with patch("vcore_scripts.cli.download_mihomo") as fetch:
            self.assertEqual(cli.main(["download", "mihomo"]), 0)
            self.assertEqual(
                cli.main(["download", "mihomo", "--target", "linux-arm64"]), 0
            )
        self.assertEqual(fetch.call_args_list, [call(None), call("linux-arm64")])

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

    def test_extended_mihomo_dispatch_and_soak_bounds(self):
        with patch("vcore_scripts.cli.run_mihomo_interop") as run:
            self.assertEqual(
                cli.main(
                    ["check", "mihomo-interop", "--extended", "--soak-seconds", "90"]
                ),
                0,
            )
        run.assert_called_once_with(extended=True, soak_seconds=90, container=False)
        for extended, seconds in [(False, 1), (True, -1), (True, 7201)]:
            with (
                self.subTest(extended=extended, seconds=seconds),
                self.assertRaises(ValueError),
            ):
                mihomo.run_mihomo_interop(extended=extended, soak_seconds=seconds)

    def test_container_cli_dispatch(self):
        with patch("vcore_scripts.cli.run_mihomo_interop") as run:
            self.assertEqual(
                cli.main(
                    [
                        "check",
                        "mihomo-interop",
                        "--container",
                    ]
                ),
                0,
            )
        run.assert_called_once_with(extended=False, soak_seconds=0, container=True)

    def test_container_bridge_ipv6_does_not_select_lan_or_utun(self):
        interfaces = """en0: flags=1
    inet 192.168.1.2 netmask 0xffffff00
    inet6 fd01::123 prefixlen 64
utun5: flags=1
    inet 198.18.0.1 netmask 0xffffff00
    inet6 fd02::1 prefixlen 64
bridge100: flags=1
    inet 192.168.128.1 netmask 0xffffff00
    inet6 fe80::1%bridge100 prefixlen 64
    inet6 fd03::11 prefixlen 64 autoconf tentative
    inet6 fd03::12 prefixlen 64 duplicated
    inet6 fd03::13 prefixlen 64 deprecated
    inet6 fd03::22 prefixlen 64
"""
        self.assertEqual(
            host_ipv6(interfaces, "192.168.128.1", "fd03::/64"), "fd03::22"
        )
        self.assertIsNone(host_ipv6(interfaces, "192.168.128.1", "fd01::/64"))
        self.assertIsNone(host_ipv6(interfaces, "192.168.129.1", "fd03::/64"))

    def test_container_config_only_exposes_owned_vm_listeners(self):
        peers = object.__new__(ContainerPeers)
        peers.host = "192.168.128.1"
        peers.addresses = ["192.168.128.2", "127.0.0.1", "127.0.0.1", "192.168.128.3"]
        peers.peers = {0: object(), 3: object()}
        native = {"allow-lan": False, "bind-address": "127.0.0.1"}
        peers.configure(1, native)
        self.assertFalse(native["allow-lan"])
        self.assertEqual(native["bind-address"], "127.0.0.1")
        vm = {
            "external-controller": "127.0.0.1:9900",
            "listeners": [
                {
                    "listen": "127.0.0.1",
                    "certificate": "/fixture/fixture.crt",
                }
            ],
        }
        peers.configure(0, vm)
        self.assertEqual(vm["external-controller"], "0.0.0.0:9900")
        self.assertEqual(vm["listeners"][0]["certificate"], "/data/fixture/fixture.crt")
        self.assertEqual(vm["hosts"]["vcore-fixture.test"], peers.host)
        self.assertEqual(vm["hosts"]["vcore-peer.test"], peers.addresses[3])

    def test_container_cleanup_is_scoped_and_handles_failed_launch(self):
        peer = ContainerPeer("vcore-mihomo-test-0")
        with patch("vcore_scripts.mihomo_container.command", return_value="[]") as run:
            peer.stop()
            self.assertEqual(run.call_count, 1)
        owned = {
            "id": peer.name,
            "configuration": {"labels": {"purpose": NETWORK}},
            "status": {"state": "running"},
        }
        with patch(
            "vcore_scripts.mihomo_container.command",
            side_effect=[json.dumps([owned]), "", ""],
        ) as run:
            peer.stop()
            self.assertEqual(
                run.call_args_list[1].args, ("stop", "--time", "5", peer.name)
            )
            self.assertEqual(
                run.call_args_list[2].args, ("delete", "--force", peer.name)
            )
        owned["configuration"]["labels"] = {}
        with patch(
            "vcore_scripts.mihomo_container.command", return_value=json.dumps([owned])
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                peer.stop()
            self.assertEqual(run.call_count, 1)

    def test_mihomo_reservations_cover_tcp_and_udp_and_release_together(self):
        with ExitStack() as stack:
            port, reservation = mihomo.reserve_port(stack)
            for family, host in [
                (mihomo.socket.AF_INET, "127.0.0.1"),
                (mihomo.socket.AF_INET6, "::1"),
            ]:
                for kind in [mihomo.socket.SOCK_STREAM, mihomo.socket.SOCK_DGRAM]:
                    with (
                        mihomo.socket.socket(family, kind) as candidate,
                        self.assertRaises(OSError),
                    ):
                        candidate.bind((host, port))
            reservation.release_ipv4()
            for kind in [mihomo.socket.SOCK_STREAM, mihomo.socket.SOCK_DGRAM]:
                with mihomo.socket.socket(type=kind) as candidate:
                    candidate.bind(("127.0.0.1", port))
                with (
                    mihomo.socket.socket(mihomo.socket.AF_INET6, kind) as guard,
                    self.assertRaises(OSError),
                ):
                    guard.bind(("::1", port))
            reservation.close()
            for family, host in [
                (mihomo.socket.AF_INET, "127.0.0.1"),
                (mihomo.socket.AF_INET6, "::1"),
            ]:
                for kind in [mihomo.socket.SOCK_STREAM, mihomo.socket.SOCK_DGRAM]:
                    with mihomo.socket.socket(family, kind) as candidate:
                        candidate.bind((host, port))

    def test_mihomo_lock_rejects_other_process_and_releases_after_failure(self):
        child = """
import sys
from pathlib import Path
from vcore_scripts.mihomo_isolation import exclusive_run
try:
    with exclusive_run(Path(sys.argv[1])):
        pass
except RuntimeError as error:
    print(error)
    sys.exit(23)
"""
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "fixture.lock"
            command = [sys.executable, "-c", child, str(lock)]
            with (
                self.assertRaisesRegex(ValueError, "fixture failure"),
                exclusive_run(lock),
            ):
                blocked = subprocess.run(
                    command, capture_output=True, text=True, timeout=5
                )
                self.assertEqual(blocked.returncode, 23, blocked.stderr)
                self.assertIn("another local mihomo harness", blocked.stdout)
                raise ValueError("fixture failure")
            released = subprocess.run(
                command, capture_output=True, text=True, timeout=5
            )
            self.assertEqual(released.returncode, 0, released.stderr)

    def test_mihomo_peer_cleanup_waits_and_escalates_only_after_timeout(self):
        peer = MagicMock()
        peer.poll.return_value = None
        mihomo._stop_peer(peer)
        peer.terminate.assert_called_once_with()
        peer.wait.assert_called_once_with(timeout=5)
        peer.kill.assert_not_called()
        peer.reset_mock()
        peer.wait.side_effect = [mihomo.subprocess.TimeoutExpired("mihomo", 5), 0]
        mihomo._stop_peer(peer)
        peer.kill.assert_called_once_with()
        self.assertEqual(peer.wait.call_count, 2)

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
                expected_digest = (
                    "bfb78d72918e79702c425f161b4889064a68981ce9f5e69da78166f4ad56e3e8"
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
                        "windowsPackageIntegrationRevision": 3,
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
                    "version": "0.23.45",
                    "source": "git+https://github.com/OneXray/rustls?branch=vcore/reality-0.23#"
                    + "a" * 40,
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
                {
                    "id": "x25519-id",
                    "name": "x25519-dalek",
                    "version": "3.0.0",
                    "source": registry,
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "rustls-id",
                        "features": ["reality", "ring", "std", "tls12"],
                        "deps": [{"pkg": "x25519-id"}],
                    },
                    {
                        "id": "x25519-id",
                        "features": ["static_secrets", "zeroize"],
                    },
                ]
            },
        }
        self.assertEqual(_tls_dependency_errors(metadata), [])

        for index, old_version in [(0, "0.23.43"), (1, "0.26.4"), (3, "2.0.1")]:
            with self.subTest(outdated_version=old_version):
                outdated = copy.deepcopy(metadata)
                outdated["packages"][index]["version"] = old_version
                self.assertTrue(_tls_dependency_errors(outdated))

        for source in [None, "git+https://example.invalid/x25519#" + "a" * 40]:
            with self.subTest(x25519_source=source):
                invalid = copy.deepcopy(metadata)
                invalid["packages"][3]["source"] = source
                self.assertTrue(_tls_dependency_errors(invalid))

        for required in ["static_secrets", "zeroize"]:
            with self.subTest(x25519_feature=required):
                invalid = copy.deepcopy(metadata)
                invalid["resolve"]["nodes"][1]["features"].remove(required)
                self.assertTrue(_tls_dependency_errors(invalid))

        for missing in ["edge", "node", "package"]:
            with self.subTest(x25519_missing=missing):
                invalid = copy.deepcopy(metadata)
                if missing == "edge":
                    invalid["resolve"]["nodes"][0]["deps"] = []
                elif missing == "node":
                    invalid["resolve"]["nodes"].pop()
                else:
                    invalid["packages"].pop()
                self.assertTrue(_tls_dependency_errors(invalid))

        old_branch = copy.deepcopy(metadata)
        old_branch["packages"][0]["source"] = (
            "git+https://github.com/OneXray/rustls?branch=chore/x25519-dalek-3#"
            + "a" * 40
        )
        self.assertTrue(_tls_dependency_errors(old_branch))

        old_origin = copy.deepcopy(metadata)
        old_origin["packages"][0]["source"] = (
            "git+https://github.com/OneVCore/rustls?branch=vcore/reality-0.23#"
            + "a" * 40
        )
        self.assertTrue(
            any(
                "vcore/reality-0.23 GitHub branch" in error
                for error in _tls_dependency_errors(old_origin)
            )
        )

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

    def test_aws_lc_exception_is_restricted_to_official_shadowsocks_chain(self):
        registry = next(iter(CRATES_IO_SOURCES))
        names = ["shadowsocks", "shadowsocks-crypto", "aws-lc-rs", "aws-lc-sys"]
        metadata = {
            "packages": [
                {"id": name, "name": name, "version": version, "source": source}
                for name, version, source in zip(
                    names,
                    ["1.25.0", "0.8.0", "1.18.1", "0.45.0"],
                    [SHADOWSOCKS_GIT_SOURCE, registry, registry, registry],
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
