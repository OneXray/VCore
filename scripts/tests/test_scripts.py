from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vcore_scripts import cli
from vcore_scripts.builds import EXPECTED_IDENTITY, _android_target, _require_identity
from vcore_scripts.checks import CRATES_IO_SOURCES, _tls_dependency_errors
from vcore_scripts.tun2socks import derive_xray_config


class ScriptTest(unittest.TestCase):
    def test_cli_dispatches_windows_architecture(self):
        with patch("vcore_scripts.cli.build_windows") as build:
            self.assertEqual(cli.main(["build", "windows", "--architecture", "x64"]), 0)
        build.assert_called_once_with("x64")

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

    def test_tls_metadata_accepts_the_locked_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            core = Path(directory) / "VCore"
            rustls_manifest = core.parent / "rustls/rustls/Cargo.toml"
            source = next(iter(CRATES_IO_SOURCES))
            metadata = {
                "packages": [
                    {
                        "id": "rustls-id",
                        "name": "rustls",
                        "version": "0.23.43",
                        "source": None,
                        "manifest_path": str(rustls_manifest),
                    },
                    {
                        "id": "tokio-rustls-id",
                        "name": "tokio-rustls",
                        "version": "0.26.4",
                        "source": source,
                    },
                    {
                        "id": "ring-id",
                        "name": "ring",
                        "version": "0.17.14",
                        "source": source,
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
            self.assertEqual(_tls_dependency_errors(metadata, core), [])
            metadata["packages"].append(
                {
                    "id": "aws-id",
                    "name": "aws-lc-rs",
                    "version": "1.0.0",
                    "source": source,
                }
            )
            self.assertTrue(
                any(
                    "AWS-LC package is forbidden" in error
                    for error in _tls_dependency_errors(metadata, core)
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
