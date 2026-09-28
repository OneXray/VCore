"""PLATFORM production delivery commands, without network servers or platform mocks."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vcore_scripts import builds, platform_delivery
from vcore_scripts.cli import main


class PlatformDeliveryTest(unittest.TestCase):
    def test_android_delivery_replaces_stale_abis_without_touching_other_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ndk = root / "ndk"
            ndk.mkdir()
            (ndk / "source.properties").write_text("Pkg.Revision = fixture")
            output = root / "dist/android"
            stale = output / "armeabi-v7a/libvcore.so"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")
            (output / "vcore-delivery.json").write_text("old manifest")
            unrelated = root / "dist/apple/keep"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_bytes(b"keep")

            def build():
                self.assertFalse(stale.exists())
                self.assertFalse((output / "vcore-delivery.json").exists())
                for abi, machine in [("arm64-v8a", 183), ("x86_64", 62)]:
                    for name in ("libvcore.so", "libc++_shared.so"):
                        path = output / abi / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(
                            b"\x7fELF\x02\x01\x01"
                            + bytes(9)
                            + b"\x03\x00"
                            + machine.to_bytes(2, "little")
                            + builds.EXPECTED_IDENTITY
                        )

            with (
                patch.dict(os.environ, {"ANDROID_NDK_HOME": str(ndk)}, clear=True),
                # Windows resolves home from environment variables that this
                # hermetic fixture clears; do not depend on a runner profile.
                patch.object(Path, "home", return_value=root),
                patch.object(builds, "CORE_DIR", root),
                patch.object(builds, "build_android", side_effect=build),
                patch.object(builds, "_android_toolchain", return_value=ndk),
                patch.object(
                    platform_delivery, "_source", return_value={"fixture": True}
                ),
                patch.object(platform_delivery, "_output", return_value="fixture"),
            ):
                platform_delivery.build_delivery("android")
                platform_delivery.check_delivery([output / "vcore-delivery.json"])
            self.assertEqual(unrelated.read_bytes(), b"keep")

    def test_delivery_rejects_debug_before_starting_a_build(self):
        with patch.dict(os.environ, {"VCORE_BUILD_PROFILE": "debug"}):
            self.assertEqual(main(["build", "android", "--delivery"]), 1)

    def test_android_evidence_checks_real_files_not_claimed_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "Cargo.lock").write_bytes(b"fixture lock\n")
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )

            def git(ref):
                return subprocess.check_output(
                    ["git", "-C", str(source), "rev-parse", ref], text=True
                ).strip()

            output = root / "android"
            artifacts = []
            identity = (
                "VCore;engine=rust;coreVersion=0.1.0;"
                "invokeApiVersion=5;configVersion=27"
            )
            for abi, machine in [("arm64-v8a", 183), ("x86_64", 62)]:
                for name in ("libvcore.so", "libc++_shared.so"):
                    # Minimal ELF header, independent of the production reader.
                    contents = (
                        b"\x7fELF\x02\x01\x01"
                        + bytes(9)
                        + b"\x03\x00"
                        + machine.to_bytes(2, "little")
                        + bytes(44)
                        + identity.encode()
                    )
                    path = output / abi / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(contents)
                    artifacts.append(
                        {
                            "path": f"{abi}/{name}",
                            "size": len(contents),
                            "sha256": hashlib.sha256(contents).hexdigest(),
                        }
                    )
            manifest = output / "vcore-delivery.json"
            record = {
                "formatVersion": 1,
                "group": "android",
                "profile": "release",
                "source": {
                    "commit": git("HEAD"),
                    "tree": git("HEAD^{tree}"),
                    "lockSha256": hashlib.sha256(b"fixture lock\n").hexdigest(),
                },
                "buildIdentity": identity,
                "features": [
                    "ffi",
                    "tun",
                    "inbound-http",
                    "inbound-socks5",
                    "outbound-anytls",
                    "outbound-socks5",
                    "outbound-shadowsocks",
                    "outbound-trojan",
                    "outbound-vmess",
                    "outbound-vless",
                    "outbound-hysteria2",
                ],
                "host": {"os": "Linux", "architecture": "x86_64"},
                "toolchain": {
                    "rustc": "fixture",
                    "cargo": "fixture",
                    "ndk": "fixture",
                    "clang": "fixture",
                    "androidApi": "24",
                },
                "artifacts": artifacts,
            }
            manifest.write_text(json.dumps(record))
            command = [
                "check",
                "platform-artifacts",
                "--manifest",
                str(manifest),
                "--source-dir",
                str(source),
            ]
            self.assertEqual(main(command), 0)
            for mutation in (
                "profile",
                "features",
                "identity",
                "source",
                "toolchain",
                "empty",
                "missing",
                "duplicate",
                "traversal",
                "architecture",
            ):
                with self.subTest(mutation=mutation):
                    bad = copy.deepcopy(record)
                    if mutation == "profile":
                        bad["profile"] = "debug"
                    elif mutation == "features":
                        bad["features"].append("interop-test")
                    elif mutation == "identity":
                        bad["buildIdentity"] = "schema14"
                    elif mutation == "source":
                        bad["source"]["commit"] = "0" * 40
                    elif mutation == "toolchain":
                        del bad["toolchain"]["ndk"]
                    elif mutation == "empty":
                        bad["artifacts"] = []
                    elif mutation == "missing":
                        bad["artifacts"].pop()
                    elif mutation == "duplicate":
                        bad["artifacts"].append(bad["artifacts"][0])
                    elif mutation == "traversal":
                        bad["artifacts"][0]["path"] = "../android/arm64-v8a/libvcore.so"
                    elif mutation == "architecture":
                        file = output / "arm64-v8a/libvcore.so"
                        original = file.read_bytes()
                        wrong = original[:18] + b"\x3e\x00" + original[20:]
                        file.write_bytes(wrong)
                        bad["artifacts"][0]["sha256"] = hashlib.sha256(
                            wrong
                        ).hexdigest()
                    manifest.write_text(json.dumps(bad))
                    try:
                        self.assertEqual(main(command), 1)
                    finally:
                        if mutation == "architecture":
                            file.write_bytes(original)
            manifest.write_text(json.dumps(record))
            self.assertEqual(main(command + ["--complete"]), 1)
            (output / "arm64-v8a/libc++_shared.so").unlink()
            self.assertEqual(main(command), 1)


if __name__ == "__main__":
    unittest.main()
