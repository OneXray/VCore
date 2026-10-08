"""Offline checks of actual archive trees; no native compiler or service is used."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds
from vole_scripts import cli_release as release

VERSION = "1.2.3"
IDENTITY = b"Vole;engine=rust;coreVersion=1.2.3"
NOTICES = b"Fixture copyright and full license terms.\n"
FEATURES = ["cli", "invoke", "tun", "inbound-http", "outbound-socks5"]


def executable(
    target: str, *, identity: bytes = IDENTITY, notices: bytes = NOTICES
) -> bytes:
    header = bytearray(512)
    system, architecture = release.TARGETS[target]
    if system == "linux":
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[16:18] = b"\x03\x00"
        header[18:20] = {"amd64": 62, "arm64": 183}[architecture].to_bytes(2, "little")
    elif system == "darwin":
        header[:4] = b"\xcf\xfa\xed\xfe"
        header[4:8] = {"amd64": 0x1000007, "arm64": 0x100000C}[architecture].to_bytes(
            4, "little"
        )
        header[12:16] = b"\x02\x00\x00\x00"
    else:
        header[:2] = b"MZ"
        header[0x3C:0x40] = (0x80).to_bytes(4, "little")
        header[0x80:0x84] = b"PE\0\0"
        header[0x84:0x86] = {"amd64": 0x8664, "arm64": 0xAA64}[architecture].to_bytes(
            2, "little"
        )
        header[0x96:0x98] = b"\x02\x00"
    return (
        bytes(header)
        + identity
        + b"\0"
        + release.NOTICES_BEGIN
        + notices
        + release.NOTICES_END
    )


def project(root: Path) -> None:
    root.mkdir()
    (root / "Cargo.toml").write_text(
        '[package]\nname = "vole"\nversion = "1.2.3"\n'
        '[features]\ndefault = ["inbound-http", "outbound-socks5"]\n'
    )
    (root / "Cargo.lock").write_text("fixture lock\n")
    (root / "LICENSE").write_bytes(NOTICES)


def record(source: dict, target: str, payload: bytes, archive: Path) -> dict:
    binary_name = "vole.exe" if release.TARGETS[target][0] == "windows" else "vole"
    return {
        "formatVersion": 1,
        "target": target,
        "profile": "release",
        "source": source,
        "buildIdentity": IDENTITY.decode(),
        "features": FEATURES
        + (["windows-wintun"] if release.TARGETS[target][0] == "windows" else []),
        "command": [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "--no-default-features",
            "--features",
            release.requested_features(target),
            "--bin",
            "vole",
        ],
        "host": {
            "os": {"linux": "Linux", "darwin": "Darwin", "windows": "Windows"}[
                release.TARGETS[target][0]
            ],
            "architecture": release.TARGETS[target][1],
        },
        "toolchain": {"rustc": "fixture", "cargo": "fixture"},
        "dependencies": [
            {"name": "linked-fixture", "version": "1.0.0"},
            {
                "name": "Rust standard library",
                "version": "1.99.0",
                "rustc": "fixture",
                "notices": [{"path": "COPYRIGHT-library.html"}],
            },
        ],
        "binary": {
            "name": binary_name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        },
        "archive": {
            "name": archive.name,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "size": archive.stat().st_size,
        },
        "noticesSha256": hashlib.sha256(NOTICES).hexdigest(),
        "noticesSize": len(NOTICES),
        "offlineSmoke": ["-h", "-v", "-t"],
    }


def archive_set(incoming: Path, source: dict) -> list[Path]:
    manifests = []
    for target in release.TARGETS:
        directory = incoming / target
        directory.mkdir(parents=True)
        archive = directory / release.archive_name(target)
        payload = executable(target)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("vole.exe", payload)
        else:
            archive.write_bytes(gzip.compress(payload, mtime=0))
        manifest = directory / "manifest.json"
        manifest.write_text(json.dumps(record(source, target, payload, archive)))
        manifests.append(manifest)
    return manifests


class CliReleaseTest(unittest.TestCase):
    def test_rust_runtime_collects_original_library_report_and_terms_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary)
            docs = sysroot / "share/doc/rust"
            terms = docs / "licenses"
            terms.mkdir(parents=True)
            report = docs / "COPYRIGHT-library.html"
            report.write_bytes(
                b"<html>Original Rust library copyright and terms.</html>"
            )
            (docs / "COPYRIGHT.html").write_bytes(
                b"Whole toolchain report must be excluded"
            )
            (terms / "MIT.txt").write_bytes(b"Original MIT terms")
            (terms / "Apache-2.0.txt").write_bytes(b"Original Apache terms")
            rustc = "rustc 1.99.0\nrelease: 1.99.0\ncommit-hash: " + "a" * 40
            with patch.object(release, "_output", side_effect=[rustc, str(sysroot)]):
                content, row = release.collect_rust_notices(sysroot)
            self.assertIn(report.read_bytes(), content)
            self.assertIn(b"Original MIT terms", content)
            self.assertIn(b"Original Apache terms", content)
            self.assertNotIn(b"Whole toolchain report", content)
            self.assertEqual(row["rustc"], rustc)
            self.assertEqual(row["version"], "1.99.0")
            self.assertEqual(
                {item["path"] for item in row["notices"]},
                {
                    "COPYRIGHT-library.html",
                    "licenses/MIT.txt",
                    "licenses/Apache-2.0.txt",
                },
            )
            report.unlink()
            with (
                patch.object(release, "_output", side_effect=[rustc, str(sysroot)]),
                self.assertRaisesRegex(ValueError, "rust-docs component"),
            ):
                release.collect_rust_notices(sysroot)
            with (
                patch.object(
                    release,
                    "_output",
                    return_value=rustc.replace(
                        "release: 1.99.0", "release: 1.99.0-nightly"
                    ),
                ),
                self.assertRaisesRegex(ValueError, "stable Rust toolchain"),
            ):
                release.collect_rust_notices(sysroot)

    def test_tag_matches_dynamic_cargo_version_and_exact_committed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            project(root)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
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
            subprocess.run(["git", "-C", str(root), "tag", "v1.2.3"], check=True)
            source = release._source(root, "v1.2.3")
            untagged = release._source(root, None)
            self.assertIsNone(untagged["tag"])
            self.assertEqual(
                {key: value for key, value in source.items() if key != "tag"},
                {key: value for key, value in untagged.items() if key != "tag"},
            )
            self.assertEqual(source["version"], VERSION)
            self.assertEqual(
                source["lockSha256"], hashlib.sha256(b"fixture lock\n").hexdigest()
            )
            for tag in ("v0.1.0", "1.2.3", "v01.2.3", "v1.2.3-rc1", "v1.2.3/other"):
                with (
                    self.subTest(tag=tag),
                    self.assertRaisesRegex(ValueError, "release tag"),
                ):
                    release._source(root, tag)
            (root / "Cargo.lock").write_text("changed lock\n")
            with self.assertRaisesRegex(ValueError, "clean committed"):
                release._source(root, "v1.2.3")

    def test_six_executable_architectures_require_identity_and_full_embedded_notices(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "executable"
            for target in release.TARGETS:
                with self.subTest(target=target):
                    path.write_bytes(executable(target))
                    self.assertEqual(
                        release.verify_binary(path, target, VERSION, NOTICES), NOTICES
                    )
                    wrong = next(
                        other
                        for other in release.TARGETS
                        if release.TARGETS[other][0] == release.TARGETS[target][0]
                        and other != target
                    )
                    with self.assertRaises((ValueError, RuntimeError)):
                        release.verify_binary(path, wrong, VERSION, NOTICES)
                    path.write_bytes(executable(target, identity=b"old identity"))
                    with self.assertRaisesRegex(ValueError, "build identity"):
                        release.verify_binary(path, target, VERSION)
                    path.write_bytes(executable(target, notices=b"truncated"))
                    with self.assertRaisesRegex(ValueError, "exact linked notice"):
                        release.verify_binary(path, target, VERSION, NOTICES)

    def test_windows_cli_archive_rejects_symlink_mode_before_unpacking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            source = {"version": VERSION, "commit": "a" * 40}
            manifests = archive_set(root / "dist/incoming", source)
            manifest = next(
                path for path in manifests if "aarch64-pc-windows" in path.parent.name
            )
            target = "aarch64-pc-windows-msvc"
            archive = manifest.parent / release.archive_name(target)
            with zipfile.ZipFile(archive, "w") as stream:
                member = zipfile.ZipInfo("vole.exe")
                member.external_attr = 0o120777 << 16
                stream.writestr(member, executable(target))
            manifest.write_text(
                json.dumps(record(source, target, executable(target), archive))
            )
            with self.assertRaisesRegex(ValueError, "regular executable"):
                release.inspect_release(manifest, source, root)

    def test_assemble_requires_complete_source_and_exact_binary_only_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            root = fixture / "checkout"
            project(root)
            source = {"version": VERSION, "commit": "a" * 40, "lockSha256": "b" * 64}
            incoming = fixture / "incoming"
            manifests = archive_set(incoming, source)
            notes = fixture / "release.md"
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(release, "_source", return_value=source),
            ):
                archives = release.assemble_release(
                    "v1.2.3", incoming, "Example/Vole", notes
                )
                self.assertEqual(
                    {archive.name for archive in archives},
                    {
                        "vole-linux-amd64.gz",
                        "vole-linux-arm64.gz",
                        "vole-darwin-amd64.gz",
                        "vole-darwin-arm64.gz",
                        "vole-windows-amd64.zip",
                        "vole-windows-arm64.zip",
                    },
                )
                self.assertIn("/tree/" + "a" * 40, notes.read_text())
                original = json.loads(manifests[0].read_text())
                for mutation in (
                    "source",
                    "features",
                    "command",
                    "toolchain",
                    "archive",
                    "binary",
                    "notices",
                ):
                    altered = copy.deepcopy(original)
                    if mutation == "source":
                        altered["source"]["lockSha256"] = "c" * 64
                    elif mutation == "features":
                        altered["features"] = ["cli", "tun"]
                    elif mutation == "command":
                        altered["command"].remove("--locked")
                    elif mutation == "toolchain":
                        del altered["toolchain"]["rustc"]
                    elif mutation in {"archive", "binary"}:
                        altered[mutation]["sha256"] = "0" * 64
                    else:
                        altered["noticesSha256"] = "0" * 64
                    manifests[0].write_text(json.dumps(altered))
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        release.assemble_release(
                            "v1.2.3", incoming, "Example/Vole", notes
                        )
                manifests[0].write_text(json.dumps(original))
                extra = manifests[0].parent / "checksums.txt"
                extra.write_text("not a release asset")
                with self.assertRaisesRegex(ValueError, "only archive"):
                    release.assemble_release("v1.2.3", incoming, "Example/Vole", notes)
                extra.unlink()
                manifests[0].unlink()
                with self.assertRaisesRegex(ValueError, "all six"):
                    release.assemble_release("v1.2.3", incoming, "Example/Vole", notes)

    def test_assembly_rejects_wrong_backend_even_when_archives_match(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            root = fixture / "checkout"
            project(root)
            source = {"version": VERSION, "commit": "a" * 40}
            incoming = fixture / "incoming"
            manifests = archive_set(incoming, source)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(release, "_source", return_value=source),
            ):
                for target, feature in (
                    ("aarch64-pc-windows-msvc", "windows-uwp"),
                    ("aarch64-pc-windows-msvc", None),
                    ("x86_64-unknown-linux-gnu", "windows-wintun"),
                ):
                    manifest = next(
                        path for path in manifests if path.parent.name == target
                    )
                    original = manifest.read_text()
                    changed = json.loads(original)
                    changed["features"] = FEATURES + ([feature] if feature else [])
                    manifest.write_text(json.dumps(changed))
                    try:
                        with (
                            self.subTest(target=target, feature=feature),
                            self.assertRaisesRegex(
                                ValueError, "incompatible CLI release evidence"
                            ),
                        ):
                            release.assemble_release(
                                "v1.2.3",
                                incoming,
                                "Example/Vole",
                                fixture / "release.md",
                            )
                    finally:
                        manifest.write_text(original)

    def test_windows_zip_rejects_dll_even_when_archive_hash_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            root = fixture / "checkout"
            project(root)
            source = {"version": VERSION, "commit": "a" * 40}
            incoming = fixture / "incoming"
            manifests = archive_set(incoming, source)
            target = "aarch64-pc-windows-msvc"
            archive = incoming / target / release.archive_name(target)
            with zipfile.ZipFile(archive, "a") as stream:
                stream.writestr("wintun.dll", b"not distributable here")
            manifest = next(path for path in manifests if path.parent.name == target)
            altered = json.loads(manifest.read_text())
            altered["archive"]["sha256"] = hashlib.sha256(
                archive.read_bytes()
            ).hexdigest()
            altered["archive"]["size"] = archive.stat().st_size
            manifest.write_text(json.dumps(altered))
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(release, "_source", return_value=source),
                self.assertRaisesRegex(ValueError, "only vole.exe"),
            ):
                release.assemble_release(
                    "v1.2.3", incoming, "Example/Vole", fixture / "release.md"
                )

    def test_linked_graph_excludes_dev_build_and_proc_macro_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            project(root)
            packages = []
            nodes = []
            for name in ("vole", "linked", "builder", "peer", "derive", "syn"):
                packages.append(
                    {
                        "id": name,
                        "name": name,
                        "manifest_path": str(
                            root / "Cargo.toml"
                            if name == "vole"
                            else root / name / "Cargo.toml"
                        ),
                        "targets": [
                            {"kind": ["proc-macro" if name == "derive" else "lib"]}
                        ],
                    }
                )
                nodes.append(
                    {
                        "id": name,
                        "features": FEATURES if name == "vole" else [],
                        "deps": [],
                    }
                )
            nodes[0]["deps"] = [
                {"pkg": name, "dep_kinds": [{"kind": kind}]}
                for name, kind in (
                    ("linked", None),
                    ("builder", "build"),
                    ("peer", "dev"),
                    ("derive", None),
                )
            ]
            nodes[4]["deps"] = [{"pkg": "syn", "dep_kinds": [{"kind": None}]}]
            metadata = {"packages": packages, "resolve": {"nodes": nodes}}
            _, _, resolved, linked = release._graph(metadata, root)
            self.assertEqual(resolved, {"vole", "linked", "builder", "derive", "syn"})
            self.assertEqual(linked, {"vole", "linked"})
            windows = "aarch64-pc-windows-msvc"
            with self.assertRaisesRegex(ValueError, "Windows backend"):
                release._graph(metadata, root, windows)
            nodes[0]["features"] = FEATURES + ["windows-wintun"]
            release._graph(metadata, root, windows)
            with self.assertRaisesRegex(ValueError, "Windows backend"):
                release._graph(metadata, root, "x86_64-unknown-linux-gnu")
            nodes[0]["features"] = FEATURES + ["windows-uwp"]
            with self.assertRaisesRegex(ValueError, "FFI or test"):
                release._graph(metadata, root, windows)
            nodes[0]["features"] = FEATURES + ["windows-wintun"]
            packages[1]["name"] = "windows"
            with self.assertRaisesRegex(ValueError, "UWP SDK"):
                release._graph(metadata, root, windows)
            packages[1]["name"] = "linked"
            nodes[1]["deps"] = [{"pkg": "windows-win32", "dep_kinds": [{"kind": None}]}]
            packages.append(
                {
                    "id": "windows-win32",
                    "name": "windows",
                    "manifest_path": str(root / "windows/Cargo.toml"),
                    "targets": [{"kind": ["lib"]}],
                }
            )
            nodes.append(
                {
                    "id": "windows-win32",
                    "features": ["std", "Win32_Foundation", "Win32_System_Threading"],
                    "deps": [],
                }
            )
            release._graph(metadata, root, windows)
            nodes[-1]["features"].append("Networking_Vpn")
            with self.assertRaisesRegex(ValueError, "WinRT features"):
                release._graph(metadata, root, windows)
            nodes[1]["deps"] = []
            packages.pop()
            nodes.pop()
            nodes[0]["features"] = FEATURES + ["ffi"]
            with self.assertRaisesRegex(ValueError, "FFI or test"):
                release._graph(metadata, root)

    def test_notice_collection_preserves_native_text_and_skips_unlinked_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            root = fixture / "checkout"
            project(root)
            stale = root / "target/unused/LICENSE"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale ignored notice")
            native = fixture / "boring-sys"
            native_license = native / "deps/boringssl/LICENSE"
            native_license.parent.mkdir(parents=True)
            native_license.write_text("Actual native BoringSSL terms.\n")
            (native / "LICENSE-MIT").write_text("Binding copyright.\n")
            packages = {
                "vole": {
                    "name": "vole",
                    "version": VERSION,
                    "manifest_path": str(root / "Cargo.toml"),
                    "source": None,
                    "license": "MIT",
                },
                "native": {
                    "name": "boring-sys",
                    "version": "5.2.0",
                    "manifest_path": str(native / "Cargo.toml"),
                    "source": release.BORING_SOURCE,
                    "license": "MIT",
                },
                "unlinked": {
                    "name": "unlinked",
                    "manifest_path": str(fixture / "missing/Cargo.toml"),
                },
            }
            with patch.object(
                release,
                "_fetch_notice",
                side_effect=AssertionError("must use packaged licenses"),
            ):
                content, records = release.collect_notices(
                    packages,
                    {"vole", "native"},
                    root,
                    {"version": VERSION, "commit": "a" * 40},
                    "Example/Vole",
                    "aarch64-apple-darwin",
                )
            self.assertIn(b"Actual native BoringSSL terms.\n", content)
            self.assertIn(b"Binding copyright.\n", content)
            self.assertNotIn(b"stale ignored notice", content)
            self.assertNotIn(b"unlinked", content)
            self.assertEqual({row["name"] for row in records}, {"vole", "boring-sys"})

    def test_windows_api_notice_retains_original_attribution_and_mit_alternative(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            root = fixture / "checkout"
            project(root)
            tun = fixture / "tun-rs"
            header = tun / "src/platform/windows/tun/wintun.h"
            header.parent.mkdir(parents=True)
            attribution = (
                b"/* SPDX-License-Identifier: GPL-2.0 OR MIT\r\n"
                b" *\r\n"
                b" * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.\r\n"
                b" */"
            )
            header.write_bytes(attribution + b"\r\n#pragma once\r\n")
            (tun / "LICENSE").write_text("Apache License Version 2.0\n")
            packages = {
                name: {
                    "name": name,
                    "version": VERSION if name == "vole" else "2.8.11",
                    "manifest_path": str(base / "Cargo.toml"),
                    "source": None if name == "vole" else next(iter(release.REGISTRY)),
                    "license": "MIT" if name == "vole" else "Apache-2.0",
                }
                for name, base in (("vole", root), ("tun-rs", tun))
            }

            def collect(target, linked):
                return release.collect_notices(
                    packages,
                    linked,
                    root,
                    {"version": VERSION, "commit": "a" * 40},
                    "Example/Vole",
                    target,
                )

            content, records = collect("aarch64-pc-windows-msvc", {"vole", "tun-rs"})
            self.assertIn(attribution, content)
            self.assertIn(b"The linked API bindings use the MIT alternative.", content)
            self.assertIn(b"The Wintun driver DLL is host-provided", content)
            self.assertIn(b"sublicense, and/or sell", content)
            self.assertIn(b"this permission notice shall be included", content)
            self.assertIn(b"OUT OF OR IN CONNECTION WITH THE SOFTWARE", content)
            self.assertNotIn(b"#pragma once", content)
            paths = {row["path"] for package in records for row in package["notices"]}
            self.assertIn("src/platform/windows/tun/wintun.h", paths)
            mac, _ = collect("aarch64-apple-darwin", {"vole", "tun-rs"})
            self.assertIn(b"Apache License Version 2.0", mac)
            self.assertNotIn(attribution, mac)
            unlinked, _ = collect("aarch64-pc-windows-msvc", {"vole"})
            self.assertNotIn(attribution, unlinked)
            header.write_text("/* missing upstream attribution */\n")
            with self.assertRaisesRegex(ValueError, "dual-license attribution"):
                collect("aarch64-pc-windows-msvc", {"vole", "tun-rs"})

    def test_derived_replay_notice_preserves_entire_source_preamble_when_linked(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            root = fixture / "checkout"
            project(root)
            replay = root / "src/outbound/shadowsocks/packet_window.rs"
            replay.parent.mkdir(parents=True)
            preamble = (
                b"// SPDX-License-Identifier: MIT\n//\n"
                b"// Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.\n"
                b"// Copyright (c) 2017 Y.T. CHUNG <zonyitoo@gmail.com>\n//\n"
                b"// Permission is hereby granted, free of charge, to any person\n"
                b"// Fixture permission conditions are preserved in full.\n//\n"
                b'// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY\n'
                b"// Fixture final warranty line is preserved too.\n\n"
            )
            replay.write_bytes(preamble + b"//! Packet window\nconst CODE: u64 = 6;\n")
            dependency = fixture / "shadowsocks"
            dependency.mkdir()
            (dependency / "LICENSE").write_text("Shadowsocks dependency MIT terms\n")
            packages = {
                name: {
                    "name": name,
                    "version": VERSION,
                    "manifest_path": str(base / "Cargo.toml"),
                    "source": None if name == "vole" else next(iter(release.REGISTRY)),
                    "license": "MIT",
                }
                for name, base in (("vole", root), ("shadowsocks", dependency))
            }

            def collect(linked):
                return release.collect_notices(
                    packages,
                    linked,
                    root,
                    {"version": VERSION, "commit": "a" * 40},
                    "Example/Vole",
                    "aarch64-apple-darwin",
                )

            content, records = collect({"vole", "shadowsocks"})
            self.assertIn(preamble, content)
            self.assertNotIn(b"const CODE", content)
            paths = {row["path"] for package in records for row in package["notices"]}
            self.assertIn("src/outbound/shadowsocks/packet_window.rs", paths)
            unlinked, _ = collect({"vole"})
            self.assertNotIn(preamble, unlinked)
            replay.write_text(
                "// missing original permission text\n//! Packet window\n"
            )
            with self.assertRaisesRegex(ValueError, "replay-window notices"):
                collect({"vole", "shadowsocks"})

    def test_missing_packaged_license_uses_exact_registry_vcs_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            revision = "d" * 40
            (base / ".cargo_vcs_info.json").write_text(
                json.dumps({"git": {"sha1": revision}})
            )
            item = {
                "name": "fixture",
                "repository": "https://github.com/Example/Dependency",
            }
            with patch.object(
                release,
                "_fetch_notice",
                side_effect=lambda url: NOTICES if url.endswith("/LICENSE") else None,
            ) as fetch:
                notices = release._upstream_notices(item, base)
            self.assertEqual(len(notices), 1)
            self.assertTrue(
                all(
                    "/" + revision + "/" in call.args[0]
                    for call in fetch.call_args_list
                )
            )
            (base / ".cargo_vcs_info.json").write_text(
                json.dumps({"git": {"sha1": "main"}})
            )
            with (
                patch.object(release, "_fetch_notice") as fetch,
                self.assertRaisesRegex(ValueError, "immutable"),
            ):
                release._upstream_notices(item, base)
            fetch.assert_not_called()

    def test_hidden_release_overrides_are_rejected_before_source_or_build(self):
        for override in (
            "RUSTFLAGS",
            "CARGO_PROFILE_RELEASE_LTO",
            "BORING_BSSL_PATH",
            "VOLE_RELEASE_NOTICES",
        ):
            with (
                self.subTest(override=override),
                patch.dict(os.environ, {override: "unsafe override"}, clear=True),
                patch.object(release, "_source") as source,
                patch.object(subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "unsupported CLI release"):
                    release.build_release(
                        "aarch64-apple-darwin", "v1.2.3", "Example/Vole"
                    )
                source.assert_not_called()
                run.assert_not_called()

    def test_release_build_owns_notice_input_and_packages_only_the_selected_bin(self):
        for target in ("x86_64-unknown-linux-gnu", "aarch64-pc-windows-msvc"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory) / "checkout"
                project(root)
                source = {"version": VERSION, "commit": "a" * 40}
                binary_name = "vole.exe" if "windows" in target else "vole"
                owned_inputs = []
                expected = [
                    "cargo",
                    "build",
                    "--locked",
                    "--release",
                    "--target",
                    target,
                    "--no-default-features",
                    "--features",
                    release.requested_features(target),
                    "--bin",
                    "vole",
                ]

                def compiler(
                    command,
                    *,
                    cwd,
                    env,
                    check,
                    expected=expected,
                    root=root,
                    owned_inputs=owned_inputs,
                    target=target,
                    binary_name=binary_name,
                ):
                    self.assertEqual(command, expected)
                    self.assertEqual(cwd, root)
                    self.assertTrue(check)
                    notices = Path(env["VOLE_RELEASE_NOTICES"])
                    self.assertTrue(notices.is_absolute())
                    self.assertEqual(notices.read_bytes(), NOTICES)
                    owned_inputs.append(notices)
                    binary = root / "target" / target / "release" / binary_name
                    binary.parent.mkdir(parents=True)
                    binary.write_bytes(executable(target))
                    (binary.parent / "wintun.dll").write_bytes(b"never packaged")
                    (binary.parent / "vole-windows-session-host.exe").write_bytes(
                        b"never packaged"
                    )

                packages = {"core": {"name": "vole"}}
                nodes = {"core": {"features": FEATURES}}
                with (
                    patch.dict(os.environ, {}, clear=True),
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(release, "_source", return_value=source),
                    patch.object(release, "_native_environment", return_value={}),
                    patch.object(release, "_output", return_value="{}"),
                    patch.object(
                        release,
                        "_graph",
                        return_value=(packages, nodes, {"core"}, {"core"}),
                    ),
                    patch.object(release, "_audit_graph"),
                    patch.object(
                        release,
                        "collect_notices",
                        return_value=(NOTICES, [{"name": "fixture"}]),
                    ),
                    patch.object(
                        release,
                        "collect_rust_notices",
                        return_value=(
                            b"",
                            {
                                "name": "Rust standard library",
                                "rustc": "{}",
                                "notices": [{"path": "fixture"}],
                            },
                        ),
                    ),
                    patch.object(release, "_smoke") as smoke,
                    patch.object(subprocess, "run", side_effect=compiler),
                ):
                    release.build_release(target, "v1.2.3", "Example/Vole")
                    smoke.assert_called_once()
                self.assertEqual(len(owned_inputs), 1)
                self.assertFalse(owned_inputs[0].exists())
                output = root / "dist/cli" / target
                archive = output / release.archive_name(target)
                self.assertEqual(
                    {path.name for path in output.iterdir()},
                    {archive.name, "manifest.json"},
                )
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as stream:
                        self.assertEqual(stream.namelist(), ["vole.exe"])
                        self.assertEqual(stream.read("vole.exe"), executable(target))
                else:
                    self.assertEqual(
                        gzip.decompress(archive.read_bytes()), executable(target)
                    )

    def test_offline_smoke_rejects_wrong_version_and_validation_side_effects(self):
        identity = IDENTITY.decode()

        def validation(arguments, *, cwd, **kwargs):
            if arguments[-1] == "-h":
                return subprocess.CompletedProcess(arguments, 0, "", "-d -f -t -v -h\n")
            if arguments[-1] == "-f=-":
                self.assertEqual(arguments[1], "-t")
                self.assertTrue(arguments[2].startswith("-d="))
                self.assertIn("release-probe.invalid", kwargs["input"])
            else:
                self.assertEqual(arguments[1:3], ["-t", "-d"])
                self.assertIn("release-probe.invalid", Path(arguments[-1]).read_text())
            self.assertFalse((cwd / "unused-data").exists())

        with (
            patch.object(subprocess, "check_output", return_value=identity + "\n"),
            patch.object(subprocess, "run", side_effect=validation),
        ):
            release._smoke(Path("/fixture/vole"), identity, {})
        with (
            patch.object(
                subprocess,
                "check_output",
                return_value=identity + "1\n",
            ),
            patch.object(subprocess, "run", side_effect=validation),
            self.assertRaisesRegex(ValueError, "version output"),
        ):
            release._smoke(Path("/fixture/vole"), identity, {})
        with (
            patch.object(subprocess, "check_output", return_value=identity + "\n"),
            patch.object(
                subprocess,
                "run",
                side_effect=lambda arguments, **kwargs: (
                    validation(arguments, **kwargs)
                    if arguments[-1] == "-h"
                    else Path(arguments[3]).mkdir()
                ),
            ),
            self.assertRaisesRegex(ValueError, "validation must not"),
        ):
            release._smoke(Path("/fixture/vole"), identity, {})

    def test_source_audit_rejects_unapproved_git_and_external_path_dependencies(self):
        root = Path("/fixture/core")
        for source, path in (
            ("git+https://github.com/Example/foreign#" + "a" * 40, root / "Cargo.toml"),
            (None, Path("/fixture/external/Cargo.toml")),
        ):
            packages = {
                "bad": {
                    "id": "bad",
                    "name": "bad",
                    "source": source,
                    "manifest_path": str(path),
                }
            }
            with (
                self.subTest(source=source),
                self.assertRaisesRegex(
                    ValueError, "unapproved release dependency|external path"
                ),
            ):
                release._audit_graph(packages, {}, {"bad"}, root)


if __name__ == "__main__":
    unittest.main()
