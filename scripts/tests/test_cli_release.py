"""Offline release packaging and linked-notice regressions."""

from __future__ import annotations

import gzip
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


def project(root: Path) -> None:
    root.mkdir(exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "vole"\nversion = "1.2.3"\n'
        '[features]\ndefault = ["inbound-http", "outbound-socks5"]\n'
    )
    (root / "Cargo.lock").write_text("fixture lock\n")
    (root / "LICENSE").write_bytes(NOTICES)


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
                content = release.collect_rust_notices(sysroot)
            self.assertIn(report.read_bytes(), content)
            self.assertIn(b"Original MIT terms", content)
            self.assertIn(b"Original Apache terms", content)
            self.assertNotIn(b"Whole toolchain report", content)
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
                content = release.collect_notices(
                    packages,
                    {"vole", "native"},
                    root,
                    {"version": VERSION, "commit": "a" * 40},
                    "Example/Vole",
                    "aarch64-apple-darwin",
                )
            self.assertIn(native_license.read_bytes(), content)
            self.assertIn((native / "LICENSE-MIT").read_bytes(), content)
            self.assertNotIn(b"stale ignored notice", content)
            self.assertNotIn(b"unlinked", content)

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

            content = collect("aarch64-pc-windows-msvc", {"vole", "tun-rs"})
            self.assertIn(attribution, content)
            self.assertIn(b"The linked API bindings use the MIT alternative.", content)
            self.assertIn(b"The Wintun driver DLL is host-provided", content)
            self.assertIn(b"sublicense, and/or sell", content)
            self.assertIn(b"this permission notice shall be included", content)
            self.assertIn(b"OUT OF OR IN CONNECTION WITH THE SOFTWARE", content)
            self.assertNotIn(b"#pragma once", content)
            self.assertIn(b"src/platform/windows/tun/wintun.h", content)
            mac = collect("aarch64-apple-darwin", {"vole", "tun-rs"})
            self.assertIn(b"Apache License Version 2.0", mac)
            self.assertNotIn(attribution, mac)
            unlinked = collect("aarch64-pc-windows-msvc", {"vole"})
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

            content = collect({"vole", "shadowsocks"})
            self.assertIn(preamble, content)
            self.assertNotIn(b"const CODE", content)
            self.assertIn(b"src/outbound/shadowsocks/packet_window.rs", content)
            unlinked = collect({"vole"})
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
                patch.object(release, "_release_info") as source,
                patch.object(subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "unsupported CLI release"):
                    release.build_release(
                        "aarch64-apple-darwin", "v1.2.3", "Example/Vole"
                    )
                source.assert_not_called()
                run.assert_not_called()

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

    def test_tag_matches_package_version_and_checked_out_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project(root)
            with patch.object(release, "_output", side_effect=["a" * 40, "a" * 40]):
                self.assertEqual(
                    release._release_info(root, "v1.2.3"),
                    {
                        "tag": "v1.2.3",
                        "version": VERSION,
                        "commit": "a" * 40,
                    },
                )
            for tag in ("v0.1.0", "1.2.3", "v01.2.3", "v1.2.3-rc1"):
                with (
                    self.subTest(tag=tag),
                    self.assertRaisesRegex(ValueError, "release tag"),
                ):
                    release._release_info(root, tag)
            with (
                patch.object(release, "_output", side_effect=["a" * 40, "b" * 40]),
                self.assertRaisesRegex(ValueError, "checked-out commit"),
            ):
                release._release_info(root, "v1.2.3")

    def test_release_build_owns_notice_input_and_packages_only_the_selected_bin(self):
        for target in release.TARGETS:
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                project(root)
                info = {"version": VERSION, "commit": "a" * 40}
                binary_name = "vole.exe" if "windows" in target else "vole"
                notice_paths = []
                payload = b"compiled CLI fixture"

                def compiler(
                    selected_target,
                    *,
                    env,
                    target=target,
                    root=root,
                    binary_name=binary_name,
                    payload=payload,
                    notice_paths=notice_paths,
                ):
                    self.assertEqual(selected_target, target)
                    notice_file = Path(env["VOLE_RELEASE_NOTICES"])
                    self.assertEqual(notice_file.read_bytes(), NOTICES)
                    notice_paths.append(notice_file)
                    binary = root / "target" / target / "release" / binary_name
                    binary.parent.mkdir(parents=True)
                    binary.write_bytes(payload)
                    (binary.parent / "wintun.dll").write_bytes(b"exclude")
                    (binary.parent / "vole-windows-session-host.exe").write_bytes(
                        b"exclude"
                    )
                    return binary

                with (
                    patch.dict(os.environ, {}, clear=True),
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(builds, "build_cli", side_effect=compiler),
                    patch.object(release, "_release_info", return_value=info),
                    patch.object(release, "_native_environment", return_value={}),
                    patch.object(release, "_output", return_value="{}"),
                    patch.object(
                        release, "_graph", return_value=({}, {}, set(), set())
                    ),
                    patch.object(release, "_audit_graph"),
                    patch.object(release, "collect_notices", return_value=NOTICES),
                    patch.object(release, "collect_rust_notices", return_value=b""),
                    patch.object(release, "_smoke") as smoke,
                ):
                    archive = release.build_release(target, None, "Example/Vole")
                smoke.assert_called_once()
                self.assertEqual(len(notice_paths), 1)
                self.assertFalse(notice_paths[0].exists())
                self.assertEqual(list(archive.parent.iterdir()), [archive])
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as stream:
                        self.assertEqual(stream.namelist(), ["vole.exe"])
                        self.assertEqual(stream.read("vole.exe"), payload)
                else:
                    self.assertEqual(gzip.decompress(archive.read_bytes()), payload)
