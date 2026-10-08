"""Test real archive contents around mocked native compilation."""

import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds, cli_release, ffi_release

VERSION = "1.2.3"
NOTICES = b"Fixture copyright and complete license terms.\r\n"
SOURCE = {"version": VERSION, "commit": "a" * 40, "tag": "v1.2.3"}


def project(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname="vole"\nversion="1.2.3"\n[features]\ndefault=["inbound-http","outbound-socks5"]\n'
    )
    (root / "Cargo.lock").write_text("locked fixture\n")
    (root / "include").mkdir()
    (root / "include/vole.h").write_bytes(b"public header fixture\n")
    (root / "include/module.modulemap").write_bytes(
        b'module LibVole { header "vole.h" link "c++" }\n'
    )


def graph(root: Path, target: str, backend: str | None) -> dict:
    features = builds.DEFAULT_FEATURES.split(",") + ["invoke"]
    if backend:
        features += ["windows-" + backend]
    packages = [
        {
            "id": "core",
            "name": "vole",
            "version": VERSION,
            "source": None,
            "license": "MIT",
            "manifest_path": str(root / "Cargo.toml"),
            "targets": [{"kind": ["lib"]}],
        }
    ]
    nodes = [{"id": "core", "features": features, "deps": []}]
    if backend == "uwp":
        packages.append(
            {
                "id": "winrt",
                "name": "windows",
                "version": "0.62.2",
                "source": next(iter(cli_release.REGISTRY)),
                "license": "MIT OR Apache-2.0",
                "manifest_path": str(root / "upstream/windows/Cargo.toml"),
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append({"id": "winrt", "features": ["Networking_Vpn"], "deps": []})
        nodes[0]["deps"] = [{"pkg": "winrt", "dep_kinds": [{"kind": None}]}]
    return {"packages": packages, "nodes": nodes}


class FfiReleaseTest(unittest.TestCase):
    def test_ffi_graph_requires_its_transport_and_exact_windows_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project(root)
            target = "aarch64-pc-windows-msvc"

            def inspect(snapshot, backend):
                return cli_release._graph(
                    {
                        "packages": snapshot["packages"],
                        "resolve": {"nodes": snapshot["nodes"]},
                    },
                    root,
                    target,
                    transport="ffi",
                    backend=backend,
                )

            for backend in ("wintun", "uwp"):
                inspect(graph(root, target, backend), backend)
            for remove, append, message in (
                ("ffi", None, "complete production"),
                (None, "cli", "CLI or test"),
                (None, "windows-uwp", "incompatible Windows"),
            ):
                invalid = graph(root, target, "wintun")
                if remove:
                    invalid["nodes"][0]["features"].remove(remove)
                if append:
                    invalid["nodes"][0]["features"].append(append)
                with (
                    self.subTest(append=append),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    inspect(invalid, "wintun")
            invalid = graph(root, target, "uwp")
            invalid["packages"][-1]["name"] = "tun-rs"
            with self.assertRaisesRegex(ValueError, "Wintun adapter"):
                inspect(invalid, "uwp")

    def test_all_eight_builds_package_only_platform_outputs(self):
        apple = {"LibVole.xcframework/Info.plist"} | {
            f"LibVole.xcframework/{part}/{name}"
            for part in (
                "ios-arm64",
                "ios-arm64-simulator",
                "macos-arm64_x86_64",
                "tvos-arm64",
                "tvos-arm64-simulator",
            )
            for name in ("libvole.a", "Headers/vole.h", "Headers/module.modulemap")
        }
        expected = {
            "apple": apple,
            "android": {
                f"{abi}/{name}"
                for abi in ("arm64-v8a", "x86_64")
                for name in ("libvole.so", "libc++_shared.so")
            }
            | {"include/vole.h"},
            "linux": {"libvole.so", "libvole.a", "include/vole.h"},
            "windows": {"vole.dll", "vole.dll.lib", "include/vole.h"},
        }
        for key, (platform, target, backend) in ffi_release.RELEASES.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project(root)
                built = root / "dist" / platform
                built.mkdir(parents=True)
                names = expected[platform].copy()
                if backend == "uwp":
                    names |= {
                        "vole-windows-vpn-host.exe",
                        "vole-windows-session-host.exe",
                    }
                for name in names:
                    path = built / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(name.encode())
                for extra in (
                    "wintun.dll",
                    "stale-manifest.json",
                    "unused-license.txt",
                ):
                    (built / extra).write_bytes(b"not a release asset")
                captured = []

                def compile_platform(
                    platform=platform,
                    expected_target=target,
                    expected_backend=backend,
                    built=built,
                    captured=captured,
                    **kwargs,
                ):
                    notice = Path(kwargs["env"]["VOLE_RELEASE_NOTICES"])
                    self.assertEqual(notice.read_bytes(), NOTICES)
                    captured.append(notice)
                    if platform == "windows":
                        self.assertEqual(kwargs["backend"], expected_backend)
                    if platform == "linux":
                        self.assertEqual(kwargs["target"], expected_target)
                    return built

                with (
                    patch.dict(os.environ, {}, clear=True),
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(builds, "native_target", return_value=target),
                    patch.object(
                        builds, "_android_ndk_home", return_value=root / "ndk"
                    ),
                    patch.object(
                        builds, "build_" + platform, side_effect=compile_platform
                    ),
                    patch.object(cli_release, "_release_info", return_value=SOURCE),
                    patch.object(ffi_release, "prepare_notices", return_value=NOTICES),
                ):
                    archive = ffi_release.build_release(
                        platform, target=target, backend=backend
                    )
                self.assertEqual(list(archive.parent.iterdir()), [archive])
                self.assertFalse(captured[0].exists())
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as stream:
                        contents = {
                            name: stream.read(name) for name in stream.namelist()
                        }
                else:
                    with tarfile.open(archive) as stream:
                        contents = {
                            member.name: stream.extractfile(member).read()
                            for member in stream.getmembers()
                        }
                self.assertEqual(set(contents), names)
                for name, data in contents.items():
                    source = (
                        root / name
                        if name == "include/vole.h"
                        and platform in {"android", "windows"}
                        else built / name
                    )
                    self.assertEqual(data, source.read_bytes())

    def test_output_cannot_replace_platform_build_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(builds, "build_linux") as build,
            ):
                with self.assertRaisesRegex(ValueError, "separate from platform"):
                    ffi_release.build_release(
                        "linux",
                        target="x86_64-unknown-linux-gnu",
                        output=Path("dist/linux/archive"),
                    )
                build.assert_not_called()

    def test_universal_graph_notice_union_preserves_each_dependency_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            (root / "LICENSE").write_bytes(NOTICES)
            upstream = root / "upstream"
            upstream.mkdir()
            (upstream / "LICENSE").write_bytes(b"Upstream oslog full license.\n")
            targets = ("aarch64-apple-ios", "aarch64-apple-darwin")
            metadata = []
            for target in targets:
                snapshot = graph(root, target, None)
                packages = snapshot["packages"]
                packages[0]["manifest_path"] = str(root / "Cargo.toml")
                if "darwin" in target:
                    packages.append(
                        {
                            "id": "oslog",
                            "name": "oslog",
                            "version": "0.2.0",
                            "source": next(iter(cli_release.REGISTRY)),
                            "license": "MIT",
                            "manifest_path": str(upstream / "Cargo.toml"),
                            "targets": [{"kind": ["lib"]}],
                        }
                    )
                    snapshot["nodes"].append(
                        {"id": "oslog", "features": [], "deps": []}
                    )
                    snapshot["nodes"][0]["deps"].append(
                        {"pkg": "oslog", "dep_kinds": [{"kind": None}]}
                    )
                metadata.append(
                    json.dumps(
                        {"packages": packages, "resolve": {"nodes": snapshot["nodes"]}}
                    )
                )
            with (
                patch.object(cli_release, "_output", side_effect=metadata),
                patch.object(cli_release, "_audit_graph"),
                patch.object(
                    cli_release,
                    "collect_rust_notices",
                    return_value=b"",
                ),
                patch.object(
                    cli_release, "collect_notices", wraps=cli_release.collect_notices
                ) as collect,
            ):
                text = ffi_release.prepare_notices(root, targets, source=SOURCE)
            self.assertEqual(collect.call_count, 1)
            self.assertEqual(text.count(b"===== vole 1.2.3 ====="), 1)
            self.assertEqual(text.count(b"Upstream oslog full license."), 1)

    def test_android_runtime_notice_origin_and_stable_revision_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            ndk = Path(temporary)
            (ndk / "source.properties").write_text("Pkg.Revision = 30.0.12345\n")
            with self.assertRaisesRegex(ValueError, "missing Android"):
                ffi_release._android_runtime_notices(ndk)
            (ndk / "NOTICE").write_text(
                "LLVM libc++ copyright and Apache full terms.\n"
            )
            text = ffi_release._android_runtime_notices(ndk)
            self.assertIn(b"LLVM libc++", text)
            self.assertIn(b"Android NDK 30.0.12345/NOTICE", text)
            (ndk / "source.properties").write_text("Pkg.Revision = 30.0.12345-beta1\n")
            with self.assertRaisesRegex(ValueError, "stable NDK"):
                ffi_release._android_runtime_notices(ndk)
