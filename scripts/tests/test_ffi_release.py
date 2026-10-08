"""Real offline archive/graph fixtures; no compiler, driver or socket is used."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import plistlib
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds, cli_release, ffi_release
from vole_scripts import platform_delivery as delivery

VERSION = "1.2.3"
NOTICES = b"Fixture full copyright and license terms.\n"
IDENTITY = f"Vole;engine=rust;coreVersion={VERSION}".encode()
RUST_RUNTIME = {
    "name": "Rust standard library",
    "version": "1.99.0",
    "rustc": "fixture",
    "notices": [
        {
            "path": "COPYRIGHT-library.html",
            "sha256": hashlib.sha256(NOTICES).hexdigest(),
        }
    ],
}
SOURCE = {
    "tag": "v1.2.3",
    "version": VERSION,
    "commit": "a" * 40,
    "tree": "b" * 40,
    "lockSha256": "c" * 64,
    "manifestSha256": "d" * 64,
}


def project(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname="vole"\nversion="1.2.3"\n[features]\ndefault=["inbound-http","outbound-socks5"]\n'
    )
    (root / "Cargo.lock").write_text("locked fixture\n")
    (root / "include").mkdir()
    (root / "include/vole.h").write_bytes(b"public header fixture\n")
    (root / "include/module.modulemap").write_bytes(
        b'module LibVole { header "vole.h" link "c++" }\n'
    )


def embedded(notices: bytes = NOTICES) -> bytes:
    return (
        IDENTITY + b"\0" + cli_release.NOTICES_BEGIN + notices + cli_release.NOTICES_END
    )


def elf(machine: int, kind: int = 3, *, notices: bool = True) -> bytes:
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = kind.to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header) + (embedded() if notices else b"runtime")


def ar(payload: bytes, name: str = "member.o") -> bytes:
    header = (
        f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n"
    ).encode()
    assert len(header) == 60
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) % 2 else b"")


def macho(architecture: str, platform: int) -> bytes:
    header = bytearray(56)
    header[:4] = b"\xcf\xfa\xed\xfe"
    header[4:8] = {"arm64": 0x100000C, "x86_64": 0x1000007}[architecture].to_bytes(
        4, "little"
    )
    header[12:16] = (1).to_bytes(4, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[20:24] = (24).to_bytes(4, "little")
    header[32:36] = (0x32).to_bytes(4, "little")
    header[36:40] = (24).to_bytes(4, "little")
    header[40:44] = platform.to_bytes(4, "little")
    return bytes(header) + embedded()


def fat(arm64: bytes, x64: bytes) -> bytes:
    header = bytearray(48)
    header[:4] = b"\xca\xfe\xba\xbe"
    header[4:8] = (2).to_bytes(4, "big")
    offset = len(header)
    for index, (cpu, payload) in enumerate(((0x100000C, arm64), (0x1000007, x64))):
        start = 8 + index * 20
        header[start : start + 4] = cpu.to_bytes(4, "big")
        header[start + 8 : start + 12] = offset.to_bytes(4, "big")
        header[start + 12 : start + 16] = len(payload).to_bytes(4, "big")
        offset += len(payload)
    return bytes(header) + arm64 + x64


def pe(machine: int, *, dll: bool) -> bytes:
    header = bytearray(512)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x84] = b"PE\0\0"
    header[0x84:0x86] = machine.to_bytes(2, "little")
    header[0x96:0x98] = (2 | (0x2000 if dll else 0)).to_bytes(2, "little")
    return bytes(header) + embedded()


def payload_tree(base: Path, root: Path, key: str) -> None:
    platform, _, _ = ffi_release.RELEASES[key]
    for name in ffi_release._expected_files(key):
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name.endswith("vole.h"):
            path.write_bytes((root / "include/vole.h").read_bytes())
        elif name.endswith("module.modulemap"):
            path.write_bytes((root / "include/module.modulemap").read_bytes())
        elif name.endswith("Info.plist"):
            libraries = []
            for identifier, (
                target_os,
                variant,
                architectures,
            ) in delivery.APPLE_LIBRARIES.items():
                libraries.append(
                    {
                        "LibraryIdentifier": identifier,
                        "SupportedPlatform": target_os,
                        **({"SupportedPlatformVariant": variant} if variant else {}),
                        "SupportedArchitectures": sorted(architectures),
                        "LibraryPath": "libvole.a",
                        "HeadersPath": "Headers",
                    }
                )
            path.write_bytes(plistlib.dumps({"AvailableLibraries": libraries}))
        elif platform == "apple":
            identifier = Path(name).parts[1]
            target_os, variant, architectures = delivery.APPLE_LIBRARIES[identifier]
            number = {
                ("macos", None): 1,
                ("ios", None): 2,
                ("tvos", None): 3,
                ("ios", "simulator"): 7,
                ("tvos", "simulator"): 8,
            }[(target_os, variant)]
            if len(architectures) == 2:
                path.write_bytes(
                    fat(ar(macho("arm64", number)), ar(macho("x86_64", number)))
                )
            else:
                path.write_bytes(ar(macho("arm64", number)))
        elif platform == "windows":
            machine = 0x8664 if key.endswith("amd64") else 0xAA64
            if name.endswith(".lib"):
                obj = bytearray(20)
                obj[:4] = b"\0\0\xff\xff"
                obj[6:8] = machine.to_bytes(2, "little")
                path.write_bytes(ar(bytes(obj)))
            else:
                path.write_bytes(pe(machine, dll=name.endswith(".dll")))
        else:
            machine = (
                183 if name.startswith("arm64-v8a/") or key.endswith("arm64") else 62
            )
            path.write_bytes(
                ar(elf(machine, 1))
                if name.endswith(".a")
                else elf(machine, notices=not name.endswith("libc++_shared.so"))
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
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append({"id": "winrt", "features": ["Networking_Vpn"], "deps": []})
        nodes[0]["deps"] = [{"pkg": "winrt", "dep_kinds": [{"kind": None}]}]
    return ffi_release._snapshot(
        {p["id"]: p for p in packages},
        {n["id"]: n for n in nodes},
        {p["id"] for p in packages},
        root,
        target,
    )


def release_record(
    root: Path, key: str, base: Path, archive: Path, source: dict = SOURCE
) -> dict:
    platform, target, backend = ffi_release.RELEASES[key]
    _, targets = ffi_release.selection(platform, target, backend)
    rows = [
        {
            "path": p.relative_to(base).as_posix(),
            "size": p.stat().st_size,
            "sha256": cli_release._sha(p),
        }
        for p in sorted(base.rglob("*"))
        if p.is_file()
    ]
    architecture = "x64" if target and target.startswith("x86_64-") else "arm64"
    group = (
        platform
        if platform in {"apple", "android"}
        else f"linux-{architecture}"
        if platform == "linux"
        else f"windows-{architecture}-{backend}"
    )
    delivery_rows = [
        row for row in rows if row["path"] != "include/vole.h" or platform == "linux"
    ]
    toolchain = {
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
            "iosDeploymentTarget",
            "macosDeploymentTarget",
            "tvosDeploymentTarget",
            "clang",
            "androidApi",
            "msvc",
            "windowsSdk",
            "cc",
            "cmake",
        )
    }
    toolchain["ndk"] = "Pkg.Revision = 30.0.12345"
    graphs = [graph(root, target, backend) for target in targets]
    dependencies = [
        {
            "target": row["target"],
            "linked": [
                {
                    "name": p["name"],
                    "version": p["version"],
                    "notices": [
                        {
                            "path": "LICENSE",
                            "sha256": hashlib.sha256(NOTICES).hexdigest(),
                        }
                    ],
                }
                for p in row["packages"]
            ],
        }
        for row in graphs
    ]
    dependencies.append({"rustRuntime": RUST_RUNTIME})
    if platform == "android":
        dependencies.append(
            {
                "nativeRuntime": {
                    "name": "Android NDK libc++_shared",
                    "version": "30.0.12345",
                    "notices": [
                        {
                            "path": "NOTICE",
                            "sha256": hashlib.sha256(NOTICES).hexdigest(),
                        }
                    ],
                }
            }
        )
    record = {
        "formatVersion": 1,
        "kind": "ffi",
        "release": key,
        "profile": "release",
        "source": source,
        "buildIdentity": IDENTITY.decode(),
        "graphs": graphs,
        "dependencies": dependencies,
        "artifacts": rows,
        "delivery": {
            "formatVersion": 1,
            "group": group,
            "profile": "release",
            "features": (
                builds.windows_features(backend) if backend else builds.DEFAULT_FEATURES
            ).split(","),
            "source": {name: source[name] for name in ("commit", "tree", "lockSha256")},
            "buildIdentity": IDENTITY.decode(),
            "toolchain": toolchain,
            "host": {
                "os": "Darwin"
                if platform == "apple"
                else "Windows"
                if platform == "windows"
                else "Linux",
                "architecture": architecture,
            },
            "artifacts": delivery_rows,
            **({"target": target} if platform in {"windows", "linux"} else {}),
            **({"backend": backend} if backend else {}),
        },
        "archive": {
            "name": archive.name,
            "size": archive.stat().st_size,
            "sha256": cli_release._sha(archive),
        },
        "noticesSha256": hashlib.sha256(NOTICES).hexdigest(),
        "noticesSize": len(NOTICES),
        "retainedNotices": sorted(
            name
            for name in ffi_release._expected_files(key)
            if name.endswith((".dll", ".exe", ".a")) or name.endswith("libvole.so")
        ),
    }
    if platform == "windows":
        package = {
            "formatVersion": 1,
            "backend": backend,
            "architecture": architecture,
            "buildIdentity": IDENTITY.decode(),
            "artifacts": {
                row["path"]: row["sha256"]
                for row in rows
                if row["path"] != "include/vole.h"
            },
            **({"windowsPackageIntegrationRevision": 3} if backend == "uwp" else {}),
        }
        text = json.dumps(package)
        record["windowsPackageIdentity"] = text
        delivery_rows.append(
            {
                "path": "vole-windows-artifacts.json",
                "size": len(text.encode()),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
        )
    return record


def archive_set(incoming: Path, root: Path, source: dict = SOURCE) -> list[Path]:
    manifests = []
    for key in ffi_release.RELEASES:
        directory = incoming / ("ffi-" + key)
        directory.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            payload_tree(base, root, key)
            archive = directory / ffi_release.archive_name(key)
            ffi_release._write_archive(base, archive)
            record = release_record(root, key, base, archive, source)
        manifest = directory / "manifest.json"
        manifest.write_text(json.dumps(record))
        manifests.append(manifest)
    return manifests


class FfiReleaseTest(unittest.TestCase):
    def test_job_output_cannot_clear_or_mix_raw_delivery_trees(self):
        cases = (
            ("apple", None, None, "dist/apple"),
            ("android", None, None, "dist/android/job"),
            ("linux", "x86_64-unknown-linux-gnu", None, "dist/linux"),
            ("windows", "aarch64-pc-windows-msvc", "uwp", "dist/windows/arm64/uwp"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(ffi_release, "prepare_notices") as notices,
                patch.object(delivery, "build_delivery") as build,
                patch.object(cli_release, "_source") as source,
                patch.object(ffi_release.shutil, "rmtree") as remove,
            ):
                for platform, target, backend, output in cases:
                    with (
                        self.subTest(output=output),
                        self.assertRaisesRegex(ValueError, "separate from raw"),
                    ):
                        ffi_release.build_release(
                            platform,
                            target=target,
                            backend=backend,
                            output=Path(output),
                        )
                source.assert_not_called()
                notices.assert_not_called()
                build.assert_not_called()
                remove.assert_not_called()

    def test_ffi_graph_requires_its_transport_and_exact_windows_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            target = "aarch64-pc-windows-msvc"
            with patch.object(cli_release, "_audit_graph"):
                wintun = graph(root, target, "wintun")
                ffi_release.inspect_graph(wintun, root, "wintun")
                uwp = graph(root, target, "uwp")
                ffi_release.inspect_graph(uwp, root, "uwp")
                for remove, append, message in (
                    ("ffi", None, "complete production"),
                    (None, "cli", "CLI or test"),
                    (None, "windows-uwp", "incompatible Windows"),
                ):
                    invalid = copy.deepcopy(wintun)
                    if remove:
                        invalid["nodes"][0]["features"].remove(remove)
                    if append:
                        invalid["nodes"][0]["features"].append(append)
                    with (
                        self.subTest(append=append),
                        self.assertRaisesRegex(ValueError, message),
                    ):
                        ffi_release.inspect_graph(invalid, root, "wintun")
                uwp["packages"][-1]["name"] = "tun-rs"
                with self.assertRaisesRegex(ValueError, "Wintun adapter"):
                    ffi_release.inspect_graph(uwp, root, "uwp")
                invalid = copy.deepcopy(wintun)
                invalid["packages"][0]["localManifest"] = "../outside/Cargo.toml"
                with self.assertRaisesRegex(
                    ValueError, "invalid archive or artifact path"
                ):
                    ffi_release.inspect_graph(invalid, root, "wintun")

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
                    return_value=(b"", RUST_RUNTIME),
                ),
                patch.object(
                    cli_release, "collect_notices", wraps=cli_release.collect_notices
                ) as collect,
            ):
                text, dependencies, snapshots = ffi_release.prepare_notices(
                    root, targets, source=SOURCE
                )
            self.assertEqual(collect.call_count, 1)
            self.assertEqual(text.count(b"===== vole 1.2.3 ====="), 1)
            self.assertEqual(text.count(b"Upstream oslog full license."), 1)
            self.assertEqual(
                {row["name"] for row in dependencies[0]["linked"]}, {"vole"}
            )
            self.assertEqual(
                {row["name"] for row in dependencies[1]["linked"]}, {"vole", "oslog"}
            )
            self.assertEqual({row["target"] for row in snapshots}, set(targets))

    def test_all_eight_archives_retain_notice_bytes_and_exact_platform_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "checkout"
            project(root)
            incoming = fixture / "incoming"
            manifests = archive_set(incoming, root)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_audit_graph"),
            ):
                for manifest in manifests:
                    with self.subTest(key=manifest.parent.name):
                        ffi_release.inspect_release(manifest, SOURCE, root)
            self.assertEqual(len(manifests), 8)

    def test_source_backend_graph_and_runtime_identity_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "checkout"
            project(root)
            manifests = archive_set(fixture / "incoming", root)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_audit_graph"),
            ):
                cases = [
                    (
                        "linux-amd64",
                        lambda r: r["source"].update(commit="e" * 40),
                        "release evidence",
                    ),
                    (
                        "windows-wintun-amd64",
                        lambda r: r["delivery"].update(backend="uwp"),
                        "backend delivery",
                    ),
                    (
                        "windows-wintun-arm64",
                        lambda r: r["delivery"].update(target="x86_64-pc-windows-msvc"),
                        "target differs",
                    ),
                    (
                        "apple",
                        lambda r: r["dependencies"].append(
                            copy.deepcopy(r["dependencies"][0])
                        ),
                        "dependency notices",
                    ),
                    (
                        "android",
                        lambda r: r["dependencies"][-1]["nativeRuntime"].update(
                            version="29.0.1"
                        ),
                        "build NDK",
                    ),
                    (
                        "linux-arm64",
                        lambda r: r.update(noticesSha256="0" * 64),
                        "notices identity",
                    ),
                    (
                        "windows-uwp-amd64",
                        lambda r: r.update(windowsPackageIdentity="{}"),
                        "package identity",
                    ),
                ]
                for key, mutate, message in cases:
                    manifest = next(
                        m for m in manifests if m.parent.name == "ffi-" + key
                    )
                    original = manifest.read_text()
                    record = json.loads(original)
                    # Source belongs to the loaded record, never the expected fixture.
                    mutate(record)
                    manifest.write_text(json.dumps(record))
                    with (
                        self.subTest(key=key),
                        self.assertRaisesRegex(ValueError, message),
                    ):
                        ffi_release.inspect_release(manifest, SOURCE, root)
                    manifest.write_text(original)

    def test_payload_architecture_hosts_and_each_apple_slice_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "checkout"
            project(root)
            with patch.object(builds, "CORE_DIR", root):
                for key in ffi_release.RELEASES:
                    base = fixture / key
                    payload_tree(base, root, key)
                    ffi_release.verify_artifacts(base, key, VERSION, NOTICES)
                windows = fixture / "windows-uwp-amd64"
                (windows / "vole-windows-vpn-host.exe").write_bytes(
                    pe(0x8664, dll=False).replace(NOTICES, b"truncated")
                )
                with self.assertRaisesRegex(ValueError, "exact linked notice"):
                    ffi_release.verify_artifacts(
                        windows, "windows-uwp-amd64", VERSION, NOTICES
                    )
                (fixture / "linux-arm64/libvole.so").write_bytes(elf(62))
                with self.assertRaisesRegex(ValueError, "architecture"):
                    ffi_release.verify_artifacts(
                        fixture / "linux-arm64", "linux-arm64", VERSION
                    )
                apple = (
                    fixture / "apple/LibVole.xcframework/ios-arm64-simulator/libvole.a"
                )
                apple.write_bytes(ar(macho("arm64", 2)))
                with self.assertRaisesRegex(ValueError, "platform"):
                    ffi_release.verify_artifacts(fixture / "apple", "apple", VERSION)
                payload_tree(fixture / "apple", root, "apple")
                universal = (
                    fixture / "apple/LibVole.xcframework/macos-arm64_x86_64/libvole.a"
                )
                universal.write_bytes(
                    fat(
                        ar(macho("arm64", 1)),
                        ar(macho("x86_64", 1).replace(NOTICES, b"truncated")),
                    )
                )
                with self.assertRaisesRegex(ValueError, "universal notices differ"):
                    ffi_release.verify_artifacts(fixture / "apple", "apple", VERSION)

    def test_tar_and_zip_reject_traversal_duplicates_symlinks_and_extra_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            archive = fixture / "payload.tar.gz"
            for name, kind in (
                ("../escape", tarfile.REGTYPE),
                ("include/vole.h", tarfile.SYMTYPE),
                ("LICENSE", tarfile.REGTYPE),
            ):
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo(name)
                    member.type, member.size, member.linkname = (
                        kind,
                        1 if kind == tarfile.REGTYPE else 0,
                        "../outside",
                    )
                    stream.addfile(member, io.BytesIO(b"x") if member.size else None)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    ffi_release._extract_archive(
                        archive, fixture / "extract", {"include/vole.h"}
                    )
                self.assertFalse((fixture / "escape").exists())
            archive = fixture / "payload.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                member = zipfile.ZipInfo("include/vole.h")
                member.external_attr = 0o120777 << 16
                stream.writestr(member, b"../outside")
            with self.assertRaisesRegex(ValueError, "zip member"):
                ffi_release._extract_archive(
                    archive, fixture / "extract", {"include/vole.h"}
                )

    def test_owned_notice_build_input_and_delivery_target_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "checkout"
            project(root)
            key, target = "linux-arm64", "aarch64-unknown-linux-gnu"
            base = root / "dist/linux/arm64"
            payload_tree(base, root, key)
            placeholder = fixture / "placeholder.tar.gz"
            ffi_release._write_archive(base, placeholder)
            record = release_record(root, key, base, placeholder)
            delivery_path = base / "vole-delivery.json"
            delivery_path.write_text(json.dumps(record["delivery"]))
            owned = []

            def build(platform, *, backend, target, env):
                self.assertEqual(
                    (platform, backend, target),
                    ("linux", "uwp", "aarch64-unknown-linux-gnu"),
                )
                path = Path(env["VOLE_RELEASE_NOTICES"])
                self.assertEqual(path.read_bytes(), NOTICES)
                owned.append(path)
                return delivery_path

            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_source", return_value=SOURCE),
                patch.object(
                    ffi_release,
                    "prepare_notices",
                    return_value=(NOTICES, record["dependencies"], record["graphs"]),
                ),
                patch.object(delivery, "build_delivery", side_effect=build),
            ):
                manifest = ffi_release.build_release("linux", "v1.2.3", target=target)
            self.assertEqual(len(owned), 1)
            self.assertFalse(owned[0].exists())
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_audit_graph"),
            ):
                ffi_release.inspect_release(manifest, SOURCE, root)
            self.assertEqual(
                {p.name for p in manifest.parent.iterdir()},
                {"manifest.json", ffi_release.archive_name(key)},
            )

    def test_native_overrides_fail_before_source_or_metadata(self):
        for name in (
            "RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "BORING_BSSL_SOURCE_PATH",
            "AWS_LC_SYS_PREBUILT_NASM",
            "VOLE_RELEASE_NOTICES",
        ):
            with (
                self.subTest(name=name),
                patch.dict(os.environ, {name: "override"}, clear=True),
                patch.object(cli_release, "_source") as source,
                patch.object(ffi_release, "prepare_notices") as notices,
            ):
                with self.assertRaisesRegex(ValueError, "overrides"):
                    ffi_release.build_release(
                        "linux", target="aarch64-unknown-linux-gnu"
                    )
                source.assert_not_called()
                notices.assert_not_called()

    def test_android_runtime_notice_origin_and_stable_revision_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            ndk = Path(temporary)
            (ndk / "source.properties").write_text("Pkg.Revision = 30.0.12345\n")
            with self.assertRaisesRegex(ValueError, "missing Android"):
                ffi_release._android_runtime_notices(ndk)
            (ndk / "NOTICE").write_text(
                "LLVM libc++ copyright and Apache full terms.\n"
            )
            text, row = ffi_release._android_runtime_notices(ndk)
            self.assertIn(b"LLVM libc++", text)
            self.assertEqual(row["version"], "30.0.12345")
            (ndk / "source.properties").write_text("Pkg.Revision = 30.0.12345-beta1\n")
            with self.assertRaisesRegex(ValueError, "stable NDK"):
                ffi_release._android_runtime_notices(ndk)


if __name__ == "__main__":
    unittest.main()
