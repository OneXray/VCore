"""Production build evidence. This is not device or signed-release acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import plistlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from . import builds

GROUPS = {"apple", "android", "windows-arm64", "windows-x64"}
APPLE_LIBRARIES = {
    "ios-arm64": ("ios", None, {"arm64"}),
    "ios-arm64_x86_64-simulator": ("ios", "simulator", {"arm64", "x86_64"}),
    "macos-arm64_x86_64": ("macos", None, {"arm64", "x86_64"}),
}


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _output(argv: list[str], root: Path) -> str:
    return subprocess.check_output(argv, cwd=root, text=True, timeout=60).strip()


def _source(root: Path) -> dict:
    if _output(["git", "status", "--porcelain", "--untracked-files=normal"], root):
        raise ValueError("delivery requires a clean committed source checkout")
    return {
        "commit": _output(["git", "rev-parse", "HEAD"], root),
        "tree": _output(["git", "rev-parse", "HEAD^{tree}"], root),
        "lockSha256": _sha(root / "Cargo.lock"),
    }


def check_delivery(
    manifests: list[Path], *, source_dir: Path | None = None, complete: bool = False
) -> None:
    source = _source(source_dir or builds.CORE_DIR)
    groups = set()
    if not manifests:
        raise ValueError("empty manifest set cannot pass")
    for manifest in manifests:
        record = json.loads(manifest.read_text(encoding="utf-8"))
        if (
            record.get("formatVersion") != 1
            or record.get("profile") != "release"
            or record.get("features") != builds.DEFAULT_FEATURES.split(",")
            or record.get("buildIdentity") != builds.EXPECTED_IDENTITY.decode()
        ):
            raise ValueError("incompatible production artifact metadata")
        if record.get("source") != source:
            raise ValueError("artifact source/lock identity does not match checkout")
        group = record.get("group")
        if group not in GROUPS or group in groups:
            raise ValueError("duplicate delivery group")
        groups.add(group)
        toolchain = record.get("toolchain", {})
        required = {"rustc", "cargo"} | (
            {"ndk", "clang", "androidApi"}
            if group == "android"
            else {"xcode", "iphoneos", "iphonesimulator", "macosx"}
            if group == "apple"
            else {"msvc", "windowsSdk"}
        )
        if not all(
            isinstance(toolchain.get(key), str) and toolchain[key] for key in required
        ):
            raise ValueError("missing toolchain evidence")
        rows = record.get("artifacts", [])
        if not rows:
            raise ValueError("empty artifact set cannot pass")
        names = set()
        for row in rows:
            name = row["path"]
            relative = PurePosixPath(name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or "\\" in name
                or str(relative) != name
                or name in names
            ):
                raise ValueError("invalid or duplicate artifact path")
            names.add(name)
            base = manifest.parent.resolve()
            path = base / name
            if not path.is_file() or any(
                base.joinpath(*relative.parts[:index]).is_symlink()
                for index in range(1, len(relative.parts) + 1)
            ):
                raise ValueError(f"missing or non-regular artifact: {name}")
            if path.stat().st_size != row["size"] or _sha(path) != row["sha256"]:
                raise ValueError(f"artifact hash/size mismatch: {name}")
        actual = {
            p.relative_to(manifest.parent).as_posix()
            for p in manifest.parent.rglob("*")
            if p.is_file() and p != manifest
        }
        if actual != names:
            raise ValueError("unrecorded or missing artifact files")
        if record.get("group") == "android":
            expected = {
                f"{abi}/{name}"
                for abi in ("arm64-v8a", "x86_64")
                for name in ("libvcore.so", "libc++_shared.so")
            }
            if names != expected:
                raise ValueError("Android delivery requires both ABIs and C++ runtimes")
            for abi, machine in (("arm64-v8a", 183), ("x86_64", 62)):
                for name in ("libvcore.so", "libc++_shared.so"):
                    path = manifest.parent / abi / name
                    with path.open("rb") as stream:
                        header = stream.read(20)
                    if (
                        header[:7] != b"\x7fELF\x02\x01\x01"
                        or len(header) != 20
                        or int.from_bytes(header[16:18], "little") != 3
                        or int.from_bytes(header[18:20], "little") != machine
                    ):
                        raise ValueError(
                            f"wrong Android ELF architecture: {abi}/{name}"
                        )
                    if name == "libvcore.so":
                        builds._require_identity(path, "Android")
        elif group == "apple":
            expected = {"LibVCore.xcframework/Info.plist"} | {
                f"LibVCore.xcframework/{identifier}/{name}"
                for identifier in APPLE_LIBRARIES
                for name in (
                    "libvcore.a",
                    "Headers/vcore.h",
                    "Headers/module.modulemap",
                )
            }
            if names != expected:
                raise ValueError("incomplete Apple XCFramework")
            with (manifest.parent / "LibVCore.xcframework/Info.plist").open(
                "rb"
            ) as stream:
                libraries = plistlib.load(stream).get("AvailableLibraries", [])
            if len(libraries) != 3:
                raise ValueError("incomplete Apple platform slices")
            identifiers = set()
            for library in libraries:
                identifier = library.get("LibraryIdentifier")
                if identifier not in APPLE_LIBRARIES or identifier in identifiers:
                    raise ValueError("invalid Apple library identifier")
                identifiers.add(identifier)
                target_os, variant, architectures = APPLE_LIBRARIES[identifier]
                if (
                    library.get("SupportedPlatform") != target_os
                    or library.get("SupportedPlatformVariant") != variant
                    or set(library.get("SupportedArchitectures", [])) != architectures
                    or library.get("LibraryPath") != "libvcore.a"
                    or library.get("HeadersPath") != "Headers"
                ):
                    raise ValueError("invalid Apple slice metadata")
                path = (
                    manifest.parent / "LibVCore.xcframework" / identifier / "libvcore.a"
                )
                actual_archs = set(
                    _output(
                        ["xcrun", "lipo", "-archs", str(path)], builds.CORE_DIR
                    ).split()
                )
                if actual_archs != architectures:
                    raise ValueError("wrong Apple binary architecture")
                builds._require_identity(path, "Apple")
        else:
            arch = group.removeprefix("windows-")
            expected = {
                "vcore.dll",
                "vcore-windows-vpn-host.exe",
                "vcore-windows-session-host.exe",
            }
            if names != expected | {"vcore-windows-artifacts.json"}:
                raise ValueError("incomplete Windows artifact set")
            if (
                record.get("host", {}).get("os") != "Windows"
                or record["host"].get("architecture") != arch
            ):
                raise ValueError(
                    "Windows delivery requires native OS architecture evidence"
                )
            for name in expected:
                builds._require_windows_architecture(manifest.parent / name, arch)
            builds._require_identity(manifest.parent / "vcore.dll", "Windows")
            package = json.loads(
                (manifest.parent / "vcore-windows-artifacts.json").read_text()
            )
            if (
                package.get("formatVersion") != 1
                or package.get("architecture") != arch
                or package.get("windowsPackageIntegrationRevision") != 3
                or package.get("buildIdentity") != record["buildIdentity"]
                or package.get("artifacts")
                != {
                    row["path"]: row["sha256"]
                    for row in rows
                    if row["path"] in expected
                }
            ):
                raise ValueError("Windows package integration identity mismatch")
        print(
            f"PASS {record['group']} artifact integrity (not device/release acceptance)"
        )
    if complete and groups != GROUPS:
        raise ValueError("N10.1 requires Apple, Android, native Windows ARM64 and x64")
    if complete:
        print(
            "PASS N10.1 production artifacts; "
            "N10.2/N10.3/N10.4 require separate evidence"
        )


def build_delivery(platform_name: str) -> None:
    if os.environ.get("VCORE_BUILD_PROFILE", "release") != "release":
        raise ValueError("delivery requires the release profile")
    if (
        os.environ.get("VCORE_FEATURES", builds.DEFAULT_FEATURES)
        != builds.DEFAULT_FEATURES
    ):
        raise ValueError("delivery requires the complete production feature set")
    # Keep the recorded build command honest: existing development builds still
    # allow customization, but acceptance must not inherit hidden overrides.
    overrides = [
        name
        for name in os.environ
        if (
            name
            in {
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_TARGET_DIR",
                "VCORE_ANDROID_OUTPUT_DIR",
                "VCORE_APPLE_DIST_DIR",
                "VCORE_ANDROID_TARGETS",
            }
            or name.startswith("CARGO_PROFILE_")
        )
        and os.environ[name]
    ]
    if overrides:
        raise ValueError(
            "unsupported delivery build overrides: " + ", ".join(sorted(overrides))
        )
    source = _source(builds.CORE_DIR)
    group = platform_name
    architecture = platform.machine().lower()
    toolchain = {
        "rustc": _output(["rustc", "-Vv"], builds.CORE_DIR),
        "cargo": _output(["cargo", "--version"], builds.CORE_DIR),
    }
    if platform_name == "windows":
        if os.name != "nt":
            raise ValueError("Windows delivery must run on native Windows")
        architecture = builds._windows_architecture()
        group += "-" + architecture
        environment = builds._windows_msvc_environment(architecture)
        # Windows env names are case insensitive, even when a subprocess returns
        # a plain Python dict. Never persist the full environment (credentials).
        normalized = {key.upper(): value for key, value in environment.items()}
        toolchain["msvc"] = normalized.get("VCTOOLSVERSION", "").strip()
        toolchain["windowsSdk"] = normalized.get("WINDOWSSDKVERSION", "").strip("\\ ")
    elif platform_name == "apple":
        toolchain["xcode"] = _output(["xcodebuild", "-version"], builds.CORE_DIR)
        for sdk in ("iphoneos", "iphonesimulator", "macosx"):
            toolchain[sdk] = _output(
                ["xcrun", "--sdk", sdk, "--show-sdk-version"], builds.CORE_DIR
            )
        toolchain["iosDeploymentTarget"] = os.environ.get(
            "VCORE_IOS_DEPLOYMENT_TARGET", "13.0"
        )
        toolchain["macosDeploymentTarget"] = os.environ.get(
            "VCORE_MACOS_DEPLOYMENT_TARGET", "10.15"
        )
    else:
        android_home = Path(
            os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk")
        )
        ndk = Path(
            os.environ.get(
                "ANDROID_NDK_HOME",
                android_home
                / "ndk"
                / os.environ.get("VCORE_ANDROID_NDK_VERSION", "28.2.13676358"),
            )
        )
        toolchain["ndk"] = (ndk / "source.properties").read_text().strip()
        toolchain["clang"] = _output(
            [str(builds._android_toolchain(ndk) / "bin/clang"), "--version"],
            builds.CORE_DIR,
        )
        toolchain["androidApi"] = os.environ.get("VCORE_ANDROID_API", "24")
    output = builds.CORE_DIR / "dist" / platform_name
    if platform_name == "windows":
        output /= architecture
    manifest = output / "vcore-delivery.json"
    manifest.unlink(missing_ok=True)
    started = datetime.now(UTC).isoformat()
    {
        "apple": builds.build_apple,
        "android": builds.build_android,
        "windows": builds.build_windows,
    }[platform_name]()
    if _source(builds.CORE_DIR) != source:
        raise ValueError("source changed during delivery build")
    record = {
        "formatVersion": 1,
        "group": group,
        "profile": "release",
        "source": source,
        "features": builds.DEFAULT_FEATURES.split(","),
        "buildIdentity": builds.EXPECTED_IDENTITY.decode(),
        "host": {
            "os": platform.system(),
            "architecture": architecture,
            "osVersion": platform.release(),
        },
        "toolchain": toolchain,
        "startedUtc": started,
        "finishedUtc": datetime.now(UTC).isoformat(),
        "artifacts": [
            {
                "path": path.relative_to(output).as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha(path),
            }
            for path in sorted(output.rglob("*"))
            if path.is_file()
        ],
    }
    manifest.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    try:
        check_delivery([manifest])
    except Exception:
        manifest.unlink(missing_ok=True)
        raise
    print(manifest)


def check_abi(manifest: Path) -> None:
    """Compile a real C consumer; no replacement library and no protocol servers."""
    check_delivery([manifest])
    record = json.loads(manifest.read_text(encoding="utf-8"))
    group = record["group"]
    root = builds.CORE_DIR
    work = root / "target/platform-delivery/abi" / group
    work.mkdir(parents=True, exist_ok=True)
    source = root / "scripts/fixtures/platform_abi.c"
    binary = work / ("abi.exe" if os.name == "nt" else "abi")
    environment = os.environ.copy()
    if group == "apple" and platform.system() == "Darwin":
        library = manifest.parent / "LibVCore.xcframework/macos-arm64_x86_64/libvcore.a"
        command = [
            "xcrun",
            "clang",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(root / "include"),
            str(source),
            str(library),
            "-lc++",
            "-lresolv",
            "-framework",
            "Security",
            "-framework",
            "SystemConfiguration",
            "-framework",
            "CoreFoundation",
            "-o",
            str(binary),
        ]
        execute = [str(binary)]
        architecture = platform.machine()
    elif group.startswith("windows-") and os.name == "nt":
        architecture = builds._windows_architecture()
        if group != "windows-" + architecture:
            raise ValueError("ABI check cannot substitute emulation for native Windows")
        environment = builds._windows_msvc_environment(architecture)
        command = [
            "cl",
            "/nologo",
            "/std:c11",
            "/W4",
            "/WX",
            "/MT",
            "/I" + str(root / "include"),
            str(source),
            "/Fe:" + str(binary),
            "/Fo:" + str(work / "abi.obj"),
        ]
        execute = [str(binary), str(manifest.parent / "vcore.dll")]
    else:
        raise ValueError(
            "native ABI runner requires a matching macOS or Windows artifact"
        )
    subprocess.run(command, cwd=work, env=environment, check=True, timeout=120)
    subprocess.run(execute, cwd=work, env=environment, check=True, timeout=60)
    if _source(root) != record["source"]:
        raise ValueError("source changed during ABI check")
    evidence = {
        "kind": "native-production-abi",
        "group": group,
        "source": record["source"],
        "manifestSha256": _sha(manifest),
        "architecture": architecture,
        "iterations": 1000,
        "invalidApiRejected": True,
        "finishedUtc": datetime.now(UTC).isoformat(),
    }
    (work / "result.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
