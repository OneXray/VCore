"""Production build evidence. This is not device or signed-release acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import plistlib
import shutil
import stat
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from . import builds

GROUPS = {"apple", "android", "linux-arm64", "linux-x64"} | {
    f"windows-{architecture}-{backend}"
    for architecture in ("arm64", "x64")
    for backend in builds.WINDOWS_BACKENDS
}
APPLE_LIBRARIES = {
    "ios-arm64": ("ios", None, {"arm64"}),
    "ios-arm64-simulator": ("ios", "simulator", {"arm64"}),
    "macos-arm64_x86_64": ("macos", None, {"arm64", "x86_64"}),
    "tvos-arm64": ("tvos", None, {"arm64"}),
    "tvos-arm64-simulator": ("tvos", "simulator", {"arm64"}),
}


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _output(argv: list[str], root: Path) -> str:
    return subprocess.check_output(argv, cwd=root, text=True, timeout=60).strip()


def _source(root: Path) -> dict:
    if _output(["git", "status", "--porcelain", "--untracked-files=normal"], root):
        raise ValueError("delivery requires a clean committed source checkout")
    source = {
        "commit": _output(["git", "rev-parse", "HEAD"], root),
        "tree": _output(["git", "rev-parse", "HEAD^{tree}"], root),
        "lockSha256": _sha(root / "Cargo.lock"),
    }
    # Local development uses the sibling fork. A lock hash alone cannot identify
    # its code; PR/release builds switch back to the locked Git release branch.
    manifest = root / "Cargo.toml"
    if manifest.exists():
        dependency = tomllib.loads(manifest.read_text())["dependencies"].get(
            "boring", {}
        )
        if "path" in dependency:
            fork = (root / dependency["path"]).resolve()
            if _output(
                ["git", "status", "--porcelain", "--untracked-files=normal"], fork
            ):
                raise ValueError(
                    "artifact evidence requires a clean local boring checkout"
                )
            source["localBoring"] = {
                "commit": _output(["git", "rev-parse", "HEAD"], fork),
                "tree": _output(["git", "rev-parse", "HEAD^{tree}"], fork),
            }
    return source


def _check_delivery(manifests: list[Path]) -> None:
    """Check newly built files before retaining their delivery manifest."""
    source = _source(builds.CORE_DIR)
    groups = set()
    if not manifests:
        raise ValueError("empty manifest set cannot pass")
    for manifest in manifests:
        record = json.loads(manifest.read_text(encoding="utf-8"))
        group = record.get("group")
        if group not in GROUPS or group in groups:
            raise ValueError("duplicate or unsupported delivery group")
        backend = record.get("backend")
        if group.startswith("windows-"):
            if backend not in builds.WINDOWS_BACKENDS or not group.endswith(
                "-" + backend
            ):
                raise ValueError("incompatible Windows backend identity")
            features = builds.windows_features(backend)
        else:
            if backend is not None:
                raise ValueError("unexpected Windows backend metadata")
            features = builds.DEFAULT_FEATURES
        if (
            record.get("formatVersion") != 1
            or record.get("profile") != "release"
            or record.get("features") != features.split(",")
            or record.get("buildIdentity") != builds.EXPECTED_IDENTITY.decode()
        ):
            raise ValueError("incompatible production artifact metadata")
        if record.get("source") != source:
            raise ValueError("artifact source/lock identity does not match checkout")
        groups.add(group)
        toolchain = record.get("toolchain", {})
        required = {"rustc", "cargo"} | (
            {"ndk", "clang", "androidApi"}
            if group == "android"
            else {
                "xcode",
                "iphoneos",
                "iphonesimulator",
                "macosx",
                "appletvos",
                "appletvsimulator",
                "iosDeploymentTarget",
                "macosDeploymentTarget",
                "tvosDeploymentTarget",
            }
            if group == "apple"
            else {"cc", "cmake"}
            if group.startswith("linux-")
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
                for name in ("libvole.so", "libc++_shared.so")
            }
            if names != expected:
                raise ValueError("Android delivery requires both ABIs and C++ runtimes")
            for abi, machine in (("arm64-v8a", 183), ("x86_64", 62)):
                for name in ("libvole.so", "libc++_shared.so"):
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
                    if name == "libvole.so":
                        builds._require_identity(path, "Android")
        elif group == "apple":
            expected = {"LibVole.xcframework/Info.plist"} | {
                f"LibVole.xcframework/{identifier}/{name}"
                for identifier in APPLE_LIBRARIES
                for name in (
                    "libvole.a",
                    "Headers/vole.h",
                    "Headers/module.modulemap",
                )
            }
            if names != expected:
                raise ValueError("incomplete Apple XCFramework")
            with (manifest.parent / "LibVole.xcframework/Info.plist").open(
                "rb"
            ) as stream:
                libraries = plistlib.load(stream).get("AvailableLibraries", [])
            if len(libraries) != len(APPLE_LIBRARIES):
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
                    or library.get("LibraryPath") != "libvole.a"
                    or library.get("HeadersPath") != "Headers"
                ):
                    raise ValueError("invalid Apple slice metadata")
                path = (
                    manifest.parent / "LibVole.xcframework" / identifier / "libvole.a"
                )
                minimum = toolchain[target_os + "DeploymentTarget"]
                if target_os == "tvos" and tuple(map(int, minimum.split("."))) < (
                    17,
                    0,
                ):
                    raise ValueError("tvOS artifact must target 17.0 or newer")
                builds.check_apple_binary(
                    path, target_os, variant, architectures, minimum
                )
                builds._require_identity(path, "Apple")
        elif group.startswith("linux-"):
            arch = group.removeprefix("linux-")
            expected = {"libvole.so", "libvole.a", "include/vole.h"}
            if names != expected:
                raise ValueError("incomplete Linux artifact set")
            target = {
                "x64": "x86_64-unknown-linux-gnu",
                "arm64": "aarch64-unknown-linux-gnu",
            }[arch]
            if (
                record.get("target") != target
                or record.get("host", {}).get("os") != "Linux"
                or record["host"].get("architecture") != arch
            ):
                raise ValueError("Linux delivery requires native GNU target evidence")
            for name in ("libvole.so", "libvole.a"):
                path = manifest.parent / name
                builds._require_linux_architecture(path, arch)
                builds._require_identity(path, "Linux")
            if _sha(manifest.parent / "include/vole.h") != _sha(
                builds.CORE_DIR / "include/vole.h"
            ):
                raise ValueError("Linux header does not match source checkout")
        else:
            arch = group.split("-")[1]
            expected = {"vole.dll", "vole.dll.lib"}
            if backend == "uwp":
                expected |= {
                    "vole-windows-vpn-host.exe",
                    "vole-windows-session-host.exe",
                }
            if names != expected | {"vole-windows-artifacts.json"}:
                raise ValueError("incomplete Windows artifact set")
            if (
                record.get("host", {}).get("os") != "Windows"
                or record["host"].get("architecture") != arch
                or record.get("target")
                != {
                    "arm64": "aarch64-pc-windows-msvc",
                    "x64": "x86_64-pc-windows-msvc",
                }[arch]
            ):
                raise ValueError(
                    "Windows delivery requires native OS architecture evidence"
                )
            for name in expected:
                if name.endswith(".lib"):
                    builds._require_windows_import_library(manifest.parent / name, arch)
                else:
                    builds._require_windows_architecture(manifest.parent / name, arch)
            builds._require_identity(manifest.parent / "vole.dll", "Windows")
            package = json.loads(
                (manifest.parent / "vole-windows-artifacts.json").read_text()
            )
            revision_valid = (
                package.get("windowsPackageIntegrationRevision") == 3
                if backend == "uwp"
                else "windowsPackageIntegrationRevision" not in package
            )
            if (
                package.get("formatVersion") != 1
                or package.get("architecture") != arch
                or package.get("backend") != backend
                or not revision_valid
                or package.get("buildIdentity") != record["buildIdentity"]
                or package.get("artifacts")
                != {
                    row["path"]: row["sha256"]
                    for row in rows
                    if row["path"] in expected
                }
            ):
                raise ValueError(
                    "Windows backend/artifact integration identity mismatch"
                )
        print(
            f"PASS {record['group']} artifact integrity (not device/release acceptance)"
        )


def build_delivery(
    platform_name: str,
    *,
    backend: str = "uwp",
    target: str | None = None,
    env: dict[str, str] | None = None,
) -> Path:
    if platform_name not in {"apple", "android", "linux", "windows"}:
        raise ValueError("unsupported delivery platform")
    if platform_name == "windows":
        builds.windows_features(backend)
    elif target is not None and platform_name != "linux":
        raise ValueError("target applies only to Windows or Linux delivery")
    environment = dict(os.environ) | (env or {})
    if environment.get("VOLE_BUILD_PROFILE", "release") != "release":
        raise ValueError("delivery requires the release profile")
    if (
        environment.get("VOLE_FEATURES", builds.DEFAULT_FEATURES)
        != builds.DEFAULT_FEATURES
    ):
        raise ValueError("delivery requires the complete production feature set")
    # Keep the recorded build command honest: existing development builds still
    # allow customization, but acceptance must not inherit hidden overrides.
    overrides = [
        name
        for name in environment
        if (
            name
            in {
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_TARGET_DIR",
                "VOLE_ANDROID_OUTPUT_DIR",
                "VOLE_APPLE_DIST_DIR",
                "VOLE_ANDROID_TARGETS",
            }
            or name.startswith("CARGO_PROFILE_")
        )
        and environment[name]
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
        native = {
            "arm64": "aarch64-pc-windows-msvc",
            "x64": "x86_64-pc-windows-msvc",
        }[architecture]
        target = native if target is None else target
        if target != native:
            raise ValueError("Windows delivery requires the native MSVC Rust target")
        group += "-" + architecture + "-" + backend
        environment = builds._windows_msvc_environment(architecture)
        # Windows env names are case insensitive, even when a subprocess returns
        # a plain Python dict. Never persist the full environment (credentials).
        normalized = {key.upper(): value for key, value in environment.items()}
        toolchain["msvc"] = normalized.get("VCTOOLSVERSION", "").strip()
        toolchain["windowsSdk"] = normalized.get("WINDOWSSDKVERSION", "").strip("\\ ")
        toolchain["cmake"] = _output(["cmake", "--version"], builds.CORE_DIR)
        toolchain["generator"] = "Ninja" if architecture == "arm64" else "Visual Studio"
        if architecture == "arm64":
            toolchain["clang"] = _output(
                [normalized["VOLE_WINDOWS_ARM64_CLANG"], "--version"], builds.CORE_DIR
            )
            toolchain["assembly"] = "enabled"
    elif platform_name == "linux":
        if platform.system() != "Linux":
            raise ValueError("Linux delivery must run on native Linux")
        native = builds.native_target()
        target = native if target is None else target
        if target != native:
            raise ValueError("Linux delivery requires the native GNU Rust target")
        architecture = builds.CLI_TARGETS[target][1]
        group += "-" + architecture
        toolchain["cc"] = _output(["cc", "--version"], builds.CORE_DIR)
        toolchain["cmake"] = _output(["cmake", "--version"], builds.CORE_DIR)
    elif platform_name == "apple":
        toolchain["xcode"] = _output(["xcodebuild", "-version"], builds.CORE_DIR)
        for sdk in (
            "iphoneos",
            "iphonesimulator",
            "macosx",
            "appletvos",
            "appletvsimulator",
        ):
            toolchain[sdk] = _output(
                ["xcrun", "--sdk", sdk, "--show-sdk-version"], builds.CORE_DIR
            )
        toolchain["iosDeploymentTarget"] = os.environ.get(
            "VOLE_IOS_DEPLOYMENT_TARGET", "13.0"
        )
        toolchain["macosDeploymentTarget"] = os.environ.get(
            "VOLE_MACOS_DEPLOYMENT_TARGET", "10.15"
        )
        toolchain["tvosDeploymentTarget"] = builds.tvos_deployment_target()
    else:
        ndk = builds._android_ndk_home()
        toolchain["ndk"] = (ndk / "source.properties").read_text().strip()
        toolchain["clang"] = _output(
            [str(builds._android_toolchain(ndk) / "bin/clang"), "--version"],
            builds.CORE_DIR,
        )
        toolchain["androidApi"] = os.environ.get("VOLE_ANDROID_API", "24")
    output = builds.CORE_DIR / "dist" / platform_name
    if platform_name == "windows":
        output = output / architecture / backend
    elif platform_name == "linux":
        output /= architecture
    # Check the lexical path before resolving, unlinking a manifest, or letting
    # a builder clean output. CORE_DIR is the canonical, trusted checkout root;
    # Windows junctions and other reparse points can redirect descendants too.
    current = builds.CORE_DIR
    for part in output.relative_to(builds.CORE_DIR).parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError(
                "delivery output must not contain symlinks or reparse points"
            )
    manifest = output / "vole-delivery.json"
    if platform_name == "android":
        # Development builds can leave additional ABIs in the same ignored
        # directory. Never mix those artifacts into a fresh delivery manifest.
        if output.exists():
            shutil.rmtree(output)
    else:
        manifest.unlink(missing_ok=True)
    started = datetime.now(UTC).isoformat()
    build_environment = {"env": env} if env is not None else {}
    if platform_name == "windows":
        builds.build_windows(backend=backend, **build_environment)
    elif platform_name == "linux":
        builds.build_linux(target=target, **build_environment)
    else:
        {"apple": builds.build_apple, "android": builds.build_android}[platform_name](
            **build_environment
        )
    if _source(builds.CORE_DIR) != source:
        raise ValueError("source changed during delivery build")
    record = {
        "formatVersion": 1,
        "group": group,
        "profile": "release",
        "source": source,
        "features": (
            builds.windows_features(backend)
            if platform_name == "windows"
            else builds.DEFAULT_FEATURES
        ).split(","),
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
    if platform_name == "windows":
        record["backend"] = backend
    if platform_name in {"linux", "windows"}:
        record["target"] = target
    manifest.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    try:
        _check_delivery([manifest])
    except Exception:
        manifest.unlink(missing_ok=True)
        raise
    print(manifest)

    return manifest
