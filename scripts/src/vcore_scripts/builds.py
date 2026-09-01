from __future__ import annotations

import hashlib
import json
import locale
import mmap
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[3]
EXPECTED_IDENTITY = (
    b"VCore;engine=rust;coreVersion=0.1.0;invokeApiVersion=5;configVersion=13"
)
DEFAULT_FEATURES = "ffi,tun,inbound-http,outbound-vless"


def _env(name: str, default: str | os.PathLike[str]) -> str:
    return os.environ.get(name) or os.fspath(default)


def _run(
    command: list[str | os.PathLike[str]], *, env: dict[str, str] | None = None
) -> None:
    subprocess.run(command, cwd=CORE_DIR, env=env, check=True)


def _profile() -> tuple[str, list[str]]:
    profile = _env("VCORE_BUILD_PROFILE", "release")
    if profile == "release":
        return profile, ["--release"]
    if profile == "debug":
        return profile, []
    raise RuntimeError(f"unsupported VCORE_BUILD_PROFILE: {profile}")


def _installed_rust_targets() -> set[str]:
    result = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return set(result.stdout.splitlines())


def _require_targets(targets: list[str]) -> None:
    installed = _installed_rust_targets()
    missing = [target for target in targets if target not in installed]
    if missing:
        raise RuntimeError(f"Rust target is not installed: {', '.join(missing)}")


def _cargo_build(
    target: str,
    profile_flags: list[str],
    features: str,
    env: dict[str, str],
) -> None:
    _run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(CORE_DIR / "Cargo.toml"),
            "--locked",
            "--target",
            target,
            *profile_flags,
            "--no-default-features",
            "--features",
            features,
        ],
        env=env,
    )


def _require_windows_architecture(artifact: Path, architecture: str) -> None:
    with artifact.open("rb") as file:
        if file.read(2) != b"MZ":
            raise RuntimeError(f"invalid Windows PE artifact: {artifact}")
        file.seek(0x3C)
        offset = file.read(4)
        if len(offset) != 4:
            raise RuntimeError(f"invalid Windows PE artifact: {artifact}")
        file.seek(int.from_bytes(offset, "little"))
        if file.read(4) != b"PE\0\0":
            raise RuntimeError(f"invalid Windows PE artifact: {artifact}")
        machine = file.read(2)
        if len(machine) != 2:
            raise RuntimeError(f"invalid Windows PE artifact: {artifact}")
    expected = {"arm64": 0xAA64, "x64": 0x8664}[architecture]
    if int.from_bytes(machine, "little") != expected:
        raise RuntimeError(f"VCore Windows artifact has wrong architecture: {artifact}")


def _require_identity(artifact: Path, platform_name: str) -> None:
    found = False
    if artifact.stat().st_size:
        with (
            artifact.open("rb") as file,
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as contents,
        ):
            found = contents.find(EXPECTED_IDENTITY) >= 0
    if not found:
        raise RuntimeError(
            f"VCore {platform_name} artifact has a missing or incompatible "
            f"Rust identity: {artifact}"
        )


def _android_target(target: str, api: str) -> tuple[str, str, str]:
    targets = {
        "aarch64-linux-android": (
            "arm64-v8a",
            f"aarch64-linux-android{api}-clang",
            "AARCH64_LINUX_ANDROID",
        ),
        "x86_64-linux-android": (
            "x86_64",
            f"x86_64-linux-android{api}-clang",
            "X86_64_LINUX_ANDROID",
        ),
        "armv7-linux-androideabi": (
            "armeabi-v7a",
            f"armv7a-linux-androideabi{api}-clang",
            "ARMV7_LINUX_ANDROIDEABI",
        ),
    }
    try:
        return targets[target]
    except KeyError as error:
        raise RuntimeError(f"unsupported Android Rust target: {target}") from error


def _android_toolchain(ndk_home: Path) -> Path:
    host_os = platform.system().lower()
    host_arch = platform.machine().lower()
    aliases = {
        "aarch64": "arm64",
        "amd64": "x86_64",
        "x86-64": "x86_64",
    }
    host_arch = aliases.get(host_arch, host_arch)
    prebuilt = ndk_home / "toolchains" / "llvm" / "prebuilt"
    for tag in dict.fromkeys(
        [f"{host_os}-{host_arch}", f"{host_os}-x86_64", f"{host_os}-arm64"]
    ):
        candidate = prebuilt / tag
        if candidate.is_dir():
            return candidate
    raise RuntimeError(f"Android NDK toolchain not found under {ndk_home}")


def build_android() -> None:
    if os.name == "nt":
        raise RuntimeError("Android artifacts must be built on macOS or Linux")
    android_home = Path(
        _env("ANDROID_HOME", Path.home() / "Library" / "Android" / "sdk")
    )
    ndk_version = _env("VCORE_ANDROID_NDK_VERSION", "28.2.13676358")
    ndk_home = Path(
        _env("ANDROID_NDK_HOME", android_home / "ndk" / ndk_version)
    ).resolve()
    android_api = _env("VCORE_ANDROID_API", "24")
    profile_name, profile_flags = _profile()
    features = _env("VCORE_FEATURES", DEFAULT_FEATURES)
    targets = _env(
        "VCORE_ANDROID_TARGETS", "aarch64-linux-android x86_64-linux-android"
    ).split()
    if not targets:
        raise RuntimeError("VCORE_ANDROID_TARGETS must not be empty")
    output = Path(
        _env("VCORE_ANDROID_OUTPUT_DIR", CORE_DIR / "dist" / "android")
    ).resolve()
    toolchain = _android_toolchain(ndk_home)
    _require_targets(targets)

    base_env = os.environ.copy()
    base_env.update(
        {
            "ANDROID_NDK_HOME": str(ndk_home),
            "ANDROID_NDK_ROOT": str(ndk_home),
            "ANDROID_NDK": str(ndk_home),
        }
    )
    if profile_name == "release":
        base_env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"

    for target in targets:
        abi, clang, cargo_name = _android_target(target, android_api)
        linker = toolchain / "bin" / clang
        archive = toolchain / "bin" / "llvm-ar"
        if not linker.is_file():
            raise RuntimeError(f"Android linker not found: {linker}")
        if not archive.is_file():
            raise RuntimeError(f"Android archiver not found: {archive}")
        target_env = target.replace("-", "_")
        env = base_env | {
            f"CC_{target_env}": str(linker),
            f"AR_{target_env}": str(archive),
            f"CARGO_TARGET_{cargo_name}_LINKER": str(linker),
            f"CARGO_TARGET_{cargo_name}_AR": str(archive),
        }
        _cargo_build(target, profile_flags, features, env)
        artifact = CORE_DIR / "target" / target / profile_name / "libvcore.so"
        _require_identity(artifact, "Android")
        destination = output / abi / "libvcore.so"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact, destination)

    print(output)


def build_apple() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("Apple artifacts must be built on macOS")
    dist = Path(_env("VCORE_APPLE_DIST_DIR", CORE_DIR / "dist" / "apple")).resolve()
    work = CORE_DIR / "target" / "vcore-apple"
    profile_name, profile_flags = _profile()
    features = _env("VCORE_FEATURES", DEFAULT_FEATURES)
    targets = [
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "x86_64-apple-ios",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ]
    _require_targets(targets)

    env = os.environ.copy()
    env["IPHONEOS_DEPLOYMENT_TARGET"] = _env("VCORE_IOS_DEPLOYMENT_TARGET", "13.0")
    env["MACOSX_DEPLOYMENT_TARGET"] = _env("VCORE_MACOS_DEPLOYMENT_TARGET", "10.15")
    if profile_name == "release":
        env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"

    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(dist / "LibVCore.xcframework", ignore_errors=True)
    for directory in ("ios-device", "ios-simulator", "macos"):
        (work / directory).mkdir(parents=True)
    dist.mkdir(parents=True, exist_ok=True)

    for target in targets:
        _cargo_build(target, profile_flags, features, env)
    artifacts = {
        target: CORE_DIR / "target" / target / profile_name / "libvcore.a"
        for target in targets
    }
    for artifact in artifacts.values():
        _require_identity(artifact, "Apple")

    shutil.copy2(artifacts["aarch64-apple-ios"], work / "ios-device/libvcore.a")
    _run(
        [
            "xcrun",
            "lipo",
            "-create",
            artifacts["aarch64-apple-ios-sim"],
            artifacts["x86_64-apple-ios"],
            "-output",
            work / "ios-simulator/libvcore.a",
        ],
        env=env,
    )
    _run(
        [
            "xcrun",
            "lipo",
            "-create",
            artifacts["aarch64-apple-darwin"],
            artifacts["x86_64-apple-darwin"],
            "-output",
            work / "macos/libvcore.a",
        ],
        env=env,
    )
    output = dist / "LibVCore.xcframework"
    _run(
        [
            "xcodebuild",
            "-create-xcframework",
            "-library",
            work / "ios-device/libvcore.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "ios-simulator/libvcore.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "macos/libvcore.a",
            "-headers",
            CORE_DIR / "include",
            "-output",
            output,
        ],
        env=env,
    )
    print(output)


def _windows_architecture() -> str:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    ) as key:
        processor = str(winreg.QueryValueEx(key, "PROCESSOR_ARCHITECTURE")[0]).lower()
    try:
        return {"amd64": "x64", "arm64": "arm64"}[processor]
    except KeyError as error:
        raise RuntimeError(
            f"unsupported native Windows processor architecture: {processor}"
        ) from error


def _windows_msvc_environment(architecture: str) -> dict[str, str]:
    program_files = os.environ.get("PROGRAMFILES(X86)")
    if not program_files:
        raise RuntimeError("ProgramFiles(x86) is unavailable")
    vswhere = (
        Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    )
    result = subprocess.run(
        [
            vswhere,
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-find",
            r"VC\Auxiliary\Build\vcvarsall.bat",
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    vcvars = next((line.strip() for line in result.stdout.splitlines() if line), None)
    if not vcvars:
        raise RuntimeError("Visual Studio C++ tools were not found")
    vc_target = "amd64_arm64" if architecture == "arm64" else "amd64"
    with tempfile.TemporaryDirectory(prefix="vcore-msvc-") as directory:
        command = Path(directory) / "environment.cmd"
        command.write_bytes(
            (
                "@echo off\r\n"
                f'call "{vcvars}" {vc_target} >nul\r\n'
                "if errorlevel 1 exit /b %errorlevel%\r\n"
                "set\r\n"
            ).encode(locale.getpreferredencoding(False))
        )
        configured = subprocess.run(
            [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", command],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
    env = {}
    for line in configured.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            env[key] = value
    return env


def build_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows artifacts must be built on Windows")
    architecture = _windows_architecture()
    output = CORE_DIR / "dist" / "windows" / architecture
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    targets = {
        "arm64": "aarch64-pc-windows-msvc",
        "x64": "x86_64-pc-windows-msvc",
    }
    target = targets[architecture]
    env = _windows_msvc_environment(architecture)
    _run(["cargo", "fmt", "--all", "--", "--check"], env=env)
    base = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "--target",
        target,
        "--no-default-features",
        "--features",
        "ffi",
    ]
    _run([*base, "--lib", "--bins"], env=env)

    release = CORE_DIR / "target" / target / "release"
    artifacts = [
        "vcore.dll",
        "vcore-windows-vpn-host.exe",
        "vcore-windows-session-host.exe",
    ]
    for name in artifacts:
        _require_windows_architecture(release / name, architecture)
    _require_identity(release / "vcore.dll", "Windows")
    for name in artifacts:
        shutil.copy2(release / name, output / name)
    digests = {}
    for name in artifacts:
        artifact = output / name
        with artifact.open("rb") as file:
            digests[name] = hashlib.file_digest(file, "sha256").hexdigest()
        print(f"{digests[name]}  {artifact}")
    (output / "vcore-windows-artifacts.json").write_text(
        json.dumps(
            {
                "formatVersion": 1,
                "windowsPackageIntegrationRevision": 3,
                "architecture": architecture,
                "buildIdentity": EXPECTED_IDENTITY.decode("ascii"),
                "artifacts": digests,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
