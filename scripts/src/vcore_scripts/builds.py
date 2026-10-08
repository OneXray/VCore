from __future__ import annotations

import hashlib
import json
import locale
import mmap
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[3]
EXPECTED_IDENTITY = b"VCore;engine=rust;coreVersion=0.1.0"
DEFAULT_FEATURES = (
    "ffi,tun,inbound-http,inbound-socks5,outbound-anytls,"
    "outbound-socks5,outbound-shadowsocks,outbound-trojan,outbound-vmess,outbound-vless,"
    "outbound-hysteria2,outbound-tuic,shadow-tls-v3"
)

WINDOWS_FEATURES = DEFAULT_FEATURES + ",windows-uwp"


def tvos_deployment_target() -> str:
    value = _env("VCORE_TVOS_DEPLOYMENT_TARGET", "17.0")
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value) or tuple(
        map(int, value.split("."))
    ) < (17, 0):
        raise ValueError("tvOS deployment target must be 17.0 or newer")
    return value


def _check_apple_load_commands(
    output: str, target_os: str, variant: str | None, architecture: str, minimum: str
) -> int:
    """Check every archive member, including native crypto and Rust std objects."""
    expected = {
        ("macos", None): "1",
        ("ios", None): "2",
        ("tvos", None): "3",
        ("ios", "simulator"): "7",
        ("tvos", "simulator"): "8",
    }[target_os, variant]
    legacy = {"macos": "MACOSX", "ios": "IPHONEOS", "tvos": "TVOS"}[target_os]
    objects = re.split(r"(?m)^\S.*:\n", output)[1:]
    if not objects:
        raise ValueError("Apple artifact contains no Mach-O objects")
    ceiling = tuple((list(map(int, minimum.split("."))) + [0, 0])[:3])
    # These architectures did not exist at the older product deployment floor.
    # Keep iOS 13 for devices and macOS 10.15 for the Intel desktop slice.
    architecture_floor = {
        ("ios", "simulator", "arm64"): (14, 0, 0),
        ("macos", None, "arm64"): (11, 0, 0),
    }.get((target_os, variant, architecture), (0, 0, 0))
    ceiling = max(ceiling, architecture_floor)
    for obj in objects:
        versions = []
        for command in re.split(r"Load command \d+\n", obj):
            fields = dict(
                line.strip().split(maxsplit=1)
                for line in command.splitlines()
                if len(line.strip().split(maxsplit=1)) == 2
            )
            kind = fields.get("cmd", "")
            if kind == "LC_BUILD_VERSION":
                if fields.get("platform") != expected:
                    raise ValueError("wrong Apple Mach-O platform")
                versions.append(fields.get("minos", ""))
            elif kind.startswith("LC_VERSION_MIN_"):
                if kind != "LC_VERSION_MIN_" + legacy or variant == "simulator":
                    raise ValueError("wrong legacy Apple Mach-O platform")
                versions.append(fields.get("version", ""))
        if len(versions) != 1 or not re.fullmatch(r"\d+(?:\.\d+){0,2}", versions[0]):
            raise ValueError("missing or ambiguous Apple deployment version")
        version = tuple((list(map(int, versions[0].split("."))) + [0, 0])[:3])
        if version > ceiling:
            raise ValueError(
                f"Apple {target_os}/{variant}/{architecture} object requires "
                f"{versions[0]}, newer than deployment target {ceiling}"
            )
    return len(objects)


def check_apple_binary(
    path: Path,
    target_os: str,
    variant: str | None,
    architectures: set[str],
    minimum: str,
) -> dict[str, int]:
    actual = set(
        subprocess.check_output(
            ["xcrun", "lipo", "-archs", str(path)], text=True, timeout=60
        ).split()
    )
    if actual != architectures:
        raise ValueError("wrong Apple binary architecture")
    result = {}
    for architecture in sorted(architectures):
        output = subprocess.check_output(
            ["xcrun", "otool", "-l", "-arch", architecture, str(path)],
            text=True,
            timeout=60,
        )
        result[architecture] = _check_apple_load_commands(
            output, target_os, variant, architecture, minimum
        )
    return result


def _env(name: str, default: str | os.PathLike[str]) -> str:
    return os.environ.get(name) or os.fspath(default)


def _cargo_target_dir(env: dict[str, str] | None = None) -> Path:
    """Resolve the output used by Cargo commands executed in this checkout."""
    value = (os.environ if env is None else env).get("CARGO_TARGET_DIR")
    if not value:
        return CORE_DIR / "target"
    directory = Path(value)
    return directory if directory.is_absolute() else CORE_DIR / directory


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


def _production_features(features: str) -> str:
    names = {name.rsplit("/", 1)[-1] for name in re.split(r"[,\s]+", features)}
    if names & {"interop-test", "benchmark-geodata-http"}:
        raise RuntimeError("platform builds cannot enable test-only features")
    return features


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
    _production_features(features)
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


def _android_ndk_home() -> Path:
    """Resolve an explicit NDK path/version or the newest installed stable major."""
    if override := os.environ.get("ANDROID_NDK_HOME"):
        return Path(override).resolve()
    android_home = (
        Path(sdk_home)
        if (sdk_home := os.environ.get("ANDROID_HOME"))
        else Path.home() / "Library" / "Android" / "sdk"
    )
    installed = android_home / "ndk"
    selector = _env("VCORE_ANDROID_NDK_VERSION", "30")
    if not selector.isdigit():
        return (installed / selector).resolve()
    candidates = []
    for path in installed.glob(selector + ".*"):
        properties = path / "source.properties"
        if (
            not path.is_dir()
            or not re.fullmatch(r"\d+\.\d+\.\d+", path.name)
            or not properties.is_file()
        ):
            continue
        revision = re.search(
            r"(?m)^\s*Pkg\.Revision\s*=\s*(\S+)\s*$",
            properties.read_text(encoding="utf-8"),
        )
        # SDK preview directories can have numeric names. Their revision still
        # carries a beta/rc suffix, so use package metadata to reject previews.
        if revision and revision.group(1) == path.name:
            candidates.append((tuple(map(int, path.name.split("."))), path))
    if not candidates:
        raise RuntimeError(f"no installed stable Android NDK for major {selector}")
    return max(candidates, key=lambda candidate: candidate[0])[1].resolve()


def build_android() -> None:
    if os.name == "nt":
        raise RuntimeError("Android artifacts must be built on macOS or Linux")
    ndk_home = _android_ndk_home()
    android_api = _env("VCORE_ANDROID_API", "24")
    profile_name, profile_flags = _profile()
    features = _production_features(_env("VCORE_FEATURES", DEFAULT_FEATURES))
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
        cpp = toolchain / "bin" / (clang + "++")
        archive = toolchain / "bin" / "llvm-ar"
        if not linker.is_file():
            raise RuntimeError(f"Android linker not found: {linker}")
        if not archive.is_file():
            raise RuntimeError(f"Android archiver not found: {archive}")
        if not cpp.is_file():
            raise RuntimeError(f"Android C++ compiler not found: {cpp}")
        runtime_target = (
            "arm-linux-androideabi" if target == "armv7-linux-androideabi" else target
        )
        cpp_runtime = (
            toolchain / "sysroot/usr/lib" / runtime_target / "libc++_shared.so"
        )
        if not cpp_runtime.is_file():
            raise RuntimeError(f"Android C++ runtime not found: {cpp_runtime}")
        target_env = target.replace("-", "_")
        bindgen_key = f"BINDGEN_EXTRA_CLANG_ARGS_{target}"
        bindgen_extra = base_env.get(
            bindgen_key,
            base_env.get(
                f"BINDGEN_EXTRA_CLANG_ARGS_{target_env}",
                base_env.get("BINDGEN_EXTRA_CLANG_ARGS", ""),
            ),
        )
        env = base_env | {
            f"CC_{target_env}": str(linker),
            f"CXX_{target_env}": str(cpp),
            f"AR_{target_env}": str(archive),
            f"CARGO_TARGET_{cargo_name}_LINKER": str(linker),
            f"CARGO_TARGET_{cargo_name}_AR": str(archive),
            f"CMAKE_TOOLCHAIN_FILE_{target_env}": str(
                CORE_DIR / "scripts/cmake/android.toolchain.cmake"
            ),
            "VCORE_CMAKE_ANDROID_ABI": abi,
            "VCORE_CMAKE_ANDROID_API": android_api,
            # NDK 30 rejects bindgen's default unversioned Rust target. Use
            # the same API-qualified compiler triple as CC/CXX and CMake.
            bindgen_key: (
                f"--target={clang.removesuffix('-clang')} {bindgen_extra}"
            ).strip(),
        }
        _cargo_build(target, profile_flags, features, env)
        artifact = _cargo_target_dir(env) / target / profile_name / "libvcore.so"
        _require_identity(artifact, "Android")
        destination = output / abi / "libvcore.so"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact, destination)
        # BoringSSL links the NDK shared C++ runtime. It is not supplied by
        # Android itself; distribute the matching ABI/runtime alongside VCore.
        shutil.copy2(cpp_runtime, destination.parent / cpp_runtime.name)

    print(output)


def build_apple() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("Apple artifacts must be built on macOS")
    dist = Path(_env("VCORE_APPLE_DIST_DIR", CORE_DIR / "dist" / "apple")).resolve()
    work = _cargo_target_dir() / "vcore-apple"
    profile_name, profile_flags = _profile()
    features = _production_features(_env("VCORE_FEATURES", DEFAULT_FEATURES))
    targets = [
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "aarch64-apple-tvos",
        "aarch64-apple-tvos-sim",
    ]
    _require_targets(targets)

    env = os.environ.copy()
    env["IPHONEOS_DEPLOYMENT_TARGET"] = _env("VCORE_IOS_DEPLOYMENT_TARGET", "13.0")
    env["MACOSX_DEPLOYMENT_TARGET"] = _env("VCORE_MACOS_DEPLOYMENT_TARGET", "10.15")
    env["TVOS_DEPLOYMENT_TARGET"] = tvos_deployment_target()
    if profile_name == "release":
        env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"

    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(dist / "LibVCore.xcframework", ignore_errors=True)
    for directory in (
        "ios-device",
        "ios-simulator",
        "macos",
        "tvos-device",
        "tvos-simulator",
    ):
        (work / directory).mkdir(parents=True)
    dist.mkdir(parents=True, exist_ok=True)

    for target in targets:
        _cargo_build(target, profile_flags, features, env)
    artifacts = {
        target: _cargo_target_dir(env) / target / profile_name / "libvcore.a"
        for target in targets
    }
    for artifact in artifacts.values():
        _require_identity(artifact, "Apple")

    shutil.copy2(artifacts["aarch64-apple-ios"], work / "ios-device/libvcore.a")
    shutil.copy2(artifacts["aarch64-apple-ios-sim"], work / "ios-simulator/libvcore.a")
    shutil.copy2(artifacts["aarch64-apple-tvos"], work / "tvos-device/libvcore.a")
    shutil.copy2(
        artifacts["aarch64-apple-tvos-sim"], work / "tvos-simulator/libvcore.a"
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
    for directory, target_os, variant, architectures, minimum in (
        ("ios-device", "ios", None, {"arm64"}, env["IPHONEOS_DEPLOYMENT_TARGET"]),
        (
            "ios-simulator",
            "ios",
            "simulator",
            {"arm64"},
            env["IPHONEOS_DEPLOYMENT_TARGET"],
        ),
        ("macos", "macos", None, {"arm64", "x86_64"}, env["MACOSX_DEPLOYMENT_TARGET"]),
        ("tvos-device", "tvos", None, {"arm64"}, env["TVOS_DEPLOYMENT_TARGET"]),
        (
            "tvos-simulator",
            "tvos",
            "simulator",
            {"arm64"},
            env["TVOS_DEPLOYMENT_TARGET"],
        ),
    ):
        check_apple_binary(
            work / directory / "libvcore.a", target_os, variant, architectures, minimum
        )
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
            "-library",
            work / "tvos-device/libvcore.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "tvos-simulator/libvcore.a",
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
    if architecture == "arm64":
        search_path = next(value for key, value in env.items() if key.upper() == "PATH")
        compilers = {
            name: shutil.which(name, path=search_path)
            for name in ("clang-cl", "clang", "ninja")
        }
        if not all(compilers.values()):
            raise RuntimeError(
                "native Windows ARM64 requires LLVM clang-cl/clang and Ninja"
            )
        # Visual Studio's generator does not assemble BoringSSL's preprocessed
        # .S inputs. Keep assembly enabled using LLVM + Ninja, still MSVC ABI,
        # the selected Windows SDK, and the same static CRT. No source patch.
        env.update(
            {
                "CC_aarch64_pc_windows_msvc": compilers["clang-cl"],
                "CXX_aarch64_pc_windows_msvc": compilers["clang-cl"],
                "VCORE_WINDOWS_ARM64_CLANG": compilers["clang"],
                "CMAKE_GENERATOR_aarch64_pc_windows_msvc": "Ninja",
                "CMAKE_TOOLCHAIN_FILE_aarch64_pc_windows_msvc": str(
                    CORE_DIR / "scripts/cmake/windows-arm64.toolchain.cmake"
                ),
            }
        )
    return env


def check_windows_wintun_cli() -> None:
    """Typecheck the other native Windows backend without staging artifacts."""
    if os.name != "nt":
        raise RuntimeError("Windows Wintun CLI must be checked on Windows")
    architecture = _windows_architecture()
    target = {
        "arm64": "aarch64-pc-windows-msvc",
        "x64": "x86_64-pc-windows-msvc",
    }[architecture]
    env = _windows_msvc_environment(architecture)
    _run(
        [
            "cargo",
            "check",
            "--locked",
            "--release",
            "--target",
            target,
            "--no-default-features",
            "--features",
            "cli,windows-wintun",
            "--lib",
            "--bin",
            "vcore",
        ],
        env=env,
    )


def build_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows artifacts must be built on Windows")
    _production_features(_env("VCORE_FEATURES", DEFAULT_FEATURES))
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
        WINDOWS_FEATURES,
    ]
    _run([*base, "--lib", "--bins"], env=env)

    release = _cargo_target_dir(env) / target / "release"
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
