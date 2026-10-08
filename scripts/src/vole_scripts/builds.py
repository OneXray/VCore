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
import tomllib
from collections.abc import Iterator
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[3]
EXPECTED_IDENTITY = (
    "Vole;engine=rust;coreVersion="
    + tomllib.loads((CORE_DIR / "Cargo.toml").read_text(encoding="utf-8"))["package"][
        "version"
    ]
).encode("ascii")
DEFAULT_FEATURES = (
    "ffi,tun,inbound-http,inbound-socks5,outbound-anytls,"
    "outbound-socks5,outbound-shadowsocks,outbound-trojan,outbound-vmess,outbound-vless,"
    "outbound-hysteria2,outbound-tuic,shadow-tls-v3"
)

WINDOWS_FEATURES = DEFAULT_FEATURES + ",windows-uwp"
WINDOWS_BACKENDS = {"wintun", "uwp"}
CLI_TARGETS = {
    "x86_64-unknown-linux-gnu": ("Linux", "x64"),
    "aarch64-unknown-linux-gnu": ("Linux", "arm64"),
    "x86_64-apple-darwin": ("Darwin", "x64"),
    "aarch64-apple-darwin": ("Darwin", "arm64"),
    "x86_64-pc-windows-msvc": ("Windows", "x64"),
    "aarch64-pc-windows-msvc": ("Windows", "arm64"),
}


def windows_features(backend: str = "uwp") -> str:
    if backend not in WINDOWS_BACKENDS:
        raise ValueError("Windows backend must be wintun or uwp")
    return DEFAULT_FEATURES + ",windows-" + backend


def native_target() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    architecture = (
        _windows_architecture()
        if system == "Windows"
        else {
            "x86_64": "x64",
            "amd64": "x64",
            "aarch64": "arm64",
            "arm64": "arm64",
        }.get(machine)
    )
    for target, identity in CLI_TARGETS.items():
        if identity == (system, architecture):
            return target
    raise RuntimeError("unsupported native build platform or architecture")


def cli_features(target: str) -> str:
    if target not in CLI_TARGETS:
        raise ValueError("unsupported CLI Rust target")
    if CLI_TARGETS[target][0] == "Windows":
        return "cli,windows-wintun"
    return "cli"


def tvos_deployment_target() -> str:
    value = _env("VOLE_TVOS_DEPLOYMENT_TARGET", "17.0")
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
    profile = _env("VOLE_BUILD_PROFILE", "release")
    if profile == "release":
        return profile, ["--release"]
    if profile == "debug":
        return profile, []
    raise RuntimeError(f"unsupported VOLE_BUILD_PROFILE: {profile}")


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
        raise RuntimeError(f"Vole Windows artifact has wrong architecture: {artifact}")


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
            f"Vole {platform_name} artifact has a missing or incompatible "
            f"Rust identity: {artifact}"
        )


def _archive_object_headers(artifact: Path) -> Iterator[bytes]:
    """Read bounded object prefixes, accepting normal GNU/LLVM/BSD ar names."""
    total = artifact.stat().st_size
    with artifact.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise RuntimeError(f"invalid object archive: {artifact}")
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b"`\n":
                raise RuntimeError(f"invalid archive member: {artifact}")
            try:
                size = int(header[48:58])
            except ValueError as error:
                raise RuntimeError(
                    f"invalid archive member size: {artifact}"
                ) from error
            if size < 0:
                raise RuntimeError(f"invalid archive member size: {artifact}")
            start = stream.tell()
            end = start + size + size % 2
            if end > total:
                raise RuntimeError(f"truncated object archive: {artifact}")
            name = header[:16].strip()
            if name not in {b"/", b"//", b"/SYM64/", b"__.SYMDEF/"}:
                if name.startswith(b"#1/"):
                    try:
                        length = int(name[3:])
                    except ValueError as error:
                        raise RuntimeError("invalid archive member name") from error
                    if not 0 <= length <= size:
                        raise RuntimeError("invalid archive member name")
                    stream.seek(length, 1)
                yield stream.read(min(20, start + size - stream.tell()))
            stream.seek(end)


def _require_linux_architecture(artifact: Path, architecture: str) -> None:
    expected = {"x64": 62, "arm64": 183}[architecture]

    def check(header: bytes) -> None:
        if (
            len(header) < 20
            or header[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(header[18:20], "little") != expected
        ):
            raise RuntimeError(f"invalid Linux artifact architecture: {artifact}")

    if artifact.suffix != ".a":
        with artifact.open("rb") as stream:
            header = stream.read(20)
        check(header)
        if int.from_bytes(header[16:18], "little") not in {2, 3}:
            raise RuntimeError(f"invalid Linux executable/shared library: {artifact}")
        return
    objects = 0
    for header in _archive_object_headers(artifact):
        check(header)
        if int.from_bytes(header[16:18], "little") != 1:
            raise RuntimeError(f"invalid Linux archive object type: {artifact}")
        objects += 1
    if not objects:
        raise RuntimeError(f"Linux static archive contains no objects: {artifact}")


def _require_windows_import_library(artifact: Path, architecture: str) -> None:
    expected = {"arm64": 0xAA64, "x64": 0x8664}[architecture]
    objects = 0
    for header in _archive_object_headers(artifact):
        if len(header) < 20:
            raise RuntimeError(f"invalid Windows import library object: {artifact}")
        offset = 6 if header[:4] == b"\x00\x00\xff\xff" else 0
        if int.from_bytes(header[offset : offset + 2], "little") != expected:
            raise RuntimeError(
                f"Windows import library has wrong architecture: {artifact}"
            )
        objects += 1
    if not objects:
        raise RuntimeError(f"Windows import library contains no objects: {artifact}")


def build_cli(
    target: str | None = None,
    profile: str = "release",
    *,
    env: dict[str, str] | None = None,
) -> Path:
    target = native_target() if target is None else target
    features = cli_features(target)
    system, architecture = CLI_TARGETS[target]
    if platform.system() != system:
        raise RuntimeError("CLI target must use the build host operating system")
    if profile not in {"debug", "release"}:
        raise ValueError("CLI profile must be debug or release")
    environment = (
        _windows_msvc_environment(architecture)
        if system == "Windows"
        else os.environ.copy()
    ) | (env or {})
    _production_features(environment.get("VOLE_FEATURES", DEFAULT_FEATURES))
    _require_targets([target])
    if system == "Darwin":
        minimum = "11.0" if architecture == "arm64" else "10.15"
        environment.setdefault("MACOSX_DEPLOYMENT_TARGET", minimum)
    _run(
        [
            "cargo",
            "build",
            "--locked",
            "--manifest-path",
            str(CORE_DIR / "Cargo.toml"),
            "--target",
            target,
            *(["--release"] if profile == "release" else []),
            "--no-default-features",
            "--features",
            features,
            "--bin",
            "vole",
        ],
        env=environment,
    )
    artifact = (
        _cargo_target_dir(environment)
        / target
        / profile
        / ("vole.exe" if system == "Windows" else "vole")
    )
    _require_identity(artifact, "CLI")
    if system == "Windows":
        _require_windows_architecture(artifact, architecture)
    elif system == "Linux":
        _require_linux_architecture(artifact, architecture)
    else:
        check_apple_binary(
            artifact,
            "macos",
            None,
            {"arm64" if architecture == "arm64" else "x86_64"},
            minimum,
        )
    print(artifact)
    return artifact


def build_linux(
    target: str | None = None, *, env: dict[str, str] | None = None
) -> Path:
    if platform.system() != "Linux":
        raise RuntimeError("Linux artifacts must be built on native Linux")
    native = native_target()
    target = native if target is None else target
    if target != native:
        raise ValueError("Linux FFI delivery requires the native GNU Rust target")
    architecture = CLI_TARGETS[target][1]
    environment = os.environ.copy() | (env or {})
    _production_features(environment.get("VOLE_FEATURES", DEFAULT_FEATURES))
    _require_targets([target])
    _run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            str(CORE_DIR / "Cargo.toml"),
            "--target",
            target,
            "--no-default-features",
            "--features",
            DEFAULT_FEATURES,
            "--lib",
        ],
        env=environment,
    )
    release = _cargo_target_dir(environment) / target / "release"
    for name in ("libvole.so", "libvole.a"):
        _require_linux_architecture(release / name, architecture)
        _require_identity(release / name, "Linux")
    output = CORE_DIR / "dist/linux" / architecture
    shutil.rmtree(output, ignore_errors=True)
    (output / "include").mkdir(parents=True)
    for name in ("libvole.so", "libvole.a"):
        shutil.copy2(release / name, output / name)
    shutil.copy2(CORE_DIR / "include/vole.h", output / "include/vole.h")
    print(output)
    return output


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
    selector = _env("VOLE_ANDROID_NDK_VERSION", "30")
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


def build_android(*, env: dict[str, str] | None = None) -> None:
    if os.name == "nt":
        raise RuntimeError("Android artifacts must be built on macOS or Linux")
    ndk_home = _android_ndk_home()
    android_api = _env("VOLE_ANDROID_API", "24")
    profile_name, profile_flags = _profile()
    features = _production_features(_env("VOLE_FEATURES", DEFAULT_FEATURES))
    targets = _env(
        "VOLE_ANDROID_TARGETS", "aarch64-linux-android x86_64-linux-android"
    ).split()
    if not targets:
        raise RuntimeError("VOLE_ANDROID_TARGETS must not be empty")
    output = Path(
        _env("VOLE_ANDROID_OUTPUT_DIR", CORE_DIR / "dist" / "android")
    ).resolve()
    toolchain = _android_toolchain(ndk_home)
    _require_targets(targets)

    base_env = os.environ.copy() | (env or {})
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
            "VOLE_CMAKE_ANDROID_ABI": abi,
            "VOLE_CMAKE_ANDROID_API": android_api,
            # NDK 30 rejects bindgen's default unversioned Rust target. Use
            # the same API-qualified compiler triple as CC/CXX and CMake.
            bindgen_key: (
                f"--target={clang.removesuffix('-clang')} {bindgen_extra}"
            ).strip(),
        }
        _cargo_build(target, profile_flags, features, env)
        artifact = _cargo_target_dir(env) / target / profile_name / "libvole.so"
        _require_identity(artifact, "Android")
        destination = output / abi / "libvole.so"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact, destination)
        # BoringSSL links the NDK shared C++ runtime. It is not supplied by
        # Android itself; distribute the matching ABI/runtime alongside Vole.
        shutil.copy2(cpp_runtime, destination.parent / cpp_runtime.name)

    print(output)


def build_apple(*, env: dict[str, str] | None = None) -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("Apple artifacts must be built on macOS")
    dist = Path(_env("VOLE_APPLE_DIST_DIR", CORE_DIR / "dist" / "apple")).resolve()
    work = _cargo_target_dir() / "vole-apple"
    profile_name, profile_flags = _profile()
    features = _production_features(_env("VOLE_FEATURES", DEFAULT_FEATURES))
    targets = [
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "aarch64-apple-tvos",
        "aarch64-apple-tvos-sim",
    ]
    _require_targets(targets)

    env = os.environ.copy() | (env or {})
    env["IPHONEOS_DEPLOYMENT_TARGET"] = _env("VOLE_IOS_DEPLOYMENT_TARGET", "13.0")
    env["MACOSX_DEPLOYMENT_TARGET"] = _env("VOLE_MACOS_DEPLOYMENT_TARGET", "10.15")
    env["TVOS_DEPLOYMENT_TARGET"] = tvos_deployment_target()
    if profile_name == "release":
        env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"

    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(dist / "LibVole.xcframework", ignore_errors=True)
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
        target: _cargo_target_dir(env) / target / profile_name / "libvole.a"
        for target in targets
    }
    for artifact in artifacts.values():
        _require_identity(artifact, "Apple")

    shutil.copy2(artifacts["aarch64-apple-ios"], work / "ios-device/libvole.a")
    shutil.copy2(artifacts["aarch64-apple-ios-sim"], work / "ios-simulator/libvole.a")
    shutil.copy2(artifacts["aarch64-apple-tvos"], work / "tvos-device/libvole.a")
    shutil.copy2(artifacts["aarch64-apple-tvos-sim"], work / "tvos-simulator/libvole.a")
    _run(
        [
            "xcrun",
            "lipo",
            "-create",
            artifacts["aarch64-apple-darwin"],
            artifacts["x86_64-apple-darwin"],
            "-output",
            work / "macos/libvole.a",
        ],
        env=env,
    )
    output = dist / "LibVole.xcframework"
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
            work / directory / "libvole.a", target_os, variant, architectures, minimum
        )
    _run(
        [
            "xcodebuild",
            "-create-xcframework",
            "-library",
            work / "ios-device/libvole.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "ios-simulator/libvole.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "macos/libvole.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "tvos-device/libvole.a",
            "-headers",
            CORE_DIR / "include",
            "-library",
            work / "tvos-simulator/libvole.a",
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
    with tempfile.TemporaryDirectory(prefix="vole-msvc-") as directory:
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
                "VOLE_WINDOWS_ARM64_CLANG": compilers["clang"],
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
            "vole",
        ],
        env=env,
    )


def build_windows(backend: str = "uwp", *, env: dict[str, str] | None = None) -> Path:
    if os.name != "nt":
        raise RuntimeError("Windows artifacts must be built on Windows")
    features = windows_features(backend)
    architecture = _windows_architecture()
    env = _windows_msvc_environment(architecture) | (env or {})
    _production_features(env.get("VOLE_FEATURES", DEFAULT_FEATURES))
    output = CORE_DIR / "dist" / "windows" / architecture / backend
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    targets = {
        "arm64": "aarch64-pc-windows-msvc",
        "x64": "x86_64-pc-windows-msvc",
    }
    target = targets[architecture]
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
        features,
    ]
    _run([*base, "--lib", *(["--bins"] if backend == "uwp" else [])], env=env)

    release = _cargo_target_dir(env) / target / "release"
    artifacts = ["vole.dll", "vole.dll.lib"]
    if backend == "uwp":
        artifacts += ["vole-windows-vpn-host.exe", "vole-windows-session-host.exe"]
    for name in artifacts:
        if name.endswith(".lib"):
            _require_windows_import_library(release / name, architecture)
        else:
            _require_windows_architecture(release / name, architecture)
    _require_identity(release / "vole.dll", "Windows")
    for name in artifacts:
        shutil.copy2(release / name, output / name)
    digests = {}
    for name in artifacts:
        artifact = output / name
        with artifact.open("rb") as file:
            digests[name] = hashlib.file_digest(file, "sha256").hexdigest()
        print(f"{digests[name]}  {artifact}")
    (output / "vole-windows-artifacts.json").write_text(
        json.dumps(
            {
                "formatVersion": 1,
                **(
                    {"windowsPackageIntegrationRevision": 3} if backend == "uwp" else {}
                ),
                "backend": backend,
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

    return output
