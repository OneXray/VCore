"""Build and package native-library release archives."""

from __future__ import annotations

import json
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from . import builds, cli_release

APPLE_TARGETS = (
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-apple-tvos",
    "aarch64-apple-tvos-sim",
)
ANDROID_TARGETS = ("aarch64-linux-android", "x86_64-linux-android")
LINUX_TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
WINDOWS_TARGETS = ("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")
APPLE_SLICES = (
    "ios-arm64",
    "ios-arm64-simulator",
    "macos-arm64_x86_64",
    "tvos-arm64",
    "tvos-arm64-simulator",
)
_require = cli_release._require


def selection(
    platform_name: str, target: str | None = None, backend: str | None = None
) -> tuple[str, tuple[str, ...]]:
    if platform_name in {"apple", "android"}:
        _require(
            target is None and backend is None,
            "mobile/universal FFI has no target or backend override",
        )
        return (
            platform_name,
            APPLE_TARGETS if platform_name == "apple" else ANDROID_TARGETS,
        )
    allowed = (
        LINUX_TARGETS
        if platform_name == "linux"
        else WINDOWS_TARGETS
        if platform_name == "windows"
        else ()
    )
    _require(target in allowed, "FFI release requires a supported target")
    architecture = "amd64" if target.startswith("x86_64-") else "arm64"
    if platform_name == "windows":
        _require(
            backend in {"wintun", "uwp"}, "Windows FFI requires an explicit backend"
        )
        return f"windows-{backend}-{architecture}", (target,)
    _require(backend is None, "non-Windows FFI has no Windows backend")
    return f"linux-{architecture}", (target,)


def archive_name(key: str) -> str:
    _require(key in RELEASES, "unsupported FFI release identity")
    return f"vole-ffi-{key}" + (".zip" if key.startswith("windows-") else ".tar.gz")


RELEASES = {
    "apple": ("apple", None, None),
    "android": ("android", None, None),
    **{
        f"linux-{'amd64' if target.startswith('x86_64-') else 'arm64'}": (
            "linux",
            target,
            None,
        )
        for target in LINUX_TARGETS
    },
    **{
        f"windows-{backend}-{'amd64' if target.startswith('x86_64-') else 'arm64'}": (
            "windows",
            target,
            backend,
        )
        for target in WINDOWS_TARGETS
        for backend in ("wintun", "uwp")
    },
}


def _android_runtime_notices(ndk: Path) -> bytes:
    properties = (ndk / "source.properties").read_text(encoding="utf-8")
    revision = re.search(r"(?m)^\s*Pkg\.Revision\s*=\s*(\d+\.\d+\.\d+)\s*$", properties)
    _require(revision is not None, "Android release requires an identified stable NDK")
    paths = sorted(path for path in ndk.glob("NOTICE*") if path.is_file())
    _require(bool(paths), "missing Android NDK runtime notices")
    sections = []
    for path in paths:
        content = path.read_bytes()
        _require(
            content and b"\0" not in content, "invalid Android NDK runtime notices"
        )
        content.decode("utf-8")
        sections.append(
            f"\n--- Android NDK {revision[1]}/{path.name} ---\n".encode()
            + content
            + b"\n"
        )
    joined = b"".join(sections)
    _require(
        b"libc++" in joined and (b"LLVM" in joined or b"Apache" in joined),
        "NDK notices must cover the shipped libc++ runtime",
    )
    return joined


def prepare_notices(
    root: Path,
    targets: tuple[str, ...],
    repository: str = "YuanDevTeam/Vole",
    *,
    backend: str | None = None,
    source: dict | None = None,
    android_ndk: Path | None = None,
) -> bytes:
    """Collect notices once from the union of the actual locked target graphs."""
    if source is None:
        source = cli_release._release_info(root, None)
    all_packages, all_linked = {}, set()
    for target in targets:
        features = (
            builds.windows_features(backend)
            if "-windows-" in target
            else builds.DEFAULT_FEATURES
        )
        metadata = json.loads(
            cli_release._output(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--no-default-features",
                    "--features",
                    features,
                    "--filter-platform",
                    target,
                    "--format-version",
                    "1",
                ],
                root,
            )
        )
        packages, nodes, resolved, linked = cli_release._graph(
            metadata, root, target, transport="ffi", backend=backend
        )
        cli_release._audit_graph(packages, nodes, resolved, root)
        all_packages.update(packages)
        all_linked.update(linked)
    text = cli_release.collect_notices(
        all_packages, all_linked, root, source, repository, targets[0]
    )
    text += cli_release.collect_rust_notices(root)
    if android_ndk is not None:
        text += _android_runtime_notices(android_ndk)
    _require(
        0 < len(text) <= cli_release.MAX_NOTICES_BYTES,
        "FFI notice bundle exceeds the embedded text limit",
    )
    return text


def _expected_files(key: str) -> set[str]:
    platform_name, _, backend = RELEASES[key]
    if platform_name == "apple":
        return {"LibVole.xcframework/Info.plist"} | {
            f"LibVole.xcframework/{identifier}/{name}"
            for identifier in APPLE_SLICES
            for name in ("libvole.a", "Headers/vole.h", "Headers/module.modulemap")
        }
    if platform_name == "android":
        return {
            f"{abi}/{name}"
            for abi in ("arm64-v8a", "x86_64")
            for name in ("libvole.so", "libc++_shared.so")
        } | {"include/vole.h"}
    if platform_name == "linux":
        return {"libvole.so", "libvole.a", "include/vole.h"}
    return {"vole.dll", "vole.dll.lib", "include/vole.h"} | (
        {"vole-windows-vpn-host.exe", "vole-windows-session-host.exe"}
        if backend == "uwp"
        else set()
    )


def _write_archive(base: Path, archive: Path) -> None:
    files = sorted(path for path in base.rglob("*") if path.is_file())
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            for path in files:
                stream.write(path, arcname=path.relative_to(base).as_posix())
    else:
        with tarfile.open(archive, "w:gz") as stream:
            for path in files:
                stream.add(
                    path, arcname=path.relative_to(base).as_posix(), recursive=False
                )


def build_release(
    platform_name: str,
    tag: str | None = None,
    repository: str = "YuanDevTeam/Vole",
    *,
    target: str | None = None,
    backend: str | None = None,
    output: Path | None = None,
) -> Path:
    root = builds.CORE_DIR
    key, targets = selection(platform_name, target, backend)
    output = root / "dist/ffi" / key if output is None else root / output
    cli_release._guard_output(root, output)
    raw = root / "dist" / platform_name
    _require(
        not output.resolve().is_relative_to(raw.resolve())
        and not raw.resolve().is_relative_to(output.resolve()),
        "FFI archive output must be separate from platform build output",
    )
    overrides = cli_release._release_overrides()
    _require(
        not overrides,
        "unsupported FFI release build overrides: " + ", ".join(overrides),
    )
    if platform_name == "windows":
        _require(
            target == builds.native_target(),
            "Windows FFI release requires the native target",
        )
    info = cli_release._release_info(root, tag)
    notices = prepare_notices(
        root,
        targets,
        repository,
        backend=backend,
        source=info,
        android_ndk=builds._android_ndk_home() if platform_name == "android" else None,
    )
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="vole-ffi-release-") as directory:
        directory = Path(directory).resolve()
        notice_file = directory / "notices.txt"
        notice_file.write_bytes(notices)
        env = {"VOLE_RELEASE_NOTICES": str(notice_file)}
        if platform_name == "windows":
            built = builds.build_windows(backend=backend, env=env)
        elif platform_name == "linux":
            built = builds.build_linux(target=target, env=env)
        elif platform_name == "apple":
            built = builds.build_apple(env=env)
        else:
            built = builds.build_android(env=env)
        staging = directory / "payload"
        for name in sorted(_expected_files(key)):
            origin = built / name
            if name == "include/vole.h" and platform_name in {"android", "windows"}:
                origin = root / "include/vole.h"
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, destination)
        archive = output / archive_name(key)
        _write_archive(staging, archive)
    print(archive)
    return archive
