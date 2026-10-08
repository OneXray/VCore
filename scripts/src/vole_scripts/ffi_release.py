"""Audit, build and inspect native-library release archives without publishing."""

from __future__ import annotations

import gzip
import hashlib
import json
import mmap
import os
import plistlib
import re
import shutil
import stat
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from . import builds, cli_release, platform_delivery

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
MAX_ARCHIVE_BYTES = 3 * 1024**3
MAX_ARTIFACT_BYTES = 1024**3
_require = cli_release._require
_sha = cli_release._sha


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


def safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    _require(
        bool(name)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in name
        and ":" not in name
        and str(path) == name
        and path.parts
        and all(part not in {"", "."} for part in path.parts),
        "invalid archive or artifact path",
    )
    return path


def regular_file(path: Path) -> None:
    info = path.lstat()
    _require(
        stat.S_ISREG(info.st_mode)
        and not getattr(info, "st_file_attributes", 0)
        & stat.FILE_ATTRIBUTE_REPARSE_POINT,
        "release input must be a regular file without symlinks or reparse points",
    )


def tree_files(base: Path) -> set[Path]:
    info = base.lstat()
    _require(
        stat.S_ISDIR(info.st_mode)
        and not getattr(info, "st_file_attributes", 0)
        & stat.FILE_ATTRIBUTE_REPARSE_POINT,
        "release input directory must not be a symlink or reparse point",
    )
    result = set()
    for parent, directories, files in os.walk(base, followlinks=False):
        for name in [*directories, *files]:
            path = Path(parent) / name
            info = path.lstat()
            _require(
                not stat.S_ISLNK(info.st_mode)
                and not getattr(info, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT,
                "release tree must not contain symlinks or reparse points",
            )
            _require(
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "release tree contains a non-regular entry",
            )
            if stat.S_ISREG(info.st_mode):
                result.add(path)
    return result


def _snapshot(
    packages: dict, nodes: dict, resolved: set, root: Path, target: str
) -> dict:
    package_rows = []
    node_rows = []
    for identifier in sorted(resolved):
        item = packages[identifier]
        row = {
            name: item.get(name)
            for name in ("id", "name", "version", "source", "license", "targets")
        }
        if item.get("source") is None:
            row["localManifest"] = (
                Path(item["manifest_path"])
                .resolve()
                .relative_to(root.resolve())
                .as_posix()
            )
        package_rows.append(row)
        node_rows.append(
            {
                "id": identifier,
                "features": nodes[identifier]["features"],
                "deps": [
                    dependency
                    for dependency in nodes[identifier]["deps"]
                    if dependency["pkg"] in resolved
                ],
            }
        )
    return {"target": target, "packages": package_rows, "nodes": node_rows}


def inspect_graph(snapshot: dict, root: Path, backend: str | None) -> tuple[dict, set]:
    packages = []
    for row in snapshot["packages"]:
        item = dict(row)
        if item.get("source") is None:
            relative = safe_relative(item.pop("localManifest"))
            expected = {
                "vole": "Cargo.toml",
                "vole-netstack": "crates/vole-netstack/Cargo.toml",
                "vole-blake3-raw": "crates/vole-blake3-raw/Cargo.toml",
            }
            _require(
                expected.get(item["name"]) == str(relative),
                "unapproved release path dependency",
            )
            item["manifest_path"] = str(root / relative)
        else:
            item["manifest_path"] = str(root / "unused-upstream-manifest")
        packages.append(item)
    metadata = {"packages": packages, "resolve": {"nodes": snapshot["nodes"]}}
    packages, nodes, resolved, linked = cli_release._graph(
        metadata, root, snapshot["target"], transport="ffi", backend=backend
    )
    _require(
        len(resolved) == len(packages),
        "FFI graph contains unreachable or development packages",
    )
    cli_release._audit_graph(packages, nodes, resolved, root)
    return packages, linked


def _android_runtime_notices(ndk: Path) -> tuple[bytes, dict]:
    properties = (ndk / "source.properties").read_text(encoding="utf-8")
    revision = re.search(r"(?m)^\s*Pkg\.Revision\s*=\s*(\d+\.\d+\.\d+)\s*$", properties)
    _require(revision is not None, "Android release requires an identified stable NDK")
    paths = sorted(path for path in ndk.glob("NOTICE*") if path.is_file())
    _require(bool(paths), "missing Android NDK runtime notices")
    sections, records = [], []
    for path in paths:
        regular_file(path)
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
        records.append(
            {"path": path.name, "sha256": hashlib.sha256(content).hexdigest()}
        )
    joined = b"".join(sections)
    _require(
        b"libc++" in joined and (b"LLVM" in joined or b"Apache" in joined),
        "NDK notices must cover the shipped libc++ runtime",
    )
    return joined, {
        "name": "Android NDK libc++_shared",
        "version": revision[1],
        "notices": records,
    }


def prepare_notices(
    root: Path,
    targets: tuple[str, ...],
    repository: str = "YuanDevTeam/Vole",
    *,
    backend: str | None = None,
    source: dict | None = None,
    android_ndk: Path | None = None,
) -> tuple[bytes, list[dict], list[dict]]:
    """Read the actual locked graphs; local anchor probes need no clean tag."""
    if source is None:
        source = {
            "version": tomllib.loads((root / "Cargo.toml").read_text())["package"][
                "version"
            ],
            "commit": cli_release._output(["git", "rev-parse", "HEAD"], root),
        }
    _require(
        bool(targets) and len(set(targets)) == len(targets),
        "notice targets must be distinct and nonempty",
    )
    graphs, dependencies, all_packages, all_linked, target_linked = (
        [],
        [],
        {},
        set(),
        {},
    )
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
        target_linked[target] = {
            (packages[i]["name"], packages[i]["version"]) for i in linked
        }
        graphs.append(_snapshot(packages, nodes, resolved, root, target))
    text, records = cli_release.collect_notices(
        all_packages, all_linked, root, source, repository, targets[0]
    )
    sections = [text]
    for target in targets:
        dependencies.append(
            {
                "target": target,
                "linked": [
                    record
                    for record in records
                    if (record["name"], record["version"]) in target_linked[target]
                ],
            }
        )
    runtime_text, runtime_record = cli_release.collect_rust_notices(root)
    sections.append(runtime_text)
    dependencies.append({"rustRuntime": runtime_record})
    if android_ndk is not None:
        text, record = _android_runtime_notices(android_ndk)
        sections.append(text)
        dependencies.append({"nativeRuntime": record})
    text = b"".join(sections)
    _require(
        0 < len(text) <= cli_release.MAX_NOTICES_BYTES,
        "FFI notice bundle exceeds the embedded text limit",
    )
    return text, dependencies, graphs


def embedded_notices(contents, version: str, expected: bytes | None = None) -> bytes:
    identity = f"Vole;engine=rust;coreVersion={version}".encode()
    _require(
        contents.find(identity) >= 0,
        "FFI binary is missing the current Rust build identity",
    )
    beginning = contents.find(cli_release.NOTICES_BEGIN)
    ending = contents.find(
        cli_release.NOTICES_END, beginning + len(cli_release.NOTICES_BEGIN)
    )
    _require(
        beginning >= 0 and ending > beginning + len(cli_release.NOTICES_BEGIN),
        "FFI binary is missing embedded license notices",
    )
    text = contents[beginning + len(cli_release.NOTICES_BEGIN) : ending]
    _require(
        0 < len(text) <= cli_release.MAX_NOTICES_BYTES and b"\0" not in text,
        "invalid embedded FFI notice text",
    )
    text.decode("utf-8")
    if expected is not None:
        _require(
            contents.find(
                cli_release.NOTICES_BEGIN + expected + cli_release.NOTICES_END
            )
            >= 0,
            "FFI binary did not retain the exact linked notice text",
        )
    return text


def _ar_members(contents) -> Iterator[bytes]:
    _require(contents[:8] == b"!<arch>\n", "invalid static archive")
    position = 8
    count = 0
    while position < len(contents):
        header = contents[position : position + 60]
        _require(
            len(header) == 60 and header[58:] == b"`\n",
            "malformed static archive member",
        )
        try:
            size = int(header[48:58])
        except ValueError as error:
            raise ValueError("invalid static archive member size") from error
        start = position + 60
        end = start + size
        _require(size >= 0 and end <= len(contents), "truncated static archive member")
        name = header[:16].rstrip()
        payload = contents[start:end]
        if name.startswith(b"#1/"):
            length = int(name[3:])
            _require(0 <= length <= len(payload), "invalid BSD archive member name")
            name, payload = payload[:length].rstrip(b"\0"), payload[length:]
        if name not in {b"/", b"//", b"/SYM64/"} and not name.startswith(b"__.SYMDEF"):
            _require(bool(payload), "empty static archive object")
            count += 1
            yield payload
        position = end + size % 2
    _require(
        position == len(contents) and count > 0,
        "static archive contains no complete objects",
    )


def _elf(contents, machine: int, shared: bool) -> None:
    _require(
        contents[:7] == b"\x7fELF\x02\x01\x01"
        and len(contents) >= 64
        and int.from_bytes(contents[16:18], "little") == (3 if shared else 1)
        and int.from_bytes(contents[18:20], "little") == machine,
        "wrong FFI ELF type or architecture",
    )


def _macho_object(
    contents, architecture: str, target_os: str, variant: str | None
) -> None:
    _require(
        contents[:4] == b"\xcf\xfa\xed\xfe"
        and len(contents) >= 32
        and int.from_bytes(contents[4:8], "little")
        == {"x86_64": 0x1000007, "arm64": 0x100000C}[architecture]
        and int.from_bytes(contents[12:16], "little") == 1,
        "wrong Apple FFI Mach-O object architecture",
    )
    expected = {
        ("macos", None): 1,
        ("ios", None): 2,
        ("tvos", None): 3,
        ("ios", "simulator"): 7,
        ("tvos", "simulator"): 8,
    }[(target_os, variant)]
    commands = int.from_bytes(contents[16:20], "little")
    size = int.from_bytes(contents[20:24], "little")
    _require(
        commands <= 4096 and 32 + size <= len(contents), "invalid Apple load commands"
    )
    position, found = 32, False
    for _ in range(commands):
        command = int.from_bytes(contents[position : position + 4], "little")
        length = int.from_bytes(contents[position + 4 : position + 8], "little")
        _require(
            length >= 8 and position + length <= 32 + size,
            "truncated Apple load command",
        )
        if command == 0x32:
            _require(
                length >= 24
                and int.from_bytes(contents[position + 8 : position + 12], "little")
                == expected,
                "wrong Apple FFI platform",
            )
            found = True
        elif command in {0x24, 0x25, 0x2F}:
            _require(
                variant is None
                and command == {"macos": 0x24, "ios": 0x25, "tvos": 0x2F}[target_os],
                "wrong legacy Apple FFI platform",
            )
            found = True
        position += length
    _require(
        position == 32 + size and found, "Apple FFI object is missing platform metadata"
    )


def _apple_slices(contents, architectures: set[str]) -> list[tuple[str, bytes]]:
    if len(architectures) == 1:
        return [(next(iter(architectures)), contents)]
    _require(
        contents[:4] in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"},
        "Apple universal archive is missing fat metadata",
    )
    wide = contents[:4] == b"\xca\xfe\xba\xbf"
    count = int.from_bytes(contents[4:8], "big")
    _require(count == len(architectures), "wrong Apple universal architecture count")
    slices, seen, ranges = [], set(), []
    row_size = 32 if wide else 20
    for index in range(count):
        position = 8 + index * row_size
        row = contents[position : position + row_size]
        _require(len(row) == row_size, "truncated Apple universal header")
        architecture = {0x1000007: "x86_64", 0x100000C: "arm64"}.get(
            int.from_bytes(row[:4], "big")
        )
        offset = int.from_bytes(row[8 : 16 if wide else 12], "big")
        size = int.from_bytes(row[16:24] if wide else row[12:16], "big")
        _require(
            architecture in architectures
            and architecture not in seen
            and offset >= 8 + count * row_size
            and size > 0
            and offset + size <= len(contents),
            "invalid Apple universal slice",
        )
        _require(
            not any(offset < end and start < offset + size for start, end in ranges),
            "overlapping Apple universal slices",
        )
        seen.add(architecture)
        ranges.append((offset, offset + size))
        slices.append((architecture, contents[offset : offset + size]))
    return slices


def _expected_files(key: str) -> set[str]:
    platform_name, _, backend = RELEASES[key]
    if platform_name == "apple":
        return {"LibVole.xcframework/Info.plist"} | {
            f"LibVole.xcframework/{identifier}/{name}"
            for identifier in platform_delivery.APPLE_LIBRARIES
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


def verify_artifacts(
    base: Path, key: str, version: str, notices: bytes | None = None
) -> dict[str, bytes]:
    files = tree_files(base)
    _require(
        {p.relative_to(base).as_posix() for p in files} == _expected_files(key),
        "incomplete or unexpected FFI archive files",
    )
    retained = {}
    for name in sorted(_expected_files(key)):
        path = base / name
        regular_file(path)
        _require(
            0 < path.stat().st_size <= MAX_ARTIFACT_BYTES, "invalid FFI artifact size"
        )
        if name.endswith("vole.h"):
            _require(
                path.read_bytes() == (builds.CORE_DIR / "include/vole.h").read_bytes(),
                "FFI public header differs from this source",
            )
            continue
        if name.endswith("module.modulemap"):
            _require(
                path.read_bytes()
                == (builds.CORE_DIR / "include/module.modulemap").read_bytes(),
                "FFI module map differs from this source",
            )
            continue
        if name.endswith("Info.plist"):
            with path.open("rb") as stream:
                libraries = plistlib.load(stream).get("AvailableLibraries", [])
            _require(
                len(libraries) == len(platform_delivery.APPLE_LIBRARIES),
                "incomplete Apple FFI slices",
            )
            seen = set()
            for library in libraries:
                identifier = library.get("LibraryIdentifier")
                _require(
                    identifier in platform_delivery.APPLE_LIBRARIES
                    and identifier not in seen,
                    "invalid Apple FFI slice",
                )
                seen.add(identifier)
                target_os, variant, architectures = platform_delivery.APPLE_LIBRARIES[
                    identifier
                ]
                _require(
                    library.get("SupportedPlatform") == target_os
                    and library.get("SupportedPlatformVariant") == variant
                    and set(library.get("SupportedArchitectures", [])) == architectures
                    and library.get("LibraryPath") == "libvole.a"
                    and library.get("HeadersPath") == "Headers",
                    "wrong Apple FFI slice metadata",
                )
            continue
        if name.endswith(".dll.lib"):
            builds._require_windows_import_library(
                path, "x64" if key.endswith("amd64") else "arm64"
            )
            continue
        with (
            path.open("rb") as stream,
            mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as contents,
        ):
            if key == "apple":
                identifier = PurePosixPath(name).parts[1]
                target_os, variant, architectures = platform_delivery.APPLE_LIBRARIES[
                    identifier
                ]
                for architecture, payload in _apple_slices(contents, architectures):
                    for member in _ar_members(payload):
                        _macho_object(member, architecture, target_os, variant)
                    text = embedded_notices(payload, version, notices)
                    _require(
                        name not in retained or retained[name] == text,
                        "Apple universal notices differ between architectures",
                    )
                    retained[name] = text
            elif key.startswith("windows-"):
                architecture = "x64" if key.endswith("amd64") else "arm64"
                builds._require_windows_architecture(path, architecture)
                offset = int.from_bytes(contents[0x3C:0x40], "little")
                flags = int.from_bytes(contents[offset + 22 : offset + 24], "little")
                _require(
                    flags & 2 and bool(flags & 0x2000) == name.endswith(".dll"),
                    "wrong FFI PE library/executable type",
                )
                retained[name] = embedded_notices(contents, version, notices)
            else:
                machine = (
                    183
                    if name.startswith("arm64-v8a/") or key.endswith("arm64")
                    else 62
                )
                if name.endswith(".a"):
                    for member in _ar_members(contents):
                        _elf(member, machine, False)
                else:
                    _elf(contents, machine, True)
                if not name.endswith("libc++_shared.so"):
                    retained[name] = embedded_notices(contents, version, notices)
    return retained


def _write_archive(base: Path, archive: Path) -> None:
    names = sorted(p.relative_to(base).as_posix() for p in tree_files(base))
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            for name in names:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                stream.writestr(info, (base / name).read_bytes())
    else:
        with (
            archive.open("wb") as file,
            gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w") as stream,
        ):
            for name in names:
                info = stream.gettarinfo(str(base / name), arcname=name)
                info.uid, info.gid, info.uname, info.gname, info.mtime = 0, 0, "", "", 0
                info.mode = 0o644
                with (base / name).open("rb") as payload:
                    stream.addfile(info, payload)


def _extract_archive(archive: Path, base: Path, expected: set[str]) -> None:
    regular_file(archive)
    _require(
        0 < archive.stat().st_size <= MAX_ARCHIVE_BYTES,
        "invalid FFI release archive size",
    )
    seen, total = set(), 0
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as stream:
            for member in stream.infolist():
                name, size = member.filename, member.file_size
                safe_relative(name)
                mode = member.external_attr >> 16
                _require(
                    name in expected
                    and name not in seen
                    and not member.is_dir()
                    and stat.S_IFMT(mode) in {0, stat.S_IFREG},
                    "invalid or duplicate FFI zip member",
                )
                _require(
                    not member.flag_bits & 1 and 0 < size <= MAX_ARTIFACT_BYTES,
                    "invalid FFI zip payload",
                )
                total += size
                _require(
                    total <= MAX_ARCHIVE_BYTES,
                    "FFI archive expands beyond the release size limit",
                )
                seen.add(name)
                destination = base / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with stream.open(member) as payload, destination.open("xb") as output:
                    shutil.copyfileobj(payload, output)
                _require(destination.stat().st_size == size, "truncated FFI zip member")
    else:
        with tarfile.open(archive, "r:gz") as stream:
            for member in stream:
                name, size = member.name, member.size
                safe_relative(name)
                _require(
                    name in expected
                    and name not in seen
                    and member.isfile()
                    and not member.issparse(),
                    "invalid or duplicate FFI tar member",
                )
                _require(0 < size <= MAX_ARTIFACT_BYTES, "invalid FFI tar payload")
                total += size
                _require(
                    total <= MAX_ARCHIVE_BYTES,
                    "FFI archive expands beyond the release size limit",
                )
                seen.add(name)
                destination = base / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with (
                    stream.extractfile(member) as payload,
                    destination.open("xb") as output,
                ):
                    shutil.copyfileobj(payload, output)
                _require(destination.stat().st_size == size, "truncated FFI tar member")
    _require(
        seen == expected, "FFI archive does not contain the complete expected file set"
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
    architecture = "x64" if target and target.startswith("x86_64-") else "arm64"
    raw = root / "dist" / platform_name
    if platform_name == "linux":
        raw /= architecture
    elif platform_name == "windows":
        raw = raw / architecture / backend
    _require(
        not output.resolve().is_relative_to(raw.resolve())
        and not raw.resolve().is_relative_to(output.resolve()),
        "FFI job output must be separate from raw platform delivery",
    )
    overrides = cli_release._release_overrides()
    _require(
        not overrides and os.environ.get("VOLE_BUILD_PROFILE", "release") == "release",
        "unsupported FFI release build overrides: " + ", ".join(overrides),
    )
    source = cli_release._source(root, tag)
    notices, dependencies, graphs = prepare_notices(
        root,
        targets,
        repository,
        backend=backend,
        source=source,
        android_ndk=builds._android_ndk_home() if platform_name == "android" else None,
    )
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="vole-ffi-release-") as directory:
        directory = Path(directory)
        notice_file = directory / "notices.txt"
        notice_file.write_bytes(notices)
        delivery_path = platform_delivery.build_delivery(
            platform_name,
            backend=backend or "uwp",
            target=target if platform_name in {"linux", "windows"} else None,
            env={"VOLE_RELEASE_NOTICES": str(notice_file)},
        )
        delivery = json.loads(delivery_path.read_text(encoding="utf-8"))
        staging = directory / "payload"
        staging.mkdir()
        expected = _expected_files(key)
        for name in sorted(expected):
            origin = delivery_path.parent / name
            if name == "include/vole.h" and platform_name in {"android", "windows"}:
                origin = root / "include/vole.h"
            regular_file(origin)
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, destination)
        retained = verify_artifacts(staging, key, source["version"], notices)
        _require(
            cli_release._source(root, tag) == source,
            "source changed during FFI release build",
        )
        archive = output / archive_name(key)
        _write_archive(staging, archive)
        rows = [
            {
                "path": name,
                "size": (staging / name).stat().st_size,
                "sha256": _sha(staging / name),
            }
            for name in sorted(expected)
        ]
        record = {
            "formatVersion": 1,
            "kind": "ffi",
            "release": key,
            "profile": "release",
            "source": source,
            "buildIdentity": f"Vole;engine=rust;coreVersion={source['version']}",
            "delivery": delivery,
            "graphs": graphs,
            "dependencies": dependencies,
            "artifacts": rows,
            "archive": {
                "name": archive.name,
                "sha256": _sha(archive),
                "size": archive.stat().st_size,
            },
            "noticesSha256": hashlib.sha256(notices).hexdigest(),
            "noticesSize": len(notices),
            "retainedNotices": sorted(retained),
        }
        if platform_name == "windows":
            record["windowsPackageIdentity"] = (
                delivery_path.parent / "vole-windows-artifacts.json"
            ).read_text(encoding="utf-8")
        _inspect_delivery(record, key, source)
        manifest = output / "manifest.json"
        manifest.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(archive)
    return manifest


def _inspect_delivery(record: dict, key: str, source: dict) -> None:
    platform_name, target, backend = RELEASES[key]
    delivery = record.get("delivery", {})
    architecture = "x64" if target and target.startswith("x86_64-") else "arm64"
    group = (
        platform_name
        if platform_name in {"apple", "android"}
        else f"linux-{architecture}"
        if platform_name == "linux"
        else f"windows-{architecture}-{backend}"
    )
    features = (
        builds.windows_features(backend)
        if platform_name == "windows"
        else builds.DEFAULT_FEATURES
    )
    _require(
        delivery.get("formatVersion") == 1
        and delivery.get("group") == group
        and delivery.get("profile") == "release"
        and delivery.get("features") == features.split(",")
        and delivery.get("source")
        == {name: source[name] for name in ("commit", "tree", "lockSha256")}
        and delivery.get("buildIdentity") == record["buildIdentity"],
        "incompatible FFI delivery identity",
    )
    toolchain = delivery.get("toolchain", {})
    required = {"rustc", "cargo"} | (
        {
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
        if platform_name == "apple"
        else {"ndk", "clang", "androidApi"}
        if platform_name == "android"
        else {"msvc", "windowsSdk"}
        if platform_name == "windows"
        else {"cc", "cmake"}
    )
    _require(
        all(
            isinstance(toolchain.get(name), str) and toolchain[name]
            for name in required
        ),
        "missing FFI toolchain evidence",
    )
    runtime = [
        row["rustRuntime"] for row in record["dependencies"] if "rustRuntime" in row
    ]
    _require(
        len(runtime) == 1
        and runtime[0].get("name") == "Rust standard library"
        and runtime[0].get("rustc") == toolchain["rustc"]
        and runtime[0].get("notices"),
        "FFI release requires matching Rust standard-library notices",
    )
    if platform_name in {"linux", "windows"}:
        _require(
            delivery.get("host", {}).get("os")
            == ("Windows" if platform_name == "windows" else "Linux")
            and delivery["host"].get("architecture") == architecture,
            "FFI release requires native OS/architecture evidence",
        )
    else:
        _require(
            delivery.get("host", {}).get("os")
            in ({"Darwin"} if platform_name == "apple" else {"Darwin", "Linux"}),
            "wrong FFI build host",
        )
    if platform_name in {"linux", "windows"}:
        _require(
            delivery.get("target") == target,
            "FFI delivery target differs from its audited graph",
        )
    if platform_name == "windows":
        _require(
            delivery.get("backend") == backend, "FFI backend delivery identity mismatch"
        )
    if platform_name == "android":
        native = [
            row["nativeRuntime"]
            for row in record["dependencies"]
            if "nativeRuntime" in row
        ]
        revision = re.search(
            r"(?m)^\s*Pkg\.Revision\s*=\s*(\d+\.\d+\.\d+)\s*$", toolchain["ndk"]
        )
        _require(
            len(native) == 1
            and revision is not None
            and native[0].get("name") == "Android NDK libc++_shared"
            and native[0].get("version") == revision[1]
            and native[0].get("notices"),
            "Android runtime notices must match the build NDK",
        )
    rows = delivery.get("artifacts", [])
    names = [row["path"] for row in rows]
    expected = _expected_files(key) - (
        {"include/vole.h"} if platform_name in {"android", "windows"} else set()
    )
    if platform_name == "windows":
        expected.add("vole-windows-artifacts.json")
    _require(
        len(names) == len(set(names)) and set(names) == expected,
        "incomplete FFI delivery artifact identities",
    )
    archive_rows = {row["path"]: row for row in record["artifacts"]}
    for row in rows:
        safe_relative(row["path"])
        if row["path"] in archive_rows:
            _require(
                row == archive_rows[row["path"]],
                "FFI archive differs from the verified platform delivery",
            )
    if platform_name == "windows":
        content = record.get("windowsPackageIdentity", "").encode("utf-8")
        identity_row = next(
            row for row in rows if row["path"] == "vole-windows-artifacts.json"
        )
        _require(
            len(content) == identity_row["size"]
            and hashlib.sha256(content).hexdigest() == identity_row["sha256"],
            "Windows package identity differs from platform delivery",
        )
        package = json.loads(content)
        _require(
            package.get("formatVersion") == 1
            and package.get("backend") == backend
            and package.get("architecture") == architecture
            and package.get("buildIdentity") == record["buildIdentity"]
            and package.get("artifacts")
            == {
                name: row["sha256"]
                for name, row in archive_rows.items()
                if name != "include/vole.h"
            }
            and (
                package.get("windowsPackageIntegrationRevision") == 3
                if backend == "uwp"
                else "windowsPackageIntegrationRevision" not in package
            ),
            "invalid Windows package integration identity",
        )


def inspect_release(manifest: Path, source: dict, root: Path) -> Path:
    regular_file(manifest)
    record = json.loads(manifest.read_text(encoding="utf-8"))
    key = record.get("release")
    _require(key in RELEASES, "unsupported FFI release identity")
    platform_name, target, backend = RELEASES[key]
    _, targets = selection(platform_name, target, backend)
    _require(
        record.get("formatVersion") == 1
        and record.get("kind") == "ffi"
        and record.get("profile") == "release"
        and record.get("source") == source
        and record.get("buildIdentity")
        == f"Vole;engine=rust;coreVersion={source['version']}",
        "incompatible FFI release evidence",
    )
    _inspect_delivery(record, key, source)
    graphs = record.get("graphs", [])
    _require(
        len(graphs) == len(targets)
        and {graph["target"] for graph in graphs} == set(targets),
        "FFI release requires all target dependency graphs",
    )
    dependencies = record.get("dependencies", [])
    target_rows = [row for row in dependencies if "target" in row]
    _require(
        len(target_rows) == len(targets)
        and {row.get("target") for row in target_rows} == set(targets),
        "FFI release requires actual linked dependency notices",
    )
    _require(
        len(dependencies) == len(targets) + 1 + (key == "android"),
        "unexpected FFI runtime notice identities",
    )
    for graph in graphs:
        packages, linked = inspect_graph(graph, root, backend)
        rows = next(
            row["linked"]
            for row in dependencies
            if row.get("target") == graph["target"]
        )
        _require(
            {(packages[i]["name"], packages[i]["version"]) for i in linked}
            == {(row["name"], row["version"]) for row in rows}
            and len(rows) == len(linked),
            "FFI linked notices do not cover the resolved graph",
        )
    if key == "android":
        _require(
            len([row for row in dependencies if "nativeRuntime" in row]) == 1,
            "missing shipped Android C++ runtime notices",
        )
    archive = manifest.parent / archive_name(key)
    _require(
        tree_files(manifest.parent) == {manifest, archive},
        "FFI job may contain only its archive and internal manifest",
    )
    regular_file(archive)
    _require(
        record.get("archive")
        == {
            "name": archive.name,
            "size": archive.stat().st_size,
            "sha256": _sha(archive),
        },
        "FFI archive identity mismatch",
    )
    rows = record.get("artifacts", [])
    _require(
        len(rows) == len(_expected_files(key))
        and {row["path"] for row in rows} == _expected_files(key),
        "invalid FFI artifact manifest paths",
    )
    with tempfile.TemporaryDirectory(prefix="vole-ffi-inspect-") as directory:
        base = Path(directory)
        _extract_archive(archive, base, _expected_files(key))
        for row in rows:
            path = base / safe_relative(row["path"])
            _require(
                row
                == {
                    "path": row["path"],
                    "size": path.stat().st_size,
                    "sha256": _sha(path),
                },
                "FFI binary hash/size mismatch",
            )
        retained = verify_artifacts(base, key, source["version"])
        _require(
            sorted(retained) == record.get("retainedNotices"),
            "incomplete FFI notice retention evidence",
        )
        for text in retained.values():
            _require(
                len(text) == record.get("noticesSize")
                and hashlib.sha256(text).hexdigest() == record.get("noticesSha256"),
                "embedded FFI linked notices identity mismatch",
            )
    return archive
