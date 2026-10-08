"""Build six native CLI archives; release publication stays in the tag workflow."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import mmap
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import builds

TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux", "amd64"),
    "aarch64-unknown-linux-gnu": ("linux", "arm64"),
    "x86_64-pc-windows-msvc": ("windows", "amd64"),
    "aarch64-pc-windows-msvc": ("windows", "arm64"),
    "x86_64-apple-darwin": ("darwin", "amd64"),
    "aarch64-apple-darwin": ("darwin", "arm64"),
}
REGISTRY = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://index.crates.io/",
}
BORING_SOURCE = (
    "git+https://github.com/YuanDevTeam/boring?branch=release#"
    "43c1c1d5b9464b3f2d5204be8664778fada7dbaf"
)
NOTICES_BEGIN = b"VOLE_CLI_RELEASE_NOTICES_BEGIN\n"
NOTICES_END = b"\nVOLE_CLI_RELEASE_NOTICES_END\n"
MAX_NOTICES_BYTES = 16 * 1024 * 1024
# Standard MIT terms (https://spdx.org/licenses/MIT.html). The original API
# header supplies the copyright attribution; no Wintun driver is distributed.
MIT_TERMS = b"""\
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
SMOKE_CONFIG = """tun:
  enable: true
proxies:
  - name: release-probe
    type: socks5
    server: release-probe.invalid
    port: 1080
rules:
  - MATCH,release-probe
"""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _output(arguments: list[str], root: Path, env: dict | None = None) -> str:
    return subprocess.check_output(
        arguments, cwd=root, env=env, text=True, timeout=60
    ).strip()


def _source(root: Path, tag: str) -> dict:
    version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    _require(
        re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag) is not None
        and tag == "v" + version,
        "release tag must be vX.Y.Z and match Cargo package version",
    )
    _require(
        not _output(["git", "status", "--porcelain", "--untracked-files=normal"], root),
        "CLI release requires a clean committed checkout",
    )
    commit = _output(["git", "rev-parse", "HEAD"], root)
    _require(
        _output(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"], root) == commit,
        "release tag must identify the checked-out commit",
    )
    return {
        "tag": tag,
        "version": version,
        "commit": commit,
        "tree": _output(["git", "rev-parse", "HEAD^{tree}"], root),
        "lockSha256": _sha(root / "Cargo.lock"),
        "manifestSha256": _sha(root / "Cargo.toml"),
    }


def archive_name(target: str) -> str:
    system, architecture = TARGETS[target]
    suffix = "zip" if system == "windows" else "gz"
    return f"vole-{system}-{architecture}.{suffix}"


def _native_environment(target: str) -> dict[str, str]:
    system, architecture = TARGETS[target]
    _require(
        platform.system()
        == {"linux": "Linux", "darwin": "Darwin", "windows": "Windows"}[system],
        "CLI release builds require the native target OS",
    )
    if system == "windows":
        native = builds._windows_architecture()
        _require(
            native == {"amd64": "x64", "arm64": "arm64"}[architecture],
            "CLI release requires native Windows architecture",
        )
        env = builds._windows_msvc_environment(native)
    else:
        native = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
            platform.machine().lower()
        )
        _require(native == architecture, "CLI release requires native CPU architecture")
        env = os.environ.copy()
        if system == "darwin":
            env["MACOSX_DEPLOYMENT_TARGET"] = (
                "10.15" if architecture == "amd64" else "11.0"
            )
    return env


def requested_features(target: str) -> str:
    return "cli,windows-wintun" if TARGETS[target][0] == "windows" else "cli"


def _backend_matches(features: set[str], target: str | None) -> bool:
    if "windows-uwp" in features:
        return False
    return target is None or ("windows-wintun" in features) == (
        TARGETS[target][0] == "windows"
    )


def _graph(
    metadata: dict, root: Path, target: str | None = None
) -> tuple[dict, dict, set, set]:
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    roots = [
        item
        for item in packages.values()
        if Path(item["manifest_path"]).resolve() == (root / "Cargo.toml").resolve()
    ]
    _require(len(roots) == 1, "expected one Vole root package")
    core = roots[0]
    features = set(nodes[core["id"]]["features"])
    production = set(
        tomllib.loads((root / "Cargo.toml").read_text())["features"]["default"]
    )
    _require(
        production | {"cli", "invoke", "tun"} <= features,
        "CLI must enable the complete production feature set",
    )
    _require(
        not features & {"ffi", "windows-uwp", "interop-test", "benchmark-geodata-http"},
        "CLI release must not enable FFI or test features",
    )
    _require(
        _backend_matches(features, target),
        "CLI release has an incompatible Windows backend",
    )

    def reachable(include_build: bool) -> set:
        result = set()
        pending = [core["id"]]
        while pending:
            identifier = pending.pop()
            if identifier in result:
                continue
            if not include_build and any(
                "proc-macro" in target["kind"]
                for target in packages[identifier]["targets"]
            ):
                continue
            result.add(identifier)
            for dependency in nodes[identifier]["deps"]:
                if any(
                    kind["kind"] is None or (include_build and kind["kind"] == "build")
                    for kind in dependency["dep_kinds"]
                ):
                    pending.append(dependency["pkg"])
        return result

    resolved, linked = reachable(True), reachable(False)
    sdk_names = {"windows", "windows-collections", "windows-core"}
    _require(
        not {
            packages[dependency["pkg"]]["name"]
            for dependency in nodes[core["id"]]["deps"]
            if any(kind["kind"] in {None, "build"} for kind in dependency["dep_kinds"])
        }
        & sdk_names,
        "CLI release root must not depend on the Windows UWP SDK",
    )
    for identifier in resolved:
        if packages[identifier]["name"] == "windows":
            # tun-rs interruptible I/O uses Windows Win32 bindings transitively.
            # Package names alone cannot distinguish those from packaged WinRT.
            _require(
                all(
                    feature in {"default", "std", "deprecated", "Win32"}
                    or feature.startswith("Win32_")
                    for feature in nodes[identifier]["features"]
                ),
                "CLI release graph must not enable Windows WinRT features",
            )
    return packages, nodes, resolved, linked


def _audit_graph(packages: dict, nodes: dict, resolved: set, root: Path) -> None:
    def package(name: str, version: str | None = None, sources: set = REGISTRY) -> dict:
        matches = [
            packages[identifier]
            for identifier in resolved
            if packages[identifier]["name"] == name
        ]
        _require(len(matches) == 1, f"expected one resolved {name}")
        item = matches[0]
        _require(
            version is None or item["version"] == version, f"unapproved {name} version"
        )
        _require(item.get("source") in sources, f"unapproved {name} source")
        return item

    def features(item: dict) -> set:
        return set(nodes[item["id"]]["features"])

    for identifier in resolved:
        item = packages[identifier]
        source = item.get("source")
        if source is None:
            base = Path(item["manifest_path"]).resolve()
            _require(
                base.is_relative_to(root),
                "release cannot use an external path dependency",
            )
        else:
            _require(
                source in REGISTRY
                or (
                    item["name"] in {"boring", "boring-sys", "tokio-boring"}
                    and source == BORING_SOURCE
                ),
                "unapproved release dependency source",
            )
    rustls = package("rustls", "0.23.45")
    package("tokio-rustls", "0.26.5")
    package("ring")
    _require(
        "ring" in features(rustls)
        and not features(rustls) & {"reality", "aws_lc_rs", "fips"},
        "rustls must use only the ring TLS provider",
    )
    _require(
        features(package("hpke", "0.14.1"))
        == {"alloc", "aes", "chacha", "x25519", "hkdfsha2"},
        "unapproved ECH algorithms",
    )
    native = {}
    for name, required in (
        ("boring", {"reality", "client-fingerprint", "shadow-tls-v3", "jls"}),
        ("boring-sys", {"reality", "shadow-tls-v3", "jls"}),
        ("tokio-boring", set()),
    ):
        item = package(name, "5.2.0", {BORING_SOURCE})
        native[name] = item
        _require(required <= features(item), f"{name} is missing required TLS features")
        _require(
            not features(item)
            & {"fips", "fips-precompiled", "rpk", "pq-experimental", "restls"},
            f"{name} enables an unapproved TLS mode",
        )
    for parent, children in (
        ("boring", {"boring-sys"}),
        ("tokio-boring", {"boring", "boring-sys"}),
    ):
        dependencies = {
            dependency["pkg"] for dependency in nodes[native[parent]["id"]]["deps"]
        }
        _require(
            all(native[child]["id"] in dependencies for child in children),
            "native TLS packages must share the approved source",
        )
    chain = {
        name: package(name, version)
        for name, version in (
            ("shadowsocks", "1.25.0"),
            ("shadowsocks-crypto", "0.8.0"),
            ("aws-lc-rs", None),
            ("aws-lc-sys", None),
        )
    }
    _require(
        {
            packages[identifier]["name"]
            for identifier in resolved
            if packages[identifier]["name"].lower().startswith("aws-lc")
        }
        == {"aws-lc-rs", "aws-lc-sys"},
        "unapproved AWS-LC package",
    )
    parents = {}
    for identifier in resolved:
        for dependency in nodes[identifier]["deps"]:
            if dependency["pkg"] in resolved and any(
                kind["kind"] in {None, "build"} for kind in dependency["dep_kinds"]
            ):
                parents.setdefault(dependency["pkg"], set()).add(identifier)
    for child, parent in (
        ("shadowsocks-crypto", "shadowsocks"),
        ("aws-lc-rs", "shadowsocks-crypto"),
        ("aws-lc-sys", "aws-lc-rs"),
    ):
        _require(
            parents.get(chain[child]["id"]) == {chain[parent]["id"]},
            f"{child} must be consumed only by {parent}",
        )
    for name, required in (
        ("shadowsocks", {"aead-cipher-2022"}),
        ("shadowsocks-crypto", {"v2", "aws-lc"}),
    ):
        _require(required <= features(chain[name]), f"{name} must enable SS 2022")
    _require(
        not any(
            features(item) & {"fips", "aead-cipher-2022-extra", "v2-extra"}
            for item in chain.values()
        ),
        "unapproved SS 2022 or AWS-LC mode",
    )


def _notice_name(path: Path) -> bool:
    return path.name.upper().startswith(
        ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT", "UNLICENSE")
    )


def _fetch_notice(url: str) -> bytes | None:
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            content = response.read(MAX_NOTICES_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    _require(
        len(content) <= MAX_NOTICES_BYTES,
        "upstream notice exceeds the embedded text limit",
    )
    return content


def _upstream_notices(item: dict, base: Path) -> list[tuple[str, bytes]]:
    repository = (item.get("repository") or "").removesuffix(".git").rstrip("/")
    _require(
        re.fullmatch(r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        is not None,
        "missing packaged notices require an immutable public upstream source",
    )
    vcs = json.loads((base / ".cargo_vcs_info.json").read_text())
    revision = vcs["git"]["sha1"]
    _require(
        re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
        "upstream notice revision must be immutable",
    )
    result = []
    # Workspace crate archives occasionally omit root license files. The
    # registry-provided VCS identity identifies that exact upstream root.
    for name in ("LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "COPYING", "NOTICE"):
        url = (
            repository.replace(
                "https://github.com/", "https://raw.githubusercontent.com/"
            )
            + f"/{revision}/{name}"
        )
        content = _fetch_notice(url)
        if content:
            result.append((url, content))
    _require(bool(result), f"no license text available for {item['name']}")
    return result


def collect_notices(
    packages: dict, linked: set, root: Path, source: dict, repository: str, target: str
) -> tuple[bytes, list[dict]]:
    _require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
        "invalid public repository identity",
    )
    sections = [
        f"Vole {source['version']} linked dependency licenses and notices\n"
        f"Source commit: {source['commit']}\n"
    ]
    records = []
    linked_names = {packages[identifier]["name"] for identifier in linked}
    for item in sorted(
        (packages[identifier] for identifier in linked),
        key=lambda item: (item["name"], item["version"]),
    ):
        base = Path(item["manifest_path"]).parent
        if item.get("source") in REGISTRY:
            url = f"https://crates.io/api/v1/crates/{item['name']}/{item['version']}/download"
        elif item.get("source") == BORING_SOURCE:
            url = (
                "https://github.com/YuanDevTeam/boring/tree/"
                + BORING_SOURCE.rsplit("#", 1)[1]
            )
        else:
            url = f"https://github.com/{repository}/tree/{source['commit']}"
        candidates = base.iterdir() if base == root else base.rglob("*")
        files = {
            path
            for path in candidates
            if path.is_file()
            and _notice_name(path)
            and not {".git", "target", ".venv"} & set(path.relative_to(base).parts)
        }
        if item.get("license_file"):
            declared = Path(item["license_file"])
            files.add(declared if declared.is_absolute() else base / declared)
        if base.is_relative_to(root):
            files.add(root / "LICENSE")
        if item["name"] == "boring-sys":
            _require(
                base.joinpath("deps/boringssl/LICENSE").is_file(),
                "missing BoringSSL native notices",
            )
        if item["name"] == "aws-lc-sys":
            _require(
                base.joinpath("aws-lc/LICENSE").is_file(),
                "missing AWS-LC native notices",
            )
        notices = []
        for path in sorted(files):
            _require(
                path.is_file() and not path.is_symlink(),
                "notice source must be a regular file",
            )
            label = (
                path.relative_to(base).as_posix()
                if path.is_relative_to(base)
                else "Vole/LICENSE"
            )
            notices.append((label, path.read_bytes()))
        if item["name"] == "vole" and "shadowsocks" in linked_names:
            # This derived source carries its own applicable MIT attribution;
            # the Vole project license cannot substitute for the upstream text.
            path = root / "src/outbound/shadowsocks/packet_window.rs"
            preamble = []
            for line in path.read_bytes().splitlines(keepends=True):
                if line.startswith(b"//!") or (
                    line.strip() and not line.startswith(b"//")
                ):
                    break
                preamble.append(line)
            content = b"".join(preamble)
            _require(
                b"SPDX-License-Identifier: MIT" in content
                and b"Copyright" in content
                and b"Permission is hereby granted" in content
                and b'THE SOFTWARE IS PROVIDED "AS IS"' in content,
                "missing derived Shadowsocks replay-window notices",
            )
            notices.append((path.relative_to(root).as_posix(), content))
        if item["name"] == "tun-rs" and TARGETS[target][0] == "windows":
            path = base / "src/platform/windows/tun/wintun.h"
            header = path.read_bytes()
            end = header.find(b"*/")
            _require(
                header.startswith(b"/* SPDX-License-Identifier: GPL-2.0 OR MIT")
                and end >= 0
                and b"Copyright" in header[:end],
                "missing Wintun API header dual-license attribution",
            )
            content = (
                header[: end + 2]
                + b"\n\nThe linked API bindings use the MIT alternative. "
                + b"The Wintun driver DLL is host-provided and is not bundled.\n\n"
                + b"MIT License\n\n"
                + MIT_TERMS
            )
            notices.append((path.relative_to(base).as_posix(), content))
        if not notices:
            notices = _upstream_notices(item, base)
        sections.append(
            f"\n===== {item['name']} {item['version']} =====\n"
            f"License: {item.get('license') or 'see license files'}\n"
            f"Source: {url}\n"
        )
        rows = []
        for label, content in notices:
            _require(
                bool(content) and b"\0" not in content,
                "license notices must be nonempty text without NUL bytes",
            )
            text = content.decode("utf-8")
            sections.append(f"\n--- {label} ---\n{text}\n")
            rows.append({"path": label, "sha256": hashlib.sha256(content).hexdigest()})
        records.append(
            {
                "name": item["name"],
                "version": item["version"],
                "license": item.get("license"),
                "sourceUrl": url,
                "notices": rows,
            }
        )
    content = "".join(sections).encode("utf-8")
    _require(
        0 < len(content) <= MAX_NOTICES_BYTES,
        "linked notices must contain at most 16 MiB of text",
    )
    return content, records


def verify_binary(
    path: Path, target: str, version: str, notices: bytes | None = None
) -> bytes:
    _require(
        path.is_file() and not path.is_symlink(), "CLI binary must be a regular file"
    )
    system, architecture = TARGETS[target]
    with path.open("rb") as stream:
        header = stream.read(64)
        if system == "linux":
            _require(
                header[:7] == b"\x7fELF\x02\x01\x01"
                and len(header) == 64
                and int.from_bytes(header[16:18], "little") in {2, 3}
                and int.from_bytes(header[18:20], "little")
                == {"amd64": 62, "arm64": 183}[architecture],
                "wrong CLI ELF executable architecture",
            )
        elif system == "darwin":
            _require(
                header[:4] == b"\xcf\xfa\xed\xfe"
                and int.from_bytes(header[4:8], "little")
                == {"amd64": 0x1000007, "arm64": 0x100000C}[architecture]
                and int.from_bytes(header[12:16], "little") == 2,
                "wrong CLI Mach-O executable architecture",
            )
        else:
            builds._require_windows_architecture(
                path, "x64" if architecture == "amd64" else "arm64"
            )
            stream.seek(int.from_bytes(header[0x3C:0x40], "little") + 22)
            characteristics = int.from_bytes(stream.read(2), "little")
            _require(
                characteristics & 2 != 0 and characteristics & 0x2000 == 0,
                "CLI PE must be an executable, not a DLL",
            )
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as contents:
            identity = f"Vole;engine=rust;coreVersion={version}".encode()
            position = contents.find(identity)
            _require(
                position >= 0, "CLI binary is missing the current Rust build identity"
            )
            beginning = contents.find(NOTICES_BEGIN)
            ending = contents.find(NOTICES_END, beginning + len(NOTICES_BEGIN))
            _require(
                beginning >= 0 and ending > beginning + len(NOTICES_BEGIN),
                "CLI binary is missing embedded license notices",
            )
            embedded = contents[beginning + len(NOTICES_BEGIN) : ending]
            _require(
                len(embedded) <= MAX_NOTICES_BYTES and b"\0" not in embedded,
                "invalid embedded notice text",
            )
            embedded.decode("utf-8")
            if notices is not None:
                _require(
                    contents.find(NOTICES_BEGIN + notices + NOTICES_END) >= 0,
                    "CLI binary did not retain the exact linked notice text",
                )
    return embedded


def _smoke(binary: Path, identity: str, env: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="vole-cli-smoke-") as directory:
        cwd = Path(directory)
        for option in ("-h", "-v"):
            if option == "-h":
                result = subprocess.run(
                    [str(binary), option],
                    cwd=cwd,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=30,
                )
                output = result.stdout + result.stderr
                _require(
                    all(flag in output for flag in ("-d", "-f", "-t", "-v", "-h")),
                    "CLI help must expose the five supported parameters",
                )
            else:
                output = subprocess.check_output(
                    [str(binary), option], cwd=cwd, env=env, text=True, timeout=30
                )
                _require(
                    re.search(re.escape(identity) + r"(?:\s|$)", output) is not None,
                    "CLI version output must match the binary identity",
                )
            _require(
                not list(cwd.iterdir()),
                "CLI help/version must not read config or initialize data",
            )
        config = cwd / "outside-data.yaml"
        config.write_text(SMOKE_CONFIG, encoding="utf-8")
        data = cwd / "unused-data"
        subprocess.run(
            [str(binary), "-t", "-d", str(data), "-f", str(config)],
            cwd=cwd,
            env=env,
            check=True,
            timeout=30,
        )
        _require(
            set(cwd.iterdir()) == {config},
            "CLI validation must not initialize data or platform resources",
        )
        subprocess.run(
            [str(binary), "-t", "-d=" + str(data), "-f=-"],
            input=SMOKE_CONFIG,
            text=True,
            cwd=cwd,
            env=env,
            check=True,
            timeout=30,
        )
        _require(
            set(cwd.iterdir()) == {config},
            "CLI stdin validation must not initialize data or platform resources",
        )


def _guard_output(root: Path, output: Path) -> None:
    current = root
    for part in output.relative_to(root).parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        _require(
            not stat.S_ISLNK(metadata.st_mode)
            and not getattr(metadata, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "CLI output must not contain symlinks or reparse points",
        )


def build_release(target: str, tag: str, repository: str) -> None:
    root = builds.CORE_DIR
    overrides = [
        name
        for name, value in os.environ.items()
        if value
        and (
            name
            in {
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_TARGET_DIR",
                "VOLE_FEATURES",
                "VOLE_CLI_RELEASE_NOTICES",
            }
            or name.startswith(("CARGO_PROFILE_", "BORING_BSSL_", "AWS_LC_"))
        )
    ]
    _require(
        not overrides,
        "unsupported CLI release build overrides: " + ", ".join(sorted(overrides)),
    )
    source = _source(root, tag)
    env = _native_environment(target)
    metadata = json.loads(
        _output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--no-default-features",
                "--features",
                requested_features(target),
                "--filter-platform",
                target,
                "--format-version",
                "1",
            ],
            root,
            env,
        )
    )
    packages, nodes, resolved, linked = _graph(metadata, root, target)
    _audit_graph(packages, nodes, resolved, root)
    notices, dependencies = collect_notices(
        packages, linked, root, source, repository, target
    )
    output = root / "dist/cli" / target
    _guard_output(root, output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="vole-cli-notices-") as directory:
        notice_file = Path(directory).resolve() / "notices.txt"
        notice_file.write_bytes(notices)
        env["VOLE_CLI_RELEASE_NOTICES"] = str(notice_file)
        command = [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "--no-default-features",
            "--features",
            requested_features(target),
            "--bin",
            "vole",
        ]
        subprocess.run(command, cwd=root, env=env, check=True)
        binary_name = "vole.exe" if TARGETS[target][0] == "windows" else "vole"
        binary = root / "target" / target / "release" / binary_name
        verify_binary(binary, target, source["version"], notices)
        identity = f"Vole;engine=rust;coreVersion={source['version']}"
        _smoke(binary, identity, env)
        _require(
            _source(root, tag) == source, "source changed during CLI release build"
        )
        archive = output / archive_name(target)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(
                archive, "w", compression=zipfile.ZIP_DEFLATED
            ) as stream:
                stream.write(binary, arcname=binary_name)
        else:
            with (
                archive.open("wb") as file,
                gzip.GzipFile(
                    filename=binary_name, mode="wb", fileobj=file, mtime=0
                ) as stream,
                binary.open("rb") as payload,
            ):
                shutil.copyfileobj(payload, stream)
        record = {
            "formatVersion": 1,
            "target": target,
            "profile": "release",
            "buildIdentity": identity,
            "source": source,
            "features": sorted(
                nodes[
                    next(
                        identifier
                        for identifier in linked
                        if packages[identifier]["name"] == "vole"
                    )
                ]["features"]
            ),
            "command": command,
            "toolchain": {
                "rustc": _output(["rustc", "-Vv"], root, env),
                "cargo": _output(["cargo", "--version"], root, env),
            },
            "host": {
                "os": platform.system(),
                "architecture": TARGETS[target][1],
                "osVersion": platform.release(),
            },
            "binary": {
                "name": binary_name,
                "sha256": _sha(binary),
                "size": binary.stat().st_size,
            },
            "archive": {
                "name": archive.name,
                "sha256": _sha(archive),
                "size": archive.stat().st_size,
            },
            "noticesSha256": hashlib.sha256(notices).hexdigest(),
            "noticesSize": len(notices),
            "dependencies": dependencies,
            "offlineSmoke": ["-h", "-v", "-t"],
        }
        (output / "manifest.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(archive)


def assemble_release(
    tag: str, incoming: Path, repository: str, notes_path: Path
) -> list[Path]:
    root = builds.CORE_DIR
    source = _source(root, tag)
    manifests = sorted(incoming.glob("*/manifest.json"))
    _require(
        len(manifests) == len(TARGETS), "release requires all six CLI target manifests"
    )
    seen = set()
    archives = []
    for manifest in manifests:
        record = json.loads(manifest.read_text(encoding="utf-8"))
        target = record.get("target")
        _require(
            target in TARGETS and target not in seen,
            "release requires six distinct supported targets",
        )
        seen.add(target)
        identity = f"Vole;engine=rust;coreVersion={source['version']}"
        production = set(
            tomllib.loads((root / "Cargo.toml").read_text())["features"]["default"]
        )
        expected_command = [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "--no-default-features",
            "--features",
            requested_features(target),
            "--bin",
            "vole",
        ]
        _require(
            record.get("formatVersion") == 1
            and record.get("profile") == "release"
            and record.get("source") == source
            and record.get("buildIdentity") == identity
            and record.get("offlineSmoke") == ["-h", "-v", "-t"]
            and not set(record.get("features", []))
            & {"ffi", "windows-uwp", "interop-test", "benchmark-geodata-http"}
            and production | {"cli", "invoke", "tun"} <= set(record.get("features", []))
            and _backend_matches(set(record.get("features", [])), target)
            and record.get("command") == expected_command
            and record.get("host", {}).get("architecture") == TARGETS[target][1]
            and record.get("host", {}).get("os")
            == {"linux": "Linux", "darwin": "Darwin", "windows": "Windows"}[
                TARGETS[target][0]
            ]
            and all(record.get("toolchain", {}).get(key) for key in ("rustc", "cargo"))
            and record.get("dependencies"),
            "incompatible CLI release evidence",
        )
        archive = manifest.parent / archive_name(target)
        _require(
            set(manifest.parent.iterdir()) == {manifest, archive},
            "release artifacts may contain only archive and internal manifest",
        )
        _require(
            record["archive"]
            == {
                "name": archive.name,
                "sha256": _sha(archive),
                "size": archive.stat().st_size,
            },
            "CLI archive identity mismatch",
        )
        binary_name = "vole.exe" if TARGETS[target][0] == "windows" else "vole"
        with tempfile.TemporaryDirectory(prefix="vole-cli-inspect-") as directory:
            binary = Path(directory) / binary_name
            with binary.open("wb") as destination:
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as compressed:
                        _require(
                            compressed.namelist() == [binary_name],
                            "Windows CLI zip must contain only vole.exe",
                        )
                        with compressed.open(binary_name) as payload:
                            shutil.copyfileobj(payload, destination)
                else:
                    with gzip.open(archive, "rb") as payload:
                        shutil.copyfileobj(payload, destination)
            _require(
                record["binary"]
                == {
                    "name": binary_name,
                    "sha256": _sha(binary),
                    "size": binary.stat().st_size,
                },
                "CLI executable hash/size mismatch",
            )
            notices = verify_binary(binary, target, source["version"])
            _require(
                hashlib.sha256(notices).hexdigest() == record.get("noticesSha256")
                and len(notices) == record.get("noticesSize"),
                "embedded linked notices identity mismatch",
            )
        archives.append(archive)
    _require(seen == set(TARGETS), "release requires the complete target matrix")
    _require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
        "invalid public repository identity",
    )
    commit_url = f"https://github.com/{repository}/tree/{source['commit']}"
    notes = (
        f"Vole {source['version']} CLI for Linux, macOS and Windows (amd64/arm64).\n\n"
        "Archives contain only the executable. Complete linked licenses and notices "
        "are retained inside each executable between the "
        "VOLE_CLI_RELEASE_NOTICES_BEGIN and VOLE_CLI_RELEASE_NOTICES_END "
        "text markers.\n\n"
        f"[Vole source and license]({commit_url}) · "
        f"[Locked dependency sources]({commit_url}/Cargo.lock)\n\n"
        "Windows Wintun requires a host-provided wintun.dll beside the executable; "
        "the host configures addresses, DNS, routes and physical egress. "
        "The DLL and WinRT package hosts are not included.\n"
    )
    notes_path.write_text(notes, encoding="utf-8")
    return archives


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--target", choices=TARGETS, required=True)
    for command in (build, commands.add_parser("assemble")):
        command.add_argument("--tag", required=True)
        command.add_argument("--repository", required=True)
        if command is not build:
            command.add_argument("--input", type=Path, required=True)
            command.add_argument("--notes", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        build_release(args.target, args.tag, args.repository)
    else:
        for path in assemble_release(args.tag, args.input, args.repository, args.notes):
            print(path)


if __name__ == "__main__":
    main()
