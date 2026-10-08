"""Collect linked dependency licenses for embedding in release binaries."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

REGISTRY = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://index.crates.io/",
}


MAX_NOTICES_BYTES = 16 * 1024 * 1024


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


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _output(arguments: list[str], root: Path, env: dict | None = None) -> str:
    return subprocess.check_output(
        arguments, cwd=root, env=env, text=True, timeout=60
    ).strip()


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
) -> bytes:
    _require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
        "invalid public repository identity",
    )
    sections = [
        f"Vole {source['version']} linked dependency licenses and notices\n"
        f"Source commit: {source['commit']}\n"
    ]
    linked_names = {packages[identifier]["name"] for identifier in linked}
    for item in sorted(
        (packages[identifier] for identifier in linked),
        key=lambda item: (item["name"], item["version"]),
    ):
        base = Path(item["manifest_path"]).parent
        if item.get("source") in REGISTRY:
            url = f"https://crates.io/api/v1/crates/{item['name']}/{item['version']}/download"
        elif (dependency_source := item.get("source") or "").startswith("git+"):
            url = (
                dependency_source.removeprefix("git+").split("?", 1)[0].split("#", 1)[0]
                + "/tree/"
                + dependency_source.rsplit("#", 1)[1]
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
        if item["name"] == "tun-rs" and "-windows-" in target:
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
        for label, content in notices:
            _require(
                bool(content) and b"\0" not in content,
                "license notices must be nonempty text without NUL bytes",
            )
            text = content.decode("utf-8")
            sections.append(f"\n--- {label} ---\n{text}\n")
    content = "".join(sections).encode("utf-8")
    _require(
        0 < len(content) <= MAX_NOTICES_BYTES,
        "linked notices must contain at most 16 MiB of text",
    )
    return content


def collect_rust_notices(root: Path) -> bytes:
    """Cargo omits the linked standard library; retain its official report."""
    rustc = _output(["rustc", "-Vv"], root)
    revision = re.search(r"(?m)^commit-hash: ([0-9a-f]{40})$", rustc)
    version = re.search(r"(?m)^release: (\d+\.\d+\.\d+)$", rustc)
    _require(
        revision is not None and version is not None,
        "release notices require an identified stable Rust toolchain",
    )
    sysroot = Path(_output(["rustc", "--print", "sysroot"], root))
    documentation = sysroot / "share/doc/rust"
    report = documentation / "COPYRIGHT-library.html"
    _require(
        report.is_file(),
        "Rust standard-library notices require the rust-docs component",
    )
    paths = [report, *sorted((documentation / "licenses").glob("*.txt"))]
    _require(
        {"MIT.txt", "Apache-2.0.txt"} <= {path.name for path in paths},
        "missing Rust standard-library license terms",
    )
    sections = [
        f"\n===== Rust standard library {version[1]} =====\n"
        f"Source: https://github.com/rust-lang/rust/tree/{revision[1]}/library\n".encode()
    ]
    for path in paths:
        _require(
            path.is_file() and not path.is_symlink(),
            "Rust notice source must be a regular file",
        )
        content = path.read_bytes()
        _require(
            content and b"\0" not in content,
            "invalid Rust standard-library notice text",
        )
        content.decode("utf-8")
        label = path.relative_to(documentation).as_posix()
        sections.append(f"\n--- {label} ---\n".encode() + content + b"\n")
    content = b"".join(sections)
    _require(
        len(content) <= MAX_NOTICES_BYTES,
        "Rust library notices exceed the embedded text limit",
    )
    return content


def linked_packages(metadata: dict) -> dict:
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    pending = [metadata["resolve"]["root"]]
    linked = {}
    while pending:
        identifier = pending.pop()
        package = packages[identifier]
        if identifier in linked or any(
            "proc-macro" in t["kind"] for t in package["targets"]
        ):
            continue
        linked[identifier] = package
        pending.extend(
            d["pkg"]
            for d in nodes[identifier]["deps"]
            if any(k["kind"] is None for k in d["dep_kinds"])
        )
    return linked


def collect(
    root: Path,
    targets: tuple[str, ...],
    features: str,
    info: dict,
    repository: str,
    android_ndk: Path | None = None,
) -> bytes:
    packages = {}
    for target in targets:
        metadata = json.loads(
            _output(
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
        packages.update(linked_packages(metadata))
    text = collect_notices(packages, set(packages), root, info, repository, targets[0])
    text += collect_rust_notices(root)
    if android_ndk is not None:
        files = sorted(p for p in android_ndk.glob("NOTICE*") if p.is_file())
        _require(bool(files), "missing Android NDK runtime notices")
        for path in files:
            text += f"\n--- Android NDK/{path.name} ---\n".encode() + path.read_bytes()
    _require(0 < len(text) <= MAX_NOTICES_BYTES, "release notices exceed 16 MiB")
    return text
