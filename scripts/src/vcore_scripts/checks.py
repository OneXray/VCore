from __future__ import annotations

import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[3]
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://index.crates.io/",
}
RUSTLS_GIT_SOURCE_PREFIX = (
    "git+https://github.com/OneXray/rustls?branch=vcore/reality-0.23#"
)
SHADOWSOCKS_REVISION = "ab388c7466d21f979430e33cc9ef10e22fb05955"
SHADOWSOCKS_GIT_SOURCE = (
    "git+https://github.com/shadowsocks/shadowsocks-rust.git"
    f"?rev={SHADOWSOCKS_REVISION}#{SHADOWSOCKS_REVISION}"
)

_C_SOURCE = r"""#include "vcore.h"
int main(void) {
  char *response = VCoreInvoke(
      "{\"apiVersion\":5,\"method\":\"version\",\"payload\":{}}");
  VCoreFree(response);
  VCoreFree((char *)0);
  return 0;
}
"""

_CPP_SOURCE = r"""#include "vcore.h"
int main() {
  char *response = VCoreInvoke(
      "{\"apiVersion\":5,\"method\":\"version\",\"payload\":{}}");
  VCoreFree(response);
  VCoreFree(nullptr);
  return 0;
}
"""


def check_c_header() -> None:
    if platform.system() == "Darwin":
        c_compiler = ["xcrun", "clang"]
        cpp_compiler = ["xcrun", "clang++"]
    else:
        clang = shutil.which("clang")
        clang_cpp = shutil.which("clang++")
        if not clang or not clang_cpp:
            raise RuntimeError("clang and clang++ are required to check vcore.h")
        c_compiler = [clang]
        cpp_compiler = [clang_cpp]

    with tempfile.TemporaryDirectory(prefix="vcore-header-") as directory:
        root = Path(directory)
        c_source = root / "header.c"
        cpp_source = root / "header.cc"
        c_source.write_text(_C_SOURCE, encoding="utf-8")
        cpp_source.write_text(_CPP_SOURCE, encoding="utf-8")
        subprocess.run(
            [
                *c_compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsyntax-only",
                "-I",
                str(CORE_DIR / "include"),
                str(c_source),
            ],
            check=True,
        )
        subprocess.run(
            [
                *cpp_compiler,
                "-std=c++17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsyntax-only",
                "-I",
                str(CORE_DIR / "include"),
                str(cpp_source),
            ],
            check=True,
        )


def _shadowsocks_aws_lc_errors(metadata: dict[str, Any]) -> list[str]:
    """Allow only the pinned official SS -> crypto -> AWS-LC dependency chain."""
    packages = metadata["packages"]
    aws = [p for p in packages if p["name"].lower().startswith("aws-lc")]
    if not aws:
        return []
    errors: list[str] = []
    allowed: dict[str, dict[str, Any]] = {}
    expected = {
        "shadowsocks": ("1.25.0", {SHADOWSOCKS_GIT_SOURCE}),
        "shadowsocks-crypto": ("0.8.0", CRATES_IO_SOURCES),
        "aws-lc-rs": (None, CRATES_IO_SOURCES),
        "aws-lc-sys": (None, CRATES_IO_SOURCES),
    }
    for name, (version, sources) in expected.items():
        matches = [p for p in packages if p["name"] == name]
        if (
            len(matches) != 1
            or (version is not None and matches[0]["version"] != version)
            or matches[0].get("source") not in sources
        ):
            errors.append(
                f"AWS-LC package is forbidden without the official {name} graph"
            )
        else:
            allowed[name] = matches[0]
    for package in aws:
        if package["name"] not in {"aws-lc-rs", "aws-lc-sys"}:
            errors.append(f"AWS-LC package is forbidden: {package['name']}")
    if len(allowed) != len(expected):
        return errors

    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    parents: dict[str, set[str]] = {}
    for node in nodes.values():
        for dependency in node.get("deps", []):
            parents.setdefault(dependency["pkg"], set()).add(node["id"])
    for child, parent in (
        ("shadowsocks-crypto", "shadowsocks"),
        ("aws-lc-rs", "shadowsocks-crypto"),
        ("aws-lc-sys", "aws-lc-rs"),
    ):
        child_id = allowed[child]["id"]
        if child_id not in nodes or parents.get(child_id) != {allowed[parent]["id"]}:
            errors.append(
                f"AWS-LC exception requires {child} to be used only by {parent}"
            )
    for name, required in (
        ("shadowsocks", {"aead-cipher-2022"}),
        ("shadowsocks-crypto", {"v2", "aws-lc"}),
    ):
        features = set(nodes.get(allowed[name]["id"], {}).get("features", []))
        if not required <= features:
            errors.append(f"AWS-LC exception requires the SS 2022 features of {name}")
        if features & {"aead-cipher-2022-extra", "v2-extra"}:
            errors.append(
                f"only the three standard SS 2022 ciphers are allowed: {name}"
            )
    return errors


def _tls_dependency_errors(metadata: dict[str, Any]) -> list[str]:
    packages = metadata["packages"]
    nodes = metadata["resolve"]["nodes"]
    errors: list[str] = []

    def named(name: str) -> list[dict[str, Any]]:
        return [package for package in packages if package["name"] == name]

    def require_single(name: str, version: str) -> dict[str, Any] | None:
        matches = named(name)
        resolved = (
            ", ".join(
                sorted(
                    f"{package['version']} ({package.get('source') or 'path'})"
                    for package in matches
                )
            )
            or "none"
        )
        if len(matches) != 1 or matches[0]["version"] != version:
            errors.append(
                f"expected exactly one {name} {version}; resolved: {resolved}"
            )
            return None
        return matches[0]

    rustls = require_single("rustls", "0.23.45")
    tokio_rustls = require_single("tokio-rustls", "0.26.5")
    ring = named("ring")

    if len(ring) != 1:
        resolved = ", ".join(sorted(package["version"] for package in ring)) or "none"
        errors.append(
            f"expected exactly one ring provider package; resolved: {resolved}"
        )
    else:
        ring_source = ring[0].get("source") or ""
        if ring_source not in CRATES_IO_SOURCES:
            resolved = ring_source or "path"
            errors.append(f"ring must come from crates.io; resolved source: {resolved}")

    if rustls is not None:
        rustls_source = rustls.get("source") or ""
        revision = rustls_source.removeprefix(RUSTLS_GIT_SOURCE_PREFIX)
        if len(revision) != 40 or any(
            character not in "0123456789abcdef" for character in revision
        ):
            errors.append(
                "rustls must come from the vcore/reality-0.23 GitHub branch; "
                f"resolved source: {rustls_source or 'path'}"
            )

    if tokio_rustls is not None:
        source = tokio_rustls.get("source") or ""
        if source not in CRATES_IO_SOURCES:
            errors.append(
                "tokio-rustls must be the crates.io release; "
                f"resolved source: {source or 'path'}"
            )

    for package in packages:
        source = (package.get("source") or "").lower()
        if "watfaq" in source:
            errors.append(
                f"Watfaq dependency is forbidden: {package['name']} "
                f"{package['version']} ({source})"
            )

    if rustls is not None:
        rustls_node = next((node for node in nodes if node["id"] == rustls["id"]), None)
        if rustls_node is None:
            errors.append("rustls is missing from the resolved dependency graph")
        else:
            features = set(rustls_node["features"])
            missing = {"reality", "ring"} - features
            forbidden = {"aws_lc_rs", "fips"} & features
            if missing:
                errors.append(
                    f"rustls is missing required features: {', '.join(sorted(missing))}"
                )
            if forbidden:
                errors.append(
                    "rustls enables forbidden provider features: "
                    f"{', '.join(sorted(forbidden))}"
                )
            # Check the fork's actual edge, not an unrelated newer copy elsewhere.
            dependencies = {dep["pkg"] for dep in rustls_node.get("deps", [])}
            x25519 = [p for p in named("x25519-dalek") if p["id"] in dependencies]
            if (
                len(x25519) != 1
                or x25519[0]["version"] != "3.0.0"
                or x25519[0].get("source") not in CRATES_IO_SOURCES
            ):
                errors.append(
                    "rustls REALITY must directly use registry x25519-dalek 3.0.0"
                )
            else:
                x25519_node = next(
                    (node for node in nodes if node["id"] == x25519[0]["id"]), None
                )
                x25519_features = set((x25519_node or {}).get("features", []))
                if not {"static_secrets", "zeroize"} <= x25519_features:
                    errors.append(
                        "rustls REALITY x25519-dalek requires "
                        "static_secrets and zeroize"
                    )

    errors.extend(_shadowsocks_aws_lc_errors(metadata))
    return errors


def check_tls_dependencies() -> None:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(CORE_DIR / "Cargo.toml"),
            "--locked",
            "--all-features",
            "--format-version",
            "1",
        ],
        cwd=CORE_DIR,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    metadata = json.loads(result.stdout)
    errors = _tls_dependency_errors(metadata)
    if errors:
        raise RuntimeError(
            "\n".join(f"TLS dependency check failed: {error}" for error in errors)
        )

    ring = next(
        package for package in metadata["packages"] if package["name"] == "ring"
    )
    rustls = next(
        package for package in metadata["packages"] if package["name"] == "rustls"
    )
    revision = rustls["source"].rsplit("#", 1)[1]
    print("TLS dependency check passed:")
    print(f"- one OneXray/rustls 0.23.45 vcore/reality-0.23 @ {revision[:12]}")
    print("- one official tokio-rustls 0.26.5")
    print("- REALITY directly uses registry x25519-dalek 3.0.0 with zeroize")
    print(f"- one registry ring {ring['version']} provider")
    print("- no Watfaq or second rustls version; TLS uses ring only")
    if any(p["name"] == "aws-lc-rs" for p in metadata["packages"]):
        print("- AWS-LC is restricted to the pinned official Shadowsocks 2022 chain")
    else:
        print("- no AWS-LC packages")
