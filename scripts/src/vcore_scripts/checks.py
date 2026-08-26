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


def _tls_dependency_errors(metadata: dict[str, Any], core_dir: Path) -> list[str]:
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

    rustls = require_single("rustls", "0.23.43")
    tokio_rustls = require_single("tokio-rustls", "0.26.4")
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
        rustls_source = rustls.get("source")
        if rustls_source is None:
            expected = (core_dir.parent / "rustls" / "rustls" / "Cargo.toml").resolve()
            actual = Path(rustls["manifest_path"]).resolve()
            if actual != expected:
                errors.append(
                    "path-patched rustls must be the adjacent OneXray fork; "
                    f"resolved manifest: {actual}"
                )
        elif "github.com/onexray/rustls" not in rustls_source.lower():
            errors.append(
                "rustls must come from the OneXray fork; "
                f"resolved source: {rustls_source}"
            )

    if tokio_rustls is not None:
        source = tokio_rustls.get("source") or ""
        if source not in CRATES_IO_SOURCES:
            errors.append(
                "tokio-rustls must be the crates.io release; "
                f"resolved source: {source or 'path'}"
            )

    for package in packages:
        name = package["name"].lower()
        source = (package.get("source") or "").lower()
        if name.startswith("aws-lc"):
            errors.append(
                f"AWS-LC package is forbidden: {package['name']} {package['version']}"
            )
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
    errors = _tls_dependency_errors(metadata, CORE_DIR)
    if errors:
        raise RuntimeError(
            "\n".join(f"TLS dependency check failed: {error}" for error in errors)
        )

    ring = next(
        package for package in metadata["packages"] if package["name"] == "ring"
    )
    print("TLS dependency check passed:")
    print("- one OneXray rustls 0.23.43")
    print("- one official tokio-rustls 0.26.4")
    print(f"- one registry ring {ring['version']} provider")
    print("- no Watfaq, AWS-LC, or second rustls version")
