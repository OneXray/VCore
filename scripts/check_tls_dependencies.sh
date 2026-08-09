#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CORE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to inspect Cargo metadata" >&2
  exit 2
}

METADATA_FILE=$(mktemp "${TMPDIR:-/tmp}/vcore-cargo-metadata.XXXXXX")
trap 'rm -f "$METADATA_FILE"' EXIT HUP INT TERM

cargo metadata \
  --manifest-path "$CORE_DIR/Cargo.toml" \
  --locked \
  --all-features \
  --format-version 1 \
  >"$METADATA_FILE"

python3 - "$METADATA_FILE" "$CORE_DIR" <<'PY'
import json
from pathlib import Path
import sys


metadata_path = Path(sys.argv[1])
core_dir = Path(sys.argv[2]).resolve()
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
packages = metadata["packages"]
nodes = metadata["resolve"]["nodes"]
errors = []
crates_io_sources = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://index.crates.io/",
}


def packages_named(name):
    return [package for package in packages if package["name"] == name]


def require_single_package(name, version):
    matches = packages_named(name)
    resolved = ", ".join(
        sorted(f'{package["version"]} ({package.get("source") or "path"})' for package in matches)
    ) or "none"
    if len(matches) != 1 or matches[0]["version"] != version:
        errors.append(f"expected exactly one {name} {version}; resolved: {resolved}")
        return None
    return matches[0]


rustls = require_single_package("rustls", "0.23.42")
tokio_rustls = require_single_package("tokio-rustls", "0.26.4")
ring = packages_named("ring")

if len(ring) != 1:
    resolved = ", ".join(sorted(package["version"] for package in ring)) or "none"
    errors.append(f"expected exactly one ring provider package; resolved: {resolved}")
elif not (ring[0].get("source") or "").startswith("registry+"):
    errors.append(f'ring must come from crates.io; resolved source: {ring[0].get("source") or "path"}')
elif ring[0].get("source") not in crates_io_sources:
    errors.append(f'ring must come from crates.io; resolved source: {ring[0].get("source")}')

if rustls is not None:
    rustls_source = rustls.get("source")
    if rustls_source is None:
        expected_manifest = (core_dir.parent / "rustls" / "rustls" / "Cargo.toml").resolve()
        actual_manifest = Path(rustls["manifest_path"]).resolve()
        if actual_manifest != expected_manifest:
            errors.append(
                "path-patched rustls must be the adjacent OneXray fork; "
                f"resolved manifest: {actual_manifest}"
            )
    elif "github.com/onexray/rustls" not in rustls_source.lower():
        errors.append(f"rustls must come from the OneXray fork; resolved source: {rustls_source}")

if tokio_rustls is not None:
    source = tokio_rustls.get("source") or ""
    if source not in crates_io_sources:
        errors.append(
            "tokio-rustls must be the crates.io release; "
            f"resolved source: {source or 'path'}"
        )

for package in packages:
    name = package["name"].lower()
    source = (package.get("source") or "").lower()
    if name.startswith("aws-lc"):
        errors.append(f'AWS-LC package is forbidden: {package["name"]} {package["version"]}')
    if "watfaq" in source:
        errors.append(
            f'Watfaq dependency is forbidden: {package["name"]} {package["version"]} ({source})'
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
            errors.append(f'rustls is missing required features: {", ".join(sorted(missing))}')
        if forbidden:
            errors.append(f'rustls enables forbidden provider features: {", ".join(sorted(forbidden))}')

if errors:
    for error in errors:
        print(f"TLS dependency check failed: {error}", file=sys.stderr)
    raise SystemExit(1)

print("TLS dependency check passed:")
print("- one OneXray rustls 0.23.42")
print("- one official tokio-rustls 0.26.4")
print(f'- one registry ring {ring[0]["version"]} provider')
print("- no Watfaq, AWS-LC, or second rustls version")
PY
