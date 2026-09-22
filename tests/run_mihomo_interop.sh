#!/bin/sh
set -eu

MIHOMO_TEST_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$MIHOMO_TEST_ROOT"
exec uv run --project scripts --locked vcore-scripts check mihomo-interop "$@"
