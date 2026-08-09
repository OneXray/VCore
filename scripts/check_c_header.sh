#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CORE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP_FILE=$(mktemp "${TMPDIR:-/tmp}/vcore-header.XXXXXX.c")
TMP_CPP_FILE=$(mktemp "${TMPDIR:-/tmp}/vcore-header.XXXXXX.cc")
trap 'rm -f "$TMP_FILE" "$TMP_CPP_FILE"' EXIT HUP INT TERM

printf '%s\n' \
  '#include "vcore.h"' \
  'int main(void) {' \
  '  char *response = VCoreInvoke("{\"apiVersion\":4,\"method\":\"version\",\"payload\":{}}");' \
  '  VCoreFree(response);' \
  '  VCoreFree((char *)0);' \
  '  return 0;' \
  '}' > "$TMP_FILE"
printf '%s\n' \
  '#include "vcore.h"' \
  'int main() {' \
  '  char *response = VCoreInvoke("{\"apiVersion\":4,\"method\":\"version\",\"payload\":{}}");' \
  '  VCoreFree(response);' \
  '  VCoreFree(nullptr);' \
  '  return 0;' \
  '}' > "$TMP_CPP_FILE"
xcrun clang -std=c11 -Wall -Wextra -Werror -fsyntax-only -I "$CORE_DIR/include" "$TMP_FILE"
xcrun clang++ -std=c++17 -Wall -Wextra -Werror -fsyntax-only -I "$CORE_DIR/include" "$TMP_CPP_FILE"
