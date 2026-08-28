#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CRATE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REFERENCE_DIR=${ANYTLS_GO_DIR:-"$CRATE_DIR/../references/anytls-go"}
PASSWORD=${ANYTLS_INTEROP_PASSWORD:-vcore-anytls-interop}
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vcore-anytls.XXXXXX")
SERVER_PID=

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build the local anytls-go reference server" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required to reserve a local interoperability port" >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  echo "Git is required to identify the anytls-go reference revision" >&2
  exit 2
fi
if [ ! -f "$REFERENCE_DIR/go.mod" ] || [ ! -d "$REFERENCE_DIR/cmd/server" ]; then
  echo "anytls-go reference checkout was not found at $REFERENCE_DIR" >&2
  echo "Set ANYTLS_GO_DIR to its local checkout" >&2
  exit 2
fi
REFERENCE_PREFIX=$(git -C "$REFERENCE_DIR" rev-parse --show-prefix 2>/dev/null) || {
  echo "anytls-go reference is not a Git checkout: $REFERENCE_DIR" >&2
  exit 2
}
if [ -n "$REFERENCE_PREFIX" ]; then
  echo "anytls-go reference must be the root of its Git checkout: $REFERENCE_DIR" >&2
  exit 2
fi
REFERENCE_REVISION=$(git -C "$REFERENCE_DIR" rev-parse --verify HEAD 2>/dev/null) || {
  echo "anytls-go reference revision is unavailable: $REFERENCE_DIR" >&2
  exit 2
}

if [ -n "${ANYTLS_INTEROP_PORT:-}" ]; then
  PORT=$ANYTLS_INTEROP_PORT
else
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
fi
ADDRESS="127.0.0.1:$PORT"

printf 'anytls-go revision: %s\n' "$REFERENCE_REVISION"
go version

(
  cd "$REFERENCE_DIR"
  go build -trimpath -o "$TMP_DIR/anytls-server" ./cmd/server
)

LOG_LEVEL=debug "$TMP_DIR/anytls-server" \
  -l "$ADDRESS" \
  -p "$PASSWORD" \
  >"$TMP_DIR/anytls-server.log" 2>&1 &
SERVER_PID=$!

ready=false
attempt=0
while [ "$attempt" -lt 50 ]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$TMP_DIR/anytls-server.log"
    exit 1
  fi
  if python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 0.2); s.close()' \
    127.0.0.1 "$PORT" 2>/dev/null
  then
    ready=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ "$ready" != true ]; then
  echo "anytls-go server did not become ready at $ADDRESS" >&2
  cat "$TMP_DIR/anytls-server.log"
  exit 1
fi

if ! (
  cd "$CRATE_DIR"
  ANYTLS_INTEROP_ADDRESS="$ADDRESS" \
    ANYTLS_INTEROP_PASSWORD="$PASSWORD" \
    cargo test --features interop-test --test anytls_interop -- --ignored --nocapture
); then
  cat "$TMP_DIR/anytls-server.log"
  exit 1
fi

printf 'AnyTLS interop passed: TCP echo, UoT v2 UDP echo, one-session reuse, shutdown\n'
