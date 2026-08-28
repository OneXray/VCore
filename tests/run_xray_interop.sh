#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CRATE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
XRAY_BIN=${XRAY_BIN:-xray}
PORT=${XRAY_INTEROP_PORT:-24443}
CAMOUFLAGE_PORT=${XRAY_INTEROP_CAMOUFLAGE_PORT:-24444}
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vcore-xray.XXXXXX")
XRAY_PID=
CAMOUFLAGE_PID=

if [ -n "${OPENSSL_BIN:-}" ]; then
  OPENSSL=$OPENSSL_BIN
else
  OPENSSL=openssl
  for candidate in \
    openssl3 \
    /opt/homebrew/opt/openssl@3/bin/openssl \
    /usr/local/opt/openssl@3/bin/openssl
  do
    if command -v "$candidate" >/dev/null 2>&1 && \
      "$candidate" s_client -help 2>&1 | grep -Fq -- '-sigalgs'
    then
      OPENSSL=$candidate
      break
    fi
  done
fi

if ! command -v "$OPENSSL" >/dev/null 2>&1 || \
  ! "$OPENSSL" s_client -help 2>&1 | grep -Fq -- '-sigalgs'
then
  echo "OpenSSL with s_client -sigalgs support is required; set OPENSSL_BIN" >&2
  exit 2
fi

cleanup() {
  if [ -n "$XRAY_PID" ]; then
    kill "$XRAY_PID" 2>/dev/null || true
    wait "$XRAY_PID" 2>/dev/null || true
  fi
  if [ -n "$CAMOUFLAGE_PID" ]; then
    kill "$CAMOUFLAGE_PID" 2>/dev/null || true
    wait "$CAMOUFLAGE_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if ! command -v "$XRAY_BIN" >/dev/null 2>&1; then
  echo "Xray is required; set XRAY_BIN to its executable" >&2
  exit 2
fi
"$XRAY_BIN" version >"$TMP_DIR/xray-version.txt"
sed -n '1,2p' "$TMP_DIR/xray-version.txt"
"$OPENSSL" version

"$OPENSSL" req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=VCore Interop CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$TMP_DIR/ca.key" -out "$TMP_DIR/ca.pem" >/dev/null 2>&1
"$OPENSSL" req -newkey rsa:2048 -sha256 -nodes \
  -subj '/CN=vcore.test' \
  -keyout "$TMP_DIR/server.key" -out "$TMP_DIR/server.csr" >/dev/null 2>&1
printf '%s\n' \
  'basicConstraints=CA:FALSE' \
  'keyUsage=digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:vcore.test' >"$TMP_DIR/server.ext"
"$OPENSSL" x509 -req -in "$TMP_DIR/server.csr" \
  -CA "$TMP_DIR/ca.pem" -CAkey "$TMP_DIR/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$TMP_DIR/server.ext" \
  -out "$TMP_DIR/server.pem" >/dev/null 2>&1
"$OPENSSL" x509 -in "$TMP_DIR/ca.pem" -outform DER -out "$TMP_DIR/ca.der"

# REALITY forwards the client's original ClientHello to its camouflage target.
# Use an ECDSA-only target so an ED25519-only signature_algorithms extension is
# rejected before ServerHello, while a browser-compatible list can proceed.
"$OPENSSL" ecparam -name prime256v1 -genkey -noout \
  -out "$TMP_DIR/camouflage.key"
"$OPENSSL" req -x509 -new -key "$TMP_DIR/camouflage.key" -sha256 -days 1 \
  -subj '/CN=www.cloudflare.com' \
  -addext 'subjectAltName=DNS:www.cloudflare.com' \
  -addext 'extendedKeyUsage=serverAuth' \
  -out "$TMP_DIR/camouflage.pem" >/dev/null 2>&1
"$OPENSSL" s_server \
  -accept "127.0.0.1:$CAMOUFLAGE_PORT" \
  -cert "$TMP_DIR/camouflage.pem" \
  -key "$TMP_DIR/camouflage.key" \
  -tls1_3 \
  -alpn h2,http/1.1 \
  -quiet \
  >"$TMP_DIR/camouflage.log" 2>&1 &
CAMOUFLAGE_PID=$!
sleep 1
if ! kill -0 "$CAMOUFLAGE_PID" 2>/dev/null; then
  cat "$TMP_DIR/camouflage.log"
  exit 1
fi

if "$OPENSSL" s_client \
  -connect "127.0.0.1:$CAMOUFLAGE_PORT" \
  -servername www.cloudflare.com \
  -tls1_3 \
  -sigalgs ed25519 \
  -alpn h2 \
  -msg \
  </dev/null >"$TMP_DIR/ed25519-only-client.log" 2>&1
then
  echo "ECDSA camouflage unexpectedly accepted an ED25519-only ClientHello" >&2
  exit 1
fi
if ! grep -Fq 'ClientHello' "$TMP_DIR/ed25519-only-client.log" || \
  grep -Fq 'ServerHello' "$TMP_DIR/ed25519-only-client.log" || \
  ! grep -Eq 'fatal handshake_failure|alert handshake failure' \
    "$TMP_DIR/ed25519-only-client.log"
then
  echo "ECDSA camouflage preflight did not fail before ServerHello as expected" >&2
  cat "$TMP_DIR/ed25519-only-client.log"
  exit 1
fi
printf 'ECDSA camouflage preflight: ED25519-only ClientHello rejected before ServerHello\n'

for SECURITY in reality tls; do
  for CASE in packet-up stream-one split; do
    CLIENT_MODE=$CASE
    SERVER_MODE=$CASE
    SPLIT=0
    if [ "$CASE" = split ]; then
      CLIENT_MODE=auto
      SPLIT=1
      if [ "$SECURITY" = reality ]; then
        SERVER_MODE=stream-up
      else
        SERVER_MODE=packet-up
      fi
    fi
    printf 'Xray interop: %s + %s (server %s, split %s)\n' \
      "$SECURITY" "$CLIENT_MODE" "$SERVER_MODE" "$SPLIT"
    sed \
      -e "s|{{PORT}}|$PORT|g" \
      -e "s|{{CERT_FILE}}|$TMP_DIR/server.pem|g" \
      -e "s|{{KEY_FILE}}|$TMP_DIR/server.key|g" \
      -e "s|www.cloudflare.com:443|127.0.0.1:$CAMOUFLAGE_PORT|g" \
      -e "s/\"mode\": \"packet-up\"/\"mode\": \"$SERVER_MODE\"/g" \
      "$SCRIPT_DIR/fixtures/xray-$SECURITY-xhttp.json" >"$TMP_DIR/xray.json"

    "$XRAY_BIN" run -c "$TMP_DIR/xray.json" \
      >"$TMP_DIR/xray-$SECURITY-$CASE.log" 2>&1 &
    XRAY_PID=$!
    sleep 6
    if ! kill -0 "$XRAY_PID" 2>/dev/null; then
      cat "$TMP_DIR/xray-$SECURITY-$CASE.log"
      exit 1
    fi

    if ! (
      cd "$CRATE_DIR"
      XRAY_INTEROP_ADDRESS="127.0.0.1:$PORT" \
        XRAY_INTEROP_MODE="$CLIENT_MODE" \
        XRAY_INTEROP_SPLIT="$SPLIT" \
        XRAY_INTEROP_SECURITY="$SECURITY" \
        XRAY_INTEROP_CA_DER="$TMP_DIR/ca.der" \
        cargo test --features interop-test,ffi --test xray_interop -- --ignored --nocapture
    ); then
      cat "$TMP_DIR/xray-$SECURITY-$CASE.log"
      exit 1
    fi

    kill "$XRAY_PID" 2>/dev/null || true
    wait "$XRAY_PID" 2>/dev/null || true
    XRAY_PID=
  done
done
