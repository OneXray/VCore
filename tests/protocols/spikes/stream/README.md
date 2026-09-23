# N0-B supplied-stream experiment

This independent workspace proves that unmodified public TLS, WS and HTTP/2
libraries can wrap a `BoxStream` provided by VCore. It is **not** a production
transport module, protocol feature or new YAML surface. No reference checkout
or repository-external path is needed.

See the [dependency assessment](../../../../docs/acceptance/next-protocols/N0-stream-dependencies.md)
and [executed acceptance record](../../../../docs/acceptance/next-protocols/N0-stream.md).
The original N0 run left the main Cargo files unchanged. The subsequent
[N1 h2 upgrade](../../../../docs/acceptance/next-protocols/N1-h2.md) updates h2 in
both workspaces to 0.4.19; historical N0 evidence remains version-specific.
Invoke v5 and schema 14 are unchanged.

## Public seam and ownership

- `tls(stream, config, server_name, absolute_deadline)`: caller-controlled trust
  and physical IO; no TLS-library dialer, root-store scan or insecure verifier.
- `websocket(stream, uri, absolute_deadline)`: plain supplied IO, optionally
  already wrapped by TLS; only tungstenite's `handshake` feature is enabled.
- `grpc(stream, uri, absolute_deadline) -> (stream, driver)`: H2/Gun adapter,
  not tonic. Response headers are read lazily so the caller can send first.
  `driver.stop().await` cancels and joins the sole H2 connection task. Drop only
  provides fallback cancellation and must not be reported as a Stop barrier.

The probe opens IO through existing `OutboundConnector` / `Dialer`; DIRECT
and a distinct official Mihomo SOCKS5 upstream are exercised. A test protector
records or rejects physical socket creation before any protocol handshake.
This is not proof of an Android device's actual protect callback.

Ordinary TLS/WS CloseWrite retains the read direction. TLS emits close_notify
and flushes for at most five seconds without shutting down the underlay. WS
flushes queued frames and delegates write shutdown to the supplied IO, without
issuing WS Close. A constant-size wire-boundary observer distinguishes clean
underlay EOF from truncated frames before mapping the library's normal-EOF
error; it does not replace tungstenite's validator/decoder. gRPC shutdown
cancels both directions and wakes a blocked reader, following Mihomo gun.
The experiment owns one physical H2 connection, so cancellation also aborts
that driver; production pooling and sibling-stream isolation are **not proven**.

Experiment budgets: 16 KiB upload chunks, 64 KiB message/record payload limit,
64 KiB H2 stream receive window, 128 KiB H2 connection receive window, 16 KiB
H2 send-buffer setting, 16 KiB header-list setting, 32 adapter iterations/poll.
H2 writes additionally respect actual flow-control capacity; the send-buffer
setting alone is not a hard buffer cap. TLS has a 64 KiB pending-send limit,
not a total handshake/connection-memory bound. These provisional budgets are
not future production configuration contracts.

## Reproduce from the VCore repository root

```sh
cargo test --locked --manifest-path tests/protocols/spikes/stream/Cargo.toml \
  --target-dir target/interop/n0-stream-build --all-targets
cargo clippy --locked --manifest-path tests/protocols/spikes/stream/Cargo.toml \
  --target-dir target/interop/n0-stream-build --all-targets --no-deps -- -D warnings
cargo fmt --manifest-path tests/protocols/spikes/stream/Cargo.toml -- --check
uv run --project scripts --locked ruff check tests/protocols/spikes/stream/run.py
uv run --project scripts --locked ruff format --check tests/protocols/spikes/stream/run.py
uv run --project scripts --locked python tests/protocols/spikes/stream/run.py
```

The last command builds the probe, freshly downloads official latest Mihomo,
queries `-v`, generates temporary synthetic TLS credentials with OpenSSL, and
runs owned loopback processes. Download/version/isolation and certificate/echo
helpers are reused from this repository's existing harness. No API lookup,
local Mihomo compilation, stale-cache fallback, host routing/DNS changes,
third-party patches or disabled loop protection are involved. Each run has a
unique `target/interop/runs/n0-stream-*` directory; failures remain separate.
Temporary credentials/configs and child processes are cleaned on exit. Local
peer logs contain synthetic traffic only and are not committed.

The 42 cases comprise 27 probe checks and 15 official-client close comparisons
(three iterations per mode): TLS/TCP, WS, WSS, gRPC/h2c and gRPC/TLS. Successful
transfers verify server-first data and 64 KiB bidirectional byte identity before
closing; this is not the later 10 MiB/long-run protocol gate. Wrong SNI, wrong
path/service and protect rejection must create no origin connection.

Cross-check the **library**, not a mobile executable, with the appropriate
installed Rust target and platform compiler:

```sh
cargo check --locked --manifest-path tests/protocols/spikes/stream/Cargo.toml \
  --target-dir target/interop/n0-stream-platforms --lib --target aarch64-apple-ios
# With ANDROID_NDK_HOME set to a real installation, API 24:
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang" \
AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar" \
cargo check --locked --manifest-path tests/protocols/spikes/stream/Cargo.toml \
  --target-dir target/interop/n0-stream-android --lib --target aarch64-linux-android
```

Use the compiler's own host directory on other operating systems; scripts do
not assume a user's SDK path. Cross-checks do not prove linking, packaging,
physical devices or Windows. Native Windows and protocol consumers remain
separate gates. WS early-data/custom headers, complete TLS
options, production task/pool integration and formal budgets remain N1/later
work; see the acceptance record for precise PASS/NOT RUN boundaries.
