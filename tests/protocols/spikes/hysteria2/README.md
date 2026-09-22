# N0 Hysteria2 feasibility probe

Test-only workspace: existing VCore `DatagramTransport` → bounded Quinn
`AsyncUdpSocket` → HTTP/3 authentication → Hysteria2 TCP stream. No production
YAML fields, dependency changes, private TLS hooks, or third-party source edits.

From the VCore root:

```sh
cargo test --locked --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml \
  --target-dir target/interop/n0-hysteria2-build
cargo build --locked --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml \
  --target-dir target/interop/n0-hysteria2-build
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/run.py \
  --native-hysteria
```

Rebuild after Rust changes. The harness requires `openssl` (override with
`--openssl`) and fresh official downloads on every run: Mihomo latest, plus
Hysteria latest with `--native-hysteria`. Versions come from the binaries; no
GitHub API, reference checkout, local peer compilation, or old-cache fallback.
The native Hysteria asset mapping is macOS/Linux only; this does not add Linux
support to VCore. Only macOS execution is recorded here.

The default seven cases use Mihomo: DIRECT, SOCKS5 UDP, incorrect password,
incorrect certificate name, and protect rejection at DIRECT UDP / SOCKS5 TCP /
SOCKS5 UDP. `--native-hysteria` adds UDP-disabled capability negotiation and a
normal TCP response from official Hysteria. That case does **not** assert native
half-close support. The public stream behavior is tested against Mihomo.

The separate diagnostic intentionally remains red with Hysteria 2.12.3:

```sh
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/run.py \
  --native-half-close
```

It requires the peer to retain the reverse direction after client FIN. Native
Hysteria closes both forwarding directions after either copy finishes; see the
[acceptance report](../../../../docs/acceptance/next-protocols/N0-hysteria2.md).
Do not reinterpret that failure as a pass or patch the peer to hide it.

Results, actual binary identities, input hashes and local peer logs stay in
`target/interop/n0-hysteria2/`. `result.json` and `half-close-result.json` are
separate; a started but unsuccessful run stays `incomplete`, with the mismatched
case in `last-failure.json`. Logs may contain synthetic loopback addresses and
local paths; do not upload them as public artifacts. Temporary credentials,
certificates and owned processes are cleaned up, including on failure. The
existing harness lock and dual-family TCP/UDP reservations are reused. No host
route, DNS, firewall, VPN, or container mutation is performed.

The adapter has one connection/peer, one reader and one writer poller; queues are
32 packets each, packets at most 1400 bytes, QUIC MTU fixed at 1200. A full send
queue returns `WouldBlock`; a full receive queue pauses consumption until Quinn
frees capacity. Explicit stop joins the owner; Drop only provides cancellation
fallback. This is not the final multi-session N1 datagram driver, HY2 UDP codec,
Brutal controller, hop adapter, or XHTTP/H3 transport.
