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
existing harness lock and dual-family TCP/UDP reservations are reused. This
`run.py` entry makes no host route, DNS, firewall, VPN, or container mutation.

## Native single-state hopping and XHTTP/H3

After rebuilding the same probe, run these additional N0 entry gates:

```sh
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/native_hop.py
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/native_hop.py --reject-hop
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/native_h3.py
```

`native_hop.py` uses the preconfigured, labelled `vcore-mihomo-interop` host-only
Apple Container network and pinned Alpine image from the main interop tooling.
It freshly downloads official Linux ARM64 Hysteria. A temporary default-network
VM updates the official APK index and fetches nftables; a separate offline peer
VM installs those signed packages. Only the peer VM receives `CAP_NET_ADMIN`.
Hysteria itself creates one UDP listener plus its native port-range redirect.
An independent nft table observes both ingress ports and source-port sets.
The VM's default MTU 1280 cannot send Go QUIC's 1280-byte UDP Initial plus IP/UDP
headers, so the harness sets **that VM's** `eth0` to 1500. Nothing changes the
host's MTU, routes, DNS, firewall or VPN. Both owned VMs and their rules are
removed, including on test failure; the shared network/image remain.

The probe echoes half of one TCP payload before opening a second protected
datagram transport and calling Quinn's public `Endpoint::rebind_abstract`.
The second socket maps one logical peer to the other physical port. It retains
the same QUIC connection and stream, without reauthentication/replay. Both
owners stop/join. `--reject-hop` refuses the second protect call: only the first
32 KiB may reach the target; the second ingress must see zero packets.
This is one deterministic IPv4 hop, not the full N6 timer/overlap/UDP matrix.

`native_h3.py` currently runs on macOS ARM64 and freshly downloads official
Xray plus Mihomo (SOCKS5 upstream, and optionally an XHTTP reference client).
One VLESS/XHTTP `stream-one` POST over
H3 uses the same controlled adapter, validates HTTP status **and** the VLESS
response, and verifies server-first / full 64 KiB echo / EOF. The eight normal
cases cover DIRECT, SOCKS5 UDP, wrong SNI/path/UUID, and three protect failures.
Mihomo's XHTTP listener has no H3 UDP entry, hence the native Xray peer.

The ninth case implements Mihomo's connection-close contract: after reading the
server-first bytes and exact echo, application upload EOF closes both request
and response directions. It must not wait for an EOF-triggered downstream tail;
the target connection and all owned drivers must finish within their deadlines.
This is not TCP half-close support or a production H3 implementation.

Use the official Mihomo **client** against the same Xray server as a differential
oracle (two additional cases, eleven total):

```sh
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/native_h3.py --compare-mihomo-close
```

The reference client trusts only the generated fixture certificate in addition
to its normal roots; certificate verification is not skipped. Both clients must
receive the exact normal response before close and terminate on application EOF
without delivering a post-close tail. Production H2 tests exercise the public
`XHttpClient` stream in all three modes and independent download connections;
see the [close contract and evidence](../../../../docs/acceptance/next-protocols/XHTTP-close.md).

The separate raw Xray request-EOF/tail diagnostic remains a failing capability
probe, **not a required Mihomo-compatible XHTTP close gate**:

```sh
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/native_h3.py --half-close
```

It adds a tenth case after the normal nine. With Xray 26.3.27, the client
receives the payload but loses the target's 14-byte EOF-triggered tail. Do not
call ordinary response EOF half-close support, swallow FIN, patch third-party
code or convert this diagnostic to an expected success. See the
[entry-gate evidence and limits](../../../../docs/acceptance/next-protocols/N0-quic-entries.md).

Each native run has a unique directory in `target/interop/n0-hysteria-hop/` or
`target/interop/n0-xray-h3/`; reports preserve failures separately and record
parent commit, input hashes, binary versions/hashes and cleanup. Downloads have
90-second/128-MiB budgets, probe cases a 30-second process watchdog, and the
VCore experiment shares one 10-second establishment/data deadline plus a
5-second driver-stop deadline. Peer launches/guest commands/APK work and cleanup
also have explicit timeouts. This is not the N1 unified fault-injection runner.

The adapter has one connection/peer, one reader and one writer poller; queues are
32 packets each, packets at most 1400 bytes, QUIC MTU fixed at 1200. A full send
queue returns `WouldBlock`; a full receive queue pauses consumption until Quinn
frees capacity. Explicit stop joins the owner; Drop only provides cancellation
fallback. A hop temporarily owns two such bounded adapters; Quinn may stop
polling the old socket after receiving a new-path connection packet, so retaining
its owner is not proof of a production overlap policy. This is not the final
multi-session N1 driver, HY2 UDP codec, Brutal controller, production hopping,
or complete XHTTP transport.
