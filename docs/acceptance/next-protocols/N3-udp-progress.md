# N3 UDP work in progress — 2026-09-23

The native-host observations and commands below are historical. New executions
must satisfy the [container-only server rule](../../testing-isolation.md);
the subsequent [isolated-client comparison](N3-udp-containers.md) is separate
evidence, not a rewrite of these failures.

This is **not N3.3 or N3 sign-off**. The approved close-contract change and its
21-group revalidation are recorded separately in [the close report](N3-close-blocker.md)
and commit `ab535f2`. The current UDP work is uncommitted; no VMess YAML or runtime
graph has been enabled. These UDP failures are unrelated to the removed universal
EOF-tail assertion.

## Implemented wire work

- Preserve a raw UDP body as one datagram, up to the native VMess 15,000-byte
  writer envelope. Keep the existing 4 KiB TCP shaping; splitting a UDP body into
  TCP-sized chunks changes datagram meaning.
- Add IP-only, address-first packetaddr encoding and decoding, bounded receive,
  caller budgets and controlled business-domain resolution. Internal magic names
  are encoded in the protocol and are not sent to a resolver.
- Exercise raw, shared XUDP and packetaddr independently against native peers.
- Omit XUDP's optional global-ID extension when the ID is all zero, matching
  Mihomo's `sing-vmess` writer. The public wire test failed before this adjustment
  and passes afterwards. V2Ray XUDP then reached normal small-packet exchanges;
  the original first-packet failures remain in their own reports.

## Native observations, not blanket acceptance

All peers were freshly obtained through official latest-download preflight.
The executed binaries identified themselves as Mihomo v1.19.31 and V2Ray 5.53.0
on Darwin ARM64. Binary hashes and full identities are retained in each run's
JSON, not inferred from the research checkout.

1. `n3-raw-udp-native-budget-v1`: raw TCP/plain, 13 cipher/flag combinations ×
   IPv4/IPv6/domain, five sizes with 100 exchanges each, passed.
2. `n3-encoded-udp-v2`: XUDP and packetaddr over TCP/plain, the same cipher/flag
   and address families, passed. Source unchanged and owned cleanup both true.
3. `n3-udp-transports-v1`: the expanded 20-group run failed; preserve both
   sporadic Mihomo timeouts and V2Ray size/content failures.
4. `n3-native-udp-diagnostic-v1`: official Mihomo client → official Mihomo TCP
   or V2Ray HTTP/H2, without VCore. Eighteen configurations × six sizes were
   observed. All owned processes joined, source unchanged. This is successful
   **observation collection**, not a passing VCore acceptance run.
5. `n3-zero-global-id-v1`: after omitting the zero extension, V2Ray XUDP small
   packets passed and its large-packet limit remained visible. The selected
   Mihomo cases passed, but that does not establish a fix for sporadic timeouts.
6. `n3-udp-native-bounds-v1`: 13/20 groups passed; five Mihomo groups timed out on
   a first request or reply, and two V2Ray H2 groups encountered a broken pipe
   while closing **after deliberately sending an oversized XUDP packet**.
   Source unchanged and cleanup true. The latter close assertion has since been
   adjusted to allow peer rejection, but has not yet been revalidated natively.

The latest 20-group run's source identity was:

- parent: `ab535f2eb54888a23742b9cc08162df507b93a0e`
- source tree SHA-256: `c061d1b0f8d17353d31b0040a1bf6dbc699b04c5a6c1c308c86d043f43cdc6d3`
- lockfile SHA-256: `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`

## Fixture capacity and retained failures

An independent loopback probe found this host's default UDP send buffer to be
9,216 bytes: 9,216 bytes arrived; 9,217 and 15,000 bytes returned `EMSGSIZE`.
Increasing only the probe-owned socket's buffer allowed 15,000 bytes. No host
sysctl, route, VPN or native-peer socket settings were changed. The harness now
measures the Darwin default instead of treating it as VMess's wire ceiling.

The native-client differential also reproduced V2Ray's smaller packet envelope:
raw packets above 2,048 bytes arrived as multiple datagrams, XUDP above 2,048
bytes did not arrive, and packetaddr could arrive truncated. Even a 2,048-byte
raw request that arrived intact did not receive an intact response. The matching
[V2Ray 5.53 packet writer](https://github.com/v2fly/v2ray-core/blob/v5.53.0/common/crypto/auth.go)
places its length, authentication tag and padding inside a
[2,048-byte buffer](https://github.com/v2fly/v2ray-core/blob/v5.53.0/common/buf/buffer.go).
Fixture budgets account for that overhead and packetaddr's address, while XUDP
has its own packet-reader limit. This is not a new production limit or permission
to truncate an application datagram. Original oversized failures remain FAIL.

## Follow-up client differential

The [matched client investigation](N3-udp-client-differential.md) reproduced
one-byte first-packet timeouts with both VCore and the official Mihomo client.
It then causally reproduced a local loopback-detector false positive: the outer
VMess TCP source port can equal a live Mihomo UDP outlet port. Non-colliding
controls pass without disabling protection or modifying either production core.
A separate host-only probe also reproduced dual-family UDP port overlap and
reply reflection. These findings do not retroactively classify every old failure,
do not fix third-party behavior, and do not sign off the UDP matrix.

## Remaining work

- Extend the container migration to the remaining native acceptance fixtures and
  investigate historical unclassified timeouts separately. Identified local
  failure mechanisms and a later isolated pass do not prove a production fix.
- Revalidate the expanded native matrix after the negative-case close adjustment.
- Complete cancellation, malformed frames, exact wire-size boundaries,
  association/source isolation and controlled DNS failures at the approved seams.
- Complete the public configuration, graph/upstream, measurement, lifecycle,
  coverage and platform work listed in the N3 plan. VMess remains optional and
  unavailable through public YAML until those paths are ready.

Local regression at this work-in-progress boundary:
`cargo test --locked --all-features --all-targets -q` passed (585 library tests,
one library test ignored, plus the listed integration tests); native tests are
ignored by that command and are **not** covered by that success. Focused clippy
and Python lint also passed before the final fixture-only close adjustment.

Reproduce the native observations with:

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_diagnostic target/interop/runs/<fresh-directory>
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess target/interop/runs/<another-fresh-directory> N3-M-RAW-UDP N3-M-ENCODED-UDP
```

These commands use repository-owned outputs and fixture resources only. They do
not load source or binaries from a shared research directory.
