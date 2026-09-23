# N3 UDP client differential — 2026-09-23

This investigation predates the mandatory [container-only server rule](../../testing-isolation.md).
Commands below are historical, not permission to restart host servers. Subsequent
container evidence is recorded separately in [the isolation report](N3-udp-containers.md).

This is a **diagnostic, not N3 acceptance**. Only owned test tooling and evidence
were changed for this investigation. Existing VMess production work, third-party
sources, host networking and Mihomo's loopback protection were not changed.
Failure records retain FAIL; a reproduced upstream limitation is not a passing
VCore acceptance case.

## Reproduction and matched comparison

The original five selected groups were rerun using:

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess \
  target/interop/runs/n3-udp-ab-repro-20260923-v1 \
  N3-M-RAW-UDP N3-M-ENCODED-UDP \
  N3-M-GRPC-PLAIN-RAW-UDP N3-M-GRPC-PLAIN-ENCODED-UDP \
  N3-M-GRPC-TLS-RAW-UDP
```

TCP/plain raw and packetaddr failed at the first one-byte packet of a new
association. The other three groups passed this time; that does not establish a
fix for their earlier failures. Source identity was unchanged and cleanup joined.

The new matched loop holds one official Mihomo server per transport and alternates
the VCore and official Mihomo client arms. The VMess codec, cipher, padding,
authenticated-length option, address family, sizes, repetition count and one-second
I/O deadlines are identical. No business packet is retried; a failed association
stops, its unattempted packets are not counted as successful, and subsequent
independent associations continue.

The official client is entered through a small fixture-only SOCKS5 adapter, not
VCore's SOCKS implementation. VCore uses its existing VMess wire seam. Mihomo owns
its own connection pooling and NAT lifetime; these are not forced to match VCore's
wire-driver lifetime. These differences preclude treating failure-rate differences
as a performance or reliability ranking. This does not exercise public VMess YAML.

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/n3-udp-ab-minimal-20260923-v1 \
  --modes tcp --tls plain --rounds 10 --packets 1 --sizes 1
```

The reduced trigger is repeated association setup with one one-byte packet:

| Client → official Mihomo | Associations | Failed | Matched server loopback rejection |
| --- | ---: | ---: | ---: |
| VCore | 1,170 | 52 | 52 |
| Official Mihomo | 1,170 | 66 | 56 |

Each arm covers raw/XUDP/packetaddr × 13 cipher/flag combinations ×
IPv4/IPv6/domain × 10 rounds. Of the 108 failures matched to rejection logs,
107 also retained a live server UDP socket with the rejected source port in the
failure-time `lsof` snapshot. The remaining snapshot is not promoted to the same
strength of evidence. Ten additional Mihomo failures (nine request timeouts and
one reply timeout) have no matched rejection and remain independently unresolved.

The first diagnostic version's `server_warnings.loopback_rejections[].ports`
also includes timestamp/IPv6 fragments before the actual ports. That artifact is
retained unchanged; its entries must not be interpreted as a clean endpoint list.
The subsequent collector extracts endpoint ports without timestamp fragments.
An intermediate collector omitted domain endpoints; that was caught by a failing
offline regression and corrected before the final transport rerun. Its older
artifacts are not rewritten to fill in missing evidence.

## Six-transport confirmation

The complete matched rerun after fixing the collector was:

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/n3-udp-ab-transports-20260923-v2 \
  --rounds 2 --packets 100 --sizes 1 64 512 1200
```

For each transport, **each client** attempted 234 associations: three encodings ×
13 cipher/flag combinations × three address families × two rounds. Each
successful association exchanged 100 packets at each of the four sizes. The
one-second send/request/reply deadlines and alternating client order were shared.
Large-packet ceilings were intentionally excluded to isolate the first-packet
problem; this is not the earlier 9,216-byte boundary acceptance matrix.

| Transport | VCore failures / matched rejection | Mihomo failures / matched rejection |
| --- | ---: | ---: |
| TCP/plain | 3 / 3 | 7 / 6 |
| TCP/TLS | 5 / 5 | 5 / 3 |
| WebSocket/plain | 5 / 5 | 2 / 2 |
| WebSocket/TLS | 5 / 5 | 6 / 6 |
| gRPC/plain | 7 / 7 | 1 / 0 |
| gRPC/TLS | 1 / 1 | 0 / 0 |
| Total, 1,404 associations per client | 26 / 26 | 21 / 17 |

Every failure occurred at the first one-byte request, not after a sustained
transfer. All 43 matched rejections have a contemporaneous live server UDP socket
with the rejected source port. Four Mihomo request timeouts remain unclassified:
TCP/plain observation 163, TCP/TLS observations 315 and 354, and gRPC/plain
observation 382. No cause is inferred for these four from the other failures.

VCore completed 551,200 request/reply pairs and Mihomo 553,200. The failed
associations' remaining packets were not attempted. All six groups retain FAIL,
even where the native-client arm passed. Source remained unchanged and owned
server/client/test processes joined. Input identity:

- Parent: `ab535f2eb54888a23742b9cc08162df507b93a0e`.
- Source tree: `96b4ece972c1253fdfe998113647efc1150e17a4ece9dfce47b8b2393d3643df`.
- Lockfile: `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`.

The earlier complete transport run, `n3-udp-ab-transports-20260923-v1`, is retained
separately, including its domain-port collector limitation and the reply failure
described below. Neither run replaces the original native boundary failures.

## Controlled causal experiment

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/n3-udp-ab-collision-20260923-v1 --collision-probe
```

The test first creates a real, working UDP association through the official
server and keeps it alive. A transparent fixture TCP relay then carries the next
VMess association without modifying any bytes. Only its TCP source port changes:

| Client | TCP source port | One-byte request and reply |
| --- | --- | --- |
| VCore | Different from the live server UDP port | PASS |
| VCore | Equal to the live server UDP port | First request timed out; loopback rejection |
| Official Mihomo | Different from the live server UDP port | PASS |
| Official Mihomo | Equal to the live server UDP port | First request timed out; loopback rejection |

All four observations completed in 2.937 seconds excluding download/build/setup.
An independent fresh-download rerun, `n3-udp-ab-collision-20260923-v2`, reproduced
the same two successful controls and two rejected collisions in 2.250 seconds.
Both rejected cases have matching server logs and live UDP socket snapshots. The
seed association still exchanged data after each probe, ruling out a generally
unusable server. The test intentionally returns nonzero for the reproduced data
failure. Source identity stayed unchanged and all owned processes joined.

## Mechanism and scope

The matching official v1.19.31 sources show:

1. [The VMess listener adapter](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/listener/sing/sing.go)
   carries the incoming connection source into UDP metadata.
2. [DIRECT](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/direct.go)
   checks the loopback detector before opening its UDP outlet.
3. [The UDP detector](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/loopback/detector.go)
   remembers outbound UDP ports in a port-only map. For a local/loopback source,
   a matching source port is rejected. It does not distinguish the outer VMess
   TCP port from the remembered UDP port.

TCP and UDP sharing a numeric port is legal; in this controlled path there is no
actual traffic loop. The experiment therefore demonstrates a loopback-protection
false positive, not broken VMess encryption or a universal UDP packet-size limit.
It is confirmed on macOS ARM64 with both clients and official Mihomo v1.19.31.
It does not imply the same outcome for a remote, non-local client, which follows
a different detector condition. It also does not retroactively explain every
historical reply timeout or V2Ray large-packet failure.

## Separate host UDP reply-delivery issue

In `n3-udp-ab-transports-20260923-v1`, TCP/plain observation 403 used the official
Mihomo client and failed while waiting for the first reply. The origin had already
received the correct request. Its IPv4 UDP port and the official server's live
IPv6 UDP outlet port were both 56191, as shown by the failure-time owned socket
snapshot. There was no matching loopback rejection for that association.

An independent, protocol-free probe tested this host behavior:

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/n3-udp-ab-socket-20260923-v1 --socket-probe
```

It binds 128 owned IPv4 loopback origins and makes at most 2,048 automatic IPv6
dual-stack UDP binds, sending traffic only after an owned port collision is
observed. After 569 attempts a socket received the same port as an origin: the
request reached the origin, but its echo returned to that origin itself instead
of the UDP outlet. All sockets closed; source identity stayed unchanged. An earlier
direct CLI probe also reproduced this in 18 attempts. Explicitly binding the
IPv6 outlet first and then the IPv4 origin was rejected as address-in-use; the
reproduced path specifically involves automatic allocation after the IPv4 bind.

This independently confirms another host-loopback failure mechanism consistent
with the captured Mihomo reply-timeout socket tuple. The failed native exchange
did not itself capture the reflected echo, so that causal link is an inference,
not an assertion that every historical reply timeout is proven to have this cause.
No sysctl, peer socket option, operating-system setting or third-party code changed.

## Evidence and next boundary

The runs live under `target/interop/runs/`; JSON records retain source/lock
identity, per-association results, official download URL, actual binary version
and SHA-256. The official latest-download preflight selected v1.19.31; the Darwin
ARM64 binary SHA-256 is
`fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`.
Temporary peer configs, keys and raw logs were removed after owned process joins.
Retained socket observations contain owned role, descriptor, family and port,
not raw addresses or payloads. Original failures are never overwritten by reruns.

For subsequent acceptance, prefer an isolated Mihomo server network namespace
(for example the existing owned Apple Container peer approach), keeping its
protection enabled and the official binary unmodified. That environment must be
validated anew; this diagnostic has not moved the VMess gate to containers or
claimed a fix. Unclassified timeouts require their own evidence.

Validation of this diagnostic tooling: the two offline collector/matrix tests
passed (the domain-port test first failed before the collector correction),
`cargo clippy --locked --all-features --test vmess_native -- -D warnings`,
`cargo fmt --all -- --check`, Python Ruff check/format and `git diff --check`
passed. This turn did not run the full Rust regression, platform builds, remote CI,
or the N3 unified acceptance gate. No commit or push was made for this diagnostic.
