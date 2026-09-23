# N3 UDP container isolation — 2026-09-23

This is a **wire-layer diagnostic and fixture migration, not N3.3 or N3 sign-off**.
The [server-test isolation rule](../../testing-isolation.md) now requires all
server roles and network origins to run in isolated containers. Historical native
host results remain historical; this change neither modifies third-party sources
nor disables Mihomo loopback protection. VMess public YAML/runtime integration
remains unavailable.

## Topology and input identity

Host: macOS 27.0 (`26A428`), ARM64, rustc 1.98.1 (`48a229cea`), Apple Container
CLI 1.4.1. Host/kernel differences from the historical Darwin peers are part of
the explicitly changed topology, not evidence that third-party code was fixed.

Each transport gets three owned Apple Container VMs on the labelled host-only
network: official Mihomo server, official Mihomo comparison-client SOCKS ingress,
and the UDP echo origin. The host runs VCore and a fixture-only SOCKS client.
No host server or published host port is used. IPv4, virtual IPv6 and synthetic
domain targets all terminate in the origin container.

The origin autonomously echoes each actual UDP request and reports the exact
received bytes through a separate bounded TCP observation stream. This replaces
the historical host-controlled UDP reply; it does not replace the official
protocol decoder. The send, origin-observation and reply deadlines remain one
second each. Clients alternate order; a failed association stops without retrying
business packets. Protocol flags, packet sizes and count are matched between arms.

Each invocation freshly downloads the official latest Linux ARM64 release and
queries its actual version inside the server container. Executed identity:

- Mihomo `v1.19.31`, Linux ARM64, Go `1.26.8`, `with_gvisor`.
- Archive SHA-256: `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4`.
- Binary SHA-256: `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`.
- Official `python:3-alpine` image, refreshed for each invocation, resolved digest
  `sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01`;
  origin reports Python `3.14.7`.

These hashes identify downloaded content, not an upstream signature verification.
Temporary credentials, certificates/configurations and raw peer logs are removed
after exact owned-container deletion and bounded log-reader joins. Retained
observations contain roles, ports, counts and failure phases, not credentials or
traffic payloads. The pre-existing host-only network is retained; other tasks'
containers are never stopped or pruned.

## Retained first comparison and isolated failure probe

`n3-udp-container-matched-20260923-v1` repeated the earlier workload: six
TCP/WS/gRPC plain/TLS modes, three codecs × 13 cipher/flag configurations ×
IPv4/IPv6/domain × two rounds, 100 packets at each of 1/64/512/1200 bytes.

- VCore: 1,404 associations, zero failures, 561,600 request/reply pairs.
- Mihomo: 1,404 associations, two first-one-byte request timeouts (TCP/TLS ordinal
  331 and gRPC/plain ordinal 211), 560,800 completed pairs.
- No server/client warning or loopback rejection in any mode. Source unchanged
  and all 18 owned VMs and log readers joined. The aggregate result remains FAIL.

The remaining comparison-fixture risk was then isolated without changing either
core. Mihomo's [packet adapter](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/constant/adapters.go)
keys UDP NAT by the incoming source address. Its [SOCKS packet](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/listener/socks/utils.go)
returns the UDP sender tuple, and the [tunnel](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/tunnel/tunnel.go)
reuses the sender for an existing key. A fixture that rapidly closes/reuses UDP
source ports can therefore inherit another case's selected outbound/encoding.

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/n3-udp-container-nat-reuse-20260923-v1 --nat-reuse-probe
```

The controlled experiment holds the first native raw association alive, sends a
new target through another SOCKS listener using the same UDP source, then tests a
distinct-source control. In 1.967 seconds of test execution it observed:

1. Initial request and reply to origin A: PASS.
2. Reused source: origin A received the new case's exact payload, while intended
   origin B received nothing — REPRODUCED.
3. Independent source: request and reply to B: PASS.

The intentionally misdirected case is not normal interop PASS; the harness exits
nonzero. The run retained source identity and complete cleanup. The first random
comparison did not record incoming SOCKS source ports, so its two timeouts are
not retroactively asserted to have this proven cause.

The corrected normal matrix keeps each comparison-client UDP socket reserved
until the transport group ends and records its port; it asserts no source reuse.
Only fixture-owned client sockets change lifetime. Mihomo's NAT timeout, pooling,
socket settings and protection remain unchanged. This prevents one nominally
independent test case from reusing another case's protocol selection.

## Corrected full boundary comparison

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/n3-udp-container-boundaries-20260923-v3 --rounds 2 --packets 100
```

**PASS for this positive wire matrix.** All six TCP/WS/gRPC plain/TLS modes passed
for both clients. Each mode/arm exercised three codecs × 13 cipher/flag settings ×
three target types × two rounds: 234 associations and 117,000 request/reply pairs.
Each association exchanged 100 packets at 1/64/512/1200 bytes and its declared
payload boundary:

- raw and XUDP: 15,000 bytes;
- packetaddr IPv4: 14,993 bytes (seven-byte address envelope);
- packetaddr IPv6/domain: 14,981 bytes (19-byte worst-case address envelope).

The domain fixture resolves to the origin's IPv4 address, but VCore's advertised
domain budget conservatively allows an IPv6 result. The packetaddr boundary is
therefore not an assertion that a 15,000-byte application payload fits a
15,000-byte wire body. Maximum+1 remains a separate, unfinished negative gate.

Aggregate: **2,808 associations and 1,404,000 request/reply pairs, zero failures**
(each client: 1,404 associations and 702,000 pairs). Each mode recorded 234 distinct
comparison-client UDP source ports for its 234 associations. All server/client
warning and loopback-rejection counts were zero. The 18 owned VMs and log readers
joined, every test command cleaned up, source stayed unchanged, and a final
container listing was empty. Temporary fixture directories were removed.

Measured test-command durations, excluding downloads/VM setup/teardown, were
53.234 / 59.064 / 54.288 / 60.215 / 60.641 / 69.318 seconds for TCP plain/TLS,
WS plain/TLS and gRPC plain/TLS respectively. These are fixture execution times,
not a comparative throughput benchmark.

Stable tested input (also used by the successful SIGINT probe):

- Parent commit: `ab535f2eb54888a23742b9cc08162df507b93a0e`.
- Source tree SHA-256: `6822fbc9de556d83ec3c4e106655e415637fc9d633ce63e624f3ae24701c8216`.
- Tracked dirty patch SHA-256: `fa300a488e8495ff98d45da2579768e39170bef1a8078cd10b3052530ad49974`.
- Cargo.lock SHA-256: `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`.

Retained artifact SHA-256 values under the run directory above:

```text
ac88bc6fd22d7475b5d17be64a15d78776bb8d3f7995c0bef9a53633420033b4  udp-ab.json
e2e148f62d87a9a3d764988e068b9e713a8e90e13a9d2ae38b27acdb88a946ad  tcp-plain.jsonl
b2d40bee86006527664a3f10e515b75f4444ab2a3e5e5a39f4ccf97ebdd8a17f  tcp-tls.jsonl
f524656ff65d3d16efef0b0cdebfcf63b96d3f0668b7666b7fe2da5258c992fa  ws-plain.jsonl
d798155e972dbe4e6e1cb527fd6c5f7bc6796fdfbbd8b67bc92ee8a1a59711e0  ws-tls.jsonl
476c13bf0519d815b666acbe8080cb18b02b37b9a68a9b6cb56c83f901ece503  grpc-plain.jsonl
6f181a8f97c08c6fa69c093748dc51a92bb2e19dcaa48dc272ba29076d3c3c58  grpc-tls.jsonl
```

## Interruption and offline checks

`n3-udp-container-sigint-20260923-v1` injects SIGINT into the harness after real
traffic has completed an association. It returned 130 / INTERRUPTED, with source
unchanged, all three VMs deleted, all log readers and driver joined, and zero of
six observed owned descendant processes remaining. Harness/VM teardown took
9.798 seconds within the 45-second interruption watchdog; this is **not** VCore's
production five-second Stop acceptance.

The interruption observation's SHA-256 is
`defc39c93dd458c1e315e7c4aeabc1194b65b1d3e44a548257b933eb85b30738`
(`sigint-observation.json` in that run directory).

An earlier interrupted attempt, `n3-udp-container-boundaries-20260923-v2`, also
cleaned its VMs but overlapped a Python formatting change during teardown;
`source_unchanged=false` is retained. It is not accepted as a stable-input test.

Offline validation: six container ownership/config/blocked-entry tests,
two diagnostic collector/matrix tests, seven owned-process tests, four VMess
library codec/auto tests and five public codec/duplex tests passed. Focused
`vmess_native` and library/binary clippy, Rust formatting, Python Ruff check/format
and diff whitespace checks passed. These tests do not launch host network servers.

## Remaining boundary

The corrected matrix supplies positive Mihomo wire evidence only. Other native
wire/close/HTTP/H2/negative fixtures still require container migration before their
next execution. The old host `--collision-probe` and `--socket-probe` CLI paths now
refuse to run.

No result here signs off malformed packets, maximum+1, cancellation/source
isolation, public configuration/graph/upstreams/measurement, lifecycle, stage
coverage, physical-device IPv6, platform builds or remote CI. Full N3 remains
in progress; no stage commit or push is made for this diagnostic boundary.
