# N3: native close diagnostics and revised acceptance

Date: 2026-09-23. Branch: `feat/vmess`. **N3 is not complete.**

The original gate required non-XHTTP transports to preserve the download tail
after application upload EOF. HTTP first-header camouflage and legacy H2 use
official V2Ray because Mihomo has no matching native listener. The current
official V2Ray peer does not pass that end-to-end gate, including when used by
the official Mihomo client. On 2026-09-23 the user removed that universal tail
requirement: align VCore's behavior with Mihomo for each protocol/transport,
prioritize Mihomo servers, and use native servers only for listener gaps.
Normal bidirectional integrity, cancellation and resource cleanup remain required.
The old assertion is no longer a blocker; no failed result is relabeled PASS.

## Evidence

All peers were freshly downloaded from official latest links. No local peer
compilation, cached fallback, third-party patch, or host VPN change was used.

| Peer | Binary-reported version | Binary SHA-256 |
| --- | --- | --- |
| Mihomo | v1.19.31 / Go 1.26.8 / Darwin ARM64 | `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090` |
| V2Ray | 5.53.0 / Go 1.26.1 / Darwin ARM64 | `2cbac9546e02d732e657cfa415aad222acd7ced5a55c1f7f04313f46c3f5852a` |

`n3-transports-v1` ran the VCore wire client:

- Mihomo TCP/WS/gRPC, each plaintext/TLS: all 13 cipher/padding/length choices
  passed. Every choice checked both directions' 10 MiB, server-first greeting,
  upload EOF and the exact seven-byte download tail. Identity/time/replay also
  passed separately. This is **not** public YAML/UDP/runtime acceptance.
- V2Ray HTTP plaintext/TLS: `none` transferred both directions' 10 MiB intact,
  then returned zero of the seven expected tail bytes after upload EOF. Later
  cipher combinations did not run because the first required assertion failed.
- Initial H2 probes used a mismatched `:authority` port and were rejected.
  Correcting the fixture to the configured `localhost` authority removed that
  setup failure. `n3-v2-h2-authority-v2` then transferred both directions' 10 MiB
  but reproduced the same zero-tail failure, plaintext and TLS. Later cipher
  choices are NOT RUN, not inherited from Mihomo.

`n3-native-close-v2` removed VCore entirely: owned official Mihomo SOCKS ingress
and VMess client → separate owned native VMess server → controlled TCP origin.
The origin sent a greeting, echoed the request, waited for upload EOF, and wrote
a 23-byte tail. All eight paths received correct normal data; all origins
observed EOF and completed their tail write, and all owned processes joined.

| Official client → server | Security | Tail received by client |
| --- | --- | --- |
| Mihomo → Mihomo TCP | plaintext / TLS | 23 / 23 bytes |
| Mihomo → V2Ray TCP | plaintext / TLS | 0 / 0 bytes; about one second to close |
| Mihomo → V2Ray HTTP | plaintext / TLS | 0 / 0 bytes |
| Mihomo → V2Ray legacy H2 | plaintext / TLS | 0 / 0 bytes |

The native differential is observational. Its successful exit means collection
and cleanup succeeded, **not** that the failed end-to-end tail contract passed.
An earlier `n3-native-close-v1` stopped at the TLS peer readiness check because
the fixture's certificate was outside that Mihomo process's data directory;
the fixture now generates certificates inside each owned server directory.
That earlier run is not counted as a complete comparison.

## Source interpretation

The matching official [V2Ray 5.53.0 Freedom implementation](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/freedom/freedom.go#L135)
finishes request copying and switches to the downlink-only timer without calling
the origin connection's `CloseWrite`. The connection is closed on handler exit.
The [VMess inbound](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/vmess/inbound/inbound.go)
closes its internal writer after decoded request EOF; that is not a TCP FIN to
the origin. This explains why an origin waiting for FIN cannot deliver its tail
through that V2Ray path before teardown. The source interpretation is consistent
with the observed native TCP timing, not a claim that all deployment paths or
future peer versions share one implementation.

The research checkout is newer (v5.54.1); it was not used as evidence for the
downloaded binary's exact version. The version-matched links above were checked
separately. The latest download URL's binary identity, not a checkout tag,
determines this run's peer.

## Approved replacement — Mihomo alignment

Do not impose a universal EOF-tail contract on non-XHTTP transports. Separate
normal bidirectional data integrity from closure behavior, and compare the
latter with the official Mihomo client on the same transport/security path.
Use Mihomo servers first, retaining native V2Ray HTTP/H2 only for listener gaps.
Do not blanket-replace every transport's shutdown with whole-close: follow the
actual wrapper chain. Existing targeted half-close tests remain useful regression
or capability evidence, but are not an extra universal product requirement.
Do not modify third-party code, force an unsupported server behavior, or rewrite
the historical failures. This does not waive UDP, fields, graph, deadline,
resource or public-runtime gates.

This scope change alone does not complete N3. VMess currently remains opt-in wire
code: no schema bump, YAML registration, default feature activation or N3 sign-off.
Remaining work is
raw/XUDP/packetaddr, all public fields and transports, graph/measurement, 20-cycle
lifecycle, unified evidence coverage, old-protocol regressions and platform builds.

## Revalidation under the approved contract

`n3-close-alignment-v1` freshly downloaded both peers and recorded 12 official
Mihomo-client paths. TCP/WS against Mihomo returned the complete 23-byte EOF tail;
gRPC against Mihomo and HTTP/H2 against V2Ray returned no tail. Each result was
the same for plaintext and TLS. Normal greetings/echoes, source identity and
owned-process/origin cleanup all passed. Additional V2Ray TCP controls returned
no tail. These are observations, not a universal tail-preservation guarantee.

`n3-native-close-final` was an earlier incomplete differential: its plaintext
V2Ray TCP control failed before any origin accept; collection correctly exited
nonzero, while cleanup and source identity checks succeeded. It is not used as
complete evidence or relabeled as passed by the later run.

The VCore-only regression `n3-grpc-close-red-v2` received a tail where the
official Mihomo client had whole-closed. VMess now uses whole-close for gRPC,
HTTP camouflage and legacy H2, retaining TCP/ordinary WS CloseWrite. No shared
Trojan or XHTTP close behavior was changed. Local whole-close wakes a blocked
reader and releases supplied IO even before the response handshake arrives.

`n3-close-aligned-wire-v1` then passed all 21 groups: identity/time/replay,
10 transport/security data groups (13 cipher/flag choices each, 10 MiB in each
direction plus exact normal response trailer), and 10 matching close groups.
Integrity is checked before upload EOF. Both the input-tree stability and all
owned process cleanup checks passed. This remains wire-only acceptance.

- Parent: `f543e378497a5f72798f320fd9b989456c18923d`.
- Source tree: `7fe31da8cc55ef0b82d4e262d9e05f573ebf287037afb49401de14332537e15a`.
- Lockfile: `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`.
- Raw evidence: `target/interop/runs/n3-close-aligned-wire-v1/vmess-results.json`
  and `target/interop/runs/n3-close-alignment-v1/native-close.json`.

The preceding `n3-normal-data-v1` independently passed the 11 identity/data
groups after separating normal trailers from EOF-generated tails; it did not
yet prove the gRPC close correction. Historical compile-only red attempts and
the original HTTP/H2 EOF-tail failures remain separate, not replaced by these
new-contract results.

Reproduce (fresh directories required):

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess target/interop/runs/<new-wire-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_close target/interop/runs/<new-close-run>
```
