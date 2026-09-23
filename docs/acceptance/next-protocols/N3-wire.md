# N3 VMess AEAD wire progress — 2026-09-23

This is a wire-layer milestone, **not N3 sign-off**. VMess YAML, runtime graph,
UDP codecs, the five-transport consumer matrix and lifecycle acceptance are not
covered by this record. Invoke v5 / schema 15 and the default protocol set are
unchanged. `outbound-vmess` remains opt-in.

## Verified

On macOS ARM64, `n3-identity-body-v1` ran the newly downloaded official Mihomo
v1.19.31 listener, with no third-party source modification. Its binary SHA-256 was
`fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`.

- 13 TCP/plaintext combinations: none; auto/AES-128-GCM/ChaCha20-Poly1305 with
  padding/authenticated-length 00/01/10/11. Each transferred 10 MiB in each
  direction, verified all bytes, server-first data and upload EOF/download tail.
- Wrong identity, timestamps 600 seconds in either direction, and replayed AEAD
  request rejected without a connection reaching the controlled origin. A valid
  request in the same fixture first proved the target was reachable.
- Two published nested-HMAC vectors, both hardware-detection branches, bounded
  framing, padding/mask sequencing, authenticated EOF, tag/length tampering and
  16-bit nonce exhaustion checked in codec tests. `none` still authenticates the
  response; an invalid response poisons both directions.
- Owned native/test processes joined; input tree remained unchanged.

Input tree: `6a54148d532aa744db6e270cc7bf399408844f96bf607c2fe42cc93d500819fd`.
Lockfile: `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`.
Parent: `4e24da2841d1b08245aa35228d4eb4c97fe31185`.
Retained machine evidence: `target/interop/runs/n3-identity-body-v1/` (not Git).

```sh
cargo test --locked --all-features --lib outbound::vmess
cargo test --locked --all-features --test vmess_codec
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess target/interop/runs/<new-run>
```

## Retained failure and client-side correction

`n3-wire-v1/v2` timed out on a 10 MiB encrypted exchange. Minimization passed
64 bytes but failed 8,193 bytes: the origin received 4,097 bytes (first frame's
4,096-byte prefix plus the second one-byte frame). The downloaded binary's Go
build metadata identified sing 0.5.7 / sing-vmess 0.2.5. Their `ChunkReader` first
caches a large frame for a small read, then its large-buffer fast path bypasses
the cached tail. This matches the observed loss at the copy-buffer transition.

VCore limits its TCP write chunks to 4 KiB; the minimized case and complete
10 MiB matrix then passed (`n3-wire-two-chunks-v3`, `n3-wire-full-v1`). This is
client-owned framing, not a patch to the native peer or a replacement decoder.
The old failures remain failures; UDP/other transports need their own evidence.

## Dependencies and remaining boundaries

Selected current stable registry packages: [aes 0.9.3](https://docs.rs/aes/0.9.3/),
[ring 0.17.14](https://docs.rs/ring/0.17.14/),
[shake 0.1.0](https://docs.rs/shake/0.1.0/) and
[crc32fast 1.5.2](https://docs.rs/crc32fast/1.5.2/). MD5/SHA-256 reuse existing
stable dependencies. TLS/REALITY remains on the existing ring provider and
approved rustls fork. Protocol code is independently implemented against the
V2Ray/Mihomo wire behavior and Clash-RS architecture, not copied upstream code.

The encrypted wire nonce counter is 16 bits. This implementation fails closed
before counter reuse; no silent wrap/retry or migration of the business stream.
This boundary requires explicit final protocol documentation and acceptance.
No platform build, physical-device, unified N3 coverage or release claim is made.
