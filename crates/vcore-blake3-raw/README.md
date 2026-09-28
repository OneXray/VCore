# Binary-context BLAKE3 DeriveKey

Private workspace crate for the byte-string DeriveKey used on the VLESS
Encryption wire. One public function accepts two byte slices and returns a
32-byte key. It performs no allocation, IO, runtime loading, or TLS operation.
Callers own input/output secrets and their erasure policy. The C adapter clears
its hasher; it cannot guarantee erasure of upstream internal temporaries.

The official Rust API takes `&str`; arbitrary binary protocol contexts cannot be
converted to UTF-8, hex, or base64 without changing the derivation. The official
C `blake3_hasher_init_derive_key_raw` is used directly. Rust does not mirror the
C hasher layout or implement a compression/KDF algorithm.

This reproduces an existing protocol, not a new cryptographic recommendation:
BLAKE3's authors recommend a fixed, globally unique application-specific context,
and caution against dynamic contexts. Compatibility does not establish the
security of VLESS Encryption's protocol design.

## Source and build

The five `vendor/blake3*` files are byte-for-byte copies from official
[BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3/tree/1.8.7/c), commit
`f3149ec5bb5449af877ba20377a11008ff499fa2` (latest stable checked 2026-09-26).
Archive SHA-256: `c6782a28842b1c0478524ac06a4f2ede784038ee298d6e2162c0b089c4306a3c`.
Upstream offers CC0-1.0, Apache-2.0, or Apache-2.0 WITH LLVM-exception; all three
license texts are preserved in `vendor/`. Vendored source is used under
Apache-2.0 WITH LLVM-exception. VCore-owned adapter/build/Rust code is MIT.

| File | SHA-256 |
| --- | --- |
| blake3.c | b118ddf7cf9e6e5ef3fded72dcb1acf9dfdc4ea923cbe4605900ad6ee9afe1af |
| blake3.h | 81bbb11ad1909341565dce4914cc0e5c29718eca27e6950b28f9226a91aaf8c5 |
| blake3_impl.h | d388dca3574602c8849805ea3c8c0a12d082ac0e428756f305e111942f099af4 |
| blake3_dispatch.c | 134f21550138c0af6312925c988aeee35df287e4119e8ad1d206fccdb2238fe3 |
| blake3_portable.c | 2bc25b0dad67b4329d0b49cfa075ab2b0d04e424addbddc4e9c389c52a192524 |

`build.rs` compiles these local files with official portable-only switches and
compile-time symbol prefixes. It never accesses research checkouts, Cargo source
caches, or the network. No bindgen, SIMD implementation, or fork is introduced.
Latest stable `cc` 1.5.1 is selected explicitly. Upgrades require rechecking the
official release, replacing unchanged files, updating provenance and hashes,
and rerunning vectors and target builds.

## Check

```sh
cargo test --locked -p vcore-blake3-raw
```

This checks a primitive, not the Encryption handshake, ticket authentication,
runtime ownership, platform integration, or end-to-end Encryption acceptance.

The binary-context fixture has 52 values generated with the independent
`github.com/metacubex/blake3 v0.1.0` implementation used by Mihomo, using Go 1.27.1.
Its SHA-256 is `16fa3198a0a6adad7de4df74010f1625b72a445991e8554842c0b12bd070b08d`.
The generator and Go module lock are in `tests/generator/`; run `go run .` there
to reproduce the JSON on stdout (not part of the Rust build). Inputs contain
invalid UTF-8 and NUL and cover 64/1024-byte boundaries and protocol contexts up
to 17005 bytes. UTF-8 cases also link and compare the official Rust crate in the
same test executable.
