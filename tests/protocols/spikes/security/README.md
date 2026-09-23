# N0 security interface spike

This independent test-only workspace probes the locked rustls/tokio-rustls
interfaces without changing VCore's production dependency graph or third-party
source. It does not implement Vision or any new production outbound.

From the VCore repository root:

```sh
cargo test --locked --manifest-path tests/protocols/spikes/security/Cargo.toml --target-dir target/interop/n0-security/target -- --nocapture
cargo fmt --manifest-path tests/protocols/spikes/security/Cargo.toml -- --check
```

The tests prove local API and record-buffer behavior, default REALITY's classic
X25519 selection, and an external Rust HPKE adapter producing an ECH offer.
They do not prove a native peer accepted ECH, Vision direct-mode interoperability,
or production socket/lifecycle integration. The hybrid group is intentionally a
sentinel, not a cryptographic implementation; its presence tests selection only.
The fork also exposes explicit hybrid selection; these default-config tests do
not exercise that opt-in API or claim hybrid is unavailable in the fork. The
[N1 TLS update](../../../../docs/acceptance/next-protocols/N1-tls.md) records the
new dependency validation without replacing the historical N0 result.

The optional `missing-session-hook` feature is an intentional **compile-fail**
probe. Do not include it in a successful-build feature set:

```sh
cargo check --locked --manifest-path tests/protocols/spikes/security/Cargo.toml --target-dir target/interop/n0-security/target --features missing-session-hook
```

Expected: exit 101 with E0599 for `connect_with_session_id_generator` on official
tokio-rustls. This proves the reference call is unavailable, not that every
possible alternative protocol implementation is impossible.

Results and remaining gates: [N0 security acceptance report](../../../../docs/acceptance/next-protocols/N0-security.md).
