# Project Overview

VCore is the standalone Rust proxy core used by the sibling OneVCore Flutter app. The current public contract is Invoke API v5 with internal schema revision 11. Runtime configuration uses the strict schema documented in `docs/config.yaml` and is passed inline as `configYaml` / `configYamls`; YAML contains neither `configVersion` nor `default-proxy`. Public lifecycle state is runtime-local and single-instance.

Apple and Android use host-owned TUN fds through the Unix `rust-tun` adapter. Windows uses `windows-rs` / `Windows.Networking.Vpn`; the packaged ARM64 foreground, AppContainer provider, per-session full-trust runtime, lifecycle, pressure, and packet-channel gates pass on Windows 11. Windows 10, native x64, physical IPv6, WACK, and Store publishing remain release gates. Linux remains unsupported.

# Sources of Truth

Current source, tests, and the public contract documents under `docs/` define implemented behavior. When touching a documented boundary, reconcile its document with API v5 and current tests in the same change.

Read the relevant document completely before changing that area:

- FFI, lifecycle, Android protect, or config delivery: `docs/invoke-api.md` and `src/ffi/`.
- YAML, proxy graph, DNS, rules, or sniffer: `docs/config.yaml`, `docs/tun-icmp-dns.md`, and `src/config/`.
- AnyTLS: `docs/anytls.md`.
- TUN traffic metrics: `docs/controller-api.md`.
- GeoData: `docs/geodata.md`.
- REALITY or the sibling rustls fork: `docs/reality-wire-protocol.md` and `docs/rustls-reality-release.md`.
- Unix TUN fd ownership or packet I/O: `docs/tun-platform.md`.
- Windows VPN/TUN, outbound binding, AppContainer packet buffers, or package lifecycle: `docs/windows-vpn.md`, `docs/windows-session-runtime.md`, and `docs/tun-platform.md`.
- Claims that something passed: `docs/acceptance.md`. Record only commands and environments actually executed; host tests and cross-builds do not prove physical-device data paths.

# Architecture Boundaries

- `src/ffi/` owns the JSON ABI, registry, lifecycle admission, panic boundary, and platform callbacks.
- `src/runtime.rs` prepares and owns DNS, routing, outbound graphs, listeners, GeoData, and long-lived tasks.
- `src/tun_runtime.rs` connects platform raw-IP I/O to `vcore-netstack` and dispatches TCP, UDP, DNS, ICMP, and sniffing.
- `src/platform/` contains platform adapters. Keep Windows callback semantics here instead of simulating a Unix fd.
- `src/dialer.rs` is the shared physical TCP/UDP socket seam. Fix socket protection or Windows `(source IP, interface index)` binding once here rather than in each outbound.
- `crates/vcore-netstack` is platform-independent raw-IP state and must not depend on WinRT, JNI, Swift, or Flutter.
- Core runtime lifecycle does not infer App, extension, service, or daemon roles and does not implement cross-process state or IPC. The Windows-only host Invoke is the explicit package integration seam for foreground profile/status/snapshot/StartupTask operations; provider runtime state remains process-local.

# Development Rules

1. Keep the latest-only schema strict. Reject unknown and obsolete fields instead of adding compatibility branches or silent migration.
2. Preserve bounded queues, packet/buffer/parser limits, cancellation, and synchronous stop barriers. Do not turn UDP callback paths into blocking waits.
3. Keep secrets, UUIDs, destinations, DNS questions, and full config/request bodies out of logs and errors.
4. Platform trust boundaries fail closed. Android protect failure, Windows physical-interface loss, invalid packet-buffer ownership, or unsupported target startup must not fall back to an unprotected socket.
5. Windows uses official `Windows.Networking.Vpn` through `windows-rs`. `VpnPacketBuffer` bytes are copied within callbacks and every framework buffer is returned according to WinRT ownership rules. Network changes stop the first release; they do not silently rebind or reconnect.
6. Reuse the existing raw-IP netstack and outbound graph. Add no second Windows proxy core, Wintun path, per-protocol socket factory, or fake fd layer.
7. Keep optional protocol/platform code feature- and target-gated. Default non-TUN builds must continue to compile.
8. Before copying, translating, linking, or distributing third-party code, update `THIRD_PARTY_NOTICES.md` with revision, license, file-level provenance, and destination.

# Validation

Choose the smallest relevant set, then expand for shared contracts:

```shell
cargo fmt --all -- --check
cargo test --all-features --all-targets
cargo clippy --locked --all-features --lib --bins -- -D warnings -A clippy::chunks-exact-to-as-chunks -A clippy::map-or-identity
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
sh -n scripts/*.sh tests/run_xray_interop.sh tests/run_anytls_interop.sh
git diff --check
```

Changes to FFI, shared runtime, TUN, socket creation, TLS, or packaging boundaries also require the affected target build and sibling OneVCore integration checks. External interop and physical-device results remain `NOT RUN` unless they were executed in the current validation run.

## Agent skills

### Issue tracker

Issues are tracked in `OneXray/VCore` GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five canonical triage labels. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository using root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
