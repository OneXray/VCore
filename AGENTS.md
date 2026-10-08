# Project Overview

VCore is a standalone Rust proxy core. The current public contract is Invoke API v5 with internal schema revision 32. Runtime configuration uses the strict schema documented in `docs/config.yaml` and is passed inline as `configYaml` / `configYamls`; YAML contains neither `configVersion` nor `default-proxy`. Business proxy listeners use only `mixed-port`: shared HTTP/SOCKS5 TCP and SOCKS5 UDP require both inbound features. Top-level `port`, `socks-port`, `udp`, and `listeners` are rejected; proxy-node `port` and `udp` retain their outbound semantics. `allow-lan` and `authentication` are independent; omitted or empty authentication leaves both loopback and wildcard bindings unauthenticated. Public lifecycle state is runtime-local and single-instance.

iOS, tvOS 17+ (ARM64 device/simulator), macOS, Android and Linux use host-owned TUN fds through the Unix `tun-rs` adapter. Linux accepts a real single-queue raw-IP TUN; the host owns namespace/routing isolation and physical egress. Apple packetFlow does not publicly guarantee raw-fd access; Linux or simulator results do not sign off a physical Network Extension. Windows uses `windows-rs` / `Windows.Networking.Vpn`; the packaged ARM64 foreground, AppContainer provider, per-session full-trust runtime, lifecycle, pressure, and packet-channel gates pass on Windows 11. Windows 10, native x64, physical IPv6, WACK, and Store publishing remain release gates.

# Sources of Truth

Current source, tests, and the public contract documents under `docs/` define implemented behavior. When touching a documented boundary, reconcile its document with API v5 and current tests in the same change.

Read the relevant document completely before changing that area:

- FFI, lifecycle, Android protect, or config delivery: `docs/invoke-api.md` and `src/ffi/`.
- YAML, proxy graph, proxy groups, DNS, rules, or sniffer: `docs/config.yaml`, `docs/tun-icmp-dns.md`, and `src/config/`.
- HTTP/SOCKS5 inbound, authentication, or listeners: `docs/inbounds.md` and `src/inbound/`.
- SOCKS5, AnyTLS, Trojan, VMess, Hysteria2, TUIC v5 or SS 2022: `docs/outbounds.md`.
- VLESS, Vision, Encryption, JLS or static ECH: `docs/vless.md`.
- XHTTP request fields, download legs, H1/H2/H3 or sing-mux: `docs/xhttp.md`.
- Runtime Controller, proxy-group selection, or TUN traffic metrics: `docs/controller-api.md` and `src/controller.rs`.
- GeoData: `docs/geodata.md`.
- TLS profiles, certificate policy or TLS dependencies: `docs/tls-client-fingerprint.md` and `docs/tls-dependencies.md`; REALITY also requires `docs/reality-wire-protocol.md`. Before local boring development or opening/updating a PR, follow the dependency-source workflow in `docs/tls-dependencies.md`.
- Unix TUN fd ownership or packet I/O: `docs/tun-platform.md`.
- Windows VPN/TUN, outbound binding, AppContainer packet buffers, or package lifecycle: `docs/windows-vpn.md` and `docs/tun-platform.md`.
- Builds: `scripts/README.md`; `vcore-scripts build` is compile-only, including delivery artifact-integrity checks.
- Offline regressions: `tests/README.md`. Rust memory/configuration tests remain in VCore; run explicit pure-memory filters, with all-target coverage limited to `--no-run`.
- Protocol interoperability or pressure: the public [container-benchmark](https://github.com/YuanDevTeam/container-benchmark) owns all container orchestration and fixtures. Supply the checkout explicitly with `--source vcore=PATH`; VCore builds do not import it or infer workspace paths.
- Server-side tests: `docs/testing-isolation.md`. Use isolated benchmark containers for every server peer and network origin; container failure is not permission for a host fallback.
- Claims that something passed: `docs/acceptance.md`. Record only commands and environments actually executed; host tests and cross-builds do not prove physical-device data paths.

# Architecture Boundaries

- `src/ffi/` owns the JSON ABI, registry, lifecycle admission, panic boundary, and platform callbacks.
- `src/runtime.rs` prepares and owns DNS, routing, outbound graphs, listeners, GeoData, and long-lived tasks.
- `src/tun_runtime.rs` connects platform raw-IP I/O to `vcore-netstack` and dispatches TCP, UDP, DNS, ICMP, and sniffing.
- `src/platform/` contains platform adapters. Keep Windows callback semantics here instead of simulating a Unix fd.
- `src/dialer.rs` is the shared physical TCP/UDP socket seam. Fix socket protection or Windows `(source IP, interface index)` binding once here rather than in each outbound.
- Static `select` groups share Running Session selection between routing and `dialer-proxy`. Keep protocol configuration immutable, validate the complete node/member DAG, and retain only declared dependencies to avoid Arc cycles. Resolve upstreams at the `OutboundConnector` seam using one setup deadline and per-group selection snapshot; prepare every potential DIRECT server endpoint. `measureDelay` remains node-only.
- `crates/vcore-netstack` is platform-independent raw-IP state and must not depend on WinRT, JNI, Swift, or host UI frameworks.
- Core runtime lifecycle does not infer App, extension, service, or daemon roles and does not implement cross-process state or IPC. The Windows-only host Invoke is the explicit package integration seam for profile/status/Session Snapshot/StartupTask operations and an optional bounded `sessionBackend`; its Session Host owns backend process liveness without interpreting arguments, files, ports, or protocols. Provider runtime state remains process-local.

# Development Rules

1. Keep the latest-only schema strict. Reject unknown and obsolete fields instead of adding compatibility branches or silent migration.
2. Preserve bounded queues, packet/buffer/parser limits, cancellation, and synchronous stop barriers. Do not turn UDP callback paths into blocking waits.
3. Keep secrets, UUIDs, DNS questions, full config/request bodies, and runtime traffic destinations out of logs and errors. Configuration-service endpoints may appear only as a bounded, sanitized origin or source index when operational diagnosis requires it; never log userinfo, query, fragment, private addresses, or redirect targets.
4. Platform trust boundaries fail closed. Android protect failure, Windows physical-interface loss, invalid packet-buffer ownership, or unsupported target startup must not fall back to an unprotected socket.
5. Windows uses official `Windows.Networking.Vpn` through `windows-rs`. `VpnPacketBuffer` bytes are copied within callbacks. After acquiring a framework buffer, return it to Windows before propagating any later local error; a return-API failure propagates the platform error and fails closed. Every framework buffer is returned exactly once. Network changes stop the first release; they do not silently rebind or reconnect.
6. Reuse the existing raw-IP netstack and outbound graph. Add no second Windows proxy core, Wintun path, per-protocol socket factory, or fake fd layer.
7. Keep optional protocol/platform code feature- and target-gated. Default non-TUN builds must continue to compile.
8. When copying or modifying third-party source, record the upstream project and preserve all applicable license terms. Audit linked dependencies against the resolved release graph. Do not describe independent rewrites, protocol interoperability, or architectural references as derived source without evidence; Credits provide context and attribution, not a substitute for release license review.
9. Keep every public surface—code, documentation, tests, examples, commits, issues, pull requests, reviews, CI output, and releases—limited to VCore and public dependencies. Keep private downstream repository or product identities, links, implementation details, status, artifacts, and roadmaps outside this repository and its GitHub surfaces. Before publishing, search the staged diff and proposed GitHub text for downstream identifiers.
10. Make changes on a separate branch, never directly on `main`.
11. Use the official latest stable third-party dependencies, including test-only experiments. Check current non-prerelease, non-yanked releases when selecting or upgrading them; reference projects' old pins are not a version policy. Keep lockfiles for reproducible validation, refresh affected dependency audits, and rerun applicable tests. If freshness conflicts with the approved fork/provider or a platform's compatible dependency set, report the conflict and obtain an explicit exception or scope decision instead of silently retaining an old version or changing the security architecture.

# Validation

Choose the smallest relevant set, then expand for shared contracts:

```shell
cargo fmt --all -- --check
# Select an explicit memory-only regression named in tests/README.md.
cargo test --locked --lib geodata::tests::
# All-target compilation only; network peers must be containerized.
cargo test --locked --all-features --all-targets --no-run
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
git diff --check
```

Changes to FFI, shared runtime, TUN, socket creation, TLS, or packaging also require affected target builds and scoped regressions. Delivery checks artifact integrity, not native-consumer execution or device behavior. External interop and physical-device results remain `NOT RUN` unless executed in the current validation run.

## Agent skills

### Issue tracker

Before GitHub issue or PR operations, read the [issue tracker](docs/agents/issue-tracker.md) for repository selection and request/spec conventions.

### Triage labels

Before triage or label operations, read the [five-role label mapping](docs/agents/triage-labels.md).

### Domain docs

Before codebase exploration or design, read the [single-context domain workflow](docs/agents/domain.md) for terminology and ADR rules.
