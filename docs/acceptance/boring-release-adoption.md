# Boring release and Shadowsocks registry adoption

2026-09-27. This records a dependency-adoption regression run, not a new full
N9 acceptance or N10 platform/device/release sign-off. Invoke v5/schema27 is unchanged.

## Inputs

- Tested worktree: parent `dda65b1dc61875d9ca413be02d10432890c8ae7e` plus the
  manifest, lockfile, dependency-audit and documentation changes in this commit.
  Documentation was finalized after testing; no production or harness source changed.
- Source-tree SHA-256: `3ac430e855f020e669330e5359e195d330a78ea17a24e8c3a9ca09f756b7a41f`.
- Dirty source-patch SHA-256: `70e92f452fbb2888beeee0b4d660c86171e96c3d5cb85b581651fd5b8e83620f`.
- Cargo.lock SHA-256: `2a39eff5682bd3d402556df4f0d1909fa00ade781b982c275d949773e0c32c72`.
- `boring`, `boring-sys` and `tokio-boring` 5.2.0 use `branch = "release"`, locked
  to `d5a5d41850886aef5b269015130ee6d6eb2129ba`. The release tree equals the
  reviewed fork tree at `12820de60127c1d153ef75b051cd156ecc4d5b0f`, including
  terminal JLS handshake credential cleanup. Patch identities are in
  [TLS dependencies](../tls-dependencies.md).
- Official registry `shadowsocks = "=1.25.0"` replaces the Git source. The official
  registry index confirmed it as the latest non-yanked stable release. Its checksum
  is `e2065b026dbe4f47048eca384adf07f693bf901050d80abd3adb7b2422709b2d`;
  package VCS metadata points to the previously pinned upstream commit
  `ab388c7466d21f979430e33cc9ef10e22fb05955`. No third-party source was modified.

## Local checks

On macOS arm64 with Rust 1.98.1:

- `cargo fetch --locked` and `check tls-dependencies`: PASS. Audits require the
  approved release-branch lock identity and official Shadowsocks registry source;
  wrong repositories, branches, revisions, mixed sources and invalid features fail.
- The frozen `protocol_n9_local.commands` sets `N9-DEBUG`, `N9-RELEASE` and
  `N9-FEATURES`: all 53 commands passed. Debug/Release each executed 261 targeted
  tests. The 23 feature commands include all-target compilation without execution
  and the standard production-feature Release library build on the host target.
- Production `ffi`, all-feature lib/bins, and `ffi,interop-test` Mihomo-harness
  Clippy checks with `-D warnings`: PASS. Netstack: 17 tests and Clippy PASS.
- 182 script tests, C/C++ header checks, Rust formatting, Ruff lint/formatting,
  shell syntax and `git diff --check`: PASS. Catalog-only validation is
  `VALID / NOT RUN` for behavior; it is not a protocol coverage result.

Local logs under `target/pr1-integration/` are not committed. SHA-256:

```text
local-gates.log  d36106d2e40496bbdf057e1a19023666d3b02b23f0d6b2c397eff9918f709fd0
script-tests.log 7e47785c14d6e94e6b5c93c23a7235f87d3fef496698bacb7877808471985241
```

## Isolated consumer interoperability

All peers and origins ran in owned Apple Container host-only networks, without
published host ports or changes to host VPN/routing/DNS/firewall. Guest MTU was
1500. Official latest downloads resolved to Mihomo 1.19.31 and ssserver 1.25.0;
no local peer builds or third-party patches were used.

| Run under `target/interop/runs/` | Executed scope | Result |
| --- | --- | --- |
| `pr1-release-deps-ss-20260927` | `N9-SS-ALGORITHMS` and `N9-SS-EIH`: all three SS 2022 algorithms against Mihomo; AES EIH against official ssserver | 2/2 gates; 4 containers reclaimed |
| `pr1-release-deps-jls-20260927` | Frozen `N7-JLS-RETAINED` selection: TCP/gRPC and XHTTP H1/H2 download legs, authentication, close behavior, identity, lifecycle and owned resources | 18/18 cases; 16 containers reclaimed |
| `pr1-release-deps-jls-chrome-20260927` | Chrome TCP/gRPC BASE/AUTH plus XHTTP stream-up download IDENTITY/OWNED | 6/6 cases; 9 containers reclaimed |

Both JLS reports also passed independent `native_envelope` and `vless_pass`
reconstruction from the exact selections, raw events and close references. The
documented unprofiled JLS/gRPC Chrome close baseline remains explicitly identified;
it is not relabelled as a same-profile Mihomo comparison. All three reports have
the input identity above, `source_unchanged=true` and `cleanup=true`. The final
container listing was empty; all 29 owned containers were reclaimed.

Local raw report SHA-256 values (reports are not committed):

```text
SS n9-suite.json       e08f373a9c5c7e3f61960d8d454c5b450a679e2527c5c048a289c7b0191198f4
JLS vless-results.json 9aee09b393f2cf72e7e3b9ee8766f8207656fa0ebbc1ce6709a6846e6c523be7
Chrome JLS report     bcaca57b574fabcc3f8e68fde0beeb6b20846b107099cd3e28753e2a1bb8d7c3
```

The common image digest was
`sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01`.
Mihomo binary SHA-256:
`1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`.
ssserver binary SHA-256:
`9a836be84d6dbacfe727dd22ea6b3e169b633568bb9e27171e1eba625ae1655f`.
Archive identities and commands remain in each raw report.

## Remaining boundaries

The full 49-pair matrix, 1,800-second stress run and every prior protocol/security
combination were not rerun for this dependency change. Historical N2–N9 evidence
keeps its original source and lock identities. Fork-level tests are separate from
the fresh VCore consumer results above.

Apple/Android multi-target packages, native Windows builds/ABI, and remote CI
must be checked on the new PR head; they are not signed off by this local run.
Physical-device data paths, signed installation and release gates remain outside
this adoption check. [N10](next-protocols/N10.md) is not fully accepted.
