# Third-party notices

This file records code distributed, linked, or adapted by VCore. Research-only checkouts that are not shipped, linked, copied, translated, or adapted are intentionally omitted from the public documentation.

## Derived source notices

The following mappings require source-level attribution in addition to the dependency license audit.

| Upstream source | VCore destination | License treatment |
| --- | --- | --- |
| Microsoft UWP VPN plug-in sample, background task / plug-in / packet worker files at `d589fe0f57af13e052c44c662ade5fb1da2bcbb0` | `src/windows_vpn.rs` | Adapted to Rust for activation, `IVpnPlugIn` lifecycle, and packet-buffer handling under MIT. Retain the Microsoft copyright and license notice. |
| `luqmana/wireguard-uwp-rs` plug-in files at `328e622fb613d611bb022874a6535e2846ac6640` | `src/windows_vpn.rs` | Adapted activation-factory, provider-instance, and buffer-access patterns under the upstream MIT option. Copyright © 2021 Luqman Aden. |
| `luqmana/wireguard-uwp-rs` application shell at `328e622fb613d611bb022874a6535e2846ac6640` | `src/bin/windows_vpn_host.rs` | Adapted the minimal Windows application activation shell under the upstream MIT option. Copyright © 2021 Luqman Aden. |
| `YtFlow/Maple` VPN plug-in at `ec052fcb014b14e50cb264abc1415807609ec07b` | `src/windows_vpn.rs`, `src/platform/windows_tun_io.rs` | Adapted loopback wake, empty-to-non-empty coalescing, `/1` routes, and packet-flow mechanics under Apache-2.0. Retain the applicable license and NOTICE terms. |
| `Watfaq/clash-rs` `clash-netstack` at `b76234d94d5918133b0806a897ed8b27aedf196e` | `crates/vcore-netstack` | Adapted under the package's MIT option. Retain the repository-root `LICENSE` and exact provenance and copyright in the crate `NOTICE`. |
| `automesh-network/netstack-smoltcp` at `ab06bc3de566fc6485a238dd4c746bb3e4f79484` | Source lineage inherited by `crates/vcore-netstack` | Retain the upstream MIT copyright notice recorded in the crate `NOTICE`. |

VCore’s bounded queues, Session Host packet channel, proxy graph, runtime DNS, rule engine, Controller, GeoData matcher, and physical-source/interface dialer policy are project code unless a source file states otherwise.

## Direct dependencies and bundled components

- `crates/vcore-netstack` uses VCore's repository-root MIT `LICENSE`; its `NOTICE` records source provenance and upstream copyright.
- `smoltcp` 0.13.1 provides the userspace IPv4/IPv6 TCP state machine and wire representations (`0BSD`).
- The project rustls fork is based on rustls 0.23 and retains `Apache-2.0 OR ISC OR MIT`. Release builds must pin an immutable fork revision in `Cargo.toml` and `Cargo.lock`.
- `tokio-rustls` 0.26.4 is the unmodified crates.io release (`MIT OR Apache-2.0`).
- `x25519-dalek` 2.0.1 is used by the REALITY feature (`BSD-3-Clause`).
- `ring` 0.17.14 is the current cryptographic provider (`Apache-2.0 AND ISC`).
- `idna` 1.1.0 is used for UTS #46/STD3 domain normalization (`MIT OR Apache-2.0`).
- `regex-automata` 0.4.15 is used for bounded GeoSite regex DFAs (`MIT OR Apache-2.0`).
- `arc-swap` 1.9.2 publishes immutable GeoData matcher snapshots (`MIT OR Apache-2.0`).
- `fs2` 0.4.3 provides the cross-process GeoData update lock (`MIT OR Apache-2.0`).
- `sha2` 0.10.9 and `url` 2.5.8 support GeoData download verification and URL validation (`MIT OR Apache-2.0`).
- `webpki-roots` 1.0.8 supplies public trust anchors (`CDLA-Permissive-2.0`).
- `oslog` 0.2.0 is used on Apple targets for Unified Logging (MIT).
- `tun` 0.8.14 is the target-specific Unix TUN dependency and declares WTFPL. VCore does not compile or link its Windows backend.
- `windows`, `windows-core` 0.62.2, and `windows-collections` 0.3.2 are target-specific Windows dependencies (`MIT OR Apache-2.0`).
- Versions above reflect the current lockfile. Every release must audit the complete resolved transitive graph rather than treating this summary as a substitute for `Cargo.lock` and packaged license files.

## Compliance rules

- Before merging copied, translated, modified, or adapted code, record the upstream path, immutable revision, destination, type of use, and resulting license obligations here.
- Preserve file-level copyright, license, and NOTICE requirements for derived code.
- Keep test fixtures and generated artifacts separate from third-party source.
- Protocol interoperability alone does not authorize source reuse.
- The VCore repository root is licensed under MIT; that license does not override obligations attached to dependencies or derived files.
