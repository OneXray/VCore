# Third-party references and notices

This file records the source and license boundaries used while designing VCore. A listed project is not automatically a binary or source dependency. Concrete copied, translated, modified, or linked code must be recorded with file-level mappings before release.

## Current research baselines

| Project | Revision | License | Role in VCore |
| --- | --- | --- | --- |
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` | MPL-2.0 | Authoritative VLESS, Addons, Mux, XUDP, XHTTP `auto`, TLS/REALITY configuration and interoperability behavior |
| [Watfaq/clash-rs](https://github.com/Watfaq/clash-rs) | `85fc16693f65c5cccb06c538c6be999c8b652cb6` | Apache-2.0 | Historical Rust module organization, async stream, and REALITY implementation research only; not a current dependency or VLESS compatibility authority |
| [eycorsican/leaf](https://github.com/eycorsican/leaf) | `1d20301570395cff1db5f3e316222b0ec3b4732e` | Apache-2.0 | Incremental parsing, split send/receive halves, mobile FFI, TUN, and bounded rule/GeoData implementation research; not a VLESS/XUDP compatibility authority |
| [XTLS/libXray](https://github.com/XTLS/libXray) | `294fb37343205b9b0cb7b7b1b423d3d4b60d9998` | MIT | Single JSON Invoke envelope, caller-owned C response, Android protect-controller API shape, and Ping request/lifecycle semantics; VCore's authenticated Rust HTTP probe is an independent implementation |
| [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) | `cbd11db1e13a75d8e680e0fe7742c95be4cba2be` (`v1.19.28`) | GPL-3.0 | Current configuration shape and routing-rule vocabulary/order research; not a VLESS, wire-protocol, linked-code, or source-code dependency |
| [anytls/anytls-go](https://github.com/anytls/anytls-go) | `0c36ca9f0d88bc1af5ddb998e619166913c7445c` | No recognizable `LICENSE` file in the recorded checkout | AnyTLS wire behavior, v2/v1 negotiation, padding, session reuse, and sing UoT research only; no source was copied, translated, modified, linked, or distributed |
| [meh/rust-tun](https://github.com/meh/rust-tun) | `d77c12a7f5536e3f72e668c5b00a4164d5acced2` (`0.8.14`) | WTFPL | Authoritative platform adapter behavior for the Apple/Android raw-fd TUN dependency; its Windows/Wintun backend is explicitly outside VCore's Windows UWP plan |
| [luqmana/wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs) | `328e622fb613d611bb022874a6535e2846ac6640` | MIT OR Apache-2.0 | Windows `IVpnPlugIn`, `VpnChannel`, packet-buffer ownership, background activation and AppX packaging reference |
| [Microsoft UWP VPN plug-in sample](https://github.com/microsoft/UwpVpnPluginSample) | `d589fe0f57af13e052c44c662ade5fb1da2bcbb0` | MIT | Authoritative Windows VPN callback, background activation, buffer and manifest sample |
| [YtFlow/Maple](https://github.com/YtFlow/Maple) | `ec052fcb014b14e50cb264abc1415807609ec07b` | Apache-2.0 | Proxy-style loopback wake, `/1` routes and physical-source-binding reference |

Mihomo is used only as a shape and behavior reference for the documented current configuration/rules subset. VCore does not claim general Mihomo configuration compatibility, and Mihomo remains outside the VLESS implementation and protocol-authority boundary. The recorded revision above is the clean local `references/mihomo` checkout from `https://github.com/MetaCubeX/mihomo.git`.

The recorded `references/anytls-go` checkout does not expose a recognizable
license file. VCore's AnyTLS client is an independent Rust implementation based
on protocol behavior research and independent duplex mock tests. Real
`anytls-go`, Mihomo, and public-server interoperability has not yet been run.
`anytls-go` is not a Cargo dependency, no source or generated code was copied
into VCore, and none of its code may be distributed with VCore unless an
upstream license is made explicit and a separate license review authorizes that
use.

## Windows source mappings

| Upstream path | VCore destination | Use and license treatment |
| --- | --- | --- |
| `UwpVpnPluginSample/CppWinRT/TestVpnPluginAppBg/{TestVpnPluginAppBgTask.cpp,VpnPlugInImpl.cpp,BackgroundPacketWorker.cpp}` @ `d589fe0` | `src/windows_vpn.rs` | Adapted to Rust for activation, `IVpnPlugIn` lifecycle and packet-buffer handling. Retains Microsoft Corporation's MIT notice through this file. |
| `wireguard-uwp-rs/plugin/src/{background.rs,plugin.rs}` @ `328e622` | `src/windows_vpn.rs` | Adapted Rust `windows-rs` activation factory, persistent provider instance and `IBufferByteAccess` handling under the upstream MIT option; copyright © 2021 Luqman Aden. |
| `Maple.Task/VpnPlugin.cpp` @ `ec052fc` | `src/windows_vpn.rs`, `src/platform/windows_tun_io.rs` | Adapted loopback `DatagramSocket` wake, empty-to-non-empty coalescing, `/1` routes and proxy packet flow under Apache-2.0. The repository's Apache-2.0 license remains applicable to these adapted portions. |

No upstream cryptographic or proxy-protocol implementation was copied into the Windows provider. The VCore-specific bounded queue, `TunRuntime` connection and `Dialer` source-bind implementation are original project code.

## Existing dependencies and derived components

- `crates/vcore-netstack` keeps its own Apache-2.0 `LICENSE` and `NOTICE`; those files remain authoritative for that crate.
- `rustls` `0.23.43` is provided by the project-owned [OneXray/rustls](https://github.com/OneXray/rustls) fork, based on the corresponding official rustls release and retaining its `Apache-2.0 OR ISC OR MIT` licensing. Local development may use the adjacent fork checkout; release builds must pin an immutable OneXray revision in `Cargo.toml`/`Cargo.lock`.
- `tokio-rustls` `0.26.4` is the unmodified, checksummed crates.io release (`MIT OR Apache-2.0`). VCore does not maintain or link a Watfaq `tokio-rustls` fork.
- `x25519-dalek` `2.0.1` is a runtime dependency of the OneXray rustls REALITY feature and is licensed under `BSD-3-Clause`.
- `ring` `0.17.14` is the sole cryptographic provider in the current resolved VCore graph and declares `Apache-2.0 AND ISC`. AWS-LC is not part of the current dependency graph.
- `idna` `1.1.0` is a direct runtime dependency used for UTS #46/STD3 domain normalization. Its crate metadata and packaged `LICENSE-MIT`/`LICENSE-APACHE` files declare `MIT OR Apache-2.0`.
- `regex-automata` `0.4.15` is a direct runtime dependency used to compile and search bounded GeoSite regex DFAs. Its crate metadata and packaged `LICENSE-MIT`/`LICENSE-APACHE` files declare `MIT OR Apache-2.0`.
- `arc-swap` `1.9.2` is a direct runtime dependency used to atomically publish immutable GeoData matcher snapshots (`MIT OR Apache-2.0`).
- `fs2` `0.4.3` is a direct runtime dependency used for the cross-process GeoData update lock (`MIT OR Apache-2.0`).
- `sha2` `0.10.9` and `url` `2.5.8` are direct runtime dependencies used by the bounded GeoData HTTPS downloader for streaming SHA-256 verification and strict redirect handling; both declare `MIT OR Apache-2.0`.
- `webpki-roots` `1.0.8` supplies the downloader and measurement clients' bundled public trust anchors and declares `CDLA-Permissive-2.0`.
- `oslog` `0.2.0` is an Apple-only direct runtime dependency used without its default `logger` feature to write bounded VCore events to Apple Unified Logging. Its crate metadata declares MIT.
- `tun` `0.8.14` (`rust-tun` in `Cargo.toml`) is an unmodified, target-specific Unix dependency used without default/async features. VCore supplies an already-nonblocking duplicate fd, wraps the synchronous device in Tokio `AsyncFd`, and uses its Apple PI/Android raw-IP packet I/O. The crate declares WTFPL. Cargo.lock records upstream target-specific Windows packages, but VCore's Unix-only dependency declaration prevents them from being compiled or linked into Windows/UWP artifacts.
- `windows` and `windows-core` `0.62.2` plus `windows-collections` `0.3.2` are unmodified, target-specific Windows dependencies used for the VPN provider and declare MIT OR Apache-2.0.
- The versions above are the versions resolved in `Cargo.lock`; their transitive dependencies remain part of the release dependency/license audit rather than the research-baseline table.
- The VCore repository root is MIT licensed.

## Source-use rules

- Protocol behavior learned from Xray-core does not by itself mean its source has been copied.
- Copying or line-by-line translating Xray-core source into VCore requires file-level MPL-2.0 review and attribution; the root MIT license does not erase those obligations.
- Code derived from clash-rs or leaf must retain the applicable Apache-2.0 copyright, license and NOTICE requirements.
- Copying or translating Mihomo implementation code would introduce GPL-3.0 obligations and requires a separate review; configuration-shape and behavior research alone is not recorded as copied code.
- Do not copy, translate, modify, link, vendor, or distribute `anytls-go` code while the recorded checkout has no recognizable license. Protocol observation and clean-room interoperability tests must remain separate from source reuse.
- Before merging derived code, add an entry describing the upstream path, revision, VCore destination path, whether the use is copied/translated/adapted/reimplemented, and the resulting license treatment.
- Keep interoperability fixtures and generated artifacts separate from copied upstream source.
