# VCore

<p align="center">
  English · <a href="./readme/README.zh_CN.md">简体中文</a> · <a href="./readme/README.ru.md">Русский</a>
</p>

VCore is an embeddable Rust proxy core for VPN clients and local proxies. It routes TCP/UDP traffic through direct connections, proxy nodes, groups, and chains, with integrated DNS, GeoData, and a cross-platform TUN data plane.

Configuration uses **Mihomo-compatible YAML for the supported feature set**. VCore focuses on client-side capabilities rather than implementing every Mihomo field or its complete Dashboard API.

## What VCore can do

- **Accept application and VPN traffic:** HTTP forwarding, CONNECT and Upgrade; SOCKS5 CONNECT and UDP ASSOCIATE; host-provided IPv4/IPv6 TUN packets.
- **Route by destination:** domain, domain suffix/keyword, IP CIDR, destination port, TCP/UDP, GeoSite and GeoIP rules, with explicit DIRECT and REJECT actions.
- **Choose and chain proxies:** nested `select` groups, live group selection, and `dialer-proxy` chains that can reference nodes or groups. Selection changes apply to new physical transports without moving existing connections.
- **Handle DNS:** controlled UDP/TCP nameservers, GeoSite-based nameserver policies, sequential failover, caching and duplicate-query coalescing; intercept TCP/UDP port 53 in TUN mode.
- **Identify traffic for routing:** HTTP, TLS and QUIC domain sniffing, plus TUN DNS hints, without rewriting the actual destination. ICMPv4/ICMPv6 Echo is answered locally.
- **Manage routing assets:** load referenced categories from `geosite.dat` / `geoip.dat` on demand and update them through the configured route. GeoSite supports Domain, Full, Plain and Regex records, attribute intersections and inverted selectors; GeoIP supports inverted selectors. All platforms retain selected records without a count cap or truncation; GeoData has no total memory quota. See [GeoData boundaries](docs/geodata.md#内存与安全边界).
- **Expose client controls:** a loopback Controller for group selection and TUN traffic rates/totals, plus isolated node/chain delay measurement through Invoke API.

## Proxy protocols

All eight protocols below are enabled in the default build. UDP support is configured per node.

| Protocol | Capabilities |
| --- | --- |
| [VLESS](docs/vless.md) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP first-packet camouflage, legacy H2, [XHTTP H1/H2/H3](docs/xhttp.md); Vision, Encryption, REALITY, JLS, static ECH and sing-mux in supported combinations |
| [VMess AEAD](docs/outbounds.md#vmess-aead) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP first-packet camouflage and legacy H2; TCP/UDP, plaintext or standard TLS |
| [Trojan](docs/outbounds.md#trojan) | TCP/UDP over TLS TCP, WebSocket / HTTPUpgrade or gRPC |
| [Shadowsocks 2022](docs/outbounds.md#shadowsocks-2022) | TCP/UDP; AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305; AES identity chains; optional strict ShadowTLS v3 TCP wrapping and UoT v2 |
| [AnyTLS](docs/outbounds.md#anytls) | TLS sessions and UDP over TCP v2 |
| [SOCKS5](docs/outbounds.md#socks5) | CONNECT and UDP ASSOCIATE, with optional username/password authentication |
| [Hysteria2](docs/outbounds.md#hysteria2) | QUIC TCP/UDP, bandwidth control, Salamander, port hopping and mTLS |
| [TUIC v5](docs/outbounds.md#tuic-v5) | QUIC TCP/UDP, native/quic UDP relay modes and selectable congestion control |

Standard TLS connections support certificate verification and SHA-256 certificate pins. Applicable TCP TLS paths can use Chrome, Firefox or Safari ClientHello templates; `client-fingerprint` is independent of the certificate `fingerprint`. See [TLS profiles and certificate policy](docs/tls-client-fingerprint.md) for the exact names and combinations. These features do not promise indistinguishability from a browser or unrestricted protocol combinations.

SS2022 uses the unmodified official Rust library; its known empty-first-write/server-first and padding risks remain documented in the [Shadowsocks contract](docs/outbounds.md#shadowsocks-2022).

## Mihomo-style configuration

Use the familiar `proxies`, `proxy-groups`, `rules`, `dns`, `port`, `socks-port` and `tun` structures. For example:

```yaml
socks-port: 1080
allow-lan: false

proxies:
  - name: edge
    type: anytls
    server: proxy.example.com
    port: 443
    password: replace-with-your-password
    client-fingerprint: chrome
    udp: true

proxy-groups:
  - name: Proxy
    type: select
    proxies: [edge, DIRECT]

dns:
  enable: true
  nameserver:
    - "udp://223.5.5.5:53#DIRECT"

rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,Proxy
```

Replace the example endpoint and credentials. GeoSite/GeoIP rules require the corresponding assets under `<dataDir>/geodata`; missing assets leave those rule types unavailable. See the [complete configuration reference](docs/config.yaml) and [GeoData behavior](docs/geodata.md).

Compatibility is scoped to documented fields and behavior, not arbitrary Mihomo configurations. Groups currently support static `select`; DNS nameservers use literal IPs over UDP/TCP. Providers, automatic group selection, encrypted DNS and fake-IP are outside the current feature set. Unknown fields and invalid combinations are rejected rather than silently ignored; VCore-specific semantics are called out in the relevant contracts.

The host passes YAML inline through `configYaml`; TUN descriptors and platform callbacks are supplied separately through the runtime API. VCore does not read host configuration paths or configure Linux system routes automatically.

## Platforms and integration

| Platform | TUN integration |
| --- | --- |
| iOS / macOS | Host-provided utun file descriptor |
| tvOS 17+ | Host-provided utun file descriptor; ARM64 device and simulator targets |
| Android | `VpnService` file descriptor with outbound socket protection |
| Linux | Real single-queue raw-IP TUN; the host owns interface creation and routing isolation |
| Windows | Native `Windows.Networking.Vpn` Provider and a full-trust Session Host, without Wintun or fd emulation |

VCore is a library, not a standalone VPN application. Unix hosts own the original TUN descriptor; VCore uses and closes its own duplicate. Apple's public packetFlow API does not guarantee raw-fd access, so actual Network Extension integration and device validation remain host responsibilities. See [TUN integration](docs/tun-platform.md) and [platform acceptance boundaries](docs/acceptance.md).

The cross-platform C ABI accepts JSON requests through Invoke API v5:

```c
char *VCoreInvoke(const char *request_json);
void VCoreFree(char *response);
```

One public instance follows `initialize → createInstance → prepare(configYaml) → start → stop → destroyInstance`. The API also provides configuration validation, state queries, GeoData status and delay measurement. See [Invoke API](docs/invoke-api.md), [Controller API](docs/controller-api.md) and the [Windows integration example](example/windows-uwp/README.md).

## Benchmark

[**VCore / Mihomo TUN benchmark**](https://github.com/YuanDevTeam/container-benchmark) contains the reproducible setup, measured results and comparison charts for both cores under the same native Linux TUN environment.

The benchmark project also owns protocol interoperability (`interop`) and memory-pressure runs (`stress`), with an explicit `--source vcore=PATH` checkout. VCore's own scripts only compile core and platform artifacts.

It measures **1 / 1.5 / 2 Gbps** mixed TCP/UDP traffic with **1,000 DNS queries/s** and enhanced `geosite:cn` / `geoip:cn` rules, reporting actual throughput, CPU, observed peak Linux RSS, UDP packet loss and successful DNS queries. It evaluates the TUN/DNS/routing path with DIRECT egress, not encrypted proxy throughput; Linux RSS is not Apple Network Extension footprint.

The separate `stress` command uses the same complete enhanced `geosite:cn` / `geoip:cn` selection with a 2 Gbps / 60-second / 1,000 DNS QPS workload. Original DAT files are downloaded without trimming; only CN categories are loaded. Optional `--geodata-update` adds real downloading and reloading during traffic. The benchmark README records actual input types, measurements and failures. No observation is a 50,000,000-byte guarantee for arbitrary input or a substitute for Apple device validation.

## Documentation

- [Documentation index](docs/README.md)
- [Configuration reference](docs/config.yaml)
- [Core and platform builds](scripts/README.md)
- [Core regression tests](tests/README.md)
- [Resource policy](docs/runtime-resource-policy.md)
- [Acceptance and known limitations](docs/acceptance.md)

## Credits

VCore builds on and learns from public dependencies, protocol implementations and platform references:

- TUN dependencies: the local [`vcore-netstack`](crates/vcore-netstack/README.md) uses [smoltcp](https://github.com/smoltcp-rs/smoltcp); Unix packet I/O uses [tun-rs](https://github.com/tun-rs/tun-rs).
- Networking and routing references: [clash-rs](https://github.com/Watfaq/clash-rs), [netstack-smoltcp](https://github.com/cavivie/netstack-smoltcp), [Mihomo](https://github.com/MetaCubeX/mihomo), [Xray-core](https://github.com/XTLS/Xray-core) and [Leaf](https://github.com/eycorsican/leaf). These reference projects are not netstack dependencies.
- TLS and Shadowsocks: [rustls](https://github.com/rustls/rustls), [boring](https://github.com/cloudflare/boring), [BoringSSL](https://boringssl.googlesource.com/boringssl/) and [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust). Derived replay-window code retains its [MIT notices](src/outbound/shadowsocks/packet_window.rs).
- Windows integration: [windows-rs](https://github.com/microsoft/windows-rs), [UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample), [wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs), [Maple](https://github.com/YtFlow/Maple) and [YtFlowCore](https://github.com/YtFlow/YtFlowCore).

## License

[MIT](LICENSE).
