# VCore

VCore 是独立的 Rust 客户端代理 core。它通过严格 YAML 配置和 Invoke API v5 提供代理图、DNS、规则、GeoData、HTTP listener、TUN 数据面与流量统计。内部配置 schema revision 为 11；revision 只出现在 `version` 响应和 `buildIdentity` 中，不写入 YAML。

## 能力

- Outbound：VLESS + XHTTP + TLS/REALITY、SOCKS5 CONNECT/UDP ASSOCIATE、AnyTLS TCP/UoT、DIRECT。
- 代理链：`dialer-proxy` 组成任意长度的有向无环图；节点 A 指向 B 时，物理路径为 `client -> B -> A -> target`。
- 路由：顺序执行 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`GEOSITE`、`GEOIP`、`IP-CIDR`、`IP-CIDR6`、`DST-PORT`、`NETWORK` 和最终 `MATCH`。
- DNS：固定 IP 的 UDP/TCP nameserver、显式出口、顺序 policy/failover、typed/opaque cache、singleflight、TUN UDP/TCP 53 劫持。
- TUN：raw IPv4/IPv6、TCP/UDP、ICMPv4/ICMPv6 Echo 本地响应、HTTP/TLS/QUIC sniffer、每 session 四字段流量统计。
- Listener：可选、仅 loopback、强制 Basic 认证的 HTTP CONNECT/forward listener。
- GeoData：VCore 管理 `dataDir/geodata` 下的 `geosite.dat` 和 `geoip.dat`，按需求加载并可通过代理链后台更新。
- 测速：`measureDelay` 单次接收 1–5 份 node-only 配置，使用最多五个私有 worker，结果保持输入顺序。

## 配置

[`docs/config.yaml`](docs/config.yaml) 是唯一完整示例。核心约束：

- YAML 最大 256 KiB，拒绝未知字段、anchor、alias、自定义 tag 和历史结构。
- 顶层至少包含一个 proxy，以及 `port` 或启用的 `tun`。
- proxy `name` 大小写敏感且唯一；引用必须存在，代理图必须无环。
- `rules` 必填，必须恰好以一个指向实际 proxy name 的 `MATCH` 结束。
- `DIRECT` 和 `REJECT` 是内置 action；其他 action 必须是实际 proxy name。
- 配置通过 `configYaml` / `configYamls` 内联交付；VCore 不读取宿主配置路径。
- Controller、TUN fd、Controller 端口/secret 等运行时值由宿主生成，不进入用户保存的 RAW YAML。

## 生命周期与 ABI

跨平台业务入口：

```c
char *VCoreInvoke(const char *request_json);
void VCoreFree(char *response);
```

Windows 安装包另提供 revision-1 host bridge：

```c
char *VCoreWindowsVpnInvoke(const char *request_json);
```

业务生命周期为单公共实例：

```text
initialize
  -> createInstance
  -> prepare(configYaml)
  -> start
  -> stop
  -> destroyInstance
```

`instanceId` 是当前 runtime 内不可复用的 generation token。同实例命令 fail-fast；纯 `validateConfig` 可并发执行。完整 envelope、method、fd 所有权和 Android protect 契约见 [`docs/invoke-api.md`](docs/invoke-api.md)。

TUN 流量通过 session-local loopback Controller 查询：

```http
GET /traffic
Authorization: Bearer <secret>
```

响应为一次 `up/down/upTotal/downTotal` snapshot，不是持续 stream。详见 [`docs/controller-api.md`](docs/controller-api.md)。

## 平台

| 平台 | 数据面 | 状态 |
| --- | --- | --- |
| iOS / macOS | 宿主提供 utun fd；VCore duplicate 后通过 `rust-tun` 同步 device + Tokio `AsyncFd` 收发 | 已实现；Release iOS 真机 footprint 仍是发布门禁 |
| Android | `VpnService` 提供 raw-IP fd；每个 outbound socket 必须先通过 protect callback | 已实现；真机矩阵仍需按发布计划执行 |
| Windows | `Windows.Networking.Vpn` AppContainer provider + 每 session full-trust runtime；同包命名管道传输 raw-IP | Windows 11 ARM64 开发签名包已通过功能、lifecycle、pressure 与有界 batching 验收 |
| Linux | — | 不支持，入口 fail closed |

Windows 不使用 fd 模拟层。Provider 只拥有 `VpnChannel`、buffer、routes、物理网络监控、packet gateway 和 fail-closed Stop；完整 VCore runtime、Controller、DNS、rules 与 outbounds 位于 Session Host。packet channel 保持 protocol v1 framing，最多合并 8 个已经就绪的 frame，不等待未来 packet。

## 资源边界

当前 TUN profile 保留局部结构边界，不按业务 flow 总数做固定 admission：

```text
raw packet / MTU                 1,500 bytes
packet queue                     256
ordinary event / UDP response    128
DNS ingress / DNS response       128 / 128
TCP buffer                       32 KiB per direction
TLS / XHTTP buffer               64 KiB
DNS typed cache                  256 entries
DNS opaque cache                 64 entries / 256 KiB
GeoData allocation capacity      8 MiB
```

TCP session、普通 UDP association、half-open、outbound handshake 和 active DNS transport 按需创建；bounded queue、每流 buffer、wire/parser size、timeout、idle cleanup 和 cache 继续提供结构安全。iOS 35/45 MiB 仅为 best-effort 优化观测，不改变生命周期结果。

## 文档

- [文档索引](docs/README.md)
- [配置协议](docs/config.yaml)
- [Invoke API](docs/invoke-api.md)
- [AnyTLS 出站](docs/anytls.md)
- [REALITY V1 客户端协议](docs/reality-wire-protocol.md)
- [rustls REALITY 依赖与发布要求](docs/rustls-reality-release.md)
- [TUN 流量 Controller](docs/controller-api.md)
- [TUN ICMP 与 DNS](docs/tun-icmp-dns.md)
- [GeoData 规则与资产](docs/geodata.md)
- [TUN 平台层](docs/tun-platform.md)
- [Windows VPN 平台边界](docs/windows-vpn.md)
- [Windows 会话运行时](docs/windows-session-runtime.md)
- [运行时资源策略](docs/runtime-resource-policy.md)
- [验收矩阵](docs/acceptance.md)

## 验证

```bash
cargo fmt --all -- --check
cargo test --all-features --all-targets
cargo clippy --locked --all-features --lib --bins -- -D warnings -A clippy::chunks-exact-to-as-chunks -A clippy::map-or-identity
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
```

平台产物：

```bash
./scripts/build_apple.sh
./scripts/build_android.sh
powershell -File scripts/build_windows.ps1 -Architecture arm64
```

执行结果与仍延期的物理设备、Windows 发布矩阵见 [`docs/acceptance.md`](docs/acceptance.md)。

## Credits

感谢以下开源项目为 VCore 提供实现基础、架构参考与互操作验证：

- [smoltcp](https://github.com/smoltcp-rs/smoltcp)、[clash-rs](https://github.com/Watfaq/clash-rs) 与 [netstack-smoltcp](https://github.com/automesh-network/netstack-smoltcp)：用户态 IP stack 与 TUN netstack。
- [windows-rs](https://github.com/microsoft/windows-rs)、[UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample)、[wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs)、[Maple](https://github.com/YtFlow/Maple) 与 [YtFlowCore](https://github.com/YtFlow/YtFlowCore)：Windows VPN、WinRT activation 与 packet flow。
- [Xray-core](https://github.com/XTLS/Xray-core)、[Mihomo](https://github.com/MetaCubeX/mihomo) 与 [Leaf](https://github.com/eycorsican/leaf)：代理协议、路由、TUN 架构与互操作参考。
- [rustls](https://github.com/rustls/rustls)：TLS 实现与 VCore REALITY fork 的基础。

## License

VCore 使用 MIT License，见 [`LICENSE`](LICENSE)。
