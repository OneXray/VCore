# VCore

<p align="center">
  <a href="../README.md">English</a> · 简体中文 · <a href="./README.ru.md">Русский</a>
</p>

VCore 是用于 VPN 客户端和本地代理的 Rust 代理内核，提供原生库和前台 CLI。它通过直连、代理节点、代理组和代理链转发 TCP/UDP 流量，并集成 DNS、GeoData 和跨平台 TUN 数据面。

配置采用**与 Mihomo 兼容的 YAML，兼容范围限于 VCore 已支持的功能**。VCore 聚焦客户端能力，并未实现 Mihomo 的全部字段或完整 Dashboard API。

## 内核能做什么

- **接入应用与 VPN 流量：**HTTP 转发、CONNECT 和 Upgrade；SOCKS5 CONNECT 和 UDP ASSOCIATE；宿主提供的 IPv4/IPv6 TUN 数据包。
- **按目标路由：**支持域名、域名后缀/关键字、IP CIDR、目标端口、TCP/UDP、GeoSite 和 GeoIP 规则，以及明确的 DIRECT 和 REJECT 动作。
- **选择和串联代理：**支持嵌套 `select` 组、实时切换组选择，以及引用节点或组的 `dialer-proxy` 代理链。选择变化只影响新建的物理传输连接，不迁移既有连接。
- **处理 DNS：**支持指定出口的 UDP/TCP 上游、基于 GeoSite 的上游策略、顺序故障转移、缓存与重复查询合并；按配置拦截 TUN TCP/UDP DNS 目标，默认 53 端口。
- **识别流量用于路由：**通过 HTTP、TLS、QUIC 域名嗅探与 TUN DNS 提示辅助路由，不改写实际目标地址。ICMPv4/ICMPv6 Echo 在本地应答。
- **管理路由数据：**按需从 `geosite.dat` / `geoip.dat` 加载被引用的类别，并通过配置的路由更新文件。GeoSite 支持 Domain、Full、Plain 和 Regex、属性交集及反选；GeoIP 支持反选。所有平台完整保留所选记录，不设条数硬上限或截断，也不设 GeoData 总内存预算。详见 [GeoData 边界](../docs/geodata.md#内存与安全边界)。
- **提供客户端控制：**回环 Controller 支持代理组选择及 TUN 流量速率/累计量查询；Invoke API 提供隔离的节点/代理链延迟测量。

## 代理协议

默认构建启用下列全部八种协议。UDP 支持按节点配置。

| 协议 | 能力 |
| --- | --- |
| [VLESS](../docs/vless.md) | TCP、WebSocket / HTTPUpgrade、gRPC、HTTP 首包伪装、传统 H2、[XHTTP H1/H2/H3](../docs/xhttp.md)；在支持的组合中提供 Vision、Encryption、REALITY、JLS、静态 ECH 和 sing-mux |
| [VMess AEAD](../docs/outbounds.md#vmess-aead) | TCP、WebSocket / HTTPUpgrade、gRPC、HTTP 首包伪装和传统 H2；TCP/UDP，明文或标准 TLS |
| [Trojan](../docs/outbounds.md#trojan) | 通过 TLS TCP、WebSocket / HTTPUpgrade 或 gRPC 传输 TCP/UDP |
| [Shadowsocks 2022](../docs/outbounds.md#shadowsocks-2022) | TCP/UDP；AES-128-GCM、AES-256-GCM 和 ChaCha20-Poly1305；AES 身份链；可选 strict ShadowTLS v3 TCP 包装和 UoT v2 |
| [AnyTLS](../docs/outbounds.md#anytls) | TLS 会话与 UDP over TCP v2 |
| [SOCKS5](../docs/outbounds.md#socks5) | CONNECT 和 UDP ASSOCIATE，可选用户名/密码认证 |
| [Hysteria2](../docs/outbounds.md#hysteria2) | QUIC TCP/UDP、带宽控制、Salamander、端口跳跃和 mTLS |
| [TUIC v5](../docs/outbounds.md#tuic-v5) | QUIC TCP/UDP、native/quic UDP 转发模式，以及可选的拥塞控制算法 |

标准 TLS 连接支持证书验证与 SHA-256 证书固定。适用的 TCP TLS 路径可使用 Chrome、Firefox 或 Safari ClientHello 模板；`client-fingerprint` 与证书 `fingerprint` 相互独立。准确的名称和支持组合见 [TLS 配置与证书策略](../docs/tls-client-fingerprint.md)。这些功能不保证与浏览器不可区分，也不支持任意协议组合。

SS2022 使用未经修改的官方 Rust 库；已知的空首写入、服务端先发送和 padding 风险见 [Shadowsocks 契约](../docs/outbounds.md#shadowsocks-2022)。

## Mihomo 风格配置

使用熟悉的 `proxies`、`proxy-groups`、`rules`、`dns`、`mixed-port` 和 `tun` 结构。例如：

```yaml
mixed-port: 1080
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

请替换示例中的服务器地址与凭据。GeoSite/GeoIP 规则需要 `<dataDir>/geodata` 下的对应数据文件；缺失文件时，相应规则类型不可用。详见[完整配置参考](../docs/config.yaml)与 [GeoData 行为](../docs/geodata.md)。

`mixed-port` 在同一 TCP 端口接入 HTTP 与 SOCKS5，并在同端口启用 SOCKS5 UDP。`allow-lan` 控制绑定地址，与 `authentication` 独立：`authentication` 省略或为 `[]` 时，回环与通配绑定均免认证；配置凭据后 HTTP 与 SOCKS5 均校验。顶层 `port`、`socks-port`、`udp` 和 `listeners` 都会拒绝；代理节点的 `port` 与 `udp` 保留出站含义。

兼容范围限于文档列出的字段和行为，不覆盖任意 Mihomo 配置。代理组目前支持静态 `select`；DNS 上游使用固定 IP，通过 UDP/TCP 查询。Providers、自动代理组选择、加密 DNS 和 fake-IP 不在当前功能范围内。未知字段与无效组合会被拒绝，不会静默忽略；VCore 特有的语义会在相应契约中说明。

库接口由宿主使用内联 `configYaml` 启动实例；TUN 设备、描述符、MTU、DNS 拦截和 UDP 超时归属于 `tun` 配置，平台回调仍在运行时本地注册。CLI 通过同一 Invoke API 传递参数，由其前台操作读取 `-f` 指定的配置。接口地址、DNS 与系统路由由宿主配置。

## CLI

通过 `cargo build --locked --release --no-default-features --features cli --bin vcore` 构建前台程序；Windows 桌面 TUN 构建在 feature 列表中加入 `windows-wintun`。

```sh
vcore -f /path/to/config.yaml
vcore -d /path/to/data -f ./config.yaml
vcore -t -f ./config.yaml
```

`-d` 设置配置及数据目录，`-f` 独立指定配置文件；相对路径均从启动工作目录解析。省略 `-f` 时读取 `<数据目录>/config.yaml`，目录默认用户的 `.config/vcore`，按 Mihomo 规则回落到 `XDG_CONFIG_HOME`。`-f -` 从标准输入读取。`VCORE_HOME_DIR` / `VCORE_CONFIG_FILE` 提供环境默认值，显式参数优先。`-t` 只校验配置，`-v` 显示版本与构建身份，`-h` 显示帮助。详见 [CLI 与 tag 发布](../docs/cli.md)。

## 平台与集成

| 平台 | TUN 集成 |
| --- | --- |
| iOS / macOS | 宿主提供 utun 文件描述符；macOS 也可打开或创建原生 utun |
| tvOS 17+ | 宿主提供 utun 文件描述符；支持 ARM64 真机和模拟器目标 |
| Android | `VpnService` 文件描述符与出站 socket 保护 |
| Linux | 借用 fd 或由内核打开设备的真实单队列 raw-IP TUN；宿主负责系统网络配置 |
| Windows | 编译时互斥的 `windows-wintun` 桌面后端与 `windows-uwp` 安装包 Provider/Session Host；共用内核 |

VCore 提供原生库和前台 CLI；系统网络配置仍由平台宿主负责。Unix 宿主持有原始 TUN 描述符；VCore 使用并关闭自己复制的描述符。Apple 公开的 packetFlow API 不保证可获取 raw fd，因此实际 Network Extension 集成和设备验证仍由宿主负责。详见 [TUN 集成](../docs/tun-platform.md)与[平台验收边界](../docs/acceptance.md)。

桌面 Wintun 从进程可执行文件所在目录加载宿主提供的 `wintun.dll`。接口地址、DNS、路由与物理出口由宿主配置；Wintun 设备验收独立于已有安装包 VPN 结果。命令行使用与交付见 [CLI 与 tag 发布](../docs/cli.md)。

跨平台 C ABI 通过 Invoke API 接受 JSON 请求：

```c
char *VCoreInvoke(const char *request_json);
void VCoreFree(char *response);
```

单个公共实例遵循 `initialize → createInstance → start(configYaml) → stop → destroyInstance` 生命周期，准备过程由 `start` 内部完成；`validateConfig` 不要求初始化。CLI 通过显式的前台 Invoke 操作处理文件、环境默认值、信号与清理。API 还提供状态查询、GeoData 状态与延迟测量。详见 [Invoke API](../docs/invoke-api.md)、[Controller API](../docs/controller-api.md)与 [Windows 集成示例](../example/windows-uwp/README.md)。

## Benchmark

[**VCore / Mihomo TUN benchmark**](https://github.com/YuanDevTeam/container-benchmark) 提供两个内核在相同原生 Linux TUN 环境下的可复现测试设置、实测结果与对比图表。

benchmark 工程同时负责协议互通（`interop`）与内存压力（`stress`），通过显式 `--source vcore=PATH` 提供被测 checkout；VCore 自有脚本只编译核心与平台产物。

测试使用 **1 / 1.5 / 2 Gbps** 混合 TCP/UDP 流量、**每秒 1,000 次 DNS 查询**和增强的 `geosite:cn` / `geoip:cn` 规则，报告实际吞吐量、CPU、观察到的 Linux 峰值 RSS、UDP 丢包与成功的 DNS 查询数。它使用 DIRECT 出口评估 TUN/DNS/路由路径，不衡量加密代理吞吐量；Linux RSS 不等同于 Apple Network Extension 内存占用。

独立 `stress` 命令使用同样的完整增强 `geosite:cn` / `geoip:cn`，叠加 2 Gbps / 60 秒 / 1,000 QPS DNS。原始 DAT 不裁剪，但只加载 CN 分类；可选 `--geodata-update` 在流量期间执行真实下载与重载。实际输入类型、测量和失败见 benchmark README。任何单次观测都不是任意输入低于 50,000,000 字节的保证，也不替代 Apple 真机验收。

## 文档

- [文档索引](../docs/README.md)
- [配置参考](../docs/config.yaml)
- [核心与平台构建](../scripts/README.md)
- [CLI 与 tag 发布](../docs/cli.md)
- [核心回归测试](../tests/README.md)
- [资源策略](../docs/runtime-resource-policy.md)
- [验收与已知限制](../docs/acceptance.md)

## Credits

VCore 使用并参考以下公开依赖、协议实现和平台资料：

- TUN 依赖：自有 [`vcore-netstack`](../crates/vcore-netstack/README.md) 使用 [smoltcp](https://github.com/smoltcp-rs/smoltcp)，Unix 与 Windows Wintun 包 I/O 使用 [tun-rs](https://github.com/tun-rs/tun-rs)（Apache-2.0）。
- [Wintun](https://www.wintun.net/)：运行时 DLL 由宿主提供，不随 VCore 捆绑。tun-rs 中的上游 [API 头文件](https://github.com/tun-rs/tun-rs/blob/2.8.11/src/platform/windows/tun/wintun.h) 版权为 2018–2021 WireGuard LLC，许可证为 `GPL-2.0 OR MIT`；分发链接的 API bindings 时须保留其版权和 MIT 可选许可证声明。
- 网络与路由参考：[clash-rs](https://github.com/Watfaq/clash-rs)、[netstack-smoltcp](https://github.com/cavivie/netstack-smoltcp)、[Mihomo](https://github.com/MetaCubeX/mihomo)、[Xray-core](https://github.com/XTLS/Xray-core) 和 [Leaf](https://github.com/eycorsican/leaf)。这些参考项目并非 netstack 依赖。
- TLS 与 Shadowsocks：[rustls](https://github.com/rustls/rustls)、[boring](https://github.com/cloudflare/boring)、[BoringSSL](https://boringssl.googlesource.com/boringssl/) 和 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)。衍生的重放窗口代码保留了 [MIT 声明](../src/outbound/shadowsocks/packet_window.rs)。
- Windows 集成：[windows-rs](https://github.com/microsoft/windows-rs)、[UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample)、[wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs)、[Maple](https://github.com/YtFlow/Maple) 和 [YtFlowCore](https://github.com/YtFlow/YtFlowCore)。

## License

[MIT](../LICENSE)。
