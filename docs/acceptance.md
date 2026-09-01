# VCore 验收矩阵

本文只记录当前能力的验证边界，不保存候选包历史、临时进程号、一次性吞吐结果或旧产物哈希。发布产物的 revision、hash 和签名结果应写入对应发布记录。

## 证据规则

- 通过结论必须在对应 PR、发布记录或验收记录中说明环境、命令、结果和适用范围；本矩阵只记录当前有效边界。
- 主机单元测试和集成测试不能证明物理 TUN 或安装包边界。
- 交叉编译不能证明目标设备可运行。
- 模拟 IPv6 不能替代真实物理 IPv6。
- x64 模拟不能替代原生 x64 Windows。
- 外网吞吐不能替代进程间通信基准，反之亦然。
- 未执行的矩阵项保持“未验证”，不能从旧产物继承结论。
- 文档和日志不得包含 secret、凭据、UUID、密钥、完整用户配置或私有目标信息。

## 自动化覆盖

当前测试覆盖以下公共边界：

- Invoke API v5 envelope、严格 payload、单实例生命周期、panic 隔离和同步清理；
- 配置修订版 13、IPv6 总开关、代理图、静态 `select` 代理组、节点测速配置和未知字段拒绝；
- VLESS/XHTTP/TLS/REALITY、SOCKS5、AnyTLS 和代理链；
- DNS wire、缓存、singleflight、policy、故障转移和 TCP 复用；
- 规则、GeoData、HTTP/TLS/QUIC 嗅探；
- ICMPv4/ICMPv6 Echo、校验和、分片、MTU 和队列满；
- Apple/Android TUN 帧格式、文件描述符副本和关闭所有权；
- Windows 单 Application manifest、Provider/Session Host token 绑定、控制/数据协议、Session Snapshot v2、会合记录、包队列、批量写入、物理网络绑定、全部 on-link prefix 去重、显式排除优先的本地路由规划和 Job Object 多进程监督；
- Controller 鉴权、速率和累计流量语义，以及代理组查询、实时选择和有界请求处理。

常用命令：

```bash
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

外部互操作按需运行：

```bash
bash tests/run_xray_interop.sh
bash tests/run_anytls_interop.sh
```

Windows 11 ARM64 开发验收的环境、命令、结果和适用范围保存在以下不可变记录中：

- [Session Runtime lifecycle、失败关闭、重连与 pressure](https://github.com/OneXray/VCore/blob/f41610c/docs/acceptance.md#windows-session-runtime-phase-6-2026-08-24)
- [protocol-v1 有界 batching](https://github.com/OneXray/VCore/blob/7856bef/docs/acceptance.md#windows-session-runtime-phase-6-2026-08-24)
- [外部 TUN/DNS 地址与安装包边界](https://github.com/OneXray/VCore/blob/1011955/docs/acceptance.md#6-windows-vpn)
- [external Xray SOCKS tun2socks demo](https://github.com/OneXray/VCore/blob/6636bd7/docs/acceptance.md#67-external-xray-socks-tun2socks-demo)
- [UWP VPN 最小示例 lifecycle](https://github.com/OneXray/VCore/blob/26e1095/docs/acceptance.md#windows-vpn)

这些记录只证明其明确列出的开发环境和场景，不是当前 release 或 Store 保证。没有保留公开命令记录的观察结果不计入下方“已验证”范围。

## 协议与数据面

| 能力 | 自动化 | 外部进程互操作 | 物理 TUN / 安装包 |
| --- | --- | --- | --- |
| VLESS + XHTTP + TLS/REALITY | 已覆盖 | 本地 Xray harness | Windows ARM64 已覆盖 |
| SOCKS5 CONNECT / UDP ASSOCIATE | 已覆盖 | 本地 SOCKS fixture | Windows ARM64 已覆盖 |
| AnyTLS TCP / UoT v2 | 已覆盖 | 本地 harness | Windows ARM64 已覆盖 |
| DIRECT 与代理链 | 已覆盖 | 本地 fixture | Windows ARM64 已覆盖 |
| DNS / rules / GeoData / sniffer | 已覆盖 | 本地 DNS 与代理 fixture | Windows ARM64 已覆盖 |
| ICMPv4 / ICMPv6 Echo | 已覆盖 | 不适用 | Windows ARM64 已覆盖 |
| Controller 四字段流量 | 已覆盖 | HTTP fixture | Windows ARM64 已覆盖 |
| Controller `select` 代理组控制 | 已覆盖 | HTTP fixture | 物理设备未验证 |

“本地互操作”只证明当前双方在受控配置下可以通信，不代表所有公网服务或配置组合。

## Apple 与 Android

主机自动化覆盖：

- `utun` / `rawIp` 帧格式；
- 借用文件描述符的复制和关闭所有权；
- nonblocking 要求、EOF、非法包和部分写入；
- Android protect 回调和失败关闭；
- 重复 prepare/start/stop。

构建脚本可以生成 Apple XCFramework 和 Android arm64-v8a/x86_64 库，但构建成功不等于真机通过。

仍需独立验证：

- Release iOS 无 debugger 的完整 TUN 生命周期和整进程内存轨迹；
- Android 物理设备上的 TUN、protect、DNS、TCP/UDP 和重复启停；
- macOS system extension 的产品安装和生命周期。

## Windows VPN

单 Application 可行性在当前 Windows 11 ARM64 build 26200.9278 机器的 Developer Mode loose-package spike 上验证。该 spike 以 `042919ab5ead6af719ae68564244966e95003b58` 为基线，并包含后来收敛为 `d9018a2dfb75ab1f55c593023cbaa60951165eb5` 的未提交目标改动；基线 SHA 本身不能复现该结果。实际执行路径为：

```powershell
Add-AppxPackage -Register <stage>\AppxManifest.xml
vcore-uwp-demo.exe environment
vcore-uwp-demo.exe status
vcore-uwp-demo.exe start <demo.yaml>
vcore-uwp-demo.exe status
vcore-uwp-demo.exe stop
```

观察结果是 manifest 只有一个 Application，Provider 是 AppContainer，Provider 通过无参数 `FullTrustProcessLauncher` 启动具有同一 package identity 的 medium-integrity Session Host，connect/stop 与 rendezvous 清理通过。该记录只证明本机可行性，不作为其他系统、架构、签名包、WACK 或 Store 的验证结论。

此前 Windows 11 ARM64 开发签名包的数据面证据覆盖：

- `Windows.Networking.Vpn` Provider 激活；
- 完全信任前台宿主、AppContainer Provider 和完全信任 Session Host 的进程边界；
- 同包限定命名管道和单一 package-owned profile；
- IPv4/IPv6 两条 `/1` 路由、外部 DNS assignment 和不可变 TUN/DNS 地址；
- ICMP、TCP、UDP、DNS、HTTP/HTTPS 和完整代理图；
- 非回环 socket 的物理源地址与接口索引绑定；
- Controller、外部回环 SOCKS5 和前台宿主退出后的会话延续；
- Provider/Session Host 退出、管道错误和网络变化时的失败关闭；
- 快速重连、持续压力、零队列丢弃和显式 Stop 清理。

### 全局 VPN policy 与 IPv4-only clean gate（2026-09-01）

当前 Windows 11 ARM64 build 26200.9278 主机重启后，先确认 package-owned route、interface 和进程均为零，再用同一源树构建、开发签名并安装单 Application MSIX。实际结果：

- `ipv6: false` 和 `ipv6: true` 都完成稳定 `start → status → TCP traffic → stop → status`；前者运行时有一个 VPN interface，后者有两个，Provider 和 Session Host 都各激活一个；
- 两种地址模式都观察到 Provider ingress/egress，显式 Stop 后 Session Host、route 和 interface 均归零；
- `ipv6: false` 向 `StartWithMainTransport` 传 null IPv6 client-address 参数后通过；传空集合的对照包稳定返回 `0x8007000E`，且不启动 Session Host；
- 主 transport 绑定当前物理地址后，目标 exclusion route 选择物理出口，而未排除的控制流量仍进入 VPN；回环绑定的对照包会使 exclusion traffic 超时；
- `allowLocalNetwork: true` 时实机局域网 peer 选择物理出口；设为 `false` 后，Provider 为当前适配器全部去重的 on-link prefixes 安装更具体的 inclusion routes，路由总数由 6 增至 10，同一 peer 选择 `/25` VPN route，并完成外网双向流量；
- profile 的 Always On capability 在连接时读回为启用，显式 Stop 后保持断开；随后用默认 policy 重建 profile 时读回为禁用；
- 已有 profile/Snapshot 在前台启动命令退出、Provider/Session Host 均不存在时，由系统 profile connect 冷启动两个 native 进程并完成双向流量；
- 类型错误的 policy 在 Provider 激活前被拒绝；运行中强制终止 Session Host 后 Provider 失败关闭，profile 变为 disconnected，route/interface 清零；
- 每个 gate 结束时都确认无 Session Host、route 或 VPN interface 残留。Provider 的已停止 AppContainer 外壳可能暂留，验收脚本在各 case 之间显式结束它。

路由规划修复后，同机开发签名包再次通过 IPv4-only/dual-stack lifecycle 与流量、LAN bypass、IPv4 exclusion/control、Always On、cold profile、失败关闭和零残留门禁。自动化同时覆盖多地址、多 IPv4/IPv6 on-link prefix、重复子网和显式 exclusion 与生成子前缀重叠；实机只探测到一个局域网 peer，未逐一验证每个 on-link prefix。

该记录证明当前机器上的 IPv4 物理出口和 Windows 分配的双栈 VPN interface；主机没有物理 IPv6/default gateway，因此真实 IPv6 exclusion 仍未执行。

Windows 路由必须保留两条 `/1`。在安装包环境中，单条 VPN `/0` 会使按产品要求绑定物理源地址和接口的外层 socket 返回 `WSAENETUNREACH`；两条 `/1` 不会产生该问题。

以下项目由发布开发者在对应机器或服务中验证，不阻塞上述本机可行性结论：

- production-signed MSIX、WACK 与 Store 安装路径；
- Windows 10 20H2；
- 原生 x64 Windows；
- 真实物理 IPv6；
- 新鲜物理网卡禁用场景；
- WACK；
- Partner Center identity、publisher 和受限能力审批；
- ARM64/x64 Store bundle 与提交；
- 多用户和远程会话矩阵；
- 带公开、可复现命令记录的 `sessionBackend` package-boundary argv、进程退出和 Job 清理矩阵；
- native x64 和正式宿主 UI 路径下的 `sessionBackend` 回归。

## rustls REALITY 发布

REALITY 线上向量、普通 TLS 回归、错误 key/short ID、HRR、并发和取消已有自动化覆盖。`Cargo.toml` 已通过 GitHub 分支 `vcore/reality-0.23` 引用 fork，`Cargo.lock` 固定实际解析 revision。以下发布门禁仍需在正式发布环境完成：

- 从无相邻 rustls 目录的干净检出执行 locked tests；
- 使用同一 lockfile 完成 Apple、Android 和 Windows 三平台构建；
- 保存并复核 VCore revision、rustls revision、lockfile hash 和产物 hash。

详细要求见 [rustls REALITY 依赖与发布要求](rustls-reality-release.md)。

## 记录要求

每次正式发布单独保存：

- VCore 和 rustls revision；
- toolchain 与目标架构；
- lockfile 和产物 SHA-256；
- 签名与安装结果；
- 实际执行的物理设备、网络和失败关闭矩阵。

没有当次记录的项目不得写成发布保证。
