# VCore Windows UWP TUN 调研

> 状态：首版架构基线已确认；Phase 0 最小数据面 spike 已通过；Phase 1 tracer bullet 的完成线已确认，尚未实现。记录于 2026-08-22，Phase 0 结果记录于 2026-08-23。

## 开发原则

以最快速度验证功能为最终目标。每次只实现并验证当前最短功能路径；不得过度进行安全设计，不得设计冗余风险验证，也不得仅因潜在风险增加步骤、抽象或产品化代码。每个阶段都不提前处理后续 packaging、UX、长期运行或完整平台矩阵；编译通过只是进入实测的门槛，不是阶段完成证据。使当前验证本身成立的 WinRT buffer 归还、bounded callback 和 source bind 防递归属于功能正确性，不是额外 hardening。

## 结论

VCore 可以复用现有 raw-IP netstack 与代理数据面；Windows 不应引入 Wintun，也不能把 WireGuard 的“单一远端 transport”实现直接套过来。最小可行方向是：

1. 用 `windows-rs` 实现 `IVpnPlugIn` 与后台激活。
2. `Encapsulate` 把 Windows 提供的 L3 包复制进 VCore 的有界 raw-IP 入口。
3. VCore 回包进入有界队列；通过一对同进程 loopback `DatagramSocket` 发送一个 dummy datagram 唤醒 `Decapsulate`，再把队列中的 raw-IP 包写入 `decapsulatedPackets`。
4. VCore 创建的每个物理 TCP/UDP socket 在 connect/send 前绑定到选定物理网卡的本地 IP，避免流量重新绕入 VPN。
5. Windows App 必须改为带包身份的 AppX/MSIX，并声明 `networkingVpnProvider`；当前 Inno/ZIP 外壳不能承载 VPN 插件。

第 3、4 点已有同类 UWP 代理 Maple/Leaf 的实际实现证据，但仍必须在 Windows 10 与 Windows 11 真机/VM 上做最小数据面验证后再进入正式实现。

## 已确认的首版基线

- **最低系统**：Windows 10 22H2，build 19045；manifest 使用 `TargetDeviceFamily MinVersion="10.0.19045.0"`。这是 Windows 10 最后一个通用版本，能满足 Win10 要求并避免为已结束常规支持的旧版本扩大测试矩阵。首版不承诺 LTSC 2019/2021。
- **架构**：ARM64 先跑通；发布前补齐 x64，最终向 Store 提交同版本的 ARM64 与 x64 架构包，并组成一个 `.msixbundle`/Store upload。
- **渠道**：产品只通过 Microsoft Store 发布；本地开发仍需 dev-signed sideload package 做调试，但不提供 sideload 作为产品分发渠道。
- **能力**：manifest 必须声明 `networkingVpnProvider`；现有 Flutter Win32 foreground 以 medium-IL full-trust app 入包时还必须声明 `runFullTrust`。两项均作为 restricted capability 在 Partner Center Submission options 中提交用途说明并接受审核。
- **网络切换**：首版 fail-closed。选定物理网卡或绑定地址失效时停止 VCore/VPN 并向前台报告 disconnected/error；不得退回未绑定 socket，也不自动选择新网卡重连。用户确认后手动重连，后续再单独增加安全的自动重连。

采用**一个 Store MSIX/AppX family package**：其中包含 Flutter 的传统 Win32/full-trust foreground 和 AppContainer 中的 UWP VPN background task。这是已确认的首版发布模型，不要求 pure-UWP foreground。

来源：

- [Flutter Windows：传统 Win32 runner 与 Store MSIX 分发](https://docs.flutter.dev/platform-integration/windows/building)
- [Microsoft Store MSIX package requirements](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-package-requirements)
- [Restricted capability approval process](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations#restricted-capabilities)

## 当前工程结构

工作区根目录包含三个独立 Git 仓库：

- `OneVCore/`：Flutter App。
  - `lib/core`：基础设施、Pigeon、FFI、模型。
  - `lib/service`：配置组合、VPN 生命周期、TUN 设置。
  - `lib/pages`：UI。
  - `swift/` 与 `android/`：当前可工作的 Apple/Android 宿主。
  - `windows/`：仅 Flutter Win32 外壳；`AppPlatform.supportsVCoreRuntime`、`AppHostApi`、runtime bundle writer、构建/发布测试都明确 fail-closed。
- `VCore/`：Rust VPN core。
  - `src/ffi`：Invoke API v5、单公共实例生命周期、独立运行线程。
  - `src/runtime.rs`：配置准备、outbound graph、DNS/routing/GeoData 与长生命周期任务组合。
  - `src/tun_runtime.rs`：raw-IP I/O、TCP/UDP/DNS/sniffer 与 `vcore-netstack` 的连接层。
  - `src/platform`：目前只有 Unix fd + `rust-tun` adapter。
  - `crates/vcore-netstack`：与平台 TUN 无关的 bounded raw-IP netstack。
- `rustls/`：官方 rustls 0.23.43 基线上的项目 fork；主要新增 feature-gated client-side REALITY。

当前 TUN 数据流为：

```text
Apple/Android host TUN fd
  -> TunFd duplicate
  -> RustTunIo.read_packet
  -> TunRuntime
  -> vcore-netstack PacketSink
  -> TCP/UDP session
  -> RoutingDispatcher
  -> outbound graph / Dialer

vcore-netstack PacketStream
  -> TunRuntime
  -> RustTunIo.write_packet
  -> host TUN fd
```

Windows 的最佳接入 seam 是 `src/platform` 的 raw-IP adapter，不是 DNS、routing、outbound 或 `vcore-netstack`。现有调用方只需要继续看到同样的 `TunIo::{read_packet, write_packet}` 形状；Unix 与 Windows adapter 可按 target 编译，不需要先引入运行时工厂或单实现 trait。

## Windows.Networking.Vpn 模型

### 生命周期与打包

`IVpnPlugIn`、`VpnChannel`、`VpnPlugInProfile` 和 `VpnManagementAgent` 从 Windows 10 build 10240 起存在。VPN background task 由包 manifest 中的 `windows.backgroundTasks` / `vpnClient` 声明触发；后台入口应把同一个 `IVpnPlugIn` 实例传给 `VpnChannel::ProcessEventAsync`，因为插件会跨多次事件保存状态。

包必须声明 restricted capability：

```xml
<rescap:Capability Name="networkingVpnProvider" />
```

Microsoft Store 发布需要说明用途并经过 restricted-capability 审核；开发模式或 sideload 不要求 Store 审批。

来源：

- [Windows.Networking.Vpn namespace](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn)
- [IVpnPlugIn](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.ivpnplugin)
- [VpnChannel](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel)
- [App capability declarations](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations#restricted-capabilities)
- [Microsoft UWP VPN sample](https://github.com/microsoft/UwpVpnPluginSample/tree/d589fe0f57af13e052c44c662ade5fb1da2bcbb0)

### packet buffer 所有权

`Encapsulate` 的 `packets` 是本机 TCP/IP stack 产生的 L3 包。插件请求或取出的每个 `VpnPacketBuffer` 都必须归还给 VPN framework：

- 不消费原包时，可复制内容后留在/放回 `packets`，由 framework 清理。
- 发往真实 outer transport 的包放入 `encapsulatedPackets`。
- 注入本机 stack 的包在 `Decapsulate` 中放入 `decapsulatedPackets`。

VCore 应在 callback 内完成复制，不把 Windows buffer 的裸指针或借用跨 callback 保存。访问 `IBuffer` 字节需通过 `IBufferByteAccess`，写入后设置 `Length`。

来源：

- [IVpnPlugIn.Encapsulate remarks](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.ivpnplugin.encapsulate)
- [IVpnPlugIn.Decapsulate remarks](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.ivpnplugin.decapsulate)
- `references/wireguard-uwp-rs/plugin/src/plugin.rs`

## Win10/Win11 共用的回包唤醒方案

`VpnChannel.AppendVpnReceivePacketBuffer` / `FlushVpnReceivePacketBuffers` 直到 UniversalApiContract v12、build 20348 才引入，不能作为 Windows 10 22H2（build 19045）路径的基础。

来源：

- [AppendVpnReceivePacketBuffer requirements](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel.appendvpnreceivepacketbuffer)
- [FlushVpnReceivePacketBuffers requirements](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel.flushvpnreceivepacketbuffers)

Maple 给出了兼容旧 API 的代理型 TUN 方案：

```text
Connect:
  create transport + backTransport DatagramSocket
  AssociateTransport(transport)
  bind/connect the pair on 127.0.0.1
  StartWithMainTransport(transport)

Encapsulate:
  Windows raw-IP buffers -> copy -> core ingress

core egress callback:
  enqueue raw-IP packet
  if queue changed empty -> non-empty:
      backTransport writes one-byte dummy to transport

Decapsulate(dummy):
  drain queued raw-IP packets
  GetVpnReceivePacketBuffer
  copy + set Length
  append to decapsulatedPackets
```

同一个 UWP 项目/进程内允许 loopback socket 通信；Windows 阻止的是同机不同 UWP app 间的普通 socket 通信。Maple 的实现正是使用同进程 loopback pair 唤醒 `Decapsulate`。

来源：

- [`Maple.Task/VpnPlugin.cpp`](https://github.com/YtFlow/Maple/blob/ec052fcb014b14e50cb264abc1415807609ec07b/Maple.Task/VpnPlugin.cpp)
- [UWP sockets/network isolation](https://github.com/MicrosoftDocs/windows-dev-docs/blob/docs/uwp/networking/sockets.md)

VCore 版必须保留自身资源边界：回包队列最多沿用 `packet_queue_capacity = 256`，只在 empty -> non-empty 时发 dummy，`Decapsulate` 一次 drain；队列满时局部丢包并记统计，不能阻塞 Windows callback，也不能采用 Maple 的无界 `std::queue`。

Windows 11 后续可测量 v12 direct append 是否值得作为优化；第一版不必同时维护两条回包路径，loopback wake 已覆盖 Win10/Win11。

## outbound socket 防递归

`AssociateTransport` 只接受最多两条由 VPN framework 托管的 `StreamSocket`/`DatagramSocket` outer transports。VCore 是逐流代理，会主动创建任意数量的 TCP/UDP socket，不能把这些 socket 逐个交给 `AssociateTransport`：framework 会把它们当 VPN outer transport 管理其 I/O。

普通新建 socket 仍会命中 VPN 路由并递归。Maple/Leaf 的做法是在 connect 前把每个 socket 绑定到选定物理网卡的本地 IPv4/IPv6 地址。VCore 已把实际 TCP/UDP socket 创建集中在 `src/dialer.rs`，因此应只在 `Dialer` 增加可选 source bind 地址：

- TCP：`TcpSocket::bind(physical_ip:0)` 后再 `connect`。
- UDP：直接在 `physical_ip:0` 上 `bind`。
- Android `protect(fd)` 保持原行为。
- 非 TUN / 非 Windows runtime 不设置 bind 地址。

这会一次覆盖 proxy root、任意 proxy chain、DIRECT TCP/UDP 和 runtime DNS，不应在每个 outbound 分别打补丁。

Maple 还使用两个 `/1` inclusion routes 代替 `/0`，并报告 `/0` 会使已经绑定物理地址的 socket 仍绕回 VPN。Windows 验证应复现这一点：

```text
IPv4: 0.0.0.0/1 + 128.0.0.0/1
IPv6: ::/1 + 8000::/1
```

来源：

- [VpnChannel.AssociateTransport](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel.associatetransport)
- [Maple issue #26](https://github.com/YtFlow/Maple/issues/26)
- [`Maple.Task/VpnPlugin.cpp`](https://github.com/YtFlow/Maple/blob/ec052fcb014b14e50cb264abc1415807609ec07b/Maple.Task/VpnPlugin.cpp)
- [`YtFlow/leaf` UWP socket binding](https://github.com/YtFlow/leaf/blob/e40217e06be1bb57b17ea73fd0a083b9da15239b/leaf/src/proxy/mod.rs)

OneVCore 已有 `TunSettingsState.autoOutboundsInterface` 与网卡选择 UI，可复用为 Windows 的“auto/manual physical interface”旋钮；plugin 在 VPN route 启动前解析为具体本地地址，再交给 VCore `Dialer`。

## wireguard-uwp-rs 可复用与不可复用部分

可参考：

- `DllGetActivationFactory` 与 background activatable class。
- `CoreApplication::Properties` 保留同一 plugin 实例。
- `VpnChannel::ProcessEventAsync`。
- `IBufferByteAccess`、buffer pool 与归还规则。
- AppX manifest 的 `vpnClient`、`networkingVpnProvider`、in-process server。
- `VpnPlugInProfile`、route、DNS namespace 的基本构造。

不可直接复用：

- 该工程是传统 VPN：一个受管 UDP transport 承载 WireGuard frame；VCore 则截获 L3 后自行建立逐流代理连接。
- 它没有解决普通 outbound socket 递归问题。
- 最后提交于 2021-12，依赖 `windows = 0.28`、`boringtun = 0.3`、`ring = 0.16`。
- 当前 ARM64 + VS 18 环境下 `cargo check --locked` 在旧 `ring 0.16.20` C build 失败，因此只应作为语义参考，不应升级后直接纳入 VCore。

来源：[luqmana/wireguard-uwp-rs @ 328e622](https://github.com/luqmana/wireguard-uwp-rs/tree/328e622fb613d611bb022874a6535e2846ac6640)

## windows-rs 与 Rust target

- crates.io 当前稳定版 `windows` 为 `0.62.2`；已在本机用它成功编译 ARM64 `IVpnPlugIn` + `IBackgroundTask` + `DllGetActivationFactory` 的最小 `cdylib` probe。
- `references/windows-rs` 当前源码为 `acaaa37be53e68f8c1be575d24dcbebce1e92b1a`，workspace 版本 `0.100.0`，尚不是 crates.io 稳定版；正式依赖应先用 `0.62.2`，不要绑未发布 Git HEAD。
- Rust 的 `*-uwp-windows-msvc` 是 Tier 3，rustup 不提供预编译 artifacts；需要 nightly `-Z build-std` 或自行构建 std。Maple 使用 nightly + `build-std`。
- 普通 `*-pc-windows-msvc` DLL 能被旧 `wireguard-uwp-rs` 方案加载，但 VCore 的完整依赖是否满足 AppContainer/WACK 限制尚未验证。不能仅凭 host `cargo check` 宣称 UWP 可发布。

来源：

- [windows-rs](https://github.com/microsoft/windows-rs/tree/acaaa37be53e68f8c1be575d24dcbebce1e92b1a)
- [Rust UWP target support](https://doc.rust-lang.org/rustc/platform-support/uwp-windows-msvc.html)

本机基线：Windows 11 build 26200、ARM64 Rust 1.98.0、VS 18、Windows SDK 26100。VCore default features 在正确 VS 环境下可通过 Windows host `cargo check`；`--all-features` 当前按预期失败于 Unix-only `TunFd/TunIo` import 与缺失的 Windows `start_tun`。

## OneVCore Windows 接入影响

当前 Flutter Windows 工程只有 Win32 runner，且所有 runtime path 都 fail-closed。正式接入至少涉及：

1. **包身份**：新增单一 Store AppX/MSIX package；其中 Flutter Win32 foreground 为 medium-IL full-trust application，VPN background task 为 AppContainer application/extension。Inno 安装不能声明 VPN provider，也不再是 Windows 发布产物。
2. **两进程**：Flutter foreground 与 VPN background task 分离；background task 内有独立 VCore registry/runtime。
3. **共享目录**：foreground 通过 Windows native bridge 获取 `ApplicationData.Current.LocalFolder`，Dart 把现有 start snapshot 与 immutable VCore YAML 发布到该包目录，plugin 从同一目录读取；不需要把 256 KiB YAML 塞进 profile custom field。
4. **profile 管理**：native bridge 用 `VpnManagementAgent` 创建/查找 `VpnPlugInProfile`，设置 package family name，并 connect/disconnect/read status。
5. **Flutter bridge**：当前 Pigeon 只生成 Dart/Kotlin/Swift；Windows 需要生成/接入 C++ host，或提供同等薄的 native bridge。不要恢复已废弃的 `OneVCoreCore.exe`/libXray donor 路径。
6. **runtime bundle**：`VCoreRuntimeBundleWriter` 当前明确拒绝 Windows，且依赖 Unix symlink 原子切换；Windows 需要 package-local 的原子文件/目录发布方式。
7. **发布**：同时声明 `networkingVpnProvider` 与 `runFullTrust`，在 Partner Center 分别说明 VPN plugin 和 Flutter Win32 foreground 的必要性；生成 ARM64/x64 Store upload，开发签名包只用于本地验证。

## 建议实施顺序

### Phase 0：先做 Windows 数据面 spike

在 `references` 中复用官方样例外壳，做可丢弃的最小 `windows-rs 0.62.2` AppX。当前完成线严格限定为：

1. 在本机 Windows 11 ARM64 安装 dev-signed package，以普通 `aarch64-pc-windows-msvc` target 激活 Rust `IVpnPlugIn` 并成功 Connect。
2. IPv4 packet 完成 `Encapsulate -> bounded queue -> dummy wake -> Decapsulate` 往返。
3. 一个普通 Tokio TCP socket 复现 VPN 递归；绑定当前物理 IPv4 并使用两个 `/1` routes 后成功出站。
4. 成功 Disconnect 一次，立即停止并报告结果。

到达这条完成线后停止，不顺带产品化。IPv6、UDP、VCore 协议、Flutter、DNS、Windows 10、x64、WACK、压力测试、网络切换、Store 与正式 package/runtime 结构全部延期到下一次明确决策。

#### Phase 0 结果：PASS

2026-08-23 在 Windows 11 ARM64 build 26200.9168、Rust 1.98.0、crates.io `windows = 0.62.2` 与普通 `aarch64-pc-windows-msvc` target 上实际执行：

- dev-signed ARM64 AppX 安装成功，系统报告 `SignatureKind=Developer`；Rust `IBackgroundTask` / `IVpnPlugIn` activation、Connect 与 Disconnect 均通过。
- IPv4 packet 经 `Encapsulate -> bounded queue -> dummy wake -> Decapsulate` 返回；对文档地址 `203.0.113.1` 的本地 fake ICMP reply 为 1 ms。
- 两个 `/1` routes 生效后，未绑定 Tokio TCP 到中国大陆可达的 `223.5.5.5:53` timeout；同一 socket 绑定物理 `172.16.29.128` 后连接成功，实际 local address 属于该物理网卡。
- 最终一次运行计数为 39 encapsulated / 1 decapsulated，随后正常 Disconnect。

`1.1.1.1:443` 曾因 GFW 环境导致 VPN 断开时也 timeout，已作为无效 fixture 排除，不能计作 source-bind 失败。本轮按约定未执行 IPv6、UDP、VCore 协议、Flutter、DNS integration、Windows 10、x64、WACK、压力测试、网络切换、Store 或 production architecture。可丢弃源码与完整命令保存在本地 ignored `references/uwp-tun-spike/`。

### Phase 1：VCore IPv4 端到端 tracer bullet

本阶段只消除一个未知：完整 VCore runtime 能否在 Windows VPN provider 中完成真实 IPv4 数据面。Phase 0 已分别证明 WinRT callback、loopback wake 和普通 Tokio source bind；host-only channel test 不能代替组合后的 AppContainer 实测。

最小实现严格限定为：

1. Windows VPN provider 作为 VCore crate 的 Windows-only module，由 `vcore.dll` 同时导出 COM activation 与现有 FFI；activation class 使用 `OneVCore.VpnBackgroundTask`，不建立独立 plugin crate 或临时公共 runtime interface。
2. 新增具体 `WindowsTunIo` 与 provider 持有的 `WindowsPacketAdapter`。bounded Tokio ingress channel 接收 callback 内复制的 raw-IP bytes；bounded `Mutex<VecDeque>` egress 只在 empty -> non-empty 时发送 dummy wake，`Decapsulate` 一次 drain。两侧容量均为 256，满时丢当前 packet，不阻塞 callback。
3. `platform::TunIo` 继续由 target cfg 在 Unix `RustTunIo` 和 Windows `WindowsTunIo` 间选择，不增加 trait、runtime factory 或 fake fd。提升 `tun_runtime` / `PreparedCore::start_tun` 的 cfg，使 Windows 可运行现有 netstack、routing 和 outbound graph。
4. `Dialer` 保存一个 runtime-local、可选 `IpAddr`。TCP connect 与 UDP bind 都使用该地址；目标地址族不匹配时 fail-closed。本阶段只实际验证 IPv4 TCP，IPv6 与 UDP 仍为 `NOT RUN`。
5. Provider 内嵌一份最小 current-schema YAML：启用 TUN，以 `IP-CIDR,223.5.5.5/32,DIRECT,no-resolve` 命中测试出口，并提供一个不会被本轮流量使用的 dummy proxy 满足最终 `MATCH` 约束。不读取 snapshot，不接 Flutter。
6. VCore startup 失败即使 Connect 失败；显式 Disconnect 必须等待 runtime 完整停止。runtime 意外退出后自动跨线程调用 `VpnChannel.Stop` 延期到正式 lifecycle；本轮脚本必须在失败路径也执行 Disconnect。
7. Invoke API v5 与 config schema revision 11 保持不变。Windows `tunFd` 继续明确 unsupported；provider 仅调用 crate-private runtime。使用现有 `ffi -> tun` feature，不增加 `windows-vpn` feature。
8. Dev-signed AppX shell 继续保存在 ignored `references/uwp-tun-spike/`；TCP DNS probe 放在 workspace `python-tools/`，不整理正式 packaging harness。

实际数据流为：

```text
VpnPacketBuffer
  -> WindowsPacketAdapter bounded ingress
  -> WindowsTunIo
  -> TunRuntime / vcore-netstack
  -> DIRECT / Dialer(source_ip)
  -> 223.5.5.5:53
```

完成线：

1. VPN 断开时，TCP DNS probe 先向中国大陆可达的 `223.5.5.5:53` 查询 `www.baidu.com` 并校验有效响应，证明 fixture 可用。
2. Windows `cargo check --all-features`、相关 focused tests 与 dev-signed ARM64 AppX build 通过。
3. AppX 激活真实 VCore provider 并成功 Connect；对文档地址 `203.0.113.1` 的 fake ICMP reply 由 VCore netstack 返回，不再由 Phase 0 plugin 生成。
4. 同一 TCP DNS probe 在 VPN 内经完整 TUN -> VCore -> DIRECT -> source-bound `Dialer` 路径收到有效响应。
5. 成功 Disconnect，确认 runtime stop barrier 完成，执行 `git diff --check` 后立即停止并报告。

IPv6、UDP 实测、VCore DNS integration、VCore 代理协议、Flutter、snapshot、Windows 10、x64、WACK、正式 packaging 与 runtime 意外退出后的自动 Stop 全部延期，不能顺带实现。

### Phase 2：Windows provider 完整化

- runtime 意外退出后 fail-closed Stop、callback 重入、panic/error COM ABI 边界与完整 lifecycle。
- IPv6、UDP、DNS namespace、物理网卡选择与网络变化 fail-closed。
- queue/drop 统计、buffer ownership 审计与长时间 pool/压力验证。
- Windows 10 22H2 与 x64 验证。

### Phase 3：Flutter/MSIX

- Windows profile/status native bridge。
- package-local config/start snapshot。
- MSIX manifest、签名、安装、卸载、升级。
- 打开 Windows runtime gates，删除对应 fail-closed 断言并替换为正向集成检查。

## 必须验收

- Windows 10 22H2 build 19045 与 Windows 11，均覆盖 x64/ARM64；实现顺序为 Win11 ARM64 -> Win10 ARM64 -> x64。
- IPv4/IPv6 TCP、UDP、DNS，ICMP fake reply。
- VLESS/SOCKS5/AnyTLS、TLS/REALITY、XHTTP、任意无环链。
- DIRECT 与 proxy 路由均不递归进入 TUN；实际 socket local address 属于选定物理网卡。
- queue 满、无效包、插件重入、App 退出后 background VPN、重复 start/stop、异常 core 退出。
- 每个 Windows packet buffer 均归还；长时间压测无 pool 泄漏。
- MSIX 安装/升级/卸载、restricted capability、Windows App Certification Kit。

## 已完成产品决策

- Windows 10 22H2 build 19045 起。
- ARM64 先行，首发同时提供 ARM64/x64。
- 仅 Microsoft Store 发布。
- Flutter full-trust foreground + UWP/AppContainer VPN background task，同包交付。
- 网络切换首版 fail-closed，用户手动重连。

## 本轮新增参考 checkout

| 目录 | Revision | License | 用途 |
| --- | --- | --- | --- |
| `references/windows-rs` | `acaaa37be53e68f8c1be575d24dcbebce1e92b1a` | MIT OR Apache-2.0 | 当前 bindings/implementation ABI |
| `references/UwpVpnPluginSample` | `d589fe0f57af13e052c44c662ade5fb1da2bcbb0` | MIT | Microsoft 官方 lifecycle/manifest/buffer 样例 |
| `references/Maple` | `ec052fcb014b14e50cb264abc1415807609ec07b` | Apache-2.0 | 代理型 UWP TUN、loopback wake、route 与网卡绑定 |
| `references/leaf-uwp` | `e40217e06be1bb57b17ea73fd0a083b9da15239b` | Apache-2.0 | Maple 对应的 UWP core/socket bind 实现 |
| `references/YtFlowCore` | `8309837e185db192b83168495cd8b9fe1e3998f6` | Apache-2.0 | 较新的 Windows netif/source-bind 参考 |

这些仍是 research checkout，不是 VCore dependency。若复制、翻译、链接或分发其中代码，合入前必须更新 `THIRD_PARTY_NOTICES.md` 并记录文件级映射。
