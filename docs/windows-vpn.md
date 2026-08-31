# Windows VPN 平台边界

Windows 数据面只使用官方 `Windows.Networking.Vpn` 和 `windows-rs`，不使用 Wintun 或文件描述符模拟层。完整代理运行时位于每会话 Session Host；AppContainer Provider 只负责 Windows VPN 平台资源和失败关闭。

## 安装包边界

- 最低目标系统：Windows 10 20H2 build 19042。
- 目标架构：ARM64 和 x64。
- 分发形式：具有 package identity 的 MSIX。
- 前台：调用 Windows 桥接接口的完全信任宿主。
- Provider：同 package family 的 AppContainer 应用。
- Session Host：同一主 Application 的完全信任 extension，每个 VPN 会话一个独立进程，可选拥有同包 session backend。
- Windows 依赖：`windows = 0.62.2`。
- Manifest：包含 `networkingVpnProvider` 和 `runFullTrust`，不配置产品级 loopback exemption。

未安装的普通桌面进程没有 package identity，Windows VPN 桥接会失败关闭。

`VCoreWindowsVpnInvoke` 当前在调用线程上初始化 MTA。调用线程必须尚未初始化 COM，或已经是 MTA；STA/ASTA 调用不受支持。

## `IVpnPlugIn` 回调

Provider 实现：

- `Connect`：选择物理网络、建立包通道、等待 Session Host 就绪，再调用 `StartWithMainTransport`；
- `Encapsulate`：复制 Windows 交付的 L3 包、归还系统缓冲区，并非阻塞地提交到有界入站队列；
- `Decapsulate`：排空已就绪的出站包，填充 `VpnPacketBuffer` 并 flush；
- `Disconnect`：停止包通道、等待有界确认、清理传输并调用 channel Stop；
- `GetKeepAlivePayload`：不承载业务数据。

所有回调都按可并发处理。Provider 只保留回调安全状态和一个会话所有者；panic 不能越过 COM 边界。

### 缓冲区所有权

- 回调内把 `IBuffer` 内容复制到 VCore 持有的内存；
- 不在回调之后保存裸 slice、`VpnPacketBuffer` 或系统列表；
- 每个系统缓冲区只归还一次；成功取得缓冲区后，任何后续本地错误都必须先归还缓冲区再传播；归还 API 自身失败时传播平台错误并失败关闭；
- 队列满时只丢当前包并计数，不能阻塞 Windows 回调。

## 原始 IP 数据面

```text
Windows route
  -> VpnChannel callback
  -> Provider 有界入站队列
  -> 命名管道数据通道
  -> Session Host WindowsTunIo
  -> vcore-netstack
  -> DNS / 规则 / 出站图
  -> 命名管道数据通道
  -> Provider 有界出站队列
  -> Decapsulate
```

数据帧：

```text
u16 大端序包长
1..=1500 字节原始 IP 包
```

- 每个方向只有一个写端；
- EOF、零长度、超限、截断和帧格式错误会停止当前会话；
- 合法帧中的非法 IP 包由原始包解析器局部丢弃，不破坏帧同步；
- 写端等待首包后，最多合并另外 7 个已经就绪的包，不等待计时器或未来数据；
- 读端使用 64 KiB 缓冲区，但仍逐帧校验；
- Provider 两侧包队列容量均为 256；从空变为非空时只发一次唤醒；
- `Decapsulate` 每次排空当前已就绪队列，队列满按包计数。

控制消息使用独立管道，避免包背压阻塞启动和停止。

## 回包唤醒

`VpnChannel` 要求 Provider 关联受管理传输。Provider 在同一 AppContainer 内建立一对回环 `DatagramSocket`：

1. 出站队列从空变为非空时发送一个哑数据报；
2. Windows 触发 `Decapsulate`；
3. 回调消费哑数据报并排空已就绪的原始包；
4. 队列持续非空时不重复唤醒。

哑数据报只用于调度，不承载业务包。

## 路由与 DNS

每个地址族使用两条 `/1` inclusion route：

```text
IPv4: 0.0.0.0/1, 128.0.0.0/1
IPv6: ::/1, 8000::/1
```

顶层 `ipv6` 默认为 `true`。设为 `false` 时，Provider 只安装 IPv4 `/1` 路由，只分配 IPv4 TUN 地址，并且只向 Windows 注册 IPv4 DNS；不会安装或分配任何 IPv6 项。

不能把 IPv4 两条 `/1` 合并为 `/0`。Windows 包环境中的验证表明，VPN `/0` 会使按产品要求绑定物理源地址和接口索引的外层 socket 返回 `WSAENETUNREACH`，而两条 `/1` 可以保持物理出口。

前台宿主在 `startVpn` payload 中提供当前会话的 TUN IPv4/IPv6 和 DNS IPv4/IPv6。四个地址始终严格必填并经过验证；即使顶层 `ipv6: false`，两个 IPv6 值仍保留在桥接契约中，但 Provider 不使用。桥接把地址、顶层 IPv6 开关与 Session token 写入 profile custom configuration，Provider 再按开关传给 `StartWithMainTransport`。这些字段不写入用户 RAW YAML。

Provider 为后缀 `.` 安装外部 DNS 地址：

- `dns.enable: true`：目标端口 53 由 VCore 运行时 DNS 处理；
- `dns.enable: false`：TCP/UDP 53 保留原 DNS 目标，作为普通业务流量执行规则。

Windows DNS assignment 本身不提供解析器或 NAT。

## 物理出口防递归

Provider 在安装路由前选择不可变的：

- 适配器 GUID；
- 网络 profile 和 network identity；
- 每个可用地址族的源 IP；
- 对应的非零接口索引。

Session Host 的每个非回环出站 socket 必须同时应用：

```text
源地址 bind + IP_UNICAST_IF / IPV6_UNICAST_IF
```

只绑定其中一项不满足契约。只有配置中显式使用 `127.0.0.0/8` 范围内的 IPv4 字面量或 `::1` 的本地出站可以跳过；物理代理服务器的域名在准备阶段解析到任何回环地址都会失败关闭。局域网和私有地址不属于例外。缺少地址族、源地址绑定或接口设置失败时，当前连接失败关闭。

`AssociateTransport` 只用于 Provider 的受管理唤醒传输，不用于普通代理流。Session Host 不持有 `VpnChannel`，不能给逐流 socket 获取同类豁免。

## 网络变化

Provider 是物理网络状态的唯一权威，并订阅 `NetworkStatusChanged`。事件到达后等待 2 秒，再复验适配器 GUID、地址和 network identity；任一项变化就停止当前 VPN。

当前实现不迁移现有 socket、不重选接口，也不回退到未绑定 socket。Session Host 不自行更新物理绑定。

## AppContainer 与 Session Host

- Provider 创建 AppContainer 本地控制管道和数据管道；
- `GetAppContainerNamedObjectPath` 提供限定对象路径；
- Provider 通过无参数 `FullTrustProcessLauncher` 激活同一 Application 的 Session Host；
- Session Host 使用当前 Windows session ID 构造限定路径并连接；
- 前台宿主退出不停止 Provider 或 Session Host，重新启动后从系统 profile 恢复状态。

会合记录只包含协议版本、Session token、相对对象路径和固定管道名称，不包含 YAML、backend 描述、参数、secret、PID、物理绑定或任意文件路径。Provider 是唯一发布者和清理者。

## 可选 session backend

`startVpn` 可以携带一个只描述进程的 `sessionBackend`。它包含 `1..=8` 个有序项目，每项只有 package-relative `.exe` 路径和 argv 数组。Bridge 把该描述与 VCore YAML 一同发布为 `vcore-session-v2:` Session Snapshot；路径或参数变化会改变 token，活动会话不能热换。

Session Host 为全部进程创建一个设置了 kill-on-close 的 Job Object，使用 suspended create 在进程执行前完成 Job assignment。任一进程退出都会停止 VCore、清理同 Job 进程树并让 Provider 失败关闭；显式 Stop 在 `Stopped` 前完成同样清理。前台宿主退出不影响它们。

第一版只监督进程存活，不包含 port、UDP、协议 readiness、heartbeat、restart、environment 或 working directory。进程仍存活时，本地 SOCKS 或其他业务流失败只影响当前流。

## 安装包与 profile

安装包必须包含：

```text
HostApplication.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

- manifest 只有一个主 Application，三个可执行参与者相互独立；
- Session Host 是 `windows.fullTrustProcess` extension，不显示在应用列表，也不注册 StartupTask 或 URI；
- Provider 的 `windows.backgroundTasks` extension 显式使用 `windowsApp + appContainer`；
- Provider activation class 来自 `vcore.dll`；
- 同一 package 只维护一个 `VCore` VPN profile；
- custom configuration 是最大 1 KiB 的严格 JSON，只含修订版 3、Session token、顶层 IPv6 开关和四个网络地址；
- Session Snapshot 是 `LocalState/vcore/windows/sessions/<sha256>.json`，覆盖 YAML、可选进程顺序、路径和参数；
- 活动 Session token、IPv6 开关或网络地址不同时必须先显式 Stop，不能热切换；
- 安装包更新只能在 VPN 已断开时进行，并要求版本递增。

## 失败关闭

| 事件 | 结果 |
| --- | --- |
| 前台宿主退出 | VPN 和 Session Host 继续运行 |
| Provider 退出 | Windows 清理 VPN，Session Host 因 EOF 退出 |
| Session Host 退出 | Job 清理受管进程，Provider 触发 channel Stop |
| 控制或数据管道非法/EOF | 停止当前会话 |
| 物理网络变化 | 消抖后停止当前会话 |
| 受管进程退出 | 清理同 Job 进程并停止当前 VPN |
| 本地 SOCKS 流失败且服务进程仍存活 | 只失败当前流 |
| 显式 Stop | 有界确认后清理路由、记录、Controller 和会话进程 |
| 启动失败 | Provider Connect 失败；未完成握手的 Session Host 最多等待 15 秒后退出 |

当前实测范围和未完成平台门禁见 [验收矩阵](acceptance.md)。

## 官方 API

- [`IVpnPlugIn`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.ivpnplugin)
- [`VpnChannel`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel)
- [`VpnChannel.AssociateTransport`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel.associatetransport)
- [`VpnPacketBuffer`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnpacketbuffer)
- [`VpnManagementAgent`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnmanagementagent)
- [`FullTrustProcessLauncher`](https://learn.microsoft.com/uwp/api/windows.applicationmodel.fulltrustprocesslauncher)
- [Package identity](https://learn.microsoft.com/windows/apps/desktop/modernize/package-identity-overview)
