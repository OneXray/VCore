# Windows VPN 平台边界

状态：Windows 11 ARM64 开发签名 package 已完成数据面、Session Host、lifecycle、pressure 和有界 packet batching 验收。Windows 10 22H2、原生 x64、物理 IPv6、WACK、正式 identity 和 Store submission 仍是发布门禁。

本文只记录 `Windows.Networking.Vpn` 的平台事实和 VCore 决策。当前 session 架构见 [`windows-session-runtime.md`](windows-session-runtime.md)。

## 1. 产品基线

- 最低系统：Windows 10 22H2 build 19045。
- Architecture：ARM64 与 x64。
- 分发：Store MSIX；开发阶段使用固定本地签名证书。
- Foreground：Flutter full-trust application。
- VPN Provider：同 package family AppContainer application。
- Session Runtime：同 package、隐藏的 full-trust application，每个 VPN session 一个进程。
- API：`windows = 0.62.2`，官方 `Windows.Networking.Vpn`。
- Manifest：`networkingVpnProvider` 与 `runFullTrust`；不配置产品级 loopback exemption。

## 2. `Windows.Networking.Vpn` 模型

Provider 实现 `IVpnPlugIn`：

- `Connect`：选择物理网络、建立 packet channel、等待 Session Host ready，随后调用 `StartWithMainTransport`。
- `Encapsulate`：复制系统交付的 outbound L3 packets，归还 framework buffers，并非阻塞地放入 bounded queue。
- `Decapsulate`：从 bounded egress queue 取回包，填入 `VpnPacketBuffer`，追加到系统列表并 flush。
- `Disconnect`：停止 packet channel、等待 bounded Session Host ack、清理 transport并调用 channel Stop。
- `GetKeepAlivePayload`：当前数据面不依赖该 callback传输业务 packet。

所有 callback 都视为可并发。Provider只保留 callback-safe state和单一session owner；panic不能越过COM boundary。

### Buffer ownership

- Callback 内把 `IBuffer` 内容复制到VCore-owned memory。
- 不能把裸slice、`VpnPacketBuffer`或framework list保存到callback之后。
- 每个系统buffer只归还一次；Provider申请的buffer也必须在成功、drop和错误路径归还。
- Queue full只丢当前packet并计数，不能阻塞Windows callback。

## 3. Raw-IP 数据面

```text
Windows route
  -> VpnChannel callback
  -> Provider bounded ingress
  -> named-pipe data channel
  -> Session Host WindowsTunIo
  -> vcore-netstack
  -> DNS / rules / outbound graph
  -> named-pipe data channel
  -> Provider bounded egress
  -> Decapsulate
```

Data frame：

```text
u16 big-endian packet length
1..=1500 raw-IP bytes
```

约束：

- 每个方向只有一个writer。
- EOF、zero/oversize length、truncated frame和非法packet使session fail closed。
- Writer等待第一包后最多drain 7个已经ready的packet，一次写入连续v1 frames；不等待timer或未来packet。
- Reader使用64 KiB user-space buffer，但仍逐frame执行相同校验。
- Provider callback queue容量为256；empty-to-non-empty时只发送一次wake。
- `Decapsulate`一次drain当前ready queue；queue full按packet-local drop统计。

Packet channel不承担control或配置。Control pipe单独传递handshake、ready/failure和stop消息，避免packet backpressure阻塞lifecycle。

## 4. 回包唤醒

`VpnChannel`要求Provider关联受管理transport。VCore使用同一AppContainer进程内的loopback `DatagramSocket` pair作为 `Decapsulate` wake：

1. Egress queue从empty变为non-empty时发送一个dummy datagram。
2. Windows触发`Decapsulate`。
3. Callback消费dummy并drain所有当前ready raw packets。
4. Queue持续非空时不重复发送wake。

Dummy只负责调度，不承载VCore packet或业务数据。

## 5. Routes 与 DNS

Windows使用两条`/1` inclusion route覆盖每个family：

```text
IPv4: 0.0.0.0/1, 128.0.0.0/1
IPv6: ::/1, 8000::/1
```

Provider安装固定TUN DNS地址和search namespace；DNS packet与普通IP packet一样进入VCore runtime。Ping、Controller port/secret和TUN地址是session运行时字段，不写回用户保存的RAW YAML。

两条`/1`不是`0.0.0.0/0`的可替换写法。Windows 11 ARM64 build 26200.9168上的隔离package差分测试中，同一TCP socket同时绑定physical source与`IP_UNICAST_IF`：`/1 + /1`前后两次均从physical source连接成功，改成VPN `/0`后立即返回`WSAENETUNREACH` 10051；不绑定的socket则取得TUN地址并进入Provider。因而Windows实现不得合并为单条`/0`。

## 6. 物理出口防递归

Provider在route安装前选择immutable physical binding：

- adapter GUID；
- network identity；
- 可用family的source IP；
- 对应nonzero interface index。

Session Host的每个非loopback outbound socket必须同时应用：

```text
source address bind + IP_UNICAST_IF / IPV6_UNICAST_IF
```

只绑定地址或只绑定interface都不满足contract。解析后的`127.0.0.0/8`与`::1`可跳过physical binding；LAN/private地址不属于例外。缺少family、source bind或setsockopt失败时当前connection fail closed。

`AssociateTransport`只用于Provider wake transport，不用于逐flow TCP/UDP proxy socket。官方示例会先关联并连接实际VPN server transport，再安装routes；该特殊transport由VPN framework标记。Session Host的普通flow socket不持有`VpnChannel`，不能获得同一例外。

## 7. 网络变化

Provider是physical network authority并订阅`NetworkStatusChanged`：

1. 事件到达后等待2秒debounce。
2. 重新读取adapter GUID、地址和network identity。
3. 任一字段与session binding不一致即Stop。

首版不迁移现有socket、不重选interface、不fallback到unbound socket。Session Host也不自行监控或更新binding。

## 8. AppContainer 与 Session Host

完整proxy runtime不能留在AppContainer，否则full-trust foreground无法可靠访问其loopback Controller，本机full-trust SOCKS fixture也不能作为普通outbound使用。

当前模型：

- Provider创建AppContainer-local control/data pipe servers。
- Provider通过`GetAppContainerNamedObjectPath`发布strict rendezvous。
- Hidden Session Host由`IApplicationActivationManager`激活。
- Session Host以当前Windows session ID构造qualified package object path并连接。
- Unpackaged同用户进程不能通过unqualified name访问pipe。
- Flutter退出不影响Provider或Session Host；Flutter重启从system profile和session record恢复状态。

Rendezvous只包含version、snapshot token、relative object path和固定leaf names，不包含YAML、secret、PID、physical binding或任意路径。Provider是唯一publisher和cleanup owner。

## 9. Package 与 profile

Package包含：

```text
OneVCore.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

- Flutter、Provider Host和Session Host是独立executable。
- Session Host `AppListEntry="none"`，不注册StartupTask或protocol handler。
- Provider activation class来自`vcore.dll`。
- 只维护一个package-owned VPN profile。
- Active token不同不hot swap；必须显式Stop后再Start。
- Unpackaged运行缺少package identity时fail closed。
- Package update必须在disconnected状态执行，版本必须递增，不能通过隐式卸载替代升级。

## 10. Fail-closed 矩阵

| 事件 | 结果 |
| --- | --- |
| Flutter退出 | VPN和Session Host继续 |
| Provider退出 | Windows清理VPN；Session Host由EOF退出 |
| Session Host退出 | Provider触发channel Stop |
| Control/data malformed或EOF | 当前session停止 |
| Physical network变化 | debounce后Stop |
| 外部loopback SOCKS flow失败 | 只失败该flow，不停止VPN |
| Explicit Stop | bounded ack后清理routes、record、Controller和process |
| Startup任一步失败 | 终止本次精确Session Host PID并收敛Disconnected |

## 11. 已验证与发布门禁

Windows 11 ARM64开发身份已覆盖：

- IPv4/IPv6 routes、DNS、ICMP、TCP、UDP和完整proxy graph；
- physical source/interface配对；
- network-change、Provider/Session Host crash和malformed/EOF fail closed；
- rapid reconnect、10分钟pressure、100 MiB以上transfer和queue drop 0；
- Flutter退出/恢复、Controller、local SOCKS5和disconnected upgrade；
- packet channel bounded batching纯IPC目标；
- signed MSIX安装与clean stop。

仍未声明通过：

- Windows 10 22H2；
- 原生x64 Windows；
- 真实物理IPv6；
- WACK；
- Partner Center identity/publisher与restricted capability approval；
- Store bundle/submission；
- 多用户和remote-session扩展矩阵。

命令、artifact hash和实测结果见 [`acceptance.md`](acceptance.md)。

## 12. 官方 API

- [`IVpnPlugIn`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.ivpnplugin)
- [`VpnChannel`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel)
- [`VpnChannel.AssociateTransport`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel.associatetransport)
- [`VpnPacketBuffer`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnpacketbuffer)
- [`VpnManagementAgent`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnmanagementagent)
- [`IApplicationActivationManager`](https://learn.microsoft.com/windows/win32/api/shobjidl_core/nn-shobjidl_core-iapplicationactivationmanager)
- [Package identity overview](https://learn.microsoft.com/windows/apps/desktop/modernize/package-identity-overview)
