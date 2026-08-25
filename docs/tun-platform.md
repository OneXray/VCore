# TUN 平台层

VCore 的 netstack、DNS、rules 和 outbound 只处理完整 raw IPv4/IPv6 packet。平台差异集中在编译期选择的 `platform::TunIo`。

## 1. Apple 与 Android fd

```text
TunRuntime -> RustTunIo -> host-owned TUN fd duplicate
```

- iOS/macOS：宿主提供 utun fd；adapter 处理四字节 packet-information header。
- Android：`VpnService` 提供 raw-IP fd。
- Linux：产品入口不支持，即使依赖可以编译也必须 fail closed。

宿主始终拥有原 fd。VCore 在 start 时：

1. 验证 fd 有效且已经设置 `O_NONBLOCK`。
2. 通过 `F_DUPFD_CLOEXEC` 建立 core-owned duplicate。
3. 把 duplicate 交给同步 TUN device，并通过 Tokio `AsyncFd` 驱动。
4. Runtime stop/drop 只关闭 duplicate。

VCore 不调用会修改共享 open-file-description flags 的异步 constructor。`tunFraming` 是严格宿主协议：Apple 只接受 `utun`，Android 只接受 `rawIp`，不自动探测。

Packet I/O：

- `recv == 0` 表示设备关闭。
- 收包首 nibble 必须是 IPv4 或 IPv6。
- 单次 read buffer 固定 1,500 bytes。
- Write 必须一次完成完整 packet；partial write 立即失败。
- Apple PI header 不进入 netstack，也不计入流量统计。

## 2. Windows VPN

```text
VpnChannel callbacks
  -> WindowsPacketAdapter
  -> bounded queues
  -> package packet channel
  -> WindowsTunIo
  -> TunRuntime
```

Windows 使用 `Windows.Networking.Vpn` callback 模型，不通过 fd 或 adapter ring：

- Provider 在 callback 内复制 `VpnPacketBuffer` bytes，不能保存 framework buffer slice。
- 系统提供和 Provider申请的 buffer 都按 WinRT ownership contract 归还。
- Callback 不等待 pipe I/O；ingress/egress queue 均保持有界。
- Empty-to-non-empty loopback wake 只用于通知 `Decapsulate` drain 回包队列。
- Provider 与 full-trust Session Host 通过 package namespace 内的 control/data named pipes交换 raw-IP。
- Data protocol 保持 `u16` length + `1..=1500` packet。Writer最多合并8个已经ready的frame，不等待未来packet；reader使用64 KiB buffer并继续逐frame严格校验。
- EOF、truncated/oversize frame、queue/task异常和进程退出都使 session fail closed。

完整 Windows ownership 和 lifecycle 见 [`windows-vpn.md`](windows-vpn.md) 与 [`windows-session-runtime.md`](windows-session-runtime.md)。

## 3. MTU 与资源

当前配置只接受 MTU 1500：

```text
raw TUN packet ceiling     1,500 bytes
final proxy UDP payload    1,452 bytes
packet queue               256
ordinary event/response    128
DNS ingress/response       128 / 128
```

TCP session、普通 UDP association、half-open 和 outbound handshake 不设固定业务总数。结构安全由 bounded queue、每流 buffer、wire/parser size、timeout、idle cleanup 和 cache 提供。

## 4. 物理出口

- Android：每个 outbound TCP/UDP socket 在 connect 前通过宿主 protect callback；失败则当前连接 fail closed。
- Windows：Provider选择 immutable physical binding，并向 Session Host传递IPv4/IPv6 source + interface index。普通 outbound socket必须成对绑定source address和WinSock interface index。
- Windows loopback目标仅对解析后的 `127.0.0.0/8` 和 `::1`跳过physical binding。
- 物理adapter、地址或network identity变化后，Provider debounce并Stop，不迁移现有socket、不自动fallback。

## 5. 验收边界

Host tests证明 framing、fd ownership、invalid packet、queue和lifecycle逻辑；它们不能代替物理设备或package证据。

发布前分别登记：

- Apple/Android 真机 ICMP、TCP、UDP、DNS、cancel和重复启停。
- Release iOS 整进程 footprint。
- Android protect fail-closed。
- Windows package activation、buffer ownership、physical binding、network-change Stop、crash、pressure和签名。

当前结果见 [`acceptance.md`](acceptance.md)。
