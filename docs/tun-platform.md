# TUN 平台层与 Windows UWP 边界

## 1. 当前实现

VCore 的 netstack、DNS、rules 和 outbound 只处理完整 raw IPv4/IPv6 packet。平台差异集中在编译期选择的 `platform::TunIo`：

```text
TunRuntime
  -> platform::TunIo
       -> RustTunIo (当前 Unix fd backend)
       -> WindowsTunIo（Windows Phase 1 IPv4 tracer 已实现）
```

当前 `RustTunIo` 使用 crates.io `tun` 0.8.14（项目内别名 `rust-tun`）：

- iOS/macOS：消费宿主提供的 utun fd，由 rust-tun 剥离和补齐四字节 packet-information header。
- Android：消费 `VpnService` 提供的 fd，rust-tun 始终输出/接收 raw IP。
- Linux：产品范围仍未启用；依赖可编译不表示 FFI TUN 已支持。
- Windows：此依赖不会被选择，也不允许回退到其 Wintun backend。

Invoke 的 `tunFraming` 没有改变。Apple 只接受 `utun`，Android 只接受 `rawIp`；它用于严格检查宿主与 target 的组合，不做自动探测。

## 2. fd 与异步契约

宿主始终拥有原 fd。VCore 在 `start` 消费 prepared state 前：

1. 用 `F_GETFL` 验证 fd 有效且已经设置 `O_NONBLOCK`。
2. 用 `F_DUPFD_CLOEXEC` 建立 core-owned duplicate。
3. 把 duplicate 所有权交给 rust-tun。
4. runtime 停止并 drop adapter 时，只关闭 duplicate。

VCore 不使用 rust-tun 的 `AsyncDevice`。其 constructor 会调用 `F_SETFL(O_NONBLOCK)`，而 duplicate 与宿主 fd 共享 open-file-description status flags。当前实现直接把同步 `rust_tun::Device` 包装进 Tokio `AsyncFd`，既使用 rust-tun 的 device/packet I/O，又保持“不修改宿主共享 flags”的既有契约。

read/write 的 packet boundary 不允许拆分重试：

- `recv == 0` 是设备关闭，不是空 packet。
- 收包后仍检查第一 nibble 只能是 IPv4 或 IPv6。
- `send` 返回长度必须等于完整 raw-IP packet 长度；partial write 立即失败。

## 3. MTU 与逐包分配

当前配置协议只接受 MTU 1500。`RustTunIo` 每次 read 传给 rust-tun 的 slice 长度固定为 1500，收到后原地 truncate；write 直接传入 netstack 的 packet。

这条规则不能放宽成 65,535-byte read buffer。rust-tun 的 Apple PI adapter 在 `payload + 4 <= 1504` 时使用固定栈缓冲，超过后会为每个 packet 创建临时 `Vec`。固定 1500 因此同时满足当前配置契约，并避免 iOS 高频流量下约 64 KiB/packet 的临时 heap allocation。

TUN raw-IP packet 固定 1,500 字节，最终 proxy UDP payload 固定 1,452 字节。
所有 Apple/Android TUN fd target 使用同一个 workload profile，但不再设置 TCP
session、ordinary UDP association、half-open TCP 或 outbound handshake 的固定并发总数。
仍保留 256 packet queue 和 128 event queue；DNS ingress 与独立 DNS response queue
各为 128，ordinary UDP response 另有 128 项 queue。两类 datagram 仍经过共享
netstack ingress receiver，因此这不是完整 ingress 隔离。TCP/UDP flow 按需创建，
普通 UDP association 通过 30 秒 idle timeout 和 10 秒 cleanup 回收。

## 4. 为什么 Windows UWP 不能复用 rust-tun

rust-tun 在 `target_os = "windows"` 下实现的是 Wintun：

- 动态加载 `wintun.dll`；
- 创建/打开 Wintun adapter；
- 使用 Wintun ring session 收发 packet。

`Windows.Networking.Vpn` 则是 `IVpnPlugIn` + `VpnChannel` callback 模型。系统用 `VpnPacketBufferList` 交付 L3 packet，plugin 必须按平台规则申请、归还和 flush buffer。两者没有可互换的 fd、handle 或 session，因此 VCore 不会 fork rust-tun 伪造 UWP backend，也不会在 UWP 产物中链接 Wintun。

## 5. Windows UWP 实现边界

当前已批准的完整设计、已通过的 Phase 0/1 结果、Phase 2 进度与产品基线见 [Windows UWP TUN 接入调研](UWP_TUN_RESEARCH.md)；它在与本节历史候选冲突时优先。Windows 11 ARM64 现已跑通 IPv4/IPv6 本地 ICMP、Windows DNS namespace、DIRECT TCP/UDP DNS、物理网卡变化 fail-closed 和重复 lifecycle；完整代理/平台矩阵与正式产品仍需完成以下边界：

1. VCore 的 Windows-only VPN provider 已用 `windows-rs` 实现最小 `IVpnPlugIn`、activation factory、Connect/Disconnect stop barrier；OneVCore 后续负责 profile、snapshot、状态和 App/MSIX 接入。
2. `WindowsTunIo` 在 callback 内复制 L3 bytes，通过有界 ingress/egress queue 接入现有 `TunRuntime`；不得把 `VpnPacketBuffer` 的裸 slice 保存到 callback 之外。
3. 所有系统提供或从 `VpnChannel` 申请的 buffer 都按 WinRT 契约归还；callback 可并发到达，core 状态由单一 runtime owner 串行管理。
4. `AssociateTransport` 只管理用于唤醒 `Decapsulate` 的 loopback `DatagramSocket` transport。VLESS/XHTTP、DIRECT 和 DNS 继续复用集中在 `Dialer` 的普通 Tokio TCP/UDP socket，并在 connect/send 前同时绑定选定物理网卡的本地 IPv4/IPv6 与 WinSock interface index，防止再次被虚拟接口捕获；不得为每个协议增加第二套 WinRT socket factory。
5. Windows TUN 生命周期由 plugin callback 驱动，不把 `VpnChannel`、COM pointer 或伪 fd 放入统一 Invoke JSON。App 进程中的非 TUN `measureDelay` 仍可使用普通 transport。
6. OneVCore 使用同一个 Store MSIX/AppX family package 交付 Flutter medium-IL full-trust foreground 与 UWP VPN background component，并声明 `runFullTrust` 和 `networkingVpnProvider`。普通 zip/exe 不能仅靠复制 DLL 获得 VPN 能力。

Windows 11 ARM64 已验证 activation、真实 VCore IPv4/IPv6 ICMP/raw packet 往返、loopback wake、DNS namespace、DIRECT TCP、runtime DNS 与普通 UDP、物理 source/interface 配对绑定、网络切换 fail-closed，以及独立 provider host 的跨 session 回收。Windows 10 22H2、x64 AppX、真实物理 IPv6、代理协议、长时间 active pressure 与正式 App/MSIX 仍待后续阶段。

## 6. 验收顺序

1. host：rawIp/utun IPv4+IPv6、invalid/EOF/partial write、fd ownership、反复 start/stop。
2. Apple/Android cross build：静态库/XCFramework/JNI symbol 与依赖图。
3. iOS/macOS/Android 真机：ICMP、TCP、UDP、DNS、取消和重复启停。
4. iOS Release：重新取得完整 TUN 生命周期的外部连续内存证据。
5. Windows 环境：UWP plugin activation、buffer ownership、transport association、suspend/resume、打包签名和真实 VPN 数据面。
