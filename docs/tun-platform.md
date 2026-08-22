# TUN 平台层与 Windows UWP 边界

## 1. 当前实现

VCore 的 netstack、DNS、rules 和 outbound 只处理完整 raw IPv4/IPv6 packet。平台差异集中在编译期选择的 `platform::TunIo`：

```text
TunRuntime
  -> platform::TunIo
       -> RustTunIo (当前 Unix fd backend)
       -> UwpTunIo  (Windows 后续 backend，尚未实现)
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

## 5. UWP 后续实现边界

Windows TUN 必须作为独立里程碑实现，至少包含以下部分：

1. 独立 `vcore-windows-vpn` `cdylib`，实现 `IVpnPlugIn`、background activation factory 和系统 `Connect`/`Disconnect` 生命周期。
2. `UwpTunIo` 立即复制 callback 中的 L3 bytes，通过有界 ingress/egress queue 接入现有 `TunRuntime`；不得把 `VpnPacketBuffer` 的裸 slice 保存到 callback 之外。
3. 所有系统提供或从 `VpnChannel` 申请的 buffer 都按 WinRT 契约归还；callback 可并发到达，core 状态由单一 runtime owner 串行管理。
4. 物理 outbound 不能继续假设 Tokio socket + Unix fd protect。VLESS/XHTTP、DIRECT、DNS 的 TCP/UDP transport 都需要 WinRT socket factory，并在连接前与 `VpnChannel` 关联，防止再次被虚拟接口捕获。
5. Windows TUN 生命周期由 plugin callback 驱动，不把 `VpnChannel`、COM pointer 或伪 fd 放入统一 Invoke JSON。App 进程中的非 TUN `measureDelay` 仍可使用普通 transport。
6. OneVCore Windows 包需要注册 VPN background component 和相应 capability；现有普通 Flutter Win32 zip/exe 不能仅靠复制 DLL 获得 UWP VPN 能力。

在具备 Windows 11、Windows SDK 和签名/安装条件之前，只保留上述编译期 adapter 边界，不声称 Windows TUN 可用。第一项平台原型应先验证 activation、ICMP/raw packet 往返和单个关联 transport，再接入 VLESS/XHTTP 多连接数据面。

## 6. 验收顺序

1. host：rawIp/utun IPv4+IPv6、invalid/EOF/partial write、fd ownership、反复 start/stop。
2. Apple/Android cross build：静态库/XCFramework/JNI symbol 与依赖图。
3. iOS/macOS/Android 真机：ICMP、TCP、UDP、DNS、取消和重复启停。
4. iOS Release：重新取得完整 TUN 生命周期的外部连续内存证据。
5. Windows 环境：UWP plugin activation、buffer ownership、transport association、suspend/resume、打包签名和真实 VPN 数据面。
