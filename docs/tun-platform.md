# TUN 平台层

VCore 的 netstack、DNS、规则和出站只处理完整的原始 IPv4/IPv6 数据包。平台差异集中在编译期选择的 `platform::TunIo`。

## Apple 与 Android

```text
TunRuntime -> RustTunIo -> 宿主持有的 TUN fd 副本
```

- iOS/macOS：宿主提供 utun 文件描述符，适配器处理四字节 packet-information 头。
- Android：`VpnService` 提供 raw-IP 文件描述符。
- Linux：产品入口不支持，即使依赖能够编译也会失败关闭。

宿主始终拥有原始文件描述符。VCore 启动时：

1. 验证文件描述符有效且已设置 `O_NONBLOCK`；
2. 通过 `F_DUPFD_CLOEXEC` 创建 VCore 持有的副本；
3. 把副本交给同步 TUN device，并用 Tokio `AsyncFd` 驱动；
4. 停止时只关闭副本。

VCore 不调用会修改共享 open-file-description 标志的异步构造器。`tunFraming` 是严格宿主协议：Apple 只接受 `utun`，Android 只接受 `rawIp`，不自动探测。

包 I/O 规则：

- `recv == 0` 表示设备关闭；
- 首个半字节必须表示 IPv4 或 IPv6；
- 单次读取缓冲区固定为 1,500 字节；
- 写入必须一次完成整个包，部分写入立即失败；
- Apple PI 头不进入 netstack，也不计入流量。

## Windows VPN

```text
VpnChannel callback
  -> WindowsPacketAdapter
  -> 有界队列
  -> 同包 packet channel
  -> WindowsTunIo
  -> TunRuntime
```

Windows 使用 `Windows.Networking.Vpn` 回调，不使用文件描述符或适配器 ring：

- Provider 在回调内复制 `VpnPacketBuffer` 字节，不保存系统缓冲区的借用；
- 顶层 `ipv6: false` 时，Provider 向 `StartWithMainTransport` 传 null IPv6 client-address 参数，不分配 IPv6 TUN 地址，也不安装 IPv6 路由或 DNS；`startVpn` 的 IPv6 地址字段仍严格必填并经过验证；
- Windows profile 固定覆盖所有应用；Provider 按 policy 设置本地子网旁路，并把最多 64 条规范目标 CIDR 加入 exclusion routes；
- 系统和 Provider 创建的缓冲区都按 WinRT 所有权规则归还；
- 回调不等待管道 I/O，入站和出站队列保持有界；
- 空到非空的回环唤醒只通知 `Decapsulate` 排空响应队列；
- Provider 与完全信任的 Session Host 通过安装包命名空间中的控制管道和数据管道交换原始 IP 包；
- 数据帧为 `u16` 长度加 `1..=1500` 字节数据。写端最多合并 8 个已经就绪的帧，读端使用 64 KiB 缓冲区并逐帧校验；
- EOF、截断、超限、任务异常和进程退出都会停止当前会话。

完整契约见 [Windows VPN 平台边界](windows-vpn.md) 和 [Windows 会话运行时](windows-session-runtime.md)。

## MTU 与结构上限

用户 TUN 配置当前只接受 MTU 1500。Windows 因 `StartWithMainTransport` 平台上限对 L3 接口和 Session Host netstack 使用 1400；packet channel 仍保留 1500 字节解析上限：

```text
原始 TUN 包                   1,500 字节
最终代理 UDP 负载             1,452 字节
包队列                        256
普通事件 / UDP 响应           128
DNS 入站 / DNS 响应           128 / 128
```

TCP 会话、普通 UDP 关联、半开连接和出站握手不设固定业务数量上限。结构安全由有界队列、每流缓冲区、解析大小、超时、空闲清理和缓存提供。

## 物理出口

- Android：每个出站 TCP/UDP socket 在 connect 前调用宿主 protect；失败则当前连接失败关闭。
- Windows：Provider 为当前会话选择不可变的物理网络绑定，并把每个地址族的源 IP 和接口索引交给 Session Host。普通出站 socket 必须同时绑定源地址和 WinSock 接口索引。
- Windows 只有配置中显式使用 `127.0.0.0/8` 范围内的 IPv4 字面量或 `::1` 的本地出站可以跳过物理绑定；物理代理服务器的域名解析到任何回环地址都会失败关闭。
- 物理适配器、地址或网络身份变化后，Provider 等待 2 秒消抖并停止会话，不迁移 socket 或自动回退。

主机测试只能证明帧、所有权、队列和生命周期逻辑；平台实测范围见 [验收矩阵](acceptance.md)。
