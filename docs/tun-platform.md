# TUN 平台层

VCore 的 netstack、DNS、规则和出站只处理完整的原始 IPv4/IPv6 数据包。平台差异集中在编译期选择的 `platform::TunIo`。

## Unix 借用 fd

```text
TunRuntime -> TunRsIo -> 宿主持有的 TUN fd 副本
```

- iOS/tvOS/macOS：宿主提供 utun 文件描述符，适配器处理四字节 packet-information 头。
- Android：`VpnService` 提供 raw-IP 文件描述符。
- Linux：宿主创建真实单队列 TUN，使用 `IFF_TUN | IFF_NO_PI`、无 VNET header、
  MTU 1500；宿主负责接口、网络命名空间和路由，VCore 不自动接管系统网络。

宿主始终拥有原始文件描述符。VCore 启动时：

1. 验证文件描述符有效且已设置 `O_NONBLOCK`；
2. 通过 `F_DUPFD_CLOEXEC` 创建 VCore 持有的副本；
3. 把副本交给 `tun-rs::SyncDevice::from_fd`，并用 Tokio `AsyncFd` 驱动；
4. 停止时只关闭副本。

VCore 不调用会修改共享 open-file-description 标志的异步构造器，不通过 device builder 创建或重配置接口。`tunFraming` 是严格宿主协议：Apple 只接受 `utun`，Android 和 Linux 只接受 `rawIp`，不自动探测。

Linux 启动前查询真实 TUN 及其所属网络命名空间，验证内核链接参数、实际 MTU 和
raw-IP 格式；普通 socket/pipe、TAP、PI、VNET header 或多队列设备失败关闭。
需要可读 procfs 和 TUN 所属 user namespace 的 `CAP_NET_ADMIN`，即使 fd 与
VCore 在同一网络 namespace，也必须能执行 `TUNGETDEVNETNS`；借用一个有效 fd
不能绕过此权限检查。
跨命名空间检查仅在专属短线程切换 namespace，完成并 join 后再启动运行时，
不改变 Invoke 或业务工作线程的 namespace；宿主还需提供 `CAP_SYS_ADMIN` 等
相应 `setns` 权限。同 namespace 不执行 `setns`。
宿主原 fd 保持有效、非阻塞，运行期间不得改变接口格式或 MTU。

Linux 压测可以把 TUN 创建在客户端 namespace，再把借用 fd 交给正常出口 namespace
中的 VCore：客户端业务经 TUN，VCore 的普通 TCP/UDP socket 经正常物理出口。
接口创建、路由隔离和清理由宿主完成；VCore 不隐式设置 default route 或保护标记。
首轮验证为 GNU/glibc 原生构建与容器真实 TUN；musl、其他架构、安装交付和设备验收
不由一次 Linux 容器压测推导。Linux RSS/VmHWM 与 Apple physical footprint 分开报告。

tvOS 首版为 17.0+、ARM64 真机和 Apple Silicon 模拟器，共用原有 TunIo、netstack 和
Dialer；不新增低内存数量上限，不改变其他平台默认行为。iOS/tvOS 的 TUN 生命周期接入
Apple Unified Logging、TASK_VM_INFO 当前/进程峰值观察及停止后的 allocator pressure relief。
既有 35/40/45 MiB 阈值仅发出诊断，不是系统限额或业务准入条件；macOS 不启用这组
移动扩展周期采样。tvOS 事件使用 tvos_memory_*，iOS 保留 ios_memory_*。

Apple 公开 NEPacketTunnelFlow API 是 packetFlow 的包读写，不承诺可取得 raw fd。
VCore 的借用 fd 契约不能证明宿主 KVC 提取 fd 是稳定公开方案。模拟器 socketpair 只验证
合成 utun 数据面；真实宿主的 fd 获取/桥接、签名与 entitlement、系统路由、设备生命周期
及物理内存须独立验收。当前没有新增 packetFlow 回调 ABI，也不暗中回退其他接入路径。

包 I/O 规则：

- `recv == 0` 表示设备关闭；
- 首个半字节必须表示 IPv4 或 IPv6；
- 单次读取缓冲区固定为 1,500 字节；
- 写入必须一次完成整个包，部分写入立即失败；
- Apple 写入的瞬时 `ENOBUFS` 不终止整个运行时：只保留当前尚未接受的包，异步退让
  1 ms 后重试，Stop/取消仍直接释放该 future；不新建后台重试任务、不扩大宿主 socket
  缓冲，也不重发已经成功写出的包。其他错误和部分写入仍失败关闭；
- Apple PI 头不进入 netstack，也不计入流量。

所有平台的公共 TUN 循环按最多 8 包的有界批次推进：等到首包后只收取已经就绪的包，
不等待计时器或未来数据。Unix 在同一次 readiness guard 下逐包读写；每次系统调用仍
对应一个独立 IP 包，不使用 `readv/writev` 拼接多个包。Windows 在同一队列临界区内
批量交接，保留非阻塞丢当前包与空到非空唤醒语义。

Unix 读缓冲区和公共批次容器复用；非法包只丢该槽位，不丢合法邻包。批次中途发生错误或
取消时保留已经完成的逐包结果，流量只统计有效的已完成前缀，未完成包不得重放已完成
前缀。批次预算和协作调度保证停止与其他任务可推进，不改变 fd 标志、线程策略
或宿主 API；不新增 Apple packetFlow 接入或私有系统调用。

公共 reader 在进入 netstack 前同步分流 UDP，直接非阻塞提交到按源地址拥有的
关联队列；DNS 劫持提交受跟踪的查询任务。普通 UDP 不进入 TCP Driver，也没有
共享 UDP 入站中转队列。TCP/ICMP 使用独立有界 ingress；满时丢当前完整 IP 包并
计数，TCP 可重传，不等待容量而阻塞其他来源的 UDP/DNS。

唯一 writer 公平轮转 TCP/ICMP raw、普通 UDP 响应和 DNS 响应三个独立通道。
UDP 直接在复用的 MTU frame 中构包，不再经过 response writer 和 raw output
的二次交接；每批最多处理 8 个已就绪项目，非法响应也消耗工作预算。DNS permit
保留到对应包被平台接受、最终丢弃或取消，ENOBUFS 待重试时不释放；Windows
Adapter 成功处理仍不承诺 Windows 框架最终交付。

平台无关的 netstack 驱动同样最多连续消费 8 个已就绪入站包，再执行全量 TCP
socket / 应用缓冲维护及 egress polling。TCP 协议 ingress 仍逐包推进，保证相邻
SYN 的连接归属，不让未推进的 TCP 包误抑制相邻 ICMP；不把 ingress 延迟到凑满批次。
TCP egress 可延后到批次后的维护，不承诺 TCP 与即时 ICMP 响应之间的输出顺序不变。
每次取下一包前检查取消与输出容量，输出满时后缀留在原 raw 入站队列；
不预取额外后缀、不新建积压队列，输入关闭时已消费前缀仍经过维护后退出。
合作调度预算按实际消费包数记账，避免 `try_recv()` 绕过逐包扣账；最多先处理
当前 8 包，再按已消费数量扣账和退让。

Device 仅保留一个尚未消费的 ingress 包，不再保留 RX/TX 双 deque。smoltcp
TxToken 在消费 RX 前预留现有 raw egress 的槽位，生成包后直接提交；未使用的
token 归还容量。满输出保留尚未处理的 TCP 包和协议状态，低优先级 ICMP 仍可
丢当前请求。writer 消费包会显式唤醒 Driver；满输出不以零延迟 timer 忙重试，
输出端关闭则停止 Driver、释放 socket 并唤醒全部等待者。

netstack 的 TCP 接收与发送缓冲可独立配置，各方向的容量包含 smoltcp 与应用
缓冲，两层各占一半。生产 TUN 仍从现有资源策略取得每方向 32 KiB，合计每流
64 KiB 数据缓冲；不扩大默认容量、不新增用户 YAML 参数，也不改变其他协议
的缓冲策略。该容量不包含代理 relay、包队列或 allocator 的内存。

Linux 目前不启用 GRO/GSO：`tun-rs` 的 Linux offload 示例通过 builder 创建并
配置带 VNET header 的设备，而当前借用 fd 构造器不识别该模式。对现有 raw-IP
设备调用 `recv_multiple` 不会自动合并读取或启用 offload。VCore 保留宿主
MTU/格式与 fd 标志，不以增加 builder 或修改宿主接口来暗中启用该能力。

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

完整契约见 [Windows VPN 平台边界](windows-vpn.md) 和 [Windows 会话运行时](windows-vpn.md)。

## MTU 与结构上限

用户 TUN 配置当前只接受 MTU 1500。Windows 因 `StartWithMainTransport` 平台上限对 L3 接口和 Session Host netstack 使用 1400；packet channel 仍保留 1500 字节解析上限：

```text
原始 TUN 包                   1,500 字节
最终代理 UDP 负载             1,452 字节（Windows 1,352）
包队列                        256
普通事件 / TCP accept         128
每关联 UDP 入站               64
普通 UDP 响应                 4,096
DNS 响应                      128
```

TCP 会话、普通 UDP 关联、半开连接和出站握手不设固定业务数量上限。结构安全由有界队列、每流缓冲区、解析大小、超时、空闲清理和缓存提供。

每关联入站、普通响应和 DNS 响应是独立内部队列预算，不扩大 TCP accept。
满时只丢当前数据报；容量不构成公开配置或活动业务数量上限。TUN 使用 TCP-only
netstack 端点及纯 UDP codec，独立 crate 的通用 UDP endpoint 不在生产 TUN 路径上。
写回受阻时 reader 仍可处理新请求。停止会取消并等待唯一 writer、reader 所有的
关联/DNS 任务和 netstack，不依赖输出队列腾出容量。

规则/建链在 TCP 握手完成前拒绝连接时，netstack 保留已 abort 的 socket，直到 smoltcp
将 RST 交给现有有界发送队列，再回收逐流状态；不因直接移除 socket 而吞掉关闭报文。
发送队列暂满仍等待原有驱动推进，Stop 可同步释放全部状态，不另建重试任务。

## 物理出口

- Linux：宿主负责网络命名空间或等效路由隔离，确保被捕获的客户端流量进入 TUN，
  VCore 出站绕过 TUN；不能把仅绑定 source IP 当作绕路保证。没有自动路由配置或降级路径。
- Android：每个出站 TCP/UDP socket 在 connect 前调用宿主 protect；失败则当前连接失败关闭。
- Windows：Provider 为当前会话选择不可变的物理网络绑定；每个地址族只从非 link-local 地址中选择一个源 IP 和接口索引交给 Session Host，同时独立保留物理适配器全部去重的 on-link prefixes（包括 link-local）用于 VPN 路由。普通出站 socket 必须同时绑定源地址和 WinSock 接口索引。
- Windows 只有配置中显式使用 `127.0.0.0/8` 范围内的 IPv4 字面量或 `::1` 的本地出站可以跳过物理绑定；物理代理服务器的域名解析到任何回环地址都会失败关闭。
- 物理适配器、选定源地址、全部 on-link prefixes 或网络身份变化后，Provider 等待 2 秒消抖并停止会话，不迁移 socket 或自动回退。

主机测试只能证明帧、所有权、队列和生命周期逻辑；平台实测范围见 [验收矩阵](acceptance.md)。
