# Hysteria2

Hysteria2 自内部 schema revision 21 起提供，Invoke API v5 不变；默认与 TUN/生产构建启用。配置、互通及资源的本地阶段证据见 [N6 验收](acceptance/next-protocols/N6.md)。

## 配置

`type: hysteria2` 需要 `outbound-hysteria2` feature。始终使用 QUIC/TLS 1.3，`skip-cert-verify` 不改变这一约束；复用共享官方 rustls 后端。不接受 `tls`、`network`、`client-fingerprint` 或 REALITY 字段。

| 字段 | 契约 |
| --- | --- |
| `name`, `server` | 沿用普通节点名称与地址规则；服务器解析使用共享的预解析端点/上游策略。 |
| `port` | 1–65535；仅提供 `ports` 时可省略。即使提供 `ports`，显式非法 `port` 仍拒绝。 |
| `password` | 字符串，默认空；保留原值、不去首尾空白，必须是最长 8192 字节的合法 HTTP 头值。 |
| `udp` | 默认 false，仅控制路由业务 UDP；QUIC 载体始终使用 UDP。 |
| `sni` | TLS 认证名，默认 `server`，不改变拨号目标。 |
| `alpn` | 缺省或空列表均为 `[h3]`；自定义列表需要对端支持相同 ALPN。 |
| `skip-cert-verify`, `fingerprint` | 共享 SHA-256 证书 pin 策略。叶证书匹配是显式信任；中间/根证书匹配作为信任锚，继续验证证书链和名称。提供 pin 后即使 skip=true 也必须匹配。 |
| `certificate`, `private-key` | 成对内联 PEM 客户端身份；格式错误、缺少配对或密钥不匹配在网络 IO 前拒绝。 |
| `dialer-proxy` | 具体节点或静态 select 组；共享无环上游图与建链期限。 |
| `up`, `down` | 独立非负整数或十进制整数字符串，裸值单位 Mbit/s。单位 `[KMGT]?[bB]ps` 使用十进制倍率；b 为 bit，B 为 byte。bit 速率向下取整为字节/秒，因此 `1 bps` 归一为零。拒绝小数、正负号、溢出或未知单位；省略/归一后为零表示自动。 |
| `udp-mtu` | 缺省/0 为 1197，否则为 64–65535；限制单个编码后 HY2 UDP 分片，而非 TUN MTU 或业务载荷上限，另与实际 QUIC DATAGRAM 预算取交集。 |
| `obfs`, `obfs-password` | 仅 `salamander`，要求非空且独立的混淆密码；不能只提供其中一个字段。 |
| `ports` | 非空的逗号分隔端口及闭区间，归一去重；控制初始和后续端口，优先于合法 `port`。 |
| `hop-interval` | 仅与 `ports` 同时使用：整数秒 N、字符串 N 或使用 ASCII `-` 的 N-M，默认 30；5 ≤ N ≤ M ≤ u32::MAX。与 Mihomo 夹小值不同，VCore 严格拒绝过短间隔。 |

## 共享会话与线协议

每个节点拥有一个当前已认证 QUIC 会话，新的逻辑 TCP 流和 UDP 关联复用它；取消一个业务流不取消兄弟流。认证使用 HTTP/3 `POST https://hysteria/auth`，要求状态 233，在任何业务请求前完成。TCP 请求类型为 0x401；响应在首次读取时解析，允许客户端先发数据，兼容 Mihomo 延迟合并成功响应头的行为，解析仍受原始建链期限约束。

认证、物理/上游建链与流请求共享一个绝对 10 秒预算。旧会话失败后，新的逻辑流可以新建物理会话；已有流的业务数据绝不自动重放。

应用写 EOF 关闭该逻辑 TCP 流的双向通道，与 Mihomo Hysteria2 客户端一致；唤醒待决读操作，不等待或保证原站在上传 EOF 后发送的尾包。同一已认证 QUIC 上的其他流和 UDP 关联不受影响。

业务 UDP 使用原生 QUIC DATAGRAM，不是 HTTP/3 DATAGRAM 扩展。每个本地关联使用连接内 ID，未知 ID 不能创建关联。业务载荷最多 4096 字节，另与调用方预算和最大可编码分片集合取交集，发送超限一字节即拒绝。重组按关联/包/地址隔离，每个 QUIC 会话最多 64 个待重组包、256 KiB 负载，TTL 为 5 秒。每关联交付队列为 32 包；超限或畸形包只丢弃，不破坏兄弟关联。官方 Hysteria 的回包缓冲另有限制，见下文。

## 带宽与混淆

`down` 以字节/秒写入 `Hysteria-CC-RX`。`up=0` 或服务端返回 `auto` 时上传使用 BBR；否则取正数 `up` 与服务端接收上限的较小值（服务端 0 表示无限制），使用 Brutal 风格的固定带宽控制器和实际 wire-byte pacer。当前 Mihomo 在 `down=0` 时可能返回 RxAuto，即使 up 为正数也优先自动模式。丢包补偿使用五秒滚动窗口及最小采样量，ACK 比例下限 0.8；允许有界初始突发，但不取消持续线速约束。

Salamander 使用 RustCrypto 实现公开的 salt + XOR/BLAKE2b-256 格式，不修改第三方源码。每个物理包增加 8 字节，配置 QUIC 前扣除这些开销，pacer 则计入它们。这是混淆而非身份认证，错误密钥最终由 QUIC 拒绝。短包丢弃并有界让出调度，取消会唤醒所属驱动。

## 端口跳跃与所有权

整个端口集合是一个服务端、同一 QUIC 状态的多个入口，不是多个独立服务端。初始和后续端口均在归一集合内随机选择。每次跳跃通过 VCore DatagramTransport/Dialer 创建新的受保护/绑定 socket。认证连接的上游组选择冻结，切组只影响新的物理会话。后续 socket 各有独立有界期限，不能延长原始认证期限，不触发重新认证或业务重放。

受控 QUIC Adapter 将当前物理 peer 映射为一个逻辑 peer，并过滤来源。发送只走新路径；切换后的一秒接收窗口同时公平轮询新旧路径，即使新路径已收到包，也继续接收旧路径迟到包。窗口结束后回收旧路径，当前与过渡 socket 最多两条；节点 Stop 取消并同步等待两条路径、HTTP/3 控制循环、重组和 QUIC runtime。禁止协议自行创建裸 socket 或回落到未受控物理路径。

官方 Hysteria v2.12.3 的 4096 字节回包序列化缓冲包含 UDPMessage 头，因此实际往返业务上限还需扣除协议头；更大回包在进入分片回退前被静默丢弃。VCore 的完整 4096 字节业务上限单独对 Mihomo 验证。原生端测试必须记录这一服务端限制，不能宣称已修复第三方或悄悄改变 VCore 的统一负载预算。

历史失败和修复保留于 [开发记录](acceptance/next-protocols/N6-progress.md)；容器互通和交叉构建不证明 Android protect 实机接线或 Apple/Windows 物理 VPN 行为。
