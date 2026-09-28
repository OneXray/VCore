# 客户端出站

字段、类型与示例由 [config.yaml](config.yaml) 维护；这里只定义行为。
VLESS/Vision/Encryption/JLS/ECH 见 [VLESS](vless.md)，XHTTP/sing-mux 见[专用契约](xhttp.md)。

## 公共规则

- 物理 TCP/UDP 只能由共享 Dialer 创建，保留 Android protect、Windows 物理绑定和受控解析。
  传输包装器只消费 IO，不另建 socket 或系统 resolver。
- `dialer-proxy` 可引用节点或静态 select 组；与业务路由共享选择，完整 DAG 在配置期验证。
  一次建链使用组快照和同一绝对期限；已有连接不随切组迁移，无自动 failover 或 DIRECT 回落。
- gRPC/legacy H2 首次读取延迟响应头时先检查原建链期限，即使响应已就绪也不能绕过
  超时；响应头已确认后的业务读取不再受该期限限制。
- HTTP、SOCKS5、TUN、DNS 选路及 node-only `measureDelay` 使用同一连接器。
  UDP 默认为 false；收发预算分别逐层扣封装开销，超限不截断交付。
- TLS 使用共享 WebPKI、叶证书 pin/非叶信任锚与 skip 策略。pin 不匹配不能被 skip 绕过，
  TLS 握手签名始终验证。节点策略与恢复缓存不可变、互相隔离，标准 TLS 总票据预算为 4。
  字段及模板详见 [TLS 证书与指纹](tls-client-fingerprint.md)。
- 未知字段、null、错型、非法枚举或不适用的传输选项在网络 IO 前拒绝。
  凭据、UUID、业务目标和完整请求不进入 Debug/错误；资源与 Stop 见[公共策略](runtime-resource-policy.md)。

## SOCKS5

仅 SOCKS5 CONNECT / UDP ASSOCIATE；用户名密码成对配置，不支持 SOCKS4。
TCP 保留域名交由上游解析；UDP 由控制连接拥有，校验 relay 来源并保留实际回包目标。
上游为 select 组时，控制连接和后续 UDP 数据报使用同次建链快照。
SOCKS5 不提供 TLS、证书 pin 或 ClientHello 模板；它的预算独立于 TUN MTU。

## AnyTLS

支持 v2、兼容 v1 的会话、内置填充与 UoT v2。password 为 1–1024 UTF-8 字节；
SNI 默认 server；ALPN 省略/空列表不发送，非空保持顺序，不强制选中某协议。
不开放 TLS 版本、ECH、mTLS、REALITY、填充和会话参数；命名指纹沿用共享 TLS。

连接先发送 SHA-256 密码摘要、认证填充和首个会话批次。Settings 固定声明 v=2 和
填充方案 MD5，不附产品/版本标识；合法 ServerSettings v>=2 启用 v2，否则兼容 v1。
首个流与认证批次一起发送。复用空闲会话时，v2 写 SYN 和目标后即返回流，再监视
最长 3 秒 SYNACK；v1 不等待。非空 SYNACK、超时、协议/读写器错误销毁整个会话，
已返回流在后续 IO 报错。仅 open 返回前发现空闲会话失效时可新建一次；不重放业务。

未知流、控制 ID/方向错误、越界负载或非法设置是会话级错误；Alert/非空 SYNACK
仅返回固定诊断，不向日志或调用方回显远端内容。
一个物理会话同时仅一个活动流，完整结束后入空闲列表；优先复用序号最大者。
检查/空闲超时均 30 秒，不预热；首次使用才启动清理 worker。ID/序号耗尽关闭会话。

写命令队列 2 项，流接收容量按运行时预算推导且至少 1；活动会话不设全局数量上限。
UoT v2 使用 `sp.v2.udp-over-tcp.arpa:0` 数据报模式，首包含请求，之后每包携带
IP/域名目标，协议负载最多 65,535 字节并取调用方预算交集；响应队列 1 项。
关闭/取消/丢弃 UoT 同时结束读取任务和底层流。

填充为内置方案；新物理会话持有不可变快照，合法 UpdatePaddingScheme 仅影响后续
会话，非法更新只产生有界警告。文本、条目、逻辑填充量和帧负载都有界。
begin_shutdown 同步禁止新流、清空空闲并取消所有会话；shutdown 等待清理 worker、
读写器和 UoT 任务。准备回滚、运行时 Stop 和测速返回前均完成此屏障，不跨运行时共享。

## Trojan

固定 TLS，network 为 tcp/标准 ws/grpc，默认 tcp。密码为非空原始 UTF-8，不 trim，
认证为 SHA-224 小写十六进制。无认证 ACK：本地建链成功不代表密码通过，负例须检查
原站零业务字节。

SNI 默认 server；WS Host 只覆盖 HTTP authority，不作为 SNI 回退。ALPN 默认 TCP 空、
WS http/1.1、gRPC h2，显式列表及实际协商均须满足传输，不能静默降级。

WS path 默认 /，可带 query；头字段不得覆盖握手保留头或大小写重复。early-data
0–2048 字节，启用时默认 Sec-WebSocket-Protocol，可自定义；空头名表示路径后缀，
此时禁止 query。禁用时不能附 ED 头名。首请求头与剩余数据只按序发送一次。
gRPC service-name 必填，普通名映射 /name/Tun，以 / 开头则为完整路径；不开放池参数。

TCP 保留半关闭；gRPC duplex 发送 END_STREAM，不用 RST_STREAM 提前结束读侧。
UDP 使用同一已认证流上的地址/长度/CRLF 帧，无额外 socket/读取泵/池。
payload 最多 8192 字节，待解析最多 8455 字节，并与调用方收发预算分别取交集。
非法/截断帧关闭，合法超接收预算整包丢弃；取消读取保留进度，部分发送取消使关联失效。
运行时先取消并 join 入站所有者，再等待节点 gRPC 驱动。

## VMess AEAD

标准 UUID，alterId 仅省略/0，请求和响应头均 AEAD，无旧认证回退。cipher 为 auto、
aes-128-gcm、chacha20-poly1305、none；zero 归一 none。auto 按实际 AES 硬件能力选择。
none 只关闭 body 加密，仍验证响应身份；不能启用 global-padding/authenticated-length，
两开关默认 false。

network 默认 tcp，另支持 ws/grpc/http/h2；均可明文或标准 TLS。tls 默认 false，
关闭时禁止 TLS 字段，即便空串、空列表或 false。认证名依次为 servername、WS Host
去端口、server；HTTP 伪装 Host/H2 authority 不替代认证名。WS 需 http/1.1，gRPC/H2 需 h2。

- WS ED/路径/头约束同 Trojan。
- gRPC service-name 必填，普通名/完整路径规则同 Trojan，无额外池调度器。
- http 是 TCP 首包伪装：method 默认 GET，path 列表省略/空为 /，按 URL.Path 转义；
  头为字符串列表，每次握手独立选择路径/头值，Host 默认物理 server authority。
  仅首包封装一次，之后恢复原流；禁止 Content-Length/Transfer-Encoding。
- h2 需要非空 authority 列表，path 默认 /，每流选一个 authority，通过 HTTP/2 PUT body
  双向传输；明文 prior knowledge、TLS h2，无 gRPC 帧。

关闭对齐 Mihomo：TCP/WS 可保留上传 EOF 后的读取；gRPC/HTTP/H2 关闭整条逻辑流，
完整响应应在关闭前读取，不统一要求半关闭尾包。

UDP packet-encoding 默认空串（raw），外层仍 TCP：

| 编码 | 目标与预算 |
| --- | --- |
| raw | 首目标写入认证头；同关联换目标失败，等待首包不重置组快照/建链期限 |
| xudp | 每帧携带目标，零 global ID 不发可选扩展；内部 mux 标记不解析 DNS |
| packetaddr | 每包仅 IP+端口，业务域名用运行时受控 DNS；没有 resolver 时不回退系统 DNS |

UDP body 最多 15,000 字节；packetaddr 另扣 IPv4 7 / IPv6 19 字节，未解析域名按 19
预检；超限一字节即写前失败，不拆业务包。对端可能更小，V2Ray 部分返回路径总缓冲
仅 2048 字节，不能当作 VCore 上限。body wire 解析最多 16 KiB，响应头/XUDP 元数据有界。
TCP 写块最多 4 KiB 以适配 Mihomo 拷贝边界；UDP 不按此切块。16 位帧计数耗尽前关闭，
不重复 nonce。半帧发送取消关闭，接收取消保留进度；认证/地址/标签错误使关联失效。
gRPC/H2 driver 由节点跟踪并同步退出，无全局会话额度或历史表。

## Hysteria2

始终 QUIC/TLS 1.3，使用官方 rustls；不接受 tls/network/client-fingerprint/REALITY。
port 为 1–65535，仅提供 ports 时可省略；显式非法 port 仍拒绝。password 默认空、
保留原值，须为最长 8192 字节的合法 HTTP 头值。SNI 默认 server；ALPN 省略/空为 h3。
支持共享证书 pin/skip 和成对内联 PEM mTLS；udp 只控制业务 UDP，不关闭 QUIC 载体。

- up/down 独立非负整数或十进制整数字符串，裸值 Mbit/s；单位 [KMGT]?[bB]ps 使用
  十进制倍率，bit 向下取整为 byte/s。省略/归一零为自动；拒绝小数、符号、溢出。
- udp-mtu 缺省/0 为 1197，其他值 64–65535，限制编码后单分片并取实际 DATAGRAM
  预算交集，不是 TUN MTU。
- obfs 只允许 salamander，须配非空独立 obfs-password。
- ports 是归一去重的非空端口/闭区间集合，优先于合法 port。hop-interval 仅随 ports：
  整数秒 N、字符串 N 或 N-M，默认 30，5 ≤ N ≤ M ≤ u32::MAX；过短严格拒绝。

每节点一个当前认证 QUIC 会话，逻辑流/关联复用且互不取消。HTTP/3 POST hysteria/auth
在业务前要求 233；TCP 类型 0x401，响应可延迟到首次读取，允许先写业务。
认证/上游/请求共用绝对 10 秒预算。旧会话失败后新流可新建会话，已有业务不重放。
写 EOF 关闭当前逻辑 TCP 双向通道，与 Mihomo 一致，不影响兄弟流。

每流接收窗口 256 KiB、连接收发各 1 MiB、DATAGRAM 收发各 256 KiB；最多 8 条单向
控制流，拒绝主动双向流。PMTUD 关闭，最大 QUIC payload 1400 并取上游预算交集；
空闲 30 秒/保活 10 秒。认证头 16 KiB，TCP 响应消息 2048/padding 4096 字节。
业务 UDP 原生 DATAGRAM，payload 最多 4096，最多 255 分片；未知关联不创建状态。
重组按关联/包/地址隔离，最多 64 个待完成包/256 KiB、TTL 5 秒，关联交付队列 32 包。
重复未完成分片忽略；完成后立即释放 16 位 Packet ID，允许后续重用，**不做业务去重**。

down 写入 Hysteria-CC-RX。up=0 或服务端 auto 使用 BBR，否则取 up 与服务端正上限
较小值（服务端 0 无限），使用固定带宽控制与实际 wire-byte pacer。Mihomo down=0
可能返回 RxAuto，优先自动模式。丢包补偿五秒窗口、最小采样量、ACK 比例下限 0.8。
Salamander 采用公开 salt + XOR/BLAKE2b-256，每包加 8 字节，先扣 QUIC 预算但计入
pacer；这是混淆不是认证，错误密钥由 QUIC 拒绝，短包有界丢弃。

端口集合须映射同一服务端 QUIC 状态；初始/后续随机选端口。跳跃创建新受控 socket，
保持认证时组快照，独立期限不延长初始认证、不重认证。发送只走新路径；一秒内公平
接收新旧路径，最多两条，之后回收旧路径。Stop 同步 join 路径/重组/HTTP3/QUIC，
关闭交换最多一秒。

官方 Hysteria 已验证版本的 4096 字节回包缓冲包含头，更大回包可能在分片前丢弃。
原生测试记录实际版本和限制，VCore 完整 4096 字节另对 Mihomo 验证，不修改第三方。

## Shadowsocks 2022

原样复用官方 shadowsocks-rust，仅三算法：

| cipher | 密钥 |
| --- | --- |
| 2022-blake3-aes-128-gcm | 16 字节 Base64 PSK，或有序 iPSK1:…:iPSKn:uPSK |
| 2022-blake3-aes-256-gcm | 32 字节，同上 |
| 2022-blake3-chacha20-poly1305 | 单一 32 字节 Base64 PSK |

标准 Base64 可省末尾 padding；空段/非法编码/长度错误拒绝，凭据不 trim。
官方库只包装已有 TCP 流，UDP codec 单包有界交接，不调用其 socket 工厂。

### ShadowTLS v3

SS 三算法的 TCP 可配置 `plugin: shadow-tls` 与完整 `plugin-opts`，不是新的代理类型。
仅整数 version 3，始终 strict/TLS 1.3；不提供 v1/v2、弱认证或版本回退。
host 为独立 cover DNS 名/IP，不参与拨号或业务解析；password 保留原始 UTF-8。
ALPN 缺省 `[h2, http/1.1]`、空列表不发送；共享 pin/skip/name-cert-verify 与
节点 client-fingerprint 只影响 cover，不能替代 ShadowTLS 密码。

顺序为受控上游流 → 原生完整 TLS 握手与 relay 认证 → v3 记录流 → 官方 SS2022。
借用原建链期限、取消和组快照，握手失败不发送 SS 目标或业务；pin/skip 不绕过
CertificateVerify 或 Finished。独立 TLS 策略，不恢复 cover 会话。
记录增量认证、未认证内容不交付；每次写最多 16 KiB，背压最多保留一条记录。
flush 排空，关闭最多五秒，不在已切换的 SS 通道中发送 TLS close_notify。

原生 SS UDP 仍走独立受控 UDP 路径，**不经过 ShadowTLS**；TCP-only v3 服务端不会
自动得到 UDP 或 UoT。裸 SS 拒绝 client-fingerprint。默认与 TUN 构建启用
shadow-tls-v3，精简构建可单独移除；无 feature 的插件配置在 IO 前拒绝。
v3 的额外四字节记录特征仍存在，完整认证和互通不等于不可识别。

### UDP over TCP v2

`udp-over-tcp` 默认 false；true 要求 `udp: true`，三算法均可用于裸 SS 或
ShadowTLS v3。开启时 `udp-over-tcp-version` 省略或整数 2 均固定使用 v2；
关闭时不得提供版本，不支持 v1、协商或原生 UDP 降级。无 SS feature 在 IO 前拒绝。

每个关联独占一条既有 SS TCP 路径，支持 TCP-only SOCKS5 上游与 select 组。
目标固定为 `sp.v2.udp-over-tcp.arpa:0`；v2 non-connect 请求只发送一次，之后每包
携带地址和 u16 长度。业务域名先经过受控 `ResolutionContext` 转为 IP，magic 不参与
DNS 或路由。AnyTLS 复用同一有界 codec，但保留自己的域名与会话/FIN 所有权。

SS 首包写入并 flush 成功前阻止后台读取；零长度 UDP 仍有非空 UoT 帧。
延迟首包沿用原建链 deadline，成功建立后的业务不再使用旧期限。未发包关闭直接释放
底层 IO，不触发官方空 SS 握手；半帧写取消使关联失效，不重发。每关联最多一个读取
任务、一个排队响应及一个正在解析/等待入队的响应；接收取消不丢 parser 状态，超接收
预算完整排空该包再读下一包。Stop 取消并等待读任务，释放流；不跨关联池化。

编码负载上限为 65,535 字节，发送/接收各自受调用方预算约束。当前官方 Mihomo
UoT 对端使用 16 KiB 接收缓冲；容器数据验收覆盖该实际边界与多一字节负例，不将
内存中的 u16 上限宣称为端到端 UDP 能力。原样 ssserver 不支持 UoT，仅作拒绝负例。

### 共享 SS 流与数据报行为

- TCP 每次最多交付 16 KiB；读或关闭先于首次写时，完成并刷新官方空首写以支持
  server-first/半关闭。Pending 继续同次握手，已有首写不重复目标头。
- 背压适配最多暂存一个 16 KiB 原文块并立即报告接受；后续保持同缓冲完成写入，
  避免官方重试长度误计。flush/关闭排空，读取也推进待写但不被写背压阻塞。
- 原生 UDP 取消前预留 packet ID，底层实际发送后才成功；Pending 不重编码，无后台发送队列。
  接收验证来源、认证、关联与完整负载，外层 wire 最大 65,507。
- 每关联随机 client session ID、递增 packet ID，最多两个 server session 的 8128 包
  重放窗口；旧 session 一分钟仍有有效包时不替换，ID 将溢出时换 client ID 并清空窗口。
  close 清空并关闭底层，不新增后台任务。

依赖仅 crates.io 版本，不使用 Git/path/源码补丁。AWS-LC 仅允许沿 shadowsocks →
shadowsocks-crypto 链使用，TLS/REALITY 不消费它，详见[TLS 依赖](tls-dependencies.md)。
启用 SS 时通过 log 的 max_level_off/release_max_level_off 关闭整个依赖图该 facade，
防止上游日志泄密；VCore tracing 不受影响。上游 Debug 不暴露。
重放窗口派生代码的来源/完整许可保留在源码头，发布仍审计实际链接图。

**已知风险：**原样上游空 TCP 首写/空 UDP padding 路径扩展长度而未显式初始化，
存在把残留缓冲传给可解密对端的风险；普通 echo 或自有背压修复不代表此风险已解决。
官方空 TCP 首写还可能随机生成零 padding，被其严格服务端拒绝；VCore 不修改或重试
该上游行为。内存回归分别验证适配器刷新与确定性的零 padding 拒绝，不将 codec
级回复算作 server-first 互通通过。
首次固定头不够单次读取时，上游按探测防护拒绝，不改成 read_exact。
Mihomo 仅提供单 PSK；原样 ssserver 验证 AES 单层 EIH 多用户 TCP/UDP 终结及错误身份。
MTU1500 大包夹具显式启用官方双向 IP 分片。自有 1/2 层身份中继不是原生任意多层证明。
所有结果与平台/发布签收分开，见[验收边界](acceptance.md)。
