# XHTTP 与 VLESS sing-mux

当前 XHTTP/sing-mux 契约；[N5 本地阶段验收](acceptance/next-protocols/N5.md)已通过，历史开发过程见 [执行记录](acceptance/next-protocols/N5-progress.md)。高级安全组合属于尚未签收的 N7，不由本文提前开放。配置保持严格类型，未知字段、null、无效或被忽略的组合在 IO 前拒绝。

## HTTP 版本和连接模式

`network: xhttp` 使用现有 Dialer、上游图、保护接口与 SecurityClient，不另建系统解析器或裸 socket。`alpn: [http/1.1]` 选择 H1；空列表、`[h2]` 或包含 H1/H2 的列表选择 H2；只有独占 `[h3]` 选择 H3。不会静默降级 HTTP 版本。

H1/H2 可使用明文、标准 TLS 1.3 或经典 REALITY。H3 必须使用标准 TLS 1.3，不允许同腿明文或 REALITY。QUIC 收发走受控数据报，上游有效预算小于 1200 字节即拒绝，不绕开代理、protect 或接口绑定；路径 MTU 探测关闭。

`xhttp-opts.mode` 接受 `auto`（默认）、`packet-up`、`stream-up`、`stream-one`。auto 在 REALITY 无下载配置时选择 stream-one，有下载配置时选择 stream-up，其余选择 packet-up。stream-one 是一条双工 POST，不允许 `download-settings`；其余模式以同一会话 ID 关联上传与下载。`path` 默认 `/`，`host` 显式非空优先，否则使用该腿 servername/server；IPv6 authority 使用方括号。

## 请求字段

区间字段均为字符串 `"N"` 或 `"N-M"`，不接受数字、负数、倒置区间、空串或溢出。每次采样保持在闭区间内。

| 字段 | 默认及约束 |
| --- | --- |
| `headers` | 字符串 map；最多 100 项 / 8 KiB。禁止 Host、定界/逐跳头、CRLF、大小写重复及与生成字段冲突。值不进入 Debug |
| `no-grpc-header` | false；true 关闭流式请求的 application/grpc，packet-up 不接受 true |
| `x-padding-bytes` | `"100-1000"`，1–4096 |
| `x-padding-obfs-mode` | false：固定 Referer 中的 `x_padding`、queryInHeader、repeat-x |
| `x-padding-placement` | 混淆开启时必填：queryInHeader/header/query/cookie |
| `x-padding-key` | 混淆 queryInHeader/query/cookie 时必填；header 不使用此字段 |
| `x-padding-header` | 混淆 header/queryInHeader 时必填合法头名；其他位置不使用 |
| `x-padding-method` | repeat-x；开启混淆后也可 tokenish，按 HPACK 编码后的长度生成 |
| `uplink-http-method` | POST，也接受 PUT/PATCH/DELETE；不将 GET 或 OPTIONS 用于上传 |
| `session-placement` / `session-key` | path（不填写 key）；header 默认 X-Session，query/cookie 默认 x_session |
| `session-table` | 空：32 字符随机 hex；uuid：标准 UUID v4；或预定义/自定义去重 ASCII 字符表 |
| `session-length` | 字符表模式默认 `"16-32"`，1–128；全部长度构成的命名空间至少 2^31。空表/uuid 不接受显式长度 |
| `seq-placement` / `seq-key` | 仅 packet-up；path，或 header 默认 X-Seq、query/cookie 默认 x_seq |
| `uplink-data-placement` | body，auto 归一 body；header/cookie 仅用于 packet-up |
| `uplink-data-key` | header/cookie payload 必填，body 不接受 |
| `uplink-chunk-size` | header/cookie 默认 `"0"` 自适应；显式区间 64–8192。自适应 header 3072–4096、cookie 2048–3072 |
| `sc-max-each-post-bytes` | packet-up，`"1000000"`，1–16 MiB；这是 POST 上限，不是预分配缓冲大小 |
| `sc-min-posts-interval-ms` | packet-up，`"30"`，0–60000 且最大值须为正；允许 `"0-N"`，不允许纯零 |

session/sequence 均支持 path/query/header/cookie。键使用至多 64 字节的 HTTP 安全 token，禁止互相冲突以及覆盖 padding、payload 或既有 query/header。字符表预定义值包括 `ALPHABET`、`Alphabet`、`alphabet`、`BASE36`、`base36`、`Base62`、`HEX`、`hex`、`number`。

路径遵循 Mihomo：session 或 sequence 任一放在 path 时补尾斜杠，否则保留显式路径。原生 Xray 的 handler 始终补尾斜杠；因此与 Xray 互通且两项均不在 path 时，须显式配置带尾斜杠的路径（例如 `/proxy/`）。这是对端路径配置差异，不通过修改 VCore 的默认规范化规则解决。

header/cookie payload 使用无填充 Base64URL，并按实际请求预算拆块；完整请求（URI、生成字段和自定义头）不超过 16 KiB / 128 项。业务数据按有界块处理，不把整个 POST 限额、对端声明或业务流读入无界 Vec。

packet-up 在发送间隔内聚合小块写入，而不是把每个 write 变成一个 POST。最多保留一个待发送批次和一个在途批次，每批最多 64 KiB，并与本连接采样的 POST 上限取较小值；头部 payload 仍按请求预算拆分。write 完成只表示数据已进入有界缓冲，flush 等待对应 POST 确认；计时器无需调用方再次读写即可发送。shutdown 立即尝试 flush 未发送批次，卡住的 POST 仍受一秒上限控制。计时器/上传任务归节点所有，Stop 同步等待。

## 独立下载腿

`download-settings` 缺省和 `{}` 不等价：存在即启用独立下载连接/池，但仍共用一次 VLESS 握手、会话 ID 和建链上下文。两腿必须汇聚到**同一个原生 XHTTP handler 的会话表**；两个独立 listener 不能构成共享会话。

可覆盖 `server/port/tls/servername/alpn/host/path/headers`、`client-fingerprint`、普通 TLS 的 `skip-cert-verify/name-cert-verify/fingerprint/certificate/private-key`、经典 `reality-opts` 和 `reuse-settings`。

- 缺省叶字段继承主腿。headers 是整体替换，`{}` 清空；显式空 host 恢复下载认证名/server 推导。
- `skip-cert-verify: false` 必须覆盖主腿 true；空 name-cert-verify/fingerprint 清除对应 override/pin。
- `client-fingerprint` 缺省继承，`chrome120` 覆盖，空串清除。下载腿切到明文或 H3 前必须清除继承的非空 profile；它不属于证书策略，不因切换 TLS/REALITY 自动清除。见 [TLS 指纹](tls-client-fingerprint.md)。
- certificate/private-key 必须配对替换或同时空串清除；PEM 与密钥匹配在 IO 前检查。
- reality-opts 缺省继承整个对象，`{}` 清除；非空对象必须提供 public-key，short-id 缺省空，不按叶合并旧对象。null 拒绝。
- 切换到明文或 REALITY 不会悄悄丢弃继承的证书策略；须显式清除冲突字段。每条腿独立重新校验最终安全配置。
- 独立地址/端口在 prepare 时分别准备；两腿共享原绝对期限和每个上游组的选择快照，下载失败不会另起超时预算或绕过原图。

## HTTP transport 复用

`reuse-settings` 缺省禁用节点池；`{}` 启用默认池。下载配置缺省继承整个主腿 reuse 对象，显式对象整体替换，未填写项回到零，不逐字段继承。

| 字段 | 语义 |
| --- | --- |
| `max-concurrency` | 候选 transport 的并发挑选阈值，默认 `"0"` |
| `max-connections` | 优先扩到的候选数，默认 `"0"`；全部忙时仍可扩容，不是全节点硬上限 |
| `c-max-reuse-times` | 复用次数预算，默认 `"0"`；耗尽后不再分配新流 |
| `h-max-request-times` | 按领取 transport 扣减，默认 `"0"`；不按每个 packet-up POST 扣减 |
| `h-max-reusable-secs` | 按物理 transport 年龄退役，默认 `"0"`；活动逻辑流继续 |
| `h-keep-alive-period` | 整数秒；0 为 H2 45 秒 / H3 10 秒，负数禁用，正数指定周期；H1 仅接受 0 |

前五项接受 0–i32::MAX 的字符串区间。h-max-request-times 和 h-max-reusable-secs 只有最大值为零才禁用；例如 `"0-1"` 采样到零仍按零预算或立即到期处理。c-max-reuse-times 则与 Mihomo 一样，采样值为零即不启用该项限制。两腿池与计数独立。已建物理连接保持原上游选择；创建新连接时才使用当前选择。H1 仅复用完整结束的上传请求连接，不复用取消的下载 GET。节点空闲缓存有界；它不构成业务流数量额度。

## VLESS sing-mux

节点级 `smux` 接受 enabled、protocol、max-connections、min-streams、max-streams、padding、only-tcp。enabled 默认 false；protocol 默认 h2mux，也支持 smux v1/yamux。计数是 0–i32::MAX 整数；正 max-connections 与正 max-streams 互斥。padding、only-tcp 默认 false。Vision 与启用的 sing-mux 互斥。

空闲物理会话优先复用；max-connections>0 分支按连接数量与 min-streams 扩容，否则按 max-streams 阈值复用。max-connections=max-streams=0 时 min-streams 归一为 8，但不会将其解释为所有调度分支的硬额度。单流关闭不关闭兄弟流，节点 Stop 才取消和等待所有自有驱动。

yamux 的内部资源边界是单物理连接累计分配 64 个流后退役；旧流继续，新请求另建连接，空闲即回收。该边界避免逻辑取消与库内 reset 回收不同步时误关兄弟流，不是全节点额度，详见 [资源策略](runtime-resource-policy.md)。

sing-mux 的外层是普通 VLESS TCP 到约定目标，**不是 VLESS CommandMux/XUDP**。only-tcp=false 时 UDP 使用 mux 的逐包地址格式，经受控解析处理域名；true 时保留所选 raw/XUDP/packetaddr 编码。`udp: false` 始终禁止业务 UDP。padding 覆盖握手及最初 16 个物理写入帧；接收增量解析和丢弃 padding，不按声明长度无限分配。

## 关闭、安全与验收边界

XHTTP 按 Mihomo 整条逻辑连接关闭：上传 EOF/shutdown 同时取消下载；packet-up 待决上传最多等待一秒。需要完整回复的应用必须在关闭前读完；不承诺 TCP 半关闭后继续收到尾包。复用只延长物理 transport 生命周期，不改变单个逻辑连接的关闭范围。

H3 的 QUIC 驱动、数据报适配器和后台任务归节点所有。Stop 先执行有界关闭交换，再取消/join 内部任务和上游 IO，不把 Drop 或“等一会儿资源消失”当作完成屏障。

H1/H2 原生验证优先使用官方 latest Mihomo；H3 使用官方 latest Xray。不被 Xray 直接解码的 packetaddr/sing-mux 使用明确标注的 Xray XHTTP → Mihomo VLESS 分层拓扑；mTLS 使用已批准的 xcaddy/Caddy H3 网关，后端仍是同一个 Xray handler。分层成功不改写直接对端失败。所有服务端与原站在隔离容器中，配置和私钥不入 Git；原生数据、公共入口、资源、跨平台构建和阶段签收分别记录。
