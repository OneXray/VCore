# N5：XHTTP / sing-mux 开发进度

2026-09-25：**N5 已完成本地阶段签收，最终结果见 [N5 验收报告](N5.md)。** `n5-acceptance-20260925-v6` 在同一冻结输入通过 416/416 个 required case、57/57 个字段及独立 coverage；schema 18 / Invoke v5。本记录保留开发过程，各段 FAIL、NOT RUN 和“待验收”均为当时状态，不追改或拼成最终 PASS。已批准的 xcaddy/Caddy H3/mTLS 拓扑继续保留；官方 Mihomo 上传认证失败联动的历史超时不改记成功。分支 `feat/xhttp-mux`，起点 `5f1317705d5c4d39694fbf7591f93d6ece6ea027`；本阶段仅本地提交，不 push。

## 实际变更边界

- 新增 `check xhttp-peers` 原生能力诊断入口。官方客户端、协议服务端、入口和原站均在带本次所有权标签的 Apple Container 中；宿主只驱动 SOCKS 请求和读取原站观察结果。
- Mihomo/Xray 每次重新下载官方 latest 二进制，在容器内读取版本。不从研究源码编译、不改第三方、不查询 GitHub API，也不使用旧缓存兜底。Caddy 使用调用方明确批准的 xcaddy 构建例外，详见下文和[隔离规则](../../testing-isolation.md)。
- `ContainerLab` 增加显式 guest MTU 1500 选项并读回核对；原来默认 1280 不变。只作用于本次临时容器，不修改共享网络/宿主 MTU、不增加 NET_ADMIN、不发布宿主端口。
- 前一轮请求头实验曾撤回；本轮已重新实现并扩展，不能重放旧 patch。当前字段与资源契约见 [XHTTP](../../xhttp.md)、[配置](../../config.yaml)和[资源策略](../../runtime-resource-policy.md)。Cargo/lock、源树和 schema 已不同于 N4。
- N5.1–N5.4 的代码与严格配置已进入统一 N5 门禁。必需集合覆盖 H1/H2/H3、明文/TLS/经典 REALITY 的合法模式、同 handler 下载、三个 mux wire 和 only-tcp 分支；六种代表拓扑各执行 20 轮公共生命周期与 20 轮自有资源检查。只有同一次完整运行通过独立 coverage 才签收，旧探针不计入该运行。

## 固定输入与原始结果

每项为独立完整探针运行，保留第一次失败，不拼接为一次全绿验收。目录均位于仓库自身 `target/interop/runs/`，二进制、合成配置和原始日志不入 Git；临时证书/私钥在清理时删除。

| 运行目录 | 目的 / 结果 | 源树 SHA-256 | 容器清理 |
| --- | --- | --- | --- |
| `n5-peer-prerequisites-20260924-v1` | 初始 HTTP 版本/模式/解码探针：72 PASS / 36 FAIL，H3 建链失败 | `2a5ebc711a15185801ea4ae220c35f5287fadbd8ce509bfbd6fd943b67a20755` | 14/14，owned remaining 为空 |
| `n5-peer-prerequisites-20260924-v2` | guest MTU 1500 后：101 PASS / 7 FAIL；直接 Xray 解码缺口保留 | `5433e88f47b4649d1c0d4b6c4282c4907d447968631030319de71653185cb2a0` | 14/14，owned remaining 为空 |
| `n5-native-identities-20260924-v1` | 下载腿身份：5 PASS / 3 FAIL，Xray H3 不拒绝缺失/过期/错误 CA 身份 | `2f22d30181bbaaf210ea4f5b1decfbc68b153e2a87cf47073032786518c56a4a` | 6/6，owned remaining 为空 |

三次 `source_unchanged=true`、`cleanup=true`；后续脚本修整与生产草稿变更产生不同输入，不能把旧运行 hash 写成当前源码 hash。上述三次前置探针的 Cargo.lock 为 `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`，不是新增 H1 依赖后的锁。镜像由官方 `docker.io/library/python:3-alpine` 解析为 `sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01`。

| 官方对端 | 容器内实际版本 | archive SHA-256 | binary SHA-256 |
| --- | --- | --- | --- |
| Mihomo | v1.19.31 / Go 1.26.8 / linux arm64 | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| Xray | 26.3.27 / d2758a0 / Go 1.26.1 / linux arm64 | `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c` | `c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04` |

实际官方来源分别为 [Mihomo latest 版本入口](https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt)解析后的该版资产，以及 [Xray latest ARM64 资产](https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip)。版本/hash 只记录本次身份，不是以后固定版本。

## 已观察到的原生能力边界

通用探针每项仅检查一次 69 字节精确请求/回包和原站观察，没有重试。不是双向 10 MiB、全部 UDP 长度/地址族、故障、复用或 Stop 资源门禁。

- Mihomo H1/H2 的明文与 TLS：四组共 72 项基本闭环通过，包含三模式、packet-up/stream-up 独立下载、packetaddr、h2mux/smux/yamux；普通 UDP 走 XUDP。未据此推导 raw UDP、完整字段或大流量能力。
- Xray H3 直接 VLESS：18 项中 11 项通过；packetaddr UDP 和三种 sing-mux 的 TCP/UDP 共 7 项失败。
- Xray H3 XHTTP + 原生 Mihomo VLESS decoder：18 项全部通过。Xray 的单个 dokodemo-door/XHTTP handler 持有真正共享的会话表，只转发字节流；Mihomo 的原生 VLESS listener 解码 packetaddr/sing-mux。这是明确标注的分层拓扑，不是 Xray 自身新增解码能力，也不是两套独立 XHTTP listener 冒充共享会话。
- 首轮 H3 建链超时在将临时 guest MTU 改为 1500 后消失，后续保持该值。该调整不是放宽客户端 UDP 预算，也不证明全部路径 MTU 用例已通过。

## 直连 Xray H3 下载腿身份：原始 BLOCKED 保留

身份探针始终使用合法主腿身份，下载腿依次使用合法、显式清空、过期、错误 CA 证书；每项独立节点/监听入口/连接池。两腿使用同一原生 handler，客户端为官方 Mihomo。Mihomo 服务端配置 `require-and-verify` 和合成 CA；Xray 只使用它真实支持的 `certificates[].usage=verify`，不注入不存在的 client-auth 配置。

| 下载腿身份 | Mihomo H2 | Xray H3 |
| --- | --- | --- |
| 合法证书 | 完成精确数据闭环 | 完成精确数据闭环 |
| 显式清空 | 未完成数据交换 | 完成精确数据闭环，原站实际观察到请求 |
| 过期证书 | 未完成数据交换 | 完成精确数据闭环，原站实际观察到请求 |
| 错误 CA | 未完成数据交换 | 完成精确数据闭环，原站实际观察到请求 |

其中三个 H3 FAIL 的含义是“计划所需的身份拒绝观察不存在”，**不是声称 Xray 承诺了 mTLS 而产生安全漏洞**，也不是 VCore 客户端错误。Mihomo 的负例这里只记录未完成交换，不以此替代未来 VCore 的零业务字节、精确错误及资源负例门禁。

已核对发布 tag `v26.3.27` 对应提交 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，而不是研究 checkout 的更新 HEAD：

- [TLS GetTLSConfig](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/transport/internet/tls/config.go)没有设置 Go TLS 的 `ClientAuth` / `ClientCAs`；根证书配置并不等于服务端请求/验证客户端证书。
- [证书池实现](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/transport/internet/tls/config_other.go)将配置证书放进 RootCAs。
- [XHTTP H3 listener](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/transport/internet/splithttp/hub.go)使用该 TLS 配置，没有另外注入客户端认证策略。

因此 `VL-XHTTP-H3-DUAL` 中 D12/D13 的客户端证书实际消费/错误身份拒绝，不能以直连 Xray 成功抵扣。后续 Caddy 补充拓扑不改变这个原始结论；整个 N5 仍不能签收。H1/H2 的 mTLS 不受这个原生对端缺口影响，但其 VCore 实现仍需开发和独立验收。

## 已批准的 Caddy H3/mTLS 网关补充验证

调用方已明确允许自行用 xcaddy 编译后导入容器。`check xhttp-gateway` 每次解析官方 latest 稳定版本，要求本机 xcaddy 与最新稳定版相同，执行 `xcaddy build latest` 交叉编译 linux/arm64，再把产物只读挂入隔离容器。没有源码 replacement、额外插件或第三方修改；保留构建日志、生成的 `go.mod`/`go.sum`/`main.go` 与摘要，不把本地构建称作官方预编译包。当前构建身份：

- [xcaddy v0.4.7](https://github.com/caddyserver/xcaddy/releases/tag/v0.4.7)，Go 1.27.1 darwin/arm64；[Caddy v2.11.4](https://github.com/caddyserver/caddy/releases/tag/v2.11.4)，容器内实际输出该版本。
- 每次构建的二进制 hash 和 manifest 摘要在该次 `result.json`，不能跨构建复制。Mihomo/Xray 仍为上述官方 latest 下载身份。
- 四个独占容器：`Mihomo H3 client → Caddy H3/mTLS → Xray h2c/XHTTP/VLESS → origin`。所有上传/下载请求汇合于**同一个**原生 Xray XHTTP handler；Caddy 不实现 XHTTP 或 VLESS，也不降级客户端 H3 为 H2。网关至 Xray 的内部明文 h2c 跳明确单列。
- Caddy 只监听 H3、设置 `require_and_verify` 和合成 CA，使用默认代理取消语义；没有负值 `flush_interval`，没有跳过证书校验。主腿与下载腿使用不同密钥/证书。原生配置定义见 [client_auth](https://caddyserver.com/docs/caddyfile/directives/tls#client_auth)和[反向代理](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)。
- 根文件系统只读，Caddy 的配置/数据目录放在容器 `/data` 临时盘；不修改宿主 HOME、网络或端口。网关日志只保留事件类型、HTTP/ALPN 和是否出现客户端证书，不保留完整请求。

### 正常流量与失败历史

| 运行目录 | 实际结果 | 边界 |
| --- | --- | --- |
| `n5-xcaddy-gateway-20260924-v1` | FAIL，构建成功但清单发现失败，未启动容器 | macOS xcaddy 在 cwd 而不是 TMPDIR 下生成 buildenv，已修正自有路径发现 |
| `n5-xcaddy-gateway-20260924-v2` | FAIL，容器内配置校验失败，4/4 清理 | Caddyfile 的 `trust_pool` 不是 JSON 字段，已按官方定义改为 `ca`；本次原始详细 stderr 未留存，不伪造为已保留 |
| `n5-xcaddy-gateway-20260924-v3` | 26 PASS / 6 FAIL；source unchanged，4/4 清理，owned remaining 为空 | 全部 20 正例和下载腿 6 负例通过；上传腿 6 负例客户端等待 5 秒超时 |
| `n5-xcaddy-gateway-20260924-v4` | 26 PASS / 6 FAIL；source unchanged，4/4 清理，owned remaining 为空 | 最终正常流量复验；补全所有负例的原站观察、只读根目录适配和日志脱敏，仍保留相同 6 项超时 |
| `n5-xcaddy-identities-20260924-v1` | 5 PASS / 21 FAIL；source unchanged，4/4 清理 | 观察器错误地要求 qlog 的文字 reason；21 负例均未观察到原站连接，但缺少结构化证据，不记认证通过 |
| `n5-xcaddy-identities-20260924-v2` | 5 PASS / 21 FAIL；source unchanged，4/4 清理 | 增加 trace 计数，现场读到本地证书 TLS alert，文字 reason 为空；失败原样保留 |
| `n5-xcaddy-identities-20260924-v3` | 20 PASS / 6 FAIL；source unchanged，4/4 清理，owned remaining 为空 | 按标准错误码读取原生证据后，21/21 无效身份均确认被网关拒绝；6 个上传错误返回超时仍 FAIL |

20 项正常用例覆盖 packet-up、stream-up、stream-one，及前两者的独立下载，共 5 种形态。每种均执行精确 TCP echo、XUDP echo、服务端先发、双向各 10 MiB SHA-256 完整性、完整回复后的关闭和独立 EOF 关闭探针。关闭记录 EOF 后尾部字节而不要求所有传输都收到尾包；5 秒内结束且原站观察到结束。不涵盖所有 placement/padding/reuse、raw/packetaddr/sing-mux 或 VCore 资源门禁。

### 上传失败的客户端联动与认证证据分开判断

身份诊断增加无独立下载腿的 9 个无效证书对照。缺失/过期/错误 CA 均使原站保持零 accept；共享身份和下载身份错误会结束 SOCKS 请求，只有 packet-up/stream-up 的“无效上传身份 + 合法下载身份”6 项保持等待直至驱动 5 秒超时。超时仍为 FAIL，不调大超时、不重试业务、不改第三方。

已核对 Mihomo `v1.19.31` 源码与研究 checkout 同为 `ab414bad5beeeac8b003bb01f60f134f6df54471`：[上传/下载实现](https://github.com/MetaCubeX/mihomo/blob/ab414bad5beeeac8b003bb01f60f134f6df54471/transport/xhttp/client.go)中两侧错误路径分离，stream-up 的上传错误只关闭 writer，而 reader 仍取下载结果。结合上述对照，判断这是官方对照客户端的错误联动限制，不是 Caddy 放过无效证书，也不归因于尚未接入的 VCore H3 实现。

证书认证必须另有本次连接的原生证据：只接受 Caddy 本地主动发送的 QUIC `CRYPTO_ERROR`，并要求与该身份类别匹配、原站零 accept、零业务交换；不以普通网络错误或 timeout 作为认证证据。[QUIC TLS 错误映射](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.8)和[TLS alert 定义](https://www.rfc-editor.org/rfc/rfc8446.html#section-6)对应缺失 `0x174`、过期 `0x12d`、错误 CA `0x130`。原始 qlog 仅在本次容器临时盘中，宿主保留错误码/类别和计数；无私钥、请求头、连接 ID 或目标地址。观察器有 128 文件 / 16 MiB 总量上限，仅小流量身份诊断开启。

身份 v3 和正常流量 v4 为同一固定源码，摘要 `07e7dd17e9f740dc3976c78e762d28c3a900c712b2cf3a0bd256e056ce132fd1`；两次 Caddy 二进制 SHA-256 均为 `8445ad608894f02c003769bf278183037844a153f29394ea947ad25458507dcf`，`go.mod` / `go.sum` 摘要分别为 `fc1807fd68eea7f79df81cc965d03aeb6498d8f76a8165c82dc2807e9874e351` / `4b05bdb7355b557adabeaf52c148256494311442f4472ae988ef502045aa192f`，但仍是两次独立运行而非拼成一次全绿。身份 v3 的 5 个合法 echo 对照通过，21 个负例的 `identity_enforced=true`；其中 15 项约 0.5 秒完成（含观察/取证开销），另 6 项在 5 秒读取限时后仍记录 timeout，不能将两个维度合并成“26 项全部通过”。正常流量 v4 再次确认 20 个正常探针全部通过，5 种形态各完成双向 10 MiB；4 个容器均删除。最终 `container list --all` 为空。

结论：补充拓扑能验证 H3 的真实证书认证，可作为后续 VCore D12/D13 开发的测试对端；**不代表 VCore 已实现这些字段，也不签收 N0-F 或 N5**。原生 Mihomo 的上传错误联动限制单独保留；VCore 后续仍须通过其规定的建链期限、取消与 Stop 资源门禁，不通过修改对端或静默丢弃失败来达成全绿。

## 复现与当前本地检查

```sh
# 每次使用新的目录；预期存在上述能力差异时非零退出。
uv run --project scripts --locked vcore-scripts check xhttp-peers \
  --run-dir target/interop/runs/<fresh-native-run>
uv run --project scripts --locked vcore-scripts check xhttp-peers \
  --identities-only --run-dir target/interop/runs/<fresh-identity-run>
# 需要 PATH 中有最新稳定 xcaddy 和 Go；每次重新构建并导入容器。
uv run --project scripts --locked vcore-scripts check xhttp-gateway \
  --run-dir target/interop/runs/<fresh-gateway-run>
uv run --project scripts --locked vcore-scripts check xhttp-gateway \
  --identities-only --run-dir target/interop/runs/<fresh-gateway-identities>
```

前置脚本修订时的离线单元测试 123 项、ruff check/format 均通过；当时 Rust fmt、既有内存 H2 关闭回归 2 项通过。这些是历史输入结果，不是本轮新增生产实现的验收。配置声明清单此前 VALID（145 fields / 69 families，behavior NOT RUN）。没有借用这些结果签收 N5；没有运行新功能的远端 CI、设备或发布验收。

## 请求字段与 H1/H2 生产草稿

- 正式 YAML 归一化接入请求头、padding、session/seq placement、会话 ID 字符表、上传方法、header/cookie payload 分块及 packet-up 限额/间隔。下载腿请求头支持继承、整体替换和空 map 清空，并检查与自动生成字段的冲突。HTTP 请求头/URI 总预算 16 KiB、128 字段；自定义头预算 8 KiB、100 字段，payload 按预算拆分而非按最大 POST 值申请内存。
- HTTP/1 使用 [Hyper 1.11.1](https://docs.rs/hyper/1.11.1/hyper/client/conn/http1/index.html) 与 [hyper-util 0.1.20](https://docs.rs/hyper-util/0.1.20/hyper_util/rt/index.html) 的 IO 适配，仅接收既有拨号路径提供的流，不引入全局连接器、DNS 或另一套 TLS。版本通过官方注册表 `cargo info` 核对。H1 分离模式走两个受控连接，共享原来的建链期限与组选择上下文。
- 第一轮 H2 原生请求字段开发检查 `n5-request-fields-20260924-v1` 为 18/18 PASS，IPv4/IPv6/域名三目标各完成服务端先发、双向各 10 MiB 和关闭；36 个自建容器清理，源码身份未变化。该输入早于后续类型调整与 H1 修复，不能冒称当前工作树全量验证，也不抵扣 UDP、资源或正式字段覆盖门禁。
- `n5-h1-public-path-20260924-v1` 暴露响应头之后驱动提前退出的自有错误。用纯内存 IO 的延迟响应正文测试复现并修复：请求发送句柄结束不意味着响应正文结束，驱动继续由逻辑连接和节点生命周期持有。无第三方修改。
- `n5-h1-public-path-20260924-v2` 的三个 H1/TLS 模式通过；明文首例因测试入口误调用只接受标准 TLS 的测试根构造器失败，尚未拨号。已改为明文使用正式构造器并启动独立全组复验；原失败目录保留。
- 截至该次修订，配置单元 71 项、请求边界 3 项、内存 HTTP wire 8 项、旧 XHTTP 18 项各自通过；定向 Clippy 在最后一次生产修改前通过，须最终重跑。此处不将分散的开发检查拼成 N5 签收。

### 后续 H1/H2、复用与 UDP 开发检查

- `n5-h1-public-path-20260924-v3`：9/9 PASS，H1/TLS、H1 明文、H2 明文分别覆盖三个模式；18 个容器清理，源码身份未变化。
- `n5-reuse-public-path-20260924-v1`：6/6 PASS，同一 VCore 节点连续建立 IPv4/IPv6/域名业务流，覆盖 H1/H2、三模式、独立下载池及 H2 上传/H1 下载；12 个容器清理，源码身份未变化。
- `n5-udp-public-path-20260924-v1`：3/3 PASS，H2 三模式分别跑 XUDP、原始 UDP、packetaddr，三目标类别，每个 1/64/512/1200/15000 字节负载各 100 包，以及预算+1 拒绝；6 个容器清理，源码身份未变化。尚不抵扣 H1/H3 UDP 或 sing-mux。
- 内存回归现覆盖复用对象缺省/空对象、两腿独立计数、扩容阈值、退役后旧流继续、packet POST 不额外领取 transport、H1 只复用已完成 POST、不复用取消的 GET、H2 默认45秒/显式/禁用PING，以及一个逻辑连接关闭不结束兄弟流。
- Stop 并发测试先复现“停止后握手仍注册新驱动”和“停止无法唤醒未完成握手”，再增加驱动准入互斥屏障与握手取消。两个回归通过。GET/packet POST 必须200、stream POST接受2xx的 Mihomo响应语义亦有独立内存回归。
- 最新一轮 H3 接入后的 XHTTP 配置8项、wire10项、复用/Stop9项通过，定向Clippy和TLS依赖检查通过；这些仍是开发检查。无第三方源码修改。

### H3 正式路径开发中

新增官方稳定 `h3 0.0.8` / `h3-quinn 0.0.10`，继续使用既有 Quinn/ring/rustls 链。H3通过受控DatagramTransport、既有节点TLS策略和原绝对deadline建链；只接受独占`[h3]`与标准TLS，禁止同腿REALITY、明文或静默H2回退。Quinn公开Runtime接点将内部任务登记到节点可等待的停止屏障。

原生Xray开发运行的失败目录保留：v1 尚未接入UDP时被拒；v2握手后因最后一个h3请求发送句柄释放而关闭连接，已把保活句柄归属物理驱动；v3/v5已收到完整10MiB和trailer，但等待原站结束标记时EOF，定位为过早取消Quinn驱动导致关闭帧没有送出（不是数据截断）；v4取消待决读取时显式调用h3-quinn `stop_sending`触发其内部空Option，已改为释放拥有待决future的接收流，由Quinn正常Drop取消。没有修改第三方或提高超时，正在验证有界QUIC关闭交换与停止屏障，**H3/N5均未签收**。

`n5-h3-public-path-20260924-v6`：三模式3/3 PASS；每种模式覆盖IPv4/IPv6/域名目标、服务端先发、双向各10MiB与trailer、5秒内原站确认关闭。源码身份未变化，容器全部清理。修复为先关闭QUIC并在1秒界限内等待关闭交换，再取消/join Quinn任务和上游数据报驱动；没有放宽测试期限。该结果只证明基础TCP路径，独立下载、完整字段、UDP与阶段资源门禁仍待验收。

### sing-mux 开发检查

`n5-sing-h2mux-20260924-v1`：隔离Mihomo上h2mux/无padding，IPv4/IPv6/域名目标双向各10MiB及关闭PASS；源码与清理均通过。严格配置与内存双流/单流取消、UDP读取取消的定向测试通过。`n5-sing-padding-red-20260924-v1`保留未实现padding时的Unsupported失败，不计为互通通过。三协议完整覆盖与N5签收尚未完成。

后续 `n5-sing-three-wire-20260924-v1` 的三种 wire protocol × padding 开关共 6 项 TCP 通过（每项三类目标、双向 10 MiB、完整回复及关闭），源码未变化且容器全部清理。UDP 首轮 `n5-sing-udp-20260924-v1` 前三项通过，smux + padding 失败，其后用例未执行；`n5-smux-udp-diagnosis-20260924-v2` 重现物理流 UnexpectedEof / 写侧 BrokenPipe。增加调度观测后的 v3 偶然通过，不能据此消除原失败。

已在正式 VLESS + XHTTP、纯内存 H2 IO 边界复现：首次读取重复 flush 握手，会取走并发 packet-up 写入的完成结果，随后写侧将已发送数据重复发送。`first_vless_read_never_acknowledges_or_replays_a_concurrent_packet_write` 修复前观察到 `headerprefacepacketpacket`，修复后精确为 `headerprefacepacket`（分别覆盖调用方显式 flush 和未显式 flush）。修复将一次性握手 flush 放在交付 payload IO 前；不修改 padding 格式或第三方代码。定向 XHTTP 请求 11、sing-mux 4、既有 VLESS 传输 3 项通过。临时 DEBUG 输出已移除。

`n5-sing-udp-20260924-v2`：三协议 × padding 开关 × only-tcp 开关共 12/12 PASS。每项三种配置的 UDP codec、三目标类别、五个尺寸各 100 包，合计 54,000 个报文；源代码未变化，容器全部清理。only-tcp 的实际 VLESS command 另由内存 wire 测试证明，不能把 sing-mux UDP 的通过冒称 raw/XUDP/packetaddr 三种 wire 都已使用。

sing-mux 内存回归增至 7 项，新增两分支调度/扩容和 only-tcp wire；H2mux idle PING 测试先观察到缺失 PING，再实现 30 秒读空闲 PING、15 秒 ACK 限时与节点拥有的驱动。没有新增 detached task 或修改第三方库。

`n5-owned-20260924-v1`：H3 packet-up/reuse 与 H2 smux/padding 各 20 轮，通过单流关闭不杀兄弟流、TCP/UDP 数据、Stop 返回当时自有资源计数为零及之后 5 秒静默检查。H3 明确使用 Xray XHTTP → Mihomo VLESS decoder 分层拓扑；source_unchanged/cleanup 均为 true。不是公开 runtime 的 20 轮启动/失败回滚，也不抵扣尚未执行的下载认证、公共入口与正式 N5 coverage 门禁。

### VCore 两腿安全与身份开发验证

`n5-vcore-security-20260924-v3`：112/112 PASS（H1 38、H2 38、H3 36）。实际消费者为 VCore；H1/H2 使用一个 Mihomo listener 的双端口共享 handler，H3 使用已批准的 Caddy H3 双绑定 → 一个 Xray h2c/XHTTP handler。

- 正例分别验证三模式、独立下载继承/替换、不同端口、IPv6 和准备好的域名别名、不同下载身份、清除 pin/name override、H1/H2 交叉 ALPN；每项服务端先发及双向各 10 MiB，读完 trailer 后关闭，原站确认结束。
- 缺失/过期/错误 CA 身份分别作用于共享、上传、下载路径；错误下载 pin/name 和显式 false 恢复证书检查均失败，受控原站零 accept。负例要求 4 秒原建链期限生效，5 秒外层看门狗不能超时；随后节点同步 shutdown，资源为零。
- H3 的 21 项身份错误另有原生 Caddy 本地 QUIC TLS alert 类别证据；这次 VCore 的“错误上传 + 合法下载”也按期限结束，与前置 Mihomo 对照的 6 项超时分开记录。不声称修复 Mihomo。
- 正常大流量和小流量身份拒绝使用不同的临时 Caddy 容器，只有后者启用有界 qlog；原始 trace 与合成私钥均随容器/临时夹具清理。source_unchanged、cleanup 为 true，owned_remaining 为空。

v1 因自有夹具复制二进制没有保留 executable bit 而未进入数据测试；v2 的正例通过后，主腿“缺失证书”误写为空 PEM，被严格配置拒绝。两次失败保留，修复只作用于测试夹具：主腿省略身份、下载腿使用明确空串清除。112 项通过仍是开发输入，不代替公开 runtime、其他请求字段和完整阶段签收。

### 公共运行时栈边界修复

`n5-h3-graph-20260924-v1` 在公开 Invoke 运行时的 1 MiB 线程栈上溢出；简化为直接 H3 stream-one 的 `n5-h3-stack-min-20260924-v1` PASS，再简化为无上游/切组的 packet-up 独立下载（v2）仍栈溢出。macOS 崩溃栈指向两腿 acquire 内构造 VLESS transport future，不是 DNS/组递归。

无服务端、首个 socket 即被 protect 拒绝的 `split_xhttp_construction_fits_the_runtime_stack_and_protect_failure_has_no_fallback` 在相同 1 MiB 线程上稳定复现原崩溃。将每腿 TLS/QUIC 建链 future 分别装箱后，H3/H2/H1 回归在 0.01 秒内通过；未修改线程栈、第三方源码或超时。原始完整 H3 嵌套组/具体 SOCKS5 UDP 上游用例在 `n5-h3-graph-20260924-v2` PASS，source_unchanged/cleanup 为 true。受控 DNS 解析该测试的代理域名；不会借系统 resolver 回落。后续仍需完整公共入口与生命周期门禁。

### 统一门禁前的补充检查

- `n5-mux-native-extensions-20260924-v1`：7/7 PASS；H3 两腿 QUIC keepalive 默认、禁用、显式周期，以及 WS/TLS、gRPC/REALITY、HTTP/H2、WS 自定义头/路径 ED 外层的 mux 数据；原生 V2Ray 只负责其传输 framing，mux 明确交给 Mihomo decoder。
- `n5-public-udp-scope-20260924-v1`：4/4 PASS；H3 packet-up 独立下载及 H2 三种 mux 的公开 UDP 来源/编码隔离。
- `n5-1p7mf3_n`：H1 完整 BASE、同模式 Mihomo 关闭对照 PASS；H3 的 TCP 和前两种 UDP 编码通过后，packetaddr 域名失败。原 DNS 夹具在最初 TCP 之前创建，进入第三轮 UDP 前已因空闲 30 秒退出。修复为每个 runtime 拥有独立 DNS 夹具，未延长 VCore 超时或重试业务报文；原始失败保留。
- `n5-zhwmd4uj`：H3 packet-up 独立下载的 BASE、同模式 Mihomo 关闭、HTTP/模拟 TUN 入口、外层 IPv6/protect、20 轮公共启停均 PASS，source_unchanged/cleanup 为 true。

新增配置回归先复现 serde 把 `[]` 反序列化成默认嵌套对象的问题，再为 xhttp-opts、smux、reuse-settings、download-settings、下载 reality-opts 强制 map 类型。全叶字段 null/错误类型和数值边界均在 IO 前拒绝。

Yamux 的“64 流后取消其中 63 个，保留兄弟流并打开替代流”内存测试先复现 connection aborted：逻辑 lease 已释放而第三方库尚未处理 reset，直接 open 触发库内整连接关闭。只在 VCore 池中增加每物理连接累计 64 次 admission 后退役；旧流继续，新流使用新连接。回归通过，未修改 yamux 源码；该行为是公开资源边界，不是全节点业务额度。smux 另增加畸形版本/命令/控制帧长度不等待 body 的有界关闭检查。

资源登记表新增 20 个实际生产常量，包括请求预算、H1 body 队列、H3 窗口和 mux 边界。统一验收独立重读结构化事件、源树/lock、官方对端身份、容器清理、字段 owner 和 120 轮自有资源检查；部分选择不能通过完整 coverage。以上仍不代表 414 个 required case 已通过。

`n5-vms33wus` 的本地门禁在共享 H2 reset 回归处停止：adapter 已把 h2::Error 转成 io::Error，上层再次包装导致原始 CANCEL 不能直接识别，而非正常 EOF。移除冗余包装后，完整 END_STREAM 后 reset 和未结束前 reset 的两条原断言均通过；原测试与第三方未修改。首次运行的 Apple/Android 构建通过不抵扣修复后的重新验收。新增三 wire × H1/H2/H3 的 padding-required 负例，正式集合扩充为 414 组。

`n5-li8fzga5` / `n5-9uvkx_kx` 的 H1 组选择夹具在首条业务流触发 Mihomo 的 `reject loopback connection`：SOCKS 首跳和最终 VLESS listener 被放进同一进程，自我连接的来源被原生保护拒绝。改成独立首跳容器，不关闭保护、不改第三方。另明确 H1 活动下载 GET 不可承载新逻辑会话：旧流保留旧路径，新 GET 必须服从新组选择；H2/H3/mux 可继续复用物理连接。`n5-6ssciooo` 的六种连接池选择和 H2/H3 三 wire padding-required 拒绝共 12/12 PASS，source_unchanged/cleanup 为 true。H1 三 wire padding 拒绝已在前两次运行中通过，但不拼接成完整签收。

默认 30ms packet-up pacing 会让同一 runtime 的 IP-only UDP 阶段超过 DNS 夹具的旧 30 秒空闲期。补充离线回归先复现空闲一次即提前退出，再改成 DNS 以控制连接存活为生命周期、最多 240 秒，控制连接关闭立即回收；数据报回包和 VCore 建链期限没有放宽。该夹具回归及全部 128 项离线测试通过，完整 N5 仍须重新执行。

`n5-acceptance-20260924-v1` 的七个本地门禁通过，原生运行中主动中断以补齐 D14 的下载腿错误 REALITY 公钥负例；12 个原生用例通过但不签收整轮。原报告保留 INTERRUPTED、顶层 cleanup=false，native 报告 cleanup=true/source_unchanged=true；退出后自有进程与容器均已清理，不追改原状态。冻结清单检查先因缺失负例失败，再加入格式合法但不匹配的公钥；`n5-reality-download-key-20260924-v1` 的 H1/H2 两个负例均 PASS、原站零连接、源码不变且清理成功。正式集合扩充为 416 组，重新完整运行。

`n5-acceptance-20260924-v2` 的七个本地门禁和 16 个原生用例通过，第 17 项 H1 默认 packet-up 公共 BASE 在 TCP 首个大流量阶段读超时失败（约 79.7 秒）。运行源码不变，native cleanup=true；顶层 cleanup=false 原样保留，所属容器均已退出。没有调低默认 30ms 或增加十秒业务读超时来通过。

源码对照确认：Mihomo `PacketUpWriter.Write` 在计时窗口内聚合多次写入，而原 VCore 实现每次小块 write 都独立等待一次 POST/间隔。新内存回归先稳定失败，再新增节点所有的有界聚合驱动：一批待发、一批在途，每批最多 64 KiB 且不超过每逻辑连接采样的 POST 上限；小块 write 只确认有界接收，flush 确认实际 POST，取消不会重复确认或重放。另一个关闭回归先发现等待普通定时器，再实现 shutdown 立即尝试 flush，保留卡住 POST 的一秒关闭上限。13 项请求检查、9 项复用检查、18 项旧 XHTTP 检查和资源登记通过；公开测试里原本假定“write 完成即收到 POST 响应”的断言改为显式 flush，数据与序号要求不变。原生复验和全部阶段门禁仍待完成。

聚合修复后的 `n5-packet-batching-20260924-v1`：H1/H2/H3 默认 packet-up 的 BASE 与同模式 Mihomo CLOSE 共 6/6 PASS。H1 的三类目标双向各 10 MiB 分别约 5.68/5.64/5.64 秒；每种 HTTP 版本均完成三种 UDP 编码、每编码三类目标五档大小各 100 包，默认 30ms 和原测试期限未变。source_unchanged/cleanup 均 true。随后开始 `n5-acceptance-20260924-v3` 的完整 416 组，定向六项不抵扣新整轮。

`n5-acceptance-20260924-v3` 的七个本地门禁通过，H1 packet-up 独立下载/复用的公共生命周期在第三轮（握手中 Stop）失败：静默检查读到额外原站事件。定向 `n5-split-handshake-red-20260924-v1` 稳定重现，明确读到 `A,D`（接受、关闭）。夹具把并发上传/下载握手送往同一个串行 TCP 黑洞，第二个已排队连接只能在第一个关闭之后被报告；原测试却只等待一组事件。

修订公共生命周期夹具：显式独立下载的两腿各自使用容器内黑洞和观察连接，Stop 前必须分别确认两条握手已在途，Stop 后逐条确认关闭，再立即核对描述符并检查五秒静默。没有忽略多余事件、追加回收宽限或修改生产行为；H3 两腿也独立确认开始。原 v3 和定向红色运行保留 FAIL；六种代表拓扑的复验使用新目录。

`n5-split-handshake-green-20260924-v1`：六个代表拓扑的公共生命周期全部 PASS，共 120 轮；每条显式握手在 Stop 前独立确认。source_unchanged/cleanup 均 true，结束后容器列表为空。仅此定向结果不签收 N5；补全文档后冻结输入，在 `n5-acceptance-20260924-v4` 重新执行全部 416 组门禁。

`n5-acceptance-20260924-v4` 在七个本地门禁和 92 个原生用例通过后停止。H1 + REALITY 默认 packet-up 的官方 Mihomo 关闭参照无法读到服务端首包；该项 VCore case 尚未启动。原报告保留 FAIL、native cleanup/source_unchanged=true、顶层 cleanup=false，所属容器已全部清理。

定向 `n5-reality-close-red-20260924-v1` 稳定重现。补齐失败时的有界对照/服务端日志后，官方 Mihomo 明确报错 `REALITY is based on uTLS, please set a client-fingerprint`。原因是自有对照配置漏了 Mihomo 必需字段，不是 VCore 数据错误，也不归为 Mihomo 实现缺陷。只对官方 REALITY 对照节点补 `client-fingerprint: chrome`（与已有 N4 对照做法相同），不将该字段加入 VCore、不修改第三方。`n5-close-all-20260924-v1` 重新验证全部 35 个关闭参照，之后须再次完整运行。

`n5-close-all-20260924-v1`：35/35 CLOSE 全部 PASS，包括 H1/H2 明文、TLS、经典 REALITY 及 H3 标准 TLS 的三个模式和两个独立下载分支。官方 Mihomo 对照与 VCore 均在相同 HTTP 版本/模式下检查整连接关闭；source_unchanged/cleanup 均 true，所属容器全部清理。随后在冻结的新输入上启动 `n5-acceptance-20260924-v5`，不复用 v4 的本地或原生 PASS 作为本轮签收结果。

2026-09-25：`n5-acceptance-20260924-v5` 在七个本地门禁、242 个原生用例通过后，H3 Cookie 元数据 / DELETE 上传请求返回 HTTP 404。运行时间 2026-09-24 15:04:29–17:07:29 UTC；source_unchanged=true，native cleanup=true、387 个所属容器均回收，顶层 cleanup=false 保留。`n5-h3-cookie-red-20260925-v1` 单用例稳定重现。分别换成 POST 或 Header 的两个控制组仍然 404；第三个路径控制被夹具固定 `/n5` 覆盖，不能作为显式尾斜杠失败的证据。

原因是原生路径规范化差异：[Mihomo 固定研究实现](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/xhttp/config.go)仅在 session/sequence 至少一个位于 path 时补尾斜杠，[Xray 26.3.27](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/splithttp/config.go)则始终补尾斜杠。VCore 已遵循 Mihomo，不能为夹具改变产品行为。只将 H3/Xray 夹具的双端显式路径设为 `/n5/`；`n5-h3-cookie-green-20260925-v1` 原失败用例 PASS，三类目标双向各 10 MiB 和原站关闭均通过。没有修改第三方或删除该字段组合。

后续完整运行固定先执行 H3 与其他外层传输，再执行 Mihomo 主矩阵，以提前暴露原生补充路径的问题；416 个 required case、57 个字段、断言和清理标准不变。历史或定向结果仍不用于拼接签收。

### 最终完整运行：N5 PASS

`n5-acceptance-20260925-v6` 于北京时间 2026-09-25 01:14:32–04:30:45 完整执行：七个本地门禁、406 个原生/公开路径和三个安全组全部通过，共 416/416 组、57/57 个适用字段。安全组内部 112/112（H1 38、H2 38、H3 36），H3 的 21 项客户端身份拒绝另有原生 TLS alert 证明。相对、绝对 run-dir 的独立 coverage 分别退出 0，不使用本节历史结果抵扣。

46 个命令均退出 0，原生 759 个与安全 10 个所属容器共 769/769 全部回收；顶层及两个子报告 `cleanup=true`、`source_unchanged=true`，结束后容器列表为空。六个代表拓扑各 20 轮 LIFE 与 20 轮 OWNED，共 240 轮；Stop 返回即空闲，随后至少五秒静默。Debug/Release、既有协议与公共基础回归、生产 feature、脚本、Clippy/依赖审计及 Apple 五目标/Android 两 ABI 构建通过。

源码树 SHA-256 `a3a7e23e3ab6665f730b0ebee94a823cd5edd03acd0c629e70d62a12b3aad5a0`，Cargo.lock SHA-256 `85b0a9211b771e528129b93479dab677e6300e772ae3bbb911a6b185850782fa`。最终文档定稿不改变被测源码、测试或脚本；完整环境、产物摘要、资源峰值和互通范围见 [N5 报告](N5.md)。新 sing-mux 的非 XHTTP 互通覆盖 17 类外层、102 组，不包含 HTTPUpgrade/fast-open + 新 sing-mux 的专项组合；不继承 N4 普通 VLESS 结果。N7、N9/N10、Windows 原生、真机、远端 CI 与发布仍未签收；不进入 N6。
