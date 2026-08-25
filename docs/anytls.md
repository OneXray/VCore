# AnyTLS outbound

状态：当前 client outbound 契约。VCore 实现 AnyTLS wire、session、padding 与 UoT v2。

## 配置边界

AnyTLS 使用以下平铺字段：

```yaml
rules:
  - MATCH,anytls-edge
proxies:
  - name: anytls-edge
    type: anytls
    server: anytls.example.com
    port: 443
    password: "private-password"
    sni: origin.example.com
    udp: true
    # dialer-proxy: socks-hop
```

- `name`、`type`、`server`、`port`、`password` 必填；`type` 固定 `anytls`。
- `password` 是 1–1024 UTF-8 byte。它不会进入 `Debug`、tracing 或错误正文。
- `sni` 可选，省略时使用 `server`；两者都必须是当前 host validator 接受的 IP
  literal 或 domain。
- `udp` 省略时为 `false`；设为 `true` 后允许 AnyTLS UoT。
- `dialer-proxy` 与 VLESS/SOCKS5 使用同一有向无环 graph 语义。
- 未列字段全部拒绝。首版没有可配置 TLS/REALITY、ALPN、fingerprint、
  `skip-cert-verify`、ECH、mTLS certificate/private-key、padding、session
  check/timeout/min-idle、reuse 开关或连接池容量。

## TLS 与认证

AnyTLS 只消费 VCore 的标准 TLS carrier：

- 支持 TLS 1.3 与 TLS 1.2；
- 使用 WebPKI root、配置归一化后的 SNI 和完整证书校验；
- 不发送 ALPN；
- 不支持 REALITY、伪造 fingerprint、证书跳过、ECH 或客户端证书。

连接建立后，client 先写 SHA-256 password hash、认证 padding，再发送第一个
session batch。配置、日志和诊断不输出 password 或 hash。

## v2 与 v1 fallback

client 的首个 Settings 固定声明 `v=2`，并携带自身版本和当前 padding MD5。
server 的 `ServerSettings` 若返回合法 `v>=2`，该 session 按 v2 工作；更高版本在
当前能力上限处按 v2 处理。未收到 `ServerSettings` 时保留 peer version 1，按
v1-compatible 行为继续，不要求显式协商。

首个 stream 随认证 batch 一次发送。复用 idle session 时：

- v2 session 写出 `SYN` 与目标后立即向调用方返回可用 stream，同时在 client
  `TaskTracker` 中启动最长 3 秒的 `SYNACK` watchdog；open 不能同步等待
  `SYNACK`，因为服务端可能要先读取 stream 上的协议数据（例如 UoT request）才
  能完成出站并回复；
- v1-compatible session 不启动 `SYNACK` watchdog；
- 非空 `SYNACK` payload 表示远端拒绝：整个 session 失败且不会回到 idle pool，
  已返回的 stream 通过后续 I/O 或 session 关闭暴露错误；API 不承诺当前 open
  同步返回 `ConnectionRefused`，也不会在后台为该 stream 静默重拨；
- watchdog timeout、writer/reader 关闭或其他 protocol failure 同样销毁整个
  session。只有 open 返回之前发生的 stale idle write/setup failure，才允许当前
  open 丢弃旧 session 后建立一次 fresh TLS/AnyTLS session；open 返回后的失败只
  能由后续独立 open 建立 fresh session。

未知 stream、错误 control-stream ID、服务端发送 client-only frame、越界 payload
或不合法 ServerSettings 都是 session 级协议错误。远端诊断最多保留 256 bytes。

## TCP session 与复用

普通 TCP 请求在 AnyTLS session 上创建 stream。当前复用策略有意保持简单：

- 每个物理 session 同时只允许一个 active stream；
- stream 完整结束后 session 才进入 idle；
- 新请求在全部 idle session 中优先选择 sequence 最大的 session；归还 idle
  的先后顺序不改变这一选择；
- idle cleanup 与 timeout 固定为 30 秒，`min-idle-session` 固定为 0；
- active session 数不设业务级固定上限；没有预热或后台补足 idle 数；
- stream ID 或 session sequence 耗尽、active 状态不一致、未完成 FIN 即 drop 等
  情况会 fail-closed 并销毁 session。

writer command channel 固定为 2；每 stream 的 incoming channel 从 runtime
buffer capacity 推导且至少为 1。frame payload、padding scheme、队列、stream
chunk 和诊断字符串都有独立上限，但这些边界不开放成 YAML session knobs。

## UDP over TCP

`udp: true` 时，AnyTLS 使用 UoT v2：

```text
sp.v2.udp-over-tcp.arpa:0
```

固定使用 datagram mode。首包携带 UoT request 和第一份 datagram；后续每包自行
编码 IPv4、IPv6 或 domain 目标，因此同一 association 可以发送到不同目标。每个
payload 最多 65535 bytes，并继续受调用方提供的 response payload ceiling 约束。
response channel 固定为 1；close/cancel 会停止 reader task 并关闭 stream，drop
也会取消和 abort 尚未收敛的 reader。

## Padding

client 内置固定默认 padding scheme，不提供 YAML 配置。每次新建 session 时取得
一次不可变 snapshot；server 的合法 `UpdatePaddingScheme` 通过 per-client 原子
替换只影响之后创建的 session，不能改变当前 session 的 frame 边界。无效更新仅
记录有界 warning 并忽略，不破坏正在运行的 session。

padding 文本、packet item 数、stop 值、单包逻辑 padding 与 frame payload 均有
固定上限。认证 padding 与后续 packet padding 都使用该 session 的同一 snapshot。

## 生命周期与清理

每个 runtime proxy graph 为 AnyTLS 节点创建共享 client 和显式 lifecycle handle：

```text
prepare graph
  -> start
  -> open TCP/UoT streams as needed
  -> begin_shutdown
  -> shutdown().await
  -> release graph
```

`begin_shutdown` 是同步第一阶段屏障：标记 client closed、清空 idle 列表、取消
client token、对所有 session 发起关闭并拒绝新 stream。`shutdown` 会再次幂等执行
第一阶段，然后等待 `TaskTracker` 中的 idle cleanup、session reader/writer 与 UoT
后台任务全部结束。runtime stop、prepare rollback、measurement worker release 和
失败清理都必须走同一生命周期，不能只 drop graph 或依赖进程退出。

AnyTLS session、idle pool、padding 和 UoT 状态都属于持有它的 runtime/measurement
worker；不同 runtime 不共享。`measureDelay` 返回前必须完成私有 graph 的 AnyTLS
shutdown，不进入公共实例表。

## 验证边界

本仓库使用 duplex mock 覆盖 frame、v2/v1 协商、复用、watchdog、padding、UoT、取消和显式 shutdown。opt-in 互操作 harness 覆盖 TCP 首流/复用、UoT v2 UDP echo、UoT 后再次 TCP、单物理 session 计数与清理。

测试 connector 可以接受测试运行时生成的自签名证书；生产 WebPKI 路径和 release library 不共享该例外。公网服务互操作仍需在发布矩阵中单独登记。
