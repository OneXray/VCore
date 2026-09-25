# VMess AEAD 出站

VMess 已完成 [N3 本地阶段验收](acceptance/next-protocols/N3.md)。默认、TUN 与标准发布 feature 均包含该出站；内部 schema 为 16，Invoke API 仍为 v5。容器互通与本地构建不代表真机或远端 CI 验收。

## 配置与认证

`type: vmess` 使用标准 UUID，`alterId` 省略或为 0。请求与响应头均使用 AEAD；没有旧式认证回退。`cipher` 接受 `auto`、`aes-128-gcm`、`chacha20-poly1305`、`none`，`zero` 归一为 `none`。`auto` 按实际 AES 硬件能力选择 AES-GCM 或 ChaCha，而不是仅按 CPU 架构名判断。`none` 只取消 body 加密，不能跳过响应身份认证。

`global-padding`、`authenticated-length` 默认 false，分别或同时开启；`none`/`zero` 不能将这两个开关设为 true。未知字段、显式 null、错误类型、非法枚举和不属于当前传输的选项均失败。

`network` 默认 `tcp`，还接受 `ws`、`grpc`、`http`、`h2`，均支持明文或标准 TLS。`tls` 默认 false；关闭 TLS 时不能配置 `servername`、`alpn`、`fingerprint`、`client-fingerprint`、`skip-cert-verify`，即使其值为空串、空列表或 false。启用 TLS 后 `client-fingerprint` 使用 [TLS 指纹](tls-client-fingerprint.md)的七值/四模板；省略、`none` 或空串关闭。

TLS 的认证名优先使用 `servername`，其次是 WebSocket Host（去端口），否则是 `server`。HTTP 伪装 Host 和 H2 authority 不替代认证名。证书策略沿用共享标准 TLS：默认 WebPKI 验证；SHA-256 pin 必须匹配，不能被 skip 绕过；匹配叶证书的 pin 与匹配链上 CA 的 pin 保留各自既有语义。WS 要求实际协商 `http/1.1`，gRPC/H2 要求 `h2`；明确 ALPN 列表保留顺序并包含所需协议。

## 传输

- `ws-opts`：绝对 `path`（默认 `/`）、字符串头映射、`max-early-data` 0–2048。ED 启用时头名默认 `Sec-WebSocket-Protocol`，可自定义，或设为空串将 ED 放入路径后缀；路径 ED 不接受 query。拒绝保留握手头、大小写重复头、非法 authority 和超限请求头。
- `grpc-opts.grpc-service-name` 必填；普通名映射 `/name/Tun`，以 `/` 开头时作为完整方法路径。没有连接池和额外调度器。
- `http-opts` 是 TCP HTTP 首包伪装，不是 HTTP 代理。`method` 默认 GET；`path` 为列表，缺省/空列表为 `/`，按 URL.Path 转义而非 query；`headers` 为字符串列表映射。每次物理握手分别选择路径和每个头的一个值，Host 默认物理 server authority。HTTP 头及一次 VMess 前缀之后恢复原始流，不对后续数据重复封装；禁止配置 Content-Length/Transfer-Encoding。
- `h2-opts.host` 是必填的非空 authority 列表，`path` 默认 `/`。每个流选一个 authority，以 HTTP/2 PUT body 双向传输；明文使用 prior knowledge，TLS 使用 h2 ALPN，没有 gRPC 消息封装。

关闭按 Mihomo 的实际包装链对齐：TCP/WS 可保留上传 EOF 后的下载；gRPC/HTTP/H2 上传 EOF 关闭整条逻辑流。正常响应应在关闭前读完，不能把全关闭路径当成通用半关闭流。Stop/取消始终覆盖全部底层 IO 和自有驱动。

## UDP 与预算

`udp` 默认 false，控制业务数据报；VMess 的外层仍是 TCP。`packet-encoding` 默认空串：

- raw：首个目标写入认证请求头。同一 transport 绑定该目标，后续不同目标明确拒绝，不能误投给首个目标。首包可延迟发送，但物理上游快照与最初建链截止时间不重置。
- `xudp`：共享 XUDP codec，每帧携带目标；零 global ID 不发送可选扩展。内部 `v1.mux.cool` 仅是协议标记，不经过 DNS。
- `packetaddr`：每包携带 IP 地址和端口；业务域名经 VCore 受控 DNS 解析，内部 `sp.packet-addr.v2fly.arpa` 不经过 DNS。无运行时 resolver 时不能悄悄使用系统 DNS。

完整 VMess UDP body 最多 15,000 字节，和调用方收发预算分别取交集。raw/XUDP 的本层业务上限为 15,000；packetaddr IPv4 扣 7 字节、IPv6 扣 19 字节，未解析域名保守按 19 字节扣减。发送最大值+1 在写入前拒绝，不拆成多个业务包、不截断。对端本身的缓冲还可能更小；V2Ray 的部分返回路径只有 2,048 字节总缓冲，不能把该测试边界误写成所有 VMess 服务端均支持 15,000。

取消半帧发送关闭该关联；取消增量读取保留已读帧状态；响应认证、非法地址、长度或标签失败关闭，不能继续使用损坏的流。各关联、来源与目标独立，不接受未经 SOCKS 控制连接授权的发送者。

## 所有权与资源

物理 socket 仅来自共享 Dialer；具体上游、嵌套 select、DIRECT/REJECT 使用原有图和一次建链快照，没有自动改选或 DIRECT 回落。TLS/传输/协议握手共享最初的绝对建链期限。支持 HTTP、SOCKS5、TUN 消费和独立 node-only `measureDelay`。

TCP 写分片固定最多 4 KiB，以兼容当前 Mihomo listener 的拷贝缓冲切换；UDP 不使用此分片策略。VMess body wire 有 16 KiB 解析上限，响应头和 XUDP 元数据各自有界。加密帧计数器为 16 位，耗尽前失败关闭，不重复 nonce；调用方需新建会话，不自动续接原业务流。

每个 gRPC/H2 driver 由节点 TaskTracker 跟踪。Stop 先撤销并 join 入站所有者，再同步退出协议驱动；成功返回不是开始后台清理。没有额外全局连接数上限、无界队列或历史会话表。协议实现、配置 Debug 与错误不包含 UUID、密钥、业务目标或完整请求。

互通入口使用官方 latest 的隔离容器。Mihomo 验证 TCP/WS/gRPC；其 listener 缺少的 HTTP/H2 与扩展 WS ED 由官方 V2Ray 补验。测试身份、失败历史与完整签收分别记录，不抵扣真实设备、远端 CI 或 N9 长测。
