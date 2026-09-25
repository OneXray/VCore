# Trojan 出站

Trojan 是固定 TLS 的 TCP/UDP 出站，支持 `tcp`、标准 WebSocket 和普通 gRPC。默认、TUN 和发布构建包含 `outbound-trojan`；也可独立启用该 feature，不会隐式启用 VLESS 或 TUN。Trojan 自 schema 15 开放；当前配置修订见 `config.yaml`，Invoke API 仍为 v5。

## 配置

```yaml
socks-port: 1080
proxies:
  - name: edge
    type: trojan
    server: proxy.example.com
    port: 443
    password: "replace-me"
    udp: true
    sni: proxy.example.com
    network: tcp
rules:
  - MATCH,edge
```

`name/server/port/password` 必填。密码为非空原始 UTF-8 字符串，不 trim；认证使用其 SHA-224 小写十六进制摘要。`udp` 默认 false，`network` 默认 tcp。严格类型、null、未知字段及不属于所选传输的参数在建网前拒绝；字段全集以 [config.yaml](config.yaml) 为准。

WebSocket 使用 `network: ws` 和可选 `ws-opts`：

```yaml
ws-opts:
  path: /edge?version=1
  headers:
    Host: cover.example.com
    X-Client: example
  max-early-data: 2048
  early-data-header-name: Sec-WebSocket-Protocol
```

路径默认 `/`，必须是绝对路径，可带 query；headers 默认空，只接受合法 HTTP 字段，不得覆盖握手保留头，大小写重复也拒绝。Host 只覆盖 HTTP authority，**不会作为 SNI 回退值**。early-data 上限 0–2048 原始字节，默认 0（禁用）；启用时缺省头为 `Sec-WebSocket-Protocol`，可指定合法自定义头，空串表示路径后缀（此时禁止 query）。禁用时附带 early-data-header-name 也拒绝。首个 Trojan 请求头经 ED 与剩余流按序发送一次，不重放、不重复发送。

gRPC 使用 `network: grpc`，必须配置非空 `grpc-opts.grpc-service-name`：普通名 `edge` 映射 `/edge/Tun`，`/edge/Tun` 这样的 `/` 开头值作为完整路径。不开放 multi-mode 或连接池调度字段。

## TLS、图与路由

- SNI 默认 server，可显式给域名或 IP 认证名。
- ALPN 保持配置顺序；TCP 默认空，WS 默认 `[http/1.1]`，gRPC 默认 `[h2]`。显式列表必须包含所需协议，实际协商也必须匹配，不能静默降级。
- `skip-cert-verify` 默认 false；`fingerprint` 为叶或非叶证书 DER SHA-256（64 hex，可带冒号）。叶 pin 本身作为信任依据；非叶 pin 作为信任锚，仍验证叶链、名称和有效期。pin 不匹配时 skip 不得绕过；TLS 握手签名始终验证。与 [AnyTLS](anytls.md) 共用已有策略及总计 4 个恢复会话预算，不跨节点复用。
- `client-fingerprint` 可为 `chrome120` 或空串，省略时关闭；TCP/WS/gRPC 仍各自拥有 ALPN 策略，见 [TLS 指纹](tls-client-fingerprint.md)。
- `dialer-proxy` 可引用具体节点或静态 select 组。与业务路由共享选择，建链使用一次组快照和同一绝对期限；切组不迁移已有 TCP/UDP，不自动 failover 或回退 DIRECT。
- 所有物理 socket 由 Dialer 创建，沿用 protect/物理绑定；Trojan 不直接解析经上游发送的业务域名或代理服务器名。
- HTTP、SOCKS5、TUN、DNS nameserver 选路和独立 node-only `measureDelay` 使用同一连接器。

Trojan 没有服务端认证 ACK。TCP CONNECT 或本地建链成功不等于远端已确认密码；错误密码随后关闭连接。负例验收检查受控源站零业务字节。

## 数据与回收

TCP 保留半关闭：上传 EOF 后仍能读取下行。gRPC 的 Trojan duplex 模式发送 END_STREAM 而不是 RST_STREAM；旧 gRPC/legacy H2 adapter 与 XHTTP 的整体关闭契约不变。

UDP 在每个独立的已认证流上使用原生 Trojan 地址/长度/CRLF 帧，不引入额外 UDP socket。单 payload 最大 8192 字节，并与调用方双向预算取交集；累计待解析数据最多 8455 字节（最大地址头 + 长度/CRLF + payload），动态缓冲的分配容量另受容器增长策略影响。超长发送在写入前失败；非法地址/长度/帧尾或截断关闭流。合法帧超过调用方接收预算时完整丢弃该包，不能截断后交付。取消 receive 保留已读部分；取消部分 send 后该关联不可重放或继续发送。

每个流/关联拥有取消令牌；运行时先取消并 join 入站所有者，释放其流和关联，再等待节点拥有的 gRPC 驱动退出。没有后台 UDP 读取泵、全局会话准入、历史连接列表或额外连接池。资源与平台约定见 [运行时资源策略](runtime-resource-policy.md)。

验收入口：`vcore-scripts check protocol-interop --stage N2`。Mihomo listener 是默认对端；它的域名 UDP 服务端缺口单独由 Xray 补验，扩展 WS ED 由 V2Ray 补验，历史失败与原生缓冲限制保持可见。完整范围与输入身份见 [N2 汇总](acceptance/next-protocols/N2.md)，分阶段证据见 [N2.1](acceptance/next-protocols/N2-codec.md)、[N2.2](acceptance/next-protocols/N2-tcp.md)、[N2.3](acceptance/next-protocols/N2-transports.md)。主机互通不代表真机或发布验收。
