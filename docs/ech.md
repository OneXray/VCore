# VLESS 静态 ECH

配置修订 27 增加 VLESS 主连接及 XHTTP 独立下载连接的静态 ECH；Invoke API
保持 v5，不增加宿主 DNS 入口。ECH 只保护 TLS ClientHello 中的内层名称等信息，
不隐藏目标 IP、外层名称或流量形态，不等于无法识别的代理协议。

## 配置

```yaml
ech-opts:
  enable: true
  config: "<服务端提供的标准 Base64 ECHConfigList>"
```

- 仅标准 TLS，内层 `servername` 必须是 DNS 名，实际只协商 TLS 1.3。
  同腿不能与 REALITY、JLS 或 Vision 混用；可与 VLESS Encryption、证书策略、
  mTLS 和既有传输组合。命名指纹仍只用于 TCP TLS，H3 仍拒绝命名指纹。
- `enable` 默认 false。启用必须同时提供非空 `config`；不查询 HTTPS RR，
  不接收 `query-server-name`，没有公共 DNS 后备或自动更新配置。
- `config` 是标准带填充 Base64，不是 URL、文件路径或 PEM。解码后的完整
  ECHConfigList 最多 65,537 字节，仍受整份配置 256 KiB 上限限制。
- 支持 ECH 版本 `0xfe0d`、X25519/HKDF-SHA256，以及 AES-128-GCM、
  AES-256-GCM、ChaCha20-Poly1305。预检选取第一个双方后端均支持的条目，
  保留其原始编码；未知版本或不兼容条目可跳过，无兼容条目、畸形长度、非法
  public_name 或不支持的必需扩展在 IO 前失败。不能依赖 BoringSSL 静默忽略。
- `{}` / `{enable: false}` 清除 ECH。关闭时不允许携带非空 config，以免
  用户认为给出的隐私配置已经生效。null、未知字段、错型均拒绝；诊断不回显配置。

`xhttp-opts.download-settings.ech-opts` 缺省继承整个主腿对象；出现时整对象替换，
不逐字段合并，替换密钥须同时写 `enable: true`。显式 `{}` 可仅清除下载腿 ECH。
切换到 REALITY/JLS/明文必须显式清除继承的 ECH，以及其他冲突的证书身份。
两腿仍须汇聚到同一原生 XHTTP handler；各自独立建立和认证外层安全连接。

## 后端与失败边界

无指纹 TCP TLS 与 H3 使用官方 rustls + ring，通过公开 HPKE trait 接入官方
`hpke 0.14.1`；命名指纹使用锁定的自有 boring fork 既有 ECH 接口。本次不修改
第三方 TLS 实现，不恢复 rustls fork，也不扩展 Shadowsocks 的 AWS-LC 例外。

两后端都必须真正接受 ECH 才交出业务连接。rustls QUIC 的 ECH 拒绝作为原生
握手错误传播，H3 在握手完成前不发送 HTTP 请求；TCP 另检查 accepted 状态。
不把 GREASE 当真实 ECH，不自动采用 retry config，不重拨、不回放业务，也不
降级为未加密 ClientHello 的成功连接。错误或轮换后的旧密钥需要宿主更新配置。

静态 ECH 连接禁用 TLS 会话恢复和 0-RTT；XHTTP/gRPC 的已认证物理连接仍可在
原节点内复用。不同节点、主/下载腿、配置替换和后续运行实例不会共享 TLS 票据。
本层只包装调用方提供的 IO，不创建 resolver、socket、后台任务或全局缓存。

正常 ECH 接受后沿用内层证书名称、pin 和 mTLS 策略。拒绝分支不返回业务成功，
也不能发送客户端证书。boring 使用原生 outer-name override，按外层名称和默认
WebPKI 验证拒绝连接，不沿用内层 pin/skip。rustls 的公共 verifier 没有独立的
ECH-rejection 回调：沿用配置的证书策略后仍由原生状态机强制失败；不获取或使用
retry config。该拒绝证书路径不宣称与 Mihomo 完全相同，但不放宽业务成功门槛。

## 验证

纯内存真实 TLS 测试覆盖两个后端/四种命名模板、三种 HPKE AEAD、错误密钥、
拒绝、内外名称、mTLS 隐私和取消。网络服务端和原站只在隔离容器中：普通传输
优先官方 latest Mihomo；H3 使用官方 latest Xray，packetaddr/sing-mux 沿用
明确标注的 Xray XHTTP → Mihomo VLESS 分层拓扑。

原生 HTTP/H2/扩展 WS 的 ECH 对端采用 Xray TLS 网关 → V2Ray transport；
需要完整 UDP/Encryption 时继续由独立 Mihomo 解码 VLESS。Xray 网关使用官方
`XRAY_BUF_SPLICE=disable`，防止透明入口的下行 raw splice 绕过 TLS；不声称
V2Ray 直接支持 ECH，也不修改第三方。来源与原始失败见
[开发记录](acceptance/next-protocols/N7-progress.md)。

Mihomo v1.19.31 的 Safari + ECH 客户端在 gRPC 关闭对照中于握手报错；VCore
Safari + ECH 的服务端互通单独验证。该关闭参照明确使用官方 Chrome 与同一个
ECH listener，不改 VCore 的 Safari 节点，不宣称双方同指纹的差分通过。

[N7 本地阶段验收](acceptance/next-protocols/N7.md)在同一冻结输入下完成静态 ECH、
保留安全组合、共享回归与平台构建。精确组合、源码/对端身份和参照差异见该记录；
不把接口可用、单次握手或交叉编译当成任意组合或物理设备通过。
