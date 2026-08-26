# REALITY V1 客户端协议

本文定义 VCore 自有 rustls fork 当前实现的 classic REALITY V1 客户端线上行为。它不是通用 REALITY 规范，也不承诺浏览器 ClientHello 模拟。

## 版本边界

当前实现基于 rustls 0.23 系列。线上行为由本文和 fork 内的确定性测试向量共同约束。升级 rustls、加密提供方或任一握手字节时，必须重新验证普通 TLS、REALITY、并发、取消和目标平台构建。

V1 只支持：

- 客户端模式；
- TLS 1.3；
- X25519；
- classic Ed25519 临时证书认证；
- 0–8 字节 short ID，在线上右侧补零到 8 字节；
- `ring` 加密提供方。

不支持 REALITY 服务端、TLS 1.2、QUIC 传输、ECH、HelloRetryRequest、会话恢复、0-RTT、混合后量子密钥交换、浏览器指纹或 `fp`。收到 HRR 或 REALITY 认证失败时立即终止，不降级为普通 WebPKI。

## ClientHello 认证

每个 `ClientConnection` 独占一份 X25519 临时私钥，同时用于：

1. TLS 1.3 ClientHello 的 X25519 key share；
2. 与配置中的服务端静态 X25519 公钥执行 ECDH。

VCore 不能读取该私钥，也不能为两个用途生成不同密钥。

ClientHello 的 legacy session ID 固定为 32 字节。生成密文前先把该字段清零，再编码完整 TLS Handshake `ClientHello`，将其作为 AES-GCM 的 AAD。

`signature_algorithms` 必须公布当前加密提供方完整支持的 ECDSA、RSA 和 Ed25519 算法。REALITY 使用 Ed25519 临时证书不意味着 ClientHello 只能声明 Ed25519；完整列表用于让采用 ECDSA/RSA 证书的伪装站点正常进入握手，不会放宽后续 REALITY 身份校验。

session ID 明文前 16 字节为：

```text
offset  size  value
0       3     客户端版本，当前为 26.7.11
3       1     保留字节 0
4       4     Unix 秒，uint32 大端序
8       8     short ID，右侧补零
```

密钥派生：

```text
auth_secret = X25519(client_ephemeral_private, server_static_public)
auth_key    = HKDF-SHA256(auth_secret,
                          salt=client_random[0..20],
                          info="REALITY",
                          length=32)
nonce       = client_random[20..32]
session_id  = AES-256-GCM-Seal(auth_key, nonce,
                               plaintext[0..16],
                               aad=zero-session-id ClientHello)
```

输出为 16 字节密文和 16 字节 GCM tag。低阶点、全零共享密钥、时钟失败、重复封装或缺少连接状态都会使握手失败。

## 服务端证书认证

服务端必须只发送一张 DER X.509 证书。解析输入上限为 16 KiB，只接受规范的 definite-length DER、RFC 5280 字段顺序、无参数 Ed25519 `AlgorithmIdentifier`、32 字节 SPKI 公钥和 64 字节外层签名。

验证顺序：

1. 从 DER 结构读取 Ed25519 公钥和外层 `signatureValue`；
2. 常数时间比较 `signatureValue` 与 `HMAC-SHA512(auth_key, ed25519_public_key)`；
3. 把通过 HMAC 的同一公钥绑定到当前连接；
4. 使用该公钥验证 TLS 1.3 `CertificateVerify`，签名算法必须为 Ed25519；
5. 无论成功或失败都立即消费认证状态，禁止再次使用。

真实站点证书、中间证书、错误 HMAC、错误 DER/SPKI、错误 `CertificateVerify` 和缺失状态全部失败。VCore 不提供 WebPKI 或 spider fallback。

## 状态与资源

共享 `Arc<ClientConfig>` 只保存不可变的服务端公钥、short ID 和客户端版本。临时私钥、ECDH 结果、`auth_key` 和已认证公钥只存在于单个连接中，不使用全局表、跨连接锁或共享认证槽位。

连接取消、失败或释放时清零临时私钥、共享密钥和 `auth_key`。证书解析深度和输入大小固定，不依据对端长度创建无界容器。fork 不创建线程、异步任务、连接池或队列。

## 固定向量

rustls fork 的测试固定：

- RFC 7748 X25519 私钥、公钥和共享密钥；
- 清零 session ID 的 ClientHello AAD、HKDF 结果和 32 字节 REALITY session ID；
- Ed25519 SPKI、证书 HMAC 和 TLS 1.3 `CertificateVerify`；
- 截断或非规范 DER、错误 HMAC、错误签名、缺失状态、低阶公钥和 HRR 负例；
- 多配置并发和连接状态隔离。

VCore 的互操作测试还覆盖 XHTTP 模式、取消重连、错误 key/short ID 和普通 TLS 回归。实际执行范围见 [验收矩阵](acceptance.md)，依赖发布要求见 [rustls REALITY 依赖](rustls-reality-release.md)。
