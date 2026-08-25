# REALITY V1 客户端协议基线

状态：实现基线。本文冻结 VCore 自有 rustls fork 当前实现的 classic REALITY V1 客户端行为；它不是通用 REALITY 或 ClientHello 模拟规范。

## 1. 版本与变更规则

当前 fork 基于 rustls 0.23 系列，并由 release dependency 固定到不可变 revision。REALITY wire 行为由本文和 fork 内确定性测试向量共同冻结。

升级 rustls base、crypto provider 或任一 wire 行为时，必须重新生成向量并执行普通 TLS、REALITY、并发、平台构建和 iOS 内存验收；协议升级不得与无关重构混在同一变更中。

## 2. V1 支持边界

V1 只支持：

- 客户端模式；
- TLS 1.3；
- X25519；
- classic Ed25519 临时证书认证；
- 0–8 字节 short ID，在线上补零为 8 字节；
- ring 作为唯一 rustls crypto provider。

本节的 REALITY V1 outbound 握手本身不支持 REALITY 服务端、TLS 1.2、QUIC transport、
ECH、HelloRetryRequest、session resumption、0-RTT、X25519MLKEM768、ML-DSA-65、
浏览器 ClientHello 模拟或 `fp`。这不限制 TUN sniffer 对 QUIC v1/v2 Initial 的解析；
两者是不同层。收到 HRR 时明确失败；REALITY 不可用时也不得降级到普通 WebPKI。

## 3. ClientHello 认证

每个 `ClientConnection` 独占一份 X25519 临时私钥。该私钥同时用于：

1. TLS 1.3 ClientHello 的 X25519 key share；
2. 与配置中的 REALITY 服务端静态 X25519 公钥执行 ECDH。

不允许为这两个用途生成不同私钥，也不允许把原始私钥暴露给 VCore。

ClientHello 的 legacy session ID 固定为 32 字节。密文生成前先将该字段全部置零，并编码完整的 TLS Handshake `ClientHello`（包含 1 字节 handshake type 和 3 字节长度）作为 AES-GCM AAD。

ClientHello 的 `signature_algorithms` 必须公布当前 crypto provider 的完整支持列表，至少覆盖 ECDSA、RSA 和 Ed25519；不能因为 REALITY 临时证书使用 Ed25519，就把 ClientHello 能力列表收窄为 Ed25519。该列表只用于握手能力协商，使采用 ECDSA/RSA 证书的真实伪装站能够先返回 ServerHello，不会放宽第 4 节的 REALITY 身份认证规则。

明文前 16 字节为：

```text
offset  size  value
0       3     client version（VCore 当前为 26.7.11）
3       1     0，保留字节
4       4     Unix seconds，uint32 big-endian
8       8     short ID，右侧补零
```

密钥派生和封装：

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

输出恰为 16 字节 ciphertext 加 16 字节 GCM tag。低阶点、全零 shared secret、时钟读取失败、重复 seal 或连接状态缺失均立即失败。

## 4. 服务端证书认证

服务端必须只发送一张 DER X.509 证书。解析器有 16 KiB 输入上限，只接受 canonical definite-length DER、RFC 5280 字段顺序、无参数的 Ed25519 AlgorithmIdentifier、32 字节对齐 SPKI BIT STRING 和 64 字节对齐外层 signature BIT STRING。

验证顺序：

1. 从 DER 结构读取 Ed25519 公钥和外层 `signatureValue`，不使用固定尾部偏移。
2. 常数时间比较 `signatureValue` 与 `HMAC-SHA512(auth_key, ed25519_public_key)`。
3. 只把通过 HMAC 的同一 Ed25519 公钥绑定到该连接。
4. 使用该公钥验证标准 TLS 1.3 server `CertificateVerify`，且 signature scheme 必须是 Ed25519。
5. 成功或失败后立即消费认证状态；第二次使用必须失败。

真实伪装站点证书、intermediate、错误 HMAC、错误 SPKI/DER、错误 `CertificateVerify` 或缺失连接级状态全部 fail closed。VCore 不提供 WebPKI 或 spider fallback。

## 5. 状态、并发与资源

共享 `Arc<ClientConfig>` 只保存公开、不可变的服务端公钥、short ID 和 client version。临时私钥、ECDH secret、`auth_key` 与已认证公钥只存在于单个 `ClientConnection`；不使用全局状态、mutex slot 或跨连接 map。

连接取消、失败或 drop 会释放并清零临时私钥、shared secret 和 `auth_key`。解析器固定深度、零 allocation，不依据对端长度创建容器；fork 不创建线程、异步任务、连接池或队列。

这些约束控制了 rustls 新增状态的上界，但不等于 iOS 内存已经验收。Release iOS
真机仍需对 TUN fd 生命周期所在的整个进程保存外部 footprint trace；35 MiB cold-start
current 与 45 MiB representative-workload peak 只作优化目标，越线不改变 VPN 生命周期结果。

## 6. 固定向量与验证入口

rustls 单元测试固定以下独立向量：

- RFC 7748 X25519 private/public/shared-secret；
- zero-session-id ClientHello AAD、HKDF auth key 和 32 字节 REALITY session ID；
- Ed25519 SPKI、证书 HMAC、TLS 1.3 CertificateVerify message/signature；
- 截断/非 canonical DER、错误 HMAC、错误签名、缺失状态、低阶公钥与 HRR 负例。

实际字节保存在相邻 rustls fork 的 `rustls/src/client/reality.rs` 测试中；HRR 线级负例和两份配置交叉运行的 100 路并发 ClientHello 位于 `rustls/src/client/test.rs`。VCore 的 opt-in 互操作 harness 覆盖 TLS/REALITY × `packet-up`/`stream-one`、共享 connector 并发、取消重连、错误 key/short ID、单公共 lifecycle 和 API v5 的最多五路 `measureDelay`。

REALITY 数据面还必须以本地 ECDSA P-256 TLS 站点作为 cover target，证明 ClientHello 公布完整 signature schemes，同时不会把 cover certificate 当作 REALITY 身份接受。实际执行状态以 [验收](acceptance.md) 为准。
