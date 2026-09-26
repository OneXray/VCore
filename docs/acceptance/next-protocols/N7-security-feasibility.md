# N7：附加安全封装的当前接口复核

> 范围更新（2026-09-26）：仅 Restls 从 VCore 与自有 boring fork 撤回，JLS 保留；
> Restls 不再属于 N7 交付或验收门槛。下文为历史记录，不代表当前支持；
> Restls 的旧命令不适用于 schema26。

日期：2026-09-26。基线：VCore `def0e19`，官方 rustls `0.23.45` / tokio-rustls `0.26.5`，自有 boring `67581195fd6388a8bfd42c4e39e945f73c99a2b2`。这是 **N0-E / N7.4 的源码可行性研究，不是互通验收**；没有运行原生服务端、原站、下载腿、平台构建或 VCore 新协议数据面。旧 [N0-security](N0-security.md) 的接口缺口不能直接推广为当前所有方案不可能。

## 结论

后续授权更新：用户已允许在自有 boring 的独立分支为 ShadowTLS v3、Restls、JLS
按协议最小扩展原生握手认证接口，保留完整认证，不恢复旧 rustls fork、不新增自制
TLS 引擎。以下仍是原基线的接口研究；新授权不使未实现、未验证项变成 PASS。

| 范围 | 当前公开接口 / 复用路线 | 本次结论 |
| --- | --- | --- |
| ShadowTLS v1/v2，S07–S08 / D20–D21 的对应版本 | 完成普通 cover TLS 后取回受控流；v1 使用 TLS1.2，v2 增加握手入站哈希与记录封装 | 没有发现与 v3 相同的 ClientHello 改写前提；可以独立验证。原生互通 **NOT RUN**，不计 N0-E PASS |
| ShadowTLS v3 | Clash-RS 需要其 tokio-rustls fork 的 session-ID generator；当前 boring 的 REALITY API 不是通用 generator | 直接移植路线有明确接口缺口。Meow / shoes 的外部改写路线不能作为相同 TLS 认证行为的证明；严格对齐方案仍未证明 |
| Restls tls12/tls13 + script，S09–S11 / D22–D24 | 原生实现把认证接入 key-share / eager ECDHE、session ID、记录密码切换；Meow 自行实现 TLS 握手与记录层 | 没有找到可直接接到当前 TLS connector 的薄公开 Adapter。自有协议/TLS 实现并非逻辑上不可能，但不属于已经验证的复用能力 |
| JLS，S12–S13 / D25–D26 | 需要按完整 ClientHello 生成 random，验证原始 ServerHello 的认证信息并保持 TLS transcript 一致；Meow 使用自有 TLS1.3 driver | 当前普通 verifier、只读 message callback 和固定 REALITY API 不等价；另一条自有实现路线存在，但尚未验证或批准为新增 TLS 后端 |

**这里的接口缺口只限定当前锁定依赖和直接复用路线，不断言 Rust 无法实现这些协议。** N7.4 及下载腿验收继续保持未签收。若要新增 native TLS hook、扩大自有 boring fork 的用途，或引入另一个自主 TLS 握手实现，应先明确该安全架构范围；不得以关闭验证、容忍未预期 TLS 失败或恢复已退役 rustls fork 代替决定。[当前 TLS 边界](../../tls-dependencies.md)

## 已核对的源码身份

| 来源 | 本地读取 revision | 本次远端核对 |
| --- | --- | --- |
| Clash-RS | `470bc5a427bfaea3fafcedf32563010f9a47b691` | `HEAD=39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`；本次比较的 ShadowTLS `mod.rs` 无差异 |
| shoes | `60ed3838b346268615c81e4eace4e15e717da23e` | 远端 HEAD 相同 |
| Meow | `53933f070ccaec6aeec5de159ebf6f0802d8c7ce` | 远端 HEAD 为 `59edf4e6abab427286113ef1498d85a8f0afe3c4`；通过 raw URL 下载到管道核对，ShadowTLS、Restls tls12/tls13、JLS tls13 四个实现文件 SHA-256 均与本地相同 |
| Mihomo | `ab405bad5beeeac8b003bb01f60f134f6df54471` | 远端 `Meta` 与 `v1.19.31` 均指向同一 revision；默认 HEAD 是另一个 `main`，不能用该分支文件缺失推断协议被删除 |
| 自有 boring | `67581195fd6388a8bfd42c4e39e945f73c99a2b2` | 使用生产锁定 revision 的本地公开 Rust API、BoringSSL header 与 feature patch；本次不升级、不修改 |

远端核对使用 `git ls-remote` 与固定 revision 的公开 raw 源码，不使用 GitHub API，没有更新参考仓库 checkout、修改第三方或运行它们的测试。研究引用不构成生产依赖选择或发布许可证结论。

## ShadowTLS：必须区分三个版本

Mihomo `DialContextConn` 的 v1/v2 均先等待 `TLSHandshake` 成功：v1 随后直接交还底层流，v2 使用握手入站哈希生成首条认证数据并继续记录封装。`NewShadowTLS` 把 v1 限制在 TLS1.2。v3 则传入 `generateSessionID`，也必须先让真实 TLS 握手成功，再检查 relay 的版本与认证结果。因此 v3 不能只以“见到合法 HMAC”抵扣所有 TLS 握手错误。[Mihomo 客户端][M-SHADOW]

Clash-RS v3 调用 `connect_with_session_id_generator`，generator 基于完整 ClientHello 替换 32 字节 session ID；其根清单 patch 到 Watfaq 的 rustls/tokio-rustls。这个方法不是 VCore 当前官方 tokio-rustls 的公开方法。流适配器、HMAC 状态与有界记录解析可作为架构参考，但直接复制调用会重新引入另一套 TLS fork。[Clash-RS 实现][C-SHADOW]、[依赖来源][C-DEPS]

Meow v3 明确采取不同路线：在 IO 层改写 ClientHello session ID，再把 ServerHello 的 echo 改回 BoringSSL 原值。其代码注释与错误分支均承认 transcript 分歧，预期握手失败后在已认证 HMAC 的条件下恢复底层流；TLS1.3 加密证书无法被当前 BoringSSL 实例验证。这个实现证明存在另一类协议驱动思路，**不证明已经严格等价于 Mihomo 的成功 TLS 握手路径**。不能把它当作 VCore 共享证书 pin / 验证名已经生效的证据。[Meow v3][MEOW-SHADOW]

shoes 同样外部改写 ClientHello；遇到首条带正确 HMAC 的 application-data record 后直接离开握手循环并构造 ShadowTlsStream，而不是先完成完整 TLS 认证。其路径还直接使用 AWS-LC HMAC，不能借此扩大 VCore 现有 provider 例外。本次没有运行 shoes 的原生互通，所以不对其实际部署结果作推断。[shoes 客户端][SHOES-SHADOW]

可独立继续的最小切片是 v1/v2：复用原 Dialer / 上游交付的 IO、完整共享 TLS 验证、单记录输入边界与原 setup deadline；原生对端测试必须在容器完成。v3 留在独立前置门禁，不因另外两个版本成功而开放。

## Restls：Meow 的方案不是普通 TLS 装饰器

Mihomo 调用 `restls-client-go`。该库 TLS1.3 的 session ID 认证覆盖 group、key-share 和 PSK identity；TLS1.2 则在 ClientHello 前生成 eager ECDHE 密钥，按布局把公钥认证写入 session ID，后续握手必须使用对应密钥。其记录层另外管理 server-auth 掩码、密码切换、ClientFinished 及脚本命令。[Mihomo 入口][M-RESTLS]、[原生 session ID][R-HS]、[原生记录状态][R-STATE]

Meow 的 `restls::dial` 接受外部已连接的 Stream，这是可参考的 IO 边界；但内部 `tls12.rs` / `tls13.rs` 自行负责 ClientHello、密钥交换、transcript、CertificateVerify / Finished 和记录 AEAD，而不是让 BoringSSL 完成这次 TLS 连接。它只在部分密码运算与证书验证上使用 boring 的公开原语。`conn.rs` / `script.rs` 继续负责流和脚本状态。[Meow Restls 入口][MEOW-RESTLS]、[TLS1.2][MEOW-R12]、[TLS1.3][MEOW-R13]

这条路线能避免修改第三方源代码，但代价是维护额外 TLS 握手与记录实现，不能描述为“已有 boring 直接支持 Restls”。参考代码还明确记录固定 ClientHello、HRR、版本提示、脚本 Respond 行为与 Go 实现的差异。VCore 不能自动继承这些差异或把其旧测试视为本项目门禁已过。若选择该路线，先冻结可接受行为与安全审查，再完成 tls12/tls13 原生握手、正确/错误密码、脚本、取消和业务零泄漏的容器验证。[Meow 差异说明][MEOW-RESTLS]

## JLS：认证 random 需要进入真正的 transcript

Mihomo 命名指纹路径先构建完整 uTLS ClientHello，以 random 清零后的序列化消息计算认证，再通过 `SetClientRandom` 重新构建状态，最后完成 TLS。它禁用 tickets / 0-RTT，因为改 random 后必须重算 PSK binder；完成后还要求 JLSAuthenticated。普通路径使用 `jls-tls`。只设置自定义证书 verifier 不会自动生成这份认证 ClientHello。[Mihomo JLS][M-JLS]、[Mihomo uTLS 接入][M-JLS-UTLS]

Meow JLS 自己构造 ClientHello/random，再复用 Restls 的 `drive_tls13`；业务层是自有 TLS record stream。其 JLSAuthenticated 路径沿用原生 `jls-tls` 的特殊证书处理，而 Mihomo 的 uTLS 路径仍由 TLS 检查 CertificateVerify。这是需要明确测试的分支差异，不能一概称两条路径与 VCore 现有 REALITY 认证相同。[Meow JLS][MEOW-JLS]、[共享 driver][MEOW-R13]、[原生 JLS 证书处理][J-HS]

## 当前 boring 扩展能做什么

`RealityClientConfig` 仅含固定 REALITY server key / short ID / client version；`set_reality_client` 进入 native 的 `seal_reality_client_hello`，固定执行 X25519/HKDF/AES-GCM session-ID 认证。它没有向 Rust 调用者开放任意 ClientHello 内容、session-ID generator 或 random setter。指纹模板能改变声明形状，不等价于新增协议认证算法。[公开 REALITY API][B-API]、[native patch][B-PATCH]

BoringSSL 的 `SSL_CTX_set_msg_callback` / `SSL_set_msg_callback` 是观察接口，消息参数是 `const void *`。`SSL_SESSION_set1_id` 设置会话对象的恢复 ID，`SSL_set_session_id_context` 设置服务端会话区分上下文；它们不是“完整新 ClientHello 序列化之后、进入 transcript 之前”的认证回调。不得通过 const-cast 或私有状态布局将观察接口变成未受支持的修改接口。[公开 BoringSSL header][B-HEADER]

混合 REALITY 是另一个独立门禁：主线新增的 [N7 公开能力探针](../../../tests/n7_security_capabilities.rs)专门区分普通 Chrome133 hybrid share、classic REALITY 和显式 PQ override；它不证明上述 wrappers 原生互通。本研究未执行该探针，也不将它的结果冒称本次 wrapper 测试。

## 后续准入边界

1. v1/v2、v3、Restls tls12/tls13 与 JLS 分别取得自己的最小原生握手和数据闭环，不能复用别的协议 PASS。
2. 新 native hook 必须另行批准并保持连接级秘密/状态、同步清理、transcript 正确及普通 TLS 回归；新增自有 TLS 实现也应作为明确架构选择，不隐藏在普通 Adapter 名称下。
3. 原生 peers、cover、业务原站与观察服务全部遵守[隔离规则](../../testing-isolation.md)。第三方项目自带宿主 loopback 测试不能直接执行或抵扣容器门禁。
4. 主腿成功不抵扣 D20–D26：下载腿仍需要独立身份/缓存、同一 XHTTP handler 拓扑与双方证据。未实测保持 **NOT RUN / BLOCKED**，不开放仅能解析的公共字段。

[M-SHADOW]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/shadowtls/client.go#L96-L197
[M-RESTLS]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/restls/restls.go
[M-JLS]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/jls/jls.go
[M-JLS-UTLS]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/jls/utls.go#L40-L114
[C-SHADOW]: https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/transport/shadow_tls/mod.rs#L34-L107
[C-DEPS]: https://github.com/Watfaq/clash-rs/blob/470bc5a427bfaea3fafcedf32563010f9a47b691/Cargo.toml#L48-L50
[SHOES-SHADOW]: https://github.com/cfal/shoes/blob/60ed3838b346268615c81e4eace4e15e717da23e/src/shadow_tls/shadow_tls_client_handler.rs#L57-L190
[MEOW-SHADOW]: https://github.com/meow-rs/meow-rs/blob/59edf4e6abab427286113ef1498d85a8f0afe3c4/crates/meow-transport/src/shadow_tls.rs#L26-L46
[MEOW-RESTLS]: https://github.com/meow-rs/meow-rs/blob/53933f070ccaec6aeec5de159ebf6f0802d8c7ce/crates/meow-transport/src/restls/mod.rs
[MEOW-R12]: https://github.com/meow-rs/meow-rs/blob/59edf4e6abab427286113ef1498d85a8f0afe3c4/crates/meow-transport/src/restls/tls12.rs
[MEOW-R13]: https://github.com/meow-rs/meow-rs/blob/59edf4e6abab427286113ef1498d85a8f0afe3c4/crates/meow-transport/src/restls/tls13.rs#L1360-L1585
[MEOW-JLS]: https://github.com/meow-rs/meow-rs/blob/59edf4e6abab427286113ef1498d85a8f0afe3c4/crates/meow-transport/src/jls/tls13.rs
[R-HS]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/handshake_client.go#L176-L233
[R-STATE]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/restls_utils.go
[J-HS]: https://github.com/MetaCubeX/jls-tls/blob/67adc0e2f796/handshake_client_tls13.go#L599-L695
[B-API]: https://github.com/OneXray/boring/blob/67581195fd6388a8bfd42c4e39e945f73c99a2b2/boring/src/ssl/reality.rs
[B-PATCH]: https://github.com/OneXray/boring/blob/67581195fd6388a8bfd42c4e39e945f73c99a2b2/boring-sys/patches/reality-client.patch
[B-HEADER]: https://github.com/google/boringssl/blob/e2a57cfb4d915b4ba820585aef9fdee7bca13fe5/include/openssl/ssl.h#L5049-L5087
