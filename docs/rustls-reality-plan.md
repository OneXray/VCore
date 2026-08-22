# 自有 rustls REALITY 客户端实现计划

状态：历史实施候选记录。自有 rustls REALITY 客户端、VCore 开发态迁移、固定
Xray-core revision 互操作、ring 产品矩阵、fuzz 和 Apple/Android 交叉构建已有
本地证据；候选提交/CI、不可变 rustls tag 与 VCore 精确 `rev`、以及 iOS Release
真机正常业务与 footprint trace 仍未完成，因此不是发布完成状态。本文件 M8 中
“未来 AnyTLS”的 carrier/ALPN 假设已由当前实现取代：AnyTLS 只使用 WebPKI 标准
TLS 1.3/1.2、不发送 ALPN，也不使用 REALITY。当前契约见
[AnyTLS outbound](anytls.md)；以下内容仅用于审计 rustls/REALITY 设计历史。

## 1. 当前基线与目标基线

| 项目 | 2026-07-19 当前状态 | 发布前剩余项 |
| --- | --- | --- |
| 自有 rustls fork | `vcore/reality-0.23` 建立在官方 `v/0.23.42` / `411fb0278820bbf81ac825b24823f31bed55190e` 上；REALITY 修改仍在未提交工作树 | 形成可定位候选提交，完成 CI 后打不可变 tag；`411fb027...` 只是上游 base，不是候选 revision |
| VCore rustls | `rustls = 0.23.42`，开发态通过相邻 `../rustls/rustls` path patch 使用自有实现 | rustls 发布后改为 `OneXray/rustls` 精确 Git `rev` 并更新 lockfile |
| VCore tokio-rustls | 官方 crates.io `tokio-rustls 0.26.4` | 保持不 fork、不 patch |
| Crypto provider | 单一 crates.io ring `0.17.14`；依赖检查确认无 AWS-LC 和第二份 rustls | 候选 CI 重放相同依赖树检查 |
| 协议基线 | 自有实现已通过 Xray-core `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` / Xray 26.7.11 的 TLS/REALITY × 两种 XHTTP mode | 发布记录固定该 revision 和最终 artifact hash |
| iOS 内存 | VCore 使用平台无关 TUN 资源档；35/45 MiB 仅为 best-effort telemetry 与优化目标，不参与生命周期控制；Apple slices 已交叉构建 | Release 真机、无调试器、完整 TUN 生命周期的正常业务与整进程 trace |

固定互操作基线为 `THIRD_PARTY_NOTICES.md` 记录的 Xray-core revision；升级该 revision 必须作为单独、可审计的基线变更，不能与 rustls 实现修改混在一起。

## 2. 目标

1. 用自有 rustls fork 替换当前 Watfaq rustls 和 tokio-rustls patch。
2. 实现与固定 Xray-core revision 对齐的 REALITY 客户端握手和证书认证。
3. 消除共享 `ClientConfig`/`TlsConnector` 并发握手时认证状态跨连接覆盖的风险。
4. REALITY 未启用时保持官方 rustls 的普通 TLS 行为。
5. 保持 TLS/REALITY carrier 与 VLESS、XHTTP、未来 AnyTLS 解耦。
6. 保持每连接新增状态固定、有界、及时释放，并通过 Release iOS 真机 trace 评估常态内存，不以降低正常业务并发换取数字。
7. 形成可追溯、可重放、可回滚的最小补丁序列。

## 3. 非目标

- 不实现 REALITY 服务端。
- 不实现浏览器 ClientHello 模拟、`fp` 或 uTLS 类能力。
- 不把 VLESS、XHTTP、AnyTLS、配置解析、分享链接、DNS、路由放进 rustls。
- 不把 Tokio、socket、超时、重试、连接池、后台任务或队列放进 rustls。
- 不实现 Shadow-TLS 通用 session ID generator。
- 不修改或 fork 第三方 tokio-rustls。
- 不在本阶段迁移到 rustls 0.24，也不同时维护 0.23/0.24 两套 TLS 栈。
- 不在 rustls 中实现 iOS 平台判断、footprint guard 或 VCore 生命周期管理。
- 不直接修改任何第三方依赖源码；所有产品修改只发生在自有 rustls fork 和 VCore。

## 4. 不可变实现原则

### 4.1 仓库、分支和发布

- `OneXray/rustls` 的 `main` 永远只 fast-forward 同步官方 rustls `main`，不提交 VCore/REALITY 产品补丁。
- 产品实现从官方标签 `v/0.23.42` 创建 `vcore/reality-0.23`。
- 已交给 VCore 使用的提交不得改写；发布使用不可变标签，例如 `vcore-rustls-0.23.42-r1`。
- VCore 只使用精确 Git `rev`，不得引用浮动 branch 或本地 path。
- 产品补丁保持线性、小型和可 `git range-diff`；不得把无关重构与安全功能混在同一提交。
- rustls 与 VCore 是独立 Git 仓库，分别提交和发布。VCore 只能在 rustls revision 已完成自身验收后更新依赖。

### 4.2 职责边界

rustls fork 只负责：

1. 在单次客户端握手中构造 REALITY session ID。
2. 使用当前 TLS X25519 key share 的同一临时私钥，对服务端 REALITY 静态公钥执行 ECDH。
3. 把该连接的 `auth_key` 传递给同一连接的证书认证流程。
4. 严格认证 REALITY 临时证书，并继续完成 TLS 1.3 `CertificateVerify`。

ALPN、SNI 的来源、XHTTP mode、普通 TLS trust roots、resumption 容量和上层 stream 生命周期仍由 VCore 决定。fork 不能硬编码 `h2`。

### 4.3 状态所有权

目标所有权模型为：

```text
Arc<ClientConfig>
└── 不可变 RealityClientConfig
    ├── server public key
    ├── short ID
    └── client version

ClientConnection / 单次握手
└── RealityHandshakeState
    ├── 当前 X25519 active key exchange
    ├── shared secret / auth_key
    ├── ClientHello 认证上下文
    └── 临时证书认证状态
```

- 临时私钥、shared secret、`auth_key` 和认证结果必须严格属于单个 `ClientConnection`。
- 禁止全局或静态可变状态、`Arc<Mutex<Option<auth_key>>>`、跨连接 map，以及在共享 `ClientConfig`/`TlsConnector` 中保存当前握手秘密。
- 秘密不得实现无必要的 `Clone`/`Copy`，不得进入日志或错误文本，并在成功、失败、取消和 drop 路径尽早清零。
- 固定长度字段优先使用定长数组；不因对端输入产生无界 allocation。

### 4.4 安全与失败语义

- 第一版 REALITY 只支持 TLS 1.3 + X25519。
- 同一临时 X25519 私钥必须同时用于 TLS key share 和 REALITY 静态公钥 ECDH；provider hook 不得向上层暴露原始私钥。
- ClientHello `signature_algorithms` 必须公布 crypto provider 的完整支持列表，至少覆盖 ECDSA、RSA 和 Ed25519；不能把它收窄为 REALITY 最终认证使用的 Ed25519。不支持 Ed25519 的 provider 必须在配置构建阶段失败。
- 错误长度、低阶点、全零 shared secret、不支持的 key exchange、时间获取失败和内部状态缺失都必须立即失败。
- session ID 的 client version、时间戳、short ID、HKDF-SHA256、AES-256-GCM、nonce 和 AAD 必须与固定 Xray-core 基线逐字节一致。
- 证书必须按 DER 结构严格解析 Ed25519 SPKI 与 `signatureValue`；禁止依靠“证书末尾 64 字节”等位置假设。
- HMAC 比较必须使用常数时间实现。
- `CertificateVerify` 只能绑定到同一连接中已通过 REALITY 认证的同一张证书。
- ClientHello 公布 ECDSA/RSA 只用于让相应证书类型的伪装站完成前置握手；REALITY 临时证书 SPKI、证书 HMAC 和服务端 `CertificateVerify` 仍只接受 Ed25519，不得按公布列表放宽认证。
- REALITY 认证失败、收到 camouflage 真实证书或缺少认证状态时一律 fail closed，不得回退到 WebPKI 成功路径。
- 第一版禁用 REALITY session resumption 和 0-RTT。HelloRetryRequest 必须正确保持全部安全不变量；若第一版不支持，则在收到时明确失败，不能静默继续。

### 4.5 普通 TLS、AnyTLS 和内存

- 新增默认关闭的 `reality` Cargo feature。
- feature 关闭时应保持官方代码和行为；feature 开启但未配置 REALITY 时，普通 TLS 的 ClientHello、WebPKI、TLS 1.2/1.3、ALPN、resumption、ECH 和 provider 行为不得改变。
- 对普通 TLS 的 parity 测试使用确定性随机源/时间源，在相同输入下比较编码握手和状态结果。
- 第一版实现可明确只支持 ring provider；不支持的 provider 必须在配置构建阶段返回错误，不能静默降级。
- API 保持上层协议无关。XHTTP 由 VCore 设置 `h2`。M8 当时曾假设未来 AnyTLS
  自行设置 ALPN 并可消费普通 TLS/REALITY stream；该假设已废弃，当前 AnyTLS
  固定使用不带 ALPN 的标准 TLS，且不支持 REALITY。
- fork 内不得创建线程、异步任务、连接池、session cache、后台清理器或无界队列。
- iOS footprint 仍由 VCore/OneVCore 对完整 TUN 生命周期和整个宿主进程观测；rustls
  只保证新增握手状态有界并及时释放。35/45 MiB 是优化目标，不是 rustls 或 VCore
  的 fail-closed 条件。

## 5. 目标 API 与内部扩展点

公共 API 名称在编码阶段可按 rustls 0.23 类型状态 builder 调整，但语义固定为高层、原子化配置。例如：

```rust,ignore
let reality = RealityClientConfig::new(
    server_public_key, // [u8; 32]
    short_id,         // 已验证的 0..=8 bytes
    client_version,   // [u8; 3]
)?;

let config = ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&TLS13])?
    .with_reality(reality)
    .with_no_client_auth();
```

API 约束：

- VCore 负责 YAML、base64url、hex/string 解码和用户错误定位；rustls 只接收已验证的二进制字段。
- `with_reality` 必须一次性安装 ClientHello 处理和证书认证，不能表示“只生成 session ID，但不认证证书”的半配置状态。
- 不向调用方公开任意修改 ClientHello 的通用 callback，也不公开 rustls 内部 handshake message 类型。
- crypto provider 的窄扩展点只执行“用当前 active X25519 私钥对指定公钥派生 shared secret”；不得导出原始私钥。
- 扩展点应允许不支持 REALITY 的 provider 返回明确错误，并为外部 provider 提供不破坏编译的默认行为。
- rustls API 不引用 Tokio 类型，不设置 ALPN，也不感知 VLESS/XHTTP/AnyTLS。

### 5.1 预计文件触点

rustls fork 的预期最小范围：

| 路径 | 预期修改 |
| --- | --- |
| `rustls/Cargo.toml` | 默认关闭的 `reality` feature，以及经过审计的最小可选依赖 |
| `rustls/src/client/reality.rs` | 高层配置、连接级状态、session ID 与临时证书认证 |
| `rustls/src/client/builder.rs` | 原子化 `with_reality` builder 入口 |
| `rustls/src/client/client_conn.rs` | 为每个连接实例化独立 REALITY 状态 |
| `rustls/src/client/hs.rs` | 在 ClientHello 编码流程中协调当前 X25519 key exchange 和认证上下文 |
| `rustls/src/client/tls13.rs` | 在确有需要时绑定连接级证书认证与 `CertificateVerify`，不得使用共享 verifier slot |
| `rustls/src/crypto/` 与 ring provider | 最窄的同一临时私钥 ECDH 能力，不导出原始私钥 |
| `rustls/src/msgs/handshake.rs` | 只有无法用现有编码接口生成准确 AAD 时才修改 |
| rustls client tests/fuzz | 协议向量、普通 TLS parity、并发、负例和畸形输入 |

VCore 的预期范围：

| 路径 | 预期修改 |
| --- | --- |
| `Cargo.toml` / `Cargo.lock` | 自有 rustls 精确 rev、官方 tokio-rustls、单一 ring 依赖树 |
| `src/security/client.rs` | 新 API、REALITY TLS 1.3 only、禁用 REALITY resumption、删除空 roots workaround |
| `tests/xray_interop.rs` / `tests/run_xray_interop.sh` | 同 connector 并发、完整安全负例与现有矩阵回归 |
| `THIRD_PARTY_NOTICES.md` | 来源、revision、依赖与许可证边界 |
| `docs/acceptance.md` | 只记录实际执行过的 revision、命令和结果 |

若实现需要修改上述范围以外的 rustls server、ECH、QUIC、通用 send path，或 VCore 配置/FFI/路由模块，必须先停止并证明该修改不可避免；不能以顺手重构扩大补丁面。

## 6. 里程碑

### M0：建立可复现基线

工作项：

1. 在自有 fork 中添加官方 rustls `upstream` remote，并获取官方标签。
2. 再次确认 fork `main` 与官方 `main` 对应提交一致且工作区干净。
3. 从官方 `v/0.23.42` 创建 `vcore/reality-0.23`，保持 package name/version 为 `rustls 0.23.42`。
4. 记录官方 base、当前 Watfaq rustls/tokio-rustls revision、VCore revision、Xray-core revision和工具链。
5. 在没有 REALITY 修改的 0.23.42 基线上执行该分支自带的 fmt、test、clippy、feature matrix 和适用 Bogo 测试。
6. 保存当前 Watfaq 实现的 VCore 正向互操作、安全负例、并发和依赖树作为迁移比较基线。
7. 确认 `vcore/**` 产品分支能够执行 rustls 完整 CI；若 upstream workflow 的 push filter 不包含该分支，则所有修改必须通过能触发完整 CI 的 PR，或在产品分支中显式补充等价检查。

退出条件：

- 产品分支父提交可直接追溯到官方 `v/0.23.42`。
- 官方基线测试通过，或所有既有上游失败均有独立记录且与本补丁无关。
- `main` 不包含任何 VCore 提交。
- 迁移前 VCore 基线证据可重复执行。
- 候选提交不能只依赖本机检查；对应 CI 运行必须可定位并完整通过。

### M1：冻结协议行为和测试向量

工作项：

1. 从固定 Xray-core revision 整理 ClientHello session ID、ECDH、KDF、AEAD 和临时证书认证步骤。
2. 固定字段长度、short ID 长度、client version、时间戳及允许的时间语义。
3. 固定 ClientHello 编码时点：SNI、ALPN、key share 等扩展全部完成后，先得到约定的 session-ID 占位编码作为 AAD，计算后写回 32-byte encrypted session ID；写回后不得再修改受认证的 ClientHello。
4. 生成不包含生产秘密的确定性测试向量，覆盖每个中间值和最终 session ID。
5. 明确定义错误 public key、short ID、时间、真实证书、畸形证书和 HRR 的结果。

退出条件：

- 每个 wire behavior 都能指向固定 Xray-core 源码位置或确定性测试向量。
- 测试向量可以独立于网络运行，并逐字节验证结果。
- 不再以“Watfaq 当前可以连接”代替协议定义。
- 所有认证异常都具有明确的 fail-closed 结果。

### M2：实现最小 API、feature 和连接状态

工作项：

1. 增加默认关闭的 `reality` feature，只启用必要代码和依赖。
2. 实现不可变、构造即校验的 `RealityClientConfig`/short ID 类型。
3. 把 `RealityHandshakeState` 放入单次客户端握手状态机。
4. 增加窄的 active X25519 派生能力；优先使用现有 ring/provider primitive，不导出私钥。
5. 为不支持的 provider、TLS 版本和 key exchange 定义结构化且不含秘密的错误。

退出条件：

- API 无法形成只启用一半 REALITY 的非法状态。
- 同一个 `Arc<ClientConfig>` 可安全创建任意数量的独立连接状态。
- 没有共享认证 slot、全局 map 或 Tokio/ALPN/协议依赖。
- feature-off 和 feature-on/config-none 的普通 TLS 构造与测试均通过。

### M3：实现 ClientHello 和连接级密钥派生

工作项：

1. 在正确编码时点取得当前 X25519 active key exchange。
2. 用同一临时私钥对服务端静态公钥执行 ECDH。
3. 按 M1 测试向量派生 `auth_key` 并生成 32-byte REALITY session ID。
4. 只把连接级认证材料移动到该连接后续证书处理状态。
5. 覆盖正常、失败、取消、drop 和 HRR 路径的秘密清理。

退出条件：

- 全部固定向量逐字节通过。
- 同一配置至少 100 路并发握手无共享状态和竞态。
- 不同 public key/short ID 的交叉并发压力测试无串扰。
- 全零 shared secret、错误长度、非 X25519 和不支持的 HRR 明确失败。
- 普通 TLS ClientHello parity 测试通过。

### M4：实现 REALITY 证书认证

工作项：

1. 使用严格 DER 解析获得临时证书的 Ed25519 SPKI 和证书签名字段。
2. 按固定 Xray-core 基线计算并常数时间验证 REALITY HMAC。
3. 把已认证公钥绑定到同一连接的 TLS 1.3 `CertificateVerify`。
4. 删除 REALITY 模式下对普通 WebPKI 成功 fallback 的依赖。
5. 对错误和畸形输入增加负例、边界测试与 fuzz target/corpus。

退出条件：

- 正确临时证书和 `CertificateVerify` 通过。
- 错误 key、short ID、时间、HMAC、SPKI、签名、截断 DER 和真实站点证书全部失败。
- 缺少连接级 `auth_key` 或认证状态时失败。
- 畸形输入不 panic、不越界，也不触发无界 allocation。
- 普通 WebPKI verifier 回归测试全部通过。

### M5：完成 fork 级回归和安全审查

工作项：

1. 执行官方 rustls 0.23.42 的完整测试、feature matrix、适用 Bogo、fmt 和 clippy。
2. 分别验证 feature-off、feature-on/config-none 和 feature-on/REALITY 三种构建/行为。
3. 检查所有 secret 的生命周期、日志、error/debug 输出和 drop 路径。
4. 检查新增依赖、许可证、binary size 和 allocation 上限。
5. 将补丁整理成最小提交序列：API/状态、ClientHello、证书认证、测试/文档；使用 `range-diff` 检查没有混入 server、ECH、Shadow-TLS 或无关发送路径修改。

退出条件：

- fork 自身全部强制检查通过。
- 普通 TLS 无可观察行为回归。
- REALITY 代码不创建后台资源或无界容器。
- 安全审查问题已关闭，并生成候选不可变 revision。

### M6：迁移 VCore

工作项：

1. 把 VCore 的 rustls 精确版本更新到 `0.23.42`，patch 到自有 fork 的候选 `rev`。
2. 删除 Watfaq tokio-rustls patch，继续使用官方 `tokio-rustls 0.26.4`。
3. 在 VCore 解析 public key、short ID 和 client version 后调用新的原子 API。
4. REALITY 只启用 TLS 1.3，并禁用 resumption/0-RTT；普通 TLS 继续保持既有 TLS 1.2/1.3 和有界 resumption 策略。
5. 保持 ALPN 在 `src/security/client.rs` 的调用层：当前 XHTTP 设置 `h2`，fork 不做任何覆盖。
6. 删除空 root store 作为 Watfaq fallback 防线的临时做法，改由新的 REALITY verifier 自身 fail closed。
7. 更新 `Cargo.lock`、第三方声明和实现状态文档。
8. 配置协议、Invoke/FFI、VLESS/XHTTP framing、`measureDelay` 请求语义和 iOS
   best-effort memory telemetry 边界保持不变；如果实现迫使这些公共契约变化，必须
   停止迁移并先重新讨论设计。

退出条件：

- `cargo tree` 中只有一份 rustls 0.23.42。
- 不同时出现 ring 和 AWS-LC provider。
- 不再依赖 Watfaq rustls 或 tokio-rustls revision。
- VCore host 测试、clippy、C header 和 shell 检查全部通过。
- Apple 与 Android 目标至少完成现有 release 脚本的交叉构建。

### M7：Xray 互操作、并发和生命周期回归

必须重新执行：

| 安全层 | XHTTP mode | TCP | UDP | 安全负例 |
| --- | --- | --- | --- | --- |
| TLS | `packet-up` | VLESS TCP | XUDP | 证书、SNI、ALPN 错误 |
| TLS | `stream-one` | VLESS TCP | XUDP | 同上 |
| REALITY | `packet-up` | VLESS TCP | XUDP | public key、short ID、时间、证书认证错误 |
| REALITY | `stream-one` | VLESS TCP | XUDP | 同上 |

并发和生命周期额外覆盖：

- 同一共享 `ClientConfig`/`TlsConnector` 的高并发 REALITY 握手、取消和重连。
- 不同配置交叉并发，证明 `auth_key`、证书认证和错误不会跨连接传播。
- 唯一 VCore 公共实例的数据面，以及单次批量 `measureDelay` 内最多 5 个私有
  worker 的 REALITY 并发。
- start/stop/destroy 后公共实例的连接与握手状态全部回收；`measureDelay` 返回前
  其 worker、connector 与连接资源全部回收。
- 普通 WebPKI、调用方 ALPN、TLS 1.2/1.3 和 XHTTP mode 选择无回归。
- `measureDelay` 自身连接目标站点的普通 WebPKI + `http/1.1` connector 保持通过，证明全局启用 `reality` feature 没有污染非 REALITY TLS。
- Xray REALITY `dest` 指向本地 ECDSA P-256 TLS 伪装站时，至少一组 REALITY 数据面必须通过；该回归验证 ClientHello 公布 provider 的完整 signature schemes，同时不把伪装站证书当作 REALITY 身份接受。

退出条件：

- `docs/acceptance.md` 中现有 TLS/REALITY × XHTTP 矩阵重新通过。
- 安全负例均不能返回可继续使用的 stream。
- 当前共享认证状态风险无法在压力测试中复现。
- 单公共实例、批量测速、停止屏障和资源回收无回归。

### M8：AnyTLS 边界检查（历史假设，已由当前契约取代）

本里程碑当时不实现 AnyTLS，只验证未来兼容性。它证明 rustls fork 没有吸收
上层 multiplexing 生命周期，但其中“AnyTLS 可使用 REALITY”和“AnyTLS 自行设置
ALPN”的设想不再是产品契约：

- TLS/REALITY 输出仍是标准 async stream，不依赖 XHTTP 或 VLESS 类型。
- fork 不设置 ALPN；XHTTP 的 `h2` 仍由 VCore profile 设置。
- 当前 AnyTLS 复用同一 rustls/provider 依赖，但只建立标准 WebPKI TLS
  1.3/1.2 carrier，不发送 ALPN，也不接受 REALITY carrier。
- fork 不包含 AnyTLS multiplexing、队列、物理连接池、任务或停止逻辑。
- CI/检查脚本能够发现 rustls 0.23/0.24 并存和 ring/AWS-LC 双栈。

退出条件：

- 同一安全层 API 可以承载当前 XHTTP 和不带 `h2` 假设的通用 stream。
- 未增加 AnyTLS 直接依赖或运行时代码。
- AnyTLS 后续实现所需的差异被记录为上层 transport 工作，而不是 rustls 补丁。

### M9：Apple 构建、iOS 内存和发布

工作项：

1. 生成 Apple XCFramework，并核对 iOS device/simulator 与 macOS slices。
2. 在 Release 真机、无调试器条件下，分别用 REALITY `packet-up` 和 `stream-one` 覆盖冷启动、TCP/UDP/DNS、并发握手、重连、stop/destroy。
3. 对比 Watfaq 基线与自有 fork 的整进程 peak、运行期 plateau 和停止后回收情况。
4. 使用 OneVCore 的 iOS 内存观测流程保存外部 trace、独立 lifecycle result 和销毁证据。
5. 全部门槛通过后，在 rustls fork 打不可变标签，并将最终 revision 固定到 VCore。
6. 发布记录包含官方 rustls base、补丁提交、Xray-core revision、VCore revision、测试矩阵、许可证变化和已知限制。

退出条件：

- 承载 iOS TUN 生命周期的整个进程在相同设备、配置和 workload 下记录 cold-start
  current、representative-workload peak、运行 plateau 与 stop 后 plateau；35/45 MiB
  只作对比目标，越线不判功能失败。

- 新实现没有连接泄漏、持续增长或 stop 后残留的握手状态。
- memory telemetry 不改变 TUN 或非 TUN API、`measureDelay` 的业务结果。
- rustls release tag、VCore `Cargo.lock` 和验收记录指向同一个不可变 revision。

## 7. 验证命令与证据

### 7.1 rustls fork

具体命令以 `v/0.23.42` 分支自带的 CI 和 `CONTRIBUTING.md` 为准，最低包括：

```bash
cargo fmt --all -- --check
cargo test --locked -p rustls --no-default-features --features ring,std,tls12
cargo test --locked -p rustls --no-default-features --features ring,std,tls12,reality
cargo test --locked --all-features --all-targets
./admin/clippy -- --deny warnings
```

还必须执行 ring provider 的适用 Bogo job，以及分别针对 `reality` feature-off、feature-on/config-none、feature-on/REALITY 的测试矩阵。若新增 fuzz target，保存触发过的畸形 DER/ClientHello corpus 和运行参数。

### 7.2 VCore

```bash
cargo fmt --all -- --check
cargo test --all-features --all-targets
cargo clippy --all-features --all-targets -- -D warnings
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
sh -n scripts/*.sh tests/run_xray_interop.sh
cargo tree -i rustls@0.23.42
cargo tree -e features -i rustls@0.23.42
cargo tree -i tokio-rustls@0.26.4
```

真实 Xray-core 互操作：

```bash
XRAY_BIN=/path/to/xray tests/run_xray_interop.sh
```

平台构建：

```bash
./scripts/build_apple.sh
./scripts/build_android.sh
```

`cargo tree` 证据必须明确：只有一份 rustls、官方 tokio-rustls 指向同一 rustls 类型、只启用 ring，不存在 AWS-LC 双栈。

### 7.3 iOS 整进程

最终流程使用相邻 OneVCore 仓库的 [iOS TUN 内存观测与生命周期验收](../../OneVCore/docs/IOS_MEMORY_ACCEPTANCE.md)。必须保留 Release 构建标识、设备/iOS 版本、VCore/rustls revision、节点 mode、外部 trace、VCore lifecycle result 和功能/观测分离的最终判定。

### 7.4 2026-07-19 本地执行记录

本轮环境为 macOS 26.5.2 arm64、Rust/Cargo 1.97.1、Xcode 26.6、Android NDK 30.0.15729638。结果属于未提交工作树的开发候选证据：

| 检查 | 实际结果 | 判定 |
| --- | --- | --- |
| rustls ring feature-off | 官方测试目标全部通过 | 已通过 |
| rustls ring feature-on/REALITY | 241 个 unit test 及官方 integration/doc test 全部通过 | 已通过 |
| rustls clippy | feature-on/off 均通过 `-D warnings` | 已通过 |
| 连接隔离 | 两份不同 public key/short ID 配置共享运行，100 路并发 ClientHello 均生成独立 32-byte session ID | 已通过 |
| REALITY DER fuzz | `cargo fuzz` 21 秒、3,660,302 次执行，无 crash；CI feature-on target 也完成 smoke build/run | 已通过本地 smoke |
| Bogo ring | 14,051 passed，3 failed | 已执行但非零失败 |
| rustls `--all-features --all-targets` | `aws-lc-fips-sys` 构建前因本机缺少 `cmake` 停止 | 环境阻塞，未通过 |
| VCore 全特性测试（DNS M1–M5 前历史快照） | 主目标 265 passed、1 ignored；`xray_interop` 另有一个默认 ignored harness；2026-07-24 当前工作树 320 passed、1 ignored，完整结果见 `acceptance.md` 顶部 M6 记录 | 已通过当时普通测试；当前候选也通过 |
| `vcore-netstack` | 13 个单元测试和 6 个集成测试，共 19 个通过 | 已通过 |
| 固定 Xray-core | `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` / Xray 26.7.11 的 TLS/REALITY × `packet-up`/`stream-one` 四组通过 | 已通过 |
| 依赖边界 | 一份自有 rustls 0.23.42、官方 tokio-rustls 0.26.4、一份 ring 0.17.14；无 Watfaq/AWS-LC/第二份 rustls | 已通过 |
| Apple/Android | Apple 五个 target 组成三组 XCFramework slices；Android arm64-v8a/x86_64，LOAD alignment 均为 16 KiB；身份/符号检查和 App 同步 smoke 通过 | 已通过构建，不代表真机验收 |

Bogo 的三个失败均为 warning-log-output 预期差异：`SendWarningAlerts-Pass`、`SendUserCanceledAlerts-TLS13`、`SendSNIWarningAlert`。不能把 macOS wrapper 的最终退出状态描述成 Bogo 零失败。

当前开发态仍通过相邻 rustls path 工作树构建。未生成候选 Git revision、不可变 tag 或 CI 链接，iOS Release 真机正常业务与 footprint trace 也未执行；这些条件完成前不得发布。

## 8. 第三方来源与许可证

- 自有 fork 保留 rustls 原有 `Apache-2.0 OR ISC OR MIT` 许可和版权声明。
- Xray-core 只作为协议行为权威、测试向量来源和互操作对象；若复制或逐行翻译 MPL-2.0 源码，必须在编码前完成文件级许可证审查。
- Watfaq rustls 和 `references/reality-rs` 只作为问题定位与设计参考。任何复制、翻译或实质改写都必须记录来源文件、revision、目标文件和许可证处理。
- 不整体 cherry-pick Watfaq 或 `reality-rs` 提交；不引入其 REALITY server、Shadow-TLS generator、ECH 或无关 send-path 修改。
- 新增依赖必须记录版本、用途、feature、许可证、binary-size/内存影响，并更新 `THIRD_PARTY_NOTICES.md`。
- 发布前对实际 `Cargo.lock` 执行完整依赖和许可证审计，研究参考列表不能替代二进制依赖清单。

## 9. 上游升级策略

官方发布新的 rustls 0.23.x 时：

1. 不修改已有发布标签或 VCore 已引用的提交。
2. 从新的官方标签建立新的维护基线。
3. 按原提交顺序重放最小 REALITY patch，并用 `range-diff` 审核差异。
4. 重新执行普通 TLS、REALITY、并发、Xray 互操作、平台构建和 iOS 内存矩阵。
5. 生成新的不可变 rustls 标签，再用独立 VCore 提交更新精确 revision 和 lockfile。

rustls 0.24 稳定后使用独立迁移分支和独立验收周期；不得直接把现有 0.23 产品分支升级为 0.24，也不得让 VCore 同时链接两个 minor 版本。

## 10. 回滚策略

- 迁移前保存当前 Watfaq revision、VCore `Cargo.lock` 和已通过的互操作/内存比较基线。
- 新 fork 出现阻断问题时，只通过恢复 VCore 依赖提交和 lockfile 回滚；不重写 rustls branch 或 tag。
- 不增加运行时“双 REALITY 实现”开关，避免一个二进制携带两套安全路径。
- Watfaq 仅作为短期应急回滚点，其共享认证状态风险不会因回滚消失；回滚记录必须注明风险、适用范围和重新迁移条件。
- 已发布的自有 fork revision 永久保留，保证线上构建可复现和可定位。

## 11. 完成定义

只有同时满足以下条件，才能把迁移状态改为“完成”：

- 自有实现基于官方稳定 rustls 0.23.x，fork `main` 仍是官方纯镜像。
- REALITY 正向互操作、完整安全负例、畸形输入和取消路径全部通过。
- 同一个共享配置高并发握手无认证状态串扰。
- feature-off 和普通 TLS 路径无行为回归。
- VCore 只有一份 rustls、一个 ring provider，并使用官方 tokio-rustls。
- XHTTP 的 ALPN 行为保持在 VCore；未来 AnyTLS carrier 边界未被破坏。
- fork 没有线程、后台任务、无界队列或长期保存握手秘密。
- iOS 单实例 TUN 的整个宿主进程完成 Release 真机正常业务、footprint/plateau 和重复启停记录；35/45 MiB 只作优化目标。
- rustls tag、VCore revision、`Cargo.lock`、许可证记录、Xray-core 基线和验收证据全部可追溯且相互一致。

## 12. 里程碑状态

| 里程碑 | 当前状态 | 主要产物 |
| --- | --- | --- |
| M0 可复现基线 | 部分完成 | 0.23.42 产品分支和上游 base 已固定；候选提交与可定位 CI 尚无 |
| M1 协议与向量 | 已完成（本地） | 固定 Xray-core 源码说明、确定性向量、失败语义 |
| M2 API 与状态 | 已完成（本地） | 默认关闭的 `reality` feature、原子高层 API、连接级状态 |
| M3 ClientHello | 已完成（本地） | 同一 X25519 临时密钥复用、session ID、100 路交叉配置并发和 HRR 拒绝 |
| M4 证书认证 | 已完成（本地） | 严格 DER/HMAC/CertificateVerify、fail-closed 负例、fuzz target/corpus 与实跑记录 |
| M5 fork 回归 | 部分完成 | ring 测试/clippy/安全审查已过；Bogo 有 3 个日志差异、全 feature 缺 cmake，候选 revision/CI 尚无 |
| M6 VCore 迁移 | 部分完成 | 新 API、官方 tokio-rustls、单一 ring 依赖树和平台构建已过；仍是开发 path 而非精确 `rev` |
| M7 互操作与并发 | 已完成（本地） | 固定 Xray 26.7.11 四矩阵、安全负例、共享 connector、取消重连；旧多实例测速证据仅为历史，当前单实例与批量测速契约另按验收文档验证 |
| M8 AnyTLS 边界 | 已完成（本地） | carrier/ALPN 分层、单 TLS/provider 依赖检查 |
| M9 Apple 与发布 | 部分完成 | Apple/Android 产物及 App 同步已有历史证据；当前物理 iOS 正常业务/footprint、不可变 tag/rev 和发布记录未完成 |
