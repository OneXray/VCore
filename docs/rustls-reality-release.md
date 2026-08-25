# rustls REALITY 发布计划

状态：REALITY V1实现、VCore迁移、普通TLS回归、并发和本地互操作已完成；release dependency仍使用相邻path checkout。剩余工作是发布不可变fork revision、更新`Cargo.toml`/`Cargo.lock`并从clean checkout复现全部构建。

## 1. 当前状态

| 项目 | 当前值 |
| --- | --- |
| rustls series | 0.23.43 |
| 开发分支 | `vcore/reality-0.23` |
| 当前 revision | `df261c84cbac4f708e63ac8644ce70daa90d771c` |
| VCore dependency | `rustls = { path = "../rustls/rustls" }` |
| Crypto provider | ring |
| Public REALITY config | `server_name`、32-byte public key、0–8-byte short ID |
| Release status | immutable tag/revision和clean-checkout build未完成 |

Wire contract由 [`reality-wire-protocol.md`](reality-wire-protocol.md) 和fork内确定性测试向量共同定义。

## 2. 目标

- VCore release不依赖本机相邻path。
- Fork release使用不可变tag和精确Git `rev`，禁止branch或floating HEAD。
- `Cargo.lock`记录同一revision和完整checksum/dependency graph。
- 普通TLS在REALITY feature启用时保持原行为。
- 每个REALITY connection独占临时私钥、auth key和认证状态。
- 所有配置、状态、日志和错误保持有界、脱敏和fail closed。
- Apple、Android和Windows artifacts都从clean checkout可复现。

## 3. 非目标

- REALITY server。
- ClientHello/fingerprint模拟。
- QUIC、ECH、0-RTT、resumption或HRR支持。
- WebPKI/spider fallback。
- 第二crypto provider或运行时provider切换。
- 公共rustls API的通用REALITY标准化。
- 在VCore内复制TLS state machine。

## 4. Fork 边界

Fork只增加连接级REALITY能力：

- Config builder接受immutable REALITY identity。
- ClientHello builder复用同一X25519 ephemeral key share完成ECDH和session-ID seal。
- Certificate verifier消费连接级auth state并验证临时证书与TLS 1.3 `CertificateVerify`。
- Error路径清零secret并使连接终止。

Fork不创建线程、async task、pool、global map或跨连接mutex。VCore只负责配置解析和选择普通TLS/REALITY；handshake byte和认证状态属于rustls。

普通TLS配置和REALITY配置必须是不同的immutable `ClientConfig`，不能在同一对象上热切换identity。

## 5. 安全要求

- TLS 1.3 + X25519。
- 0–8-byte short ID补零到8 byte。
- HKDF-SHA256、AES-256-GCM、nonce和AAD严格按wire文档。
- Low-order point、全零shared secret、时钟失败、重复seal或缺失state立即失败。
- 服务端只允许一张canonical Ed25519 temporary certificate。
- HMAC、SPKI、DER和`CertificateVerify`全部验证。
- 认证state成功或失败后立即消费，不能复用。
- HRR、真实cover certificate、intermediate、错误scheme和未知state都fail closed。
- Secret类型实现zeroize；Debug/Display/error不输出private key、auth key、public key原文或short ID。

## 6. 已完成

- REALITY feature与最小builder API。
- Connection-local ephemeral/auth/certificate state。
- ClientHello session ID seal。
- Canonical temporary certificate parser和HMAC验证。
- TLS 1.3 `CertificateVerify`绑定。
- Low-order key、错误key/short ID、HRR、DER和state负例。
- 两份配置交叉运行的100路并发ClientHello。
- VCore普通TLS与REALITY connector迁移。
- XHTTP `packet-up`、`stream-one`和split download路径回归。
- Shared connector、cancel/reconnect和单公共lifecycle回归。
- Apple/Android/Windows target构建与ring provider检查。

实际PASS以 [`acceptance.md`](acceptance.md) 为准。

## 7. 剩余发布步骤

### 7.1 整理fork

1. 确认工作树clean。
2. 确认REALITY commits只包含必要实现、测试和license更新。
3. 记录base release、fork revision和diffstat。
4. 运行fork完整fmt、tests、clippy和provider矩阵。
5. 创建不可变tag并验证remote object ID。

完成标准：tag解析到唯一commit，release branch变化不会改变依赖内容。

### 7.2 固定VCore dependency

把path dependency替换为精确Git revision，例如：

```toml
rustls = { git = "https://github.com/OneXray/rustls", rev = "<immutable-commit>", ... }
```

随后：

1. `cargo update -p rustls --precise <rev>`。
2. 检查`Cargo.lock`不包含path source。
3. 检查只解析ring provider和预期REALITY feature。
4. 提交`Cargo.toml`与`Cargo.lock`同一变更。

完成标准：删除相邻rustls目录后VCore仍能locked build。

### 7.3 Clean-checkout 验证

在新目录clone VCore并执行：

```bash
cargo fetch --locked
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
./scripts/check_c_header.sh
```

再构建：

```bash
./scripts/build_apple.sh
./scripts/build_android.sh
powershell -File scripts/build_windows.ps1 -Architecture arm64
```

记录VCore revision、rustls tag/rev、`Cargo.lock` hash、toolchain和artifact SHA-256。

完成标准：不使用本机path patch、未提交文件、预热target目录或额外环境覆盖即可成功。

### 7.4 平台与产品回归

- 普通TLS和REALITY各至少一组真实进程数据面。
- 错误public key、short ID、cover certificate和HRR负例。
- Shared connector并发、cancel/reconnect和runtime Stop。
- AnyTLS保持标准TLS路径，不继承REALITY identity。
- Apple XCFramework、Android `.so`、Windows DLL/hosts architecture和static CRT。
- Release iOS整进程memory trace；35/45 MiB只作优化目标。

## 8. Upgrade 规则

升级rustls base或crypto dependency时单独提交：

1. 先同步base并解决普通TLS回归。
2. 重新运行全部确定性wire向量。
3. 审查ClientHello、key share、certificate verifier和provider API变化。
4. 重新执行平台build和产品数据面。
5. 发布新的immutable revision并更新lockfile。

不得在同一提交中混入配置schema、proxy protocol或unrelated runtime重构。

## 9. Rollback

- VCore dependency始终指向一个已验证immutable revision。
- 新fork revision失败时，发布下一次VCore源码回退到上一个known-good revision。
- 不在binary中保留双REALITY实现或runtime开关。
- 已发布tag不移动、不删除、不复用。

## 10. 完成定义

全部满足后才能关闭发布计划：

- Fork tag/revision immutable且可远程获取。
- VCore无path dependency。
- `Cargo.lock`与`Cargo.toml`指向同一revision。
- Clean checkout完成locked tests、clippy和三平台build。
- 普通TLS、REALITY、并发、cancel和安全负例通过。
- Release artifacts记录hash并通过license audit。
- 文档与验收记录最终revision，不包含本机路径假设。

许可证和实际派生源码声明见 [`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)。
