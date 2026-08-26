# rustls REALITY 依赖与发布要求

VCore 的 REALITY 客户端依赖自有 rustls 0.23 fork。开发工作区当前通过 `[patch.crates-io]` 指向相邻的 `../rustls/rustls`；这种本地路径只适用于开发，不能作为发布依赖。

## 实现边界

fork 只增加连接级 REALITY 能力：

- 配置构建器接收不可变的服务端公钥、short ID 和客户端版本；
- ClientHello 使用同一 X25519 临时密钥完成 key share、ECDH 和 session ID 封装；
- 证书验证器消费当前连接的认证状态，验证临时证书和 TLS 1.3 `CertificateVerify`；
- 所有失败路径清零秘密并终止连接。

fork 不创建线程、异步任务、连接池、全局映射或跨连接锁。VCore 只负责配置解析并选择普通 TLS 或 REALITY；握手字节和认证状态属于 rustls。

普通 TLS 与 REALITY 必须使用不同的不可变 `ClientConfig`，不能在同一对象上热切换身份。线上协议见 [REALITY V1 客户端协议](reality-wire-protocol.md)。

## 发布依赖

发布前必须把本地 path patch 替换为远端不可变提交：

```toml
rustls = { git = "https://github.com/OneXray/rustls", rev = "<immutable-commit>", ... }
```

要求：

1. `rev` 指向已推送且不可移动的提交，不使用 branch、tag 浮动引用或本机路径；
2. `Cargo.toml` 和 `Cargo.lock` 在同一提交中更新；
3. 删除相邻 rustls 目录后，`cargo fetch --locked` 和后续构建仍能成功；
4. 只启用预期的 `ring` 提供方和 REALITY feature；
5. 发布记录保存 VCore revision、rustls revision、lockfile hash 和产物 SHA-256。

当前仓库仍有本地 path patch，因此满足上述条件前不能把构建称为可从干净检出复现的发布构建。

## 验证门禁

在全新目录中执行：

```bash
cargo fetch --locked
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
./scripts/check_c_header.sh
./scripts/build_apple.sh
./scripts/build_android.sh
powershell -File scripts/build_windows.ps1 -Architecture arm64
```

同时验证：

- 普通 TLS 与 REALITY 的真实进程数据面；
- 错误 public key、short ID、伪装站证书和 HRR；
- 共享连接器并发、取消重连和运行时停止；
- AnyTLS 继续使用标准 TLS，不继承 REALITY 身份；
- Apple、Android 和 Windows 产物使用同一锁定依赖。

具体执行结果只记录在 [验收矩阵](acceptance.md)。

## 升级与回退

升级 rustls 基线或加密依赖时，单独完成以下变更：

1. 同步上游并先解决普通 TLS 回归；
2. 重新运行全部确定性线上向量；
3. 审查 ClientHello、key share、证书验证器和 provider API 的变化；
4. 重新执行平台构建和产品数据面；
5. 发布新的不可变 revision 并更新 lockfile。

回退通过新的 VCore 提交改回上一个已验证 revision；已发布对象不得移动、删除或复用。VCore 不保留双 REALITY 实现或运行时降级开关。
