# TLS 依赖与发布要求

VCore 通过 GitHub 的不可变提交引用自有 boring 5.2.0 fork，承载命名 ClientHello 和经典 REALITY。普通无指纹 TLS、QUIC 和共享 WebPKI 验证使用 crates.io 官方 rustls 0.23.45 + tokio-rustls 0.26.5，仅启用 ring provider。生产和四个独立实验工程均不再依赖自有 rustls fork，不保留第二套 REALITY 后端。

## 实现边界

boring fork 提供 Chrome120、Chrome133、Firefox120、Safari16.0 模板及连接级 REALITY 能力：

- 配置构建器接收不可变的服务端公钥、short ID 和客户端版本；
- ClientHello 使用同一 X25519 临时密钥完成 key share、ECDH 和 session ID 封装；
- 证书验证器消费当前连接的认证状态，验证临时证书和 TLS 1.3 `CertificateVerify`；
- 所有失败路径清零秘密并终止连接。

REALITY 扩展不创建线程、异步任务、连接池或全局认证映射。VCore 负责策略和 IO 生命周期；握手字节、认证状态及临时秘密属于 BoringSSL。命名指纹普通 TLS 通过回调复用 VCore 原 WebPKI 验证器，而不是改用系统 OpenSSL 信任。

普通 TLS 与 REALITY 使用不同的不可变连接器，不能热切换身份。只启用 classic X25519 REALITY，不启用 FIPS、RPK、QUIC 或外部预编译 TLS 库。配置与 ALPS 限制见 [TLS 指纹](tls-client-fingerprint.md)，认证线格式见 [REALITY V1](reality-wire-protocol.md)。

## 锁定依赖来源

```toml
boring = { git = "https://github.com/OneXray/boring", rev = "e81c6837a302241d81c0930610b4f34dd4328167", version = "=5.2.0", features = ["client-fingerprint"] }
tokio-boring = { git = "https://github.com/OneXray/boring", rev = "e81c6837a302241d81c0930610b4f34dd4328167", version = "=5.2.0" }
rustls = { version = "=0.23.45", default-features = false, features = ["ring", "std", "tls12"] }
tokio-rustls = { version = "=0.26.5", default-features = false, features = ["ring", "tls12"] }
```

要求：

1. boring 三个 crate 必须来自同一已发布 revision；rustls/tokio-rustls 只使用官方 crates.io 发行版。不使用本机路径、`references` 依赖、rustls Git patch 或第二个 source；
2. `Cargo.toml` 和 `Cargo.lock` 在同一提交中更新，lockfile 必须包含 registry 校验值和 boring 完整 Git revision；
3. 没有相邻 rustls/boring 目录时，`cargo fetch --locked` 和后续构建仍能成功；
4. rustls 只启用 ring；`outbound-vless` 启用 `boring/reality`，命名指纹由 `tls-fingerprint` feature 统一拥有；
5. 发布记录保存 VCore/boring revision、rustls/tokio-rustls 版本与 registry 校验值、BoringSSL 子模块和补丁校验值、lockfile hash 及产物 SHA-256。

旧 rustls fork 已退役，远端计划永久删除，不再作为依赖、回退或重建来源。旧 REALITY 选择实验已从 security spike 移除；纯内存 TLS/record、HPKE/ECH 与官方 binding 接口实验仍保留。历史 N0/N1 验收保留当时的结果与摘要，不追改为官方 rustls 或 boring 的新结果；旧 Git 提交可能无法再重建。当前替换验证见 [fork 退役验收](acceptance/rustls-fork-retirement.md)。

本次 boring revision 内的 BoringSSL 子模块为 `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`，
指纹构建补丁 SHA-256 为 `5d91f9d8a5200df1d8581b5fbbf53ad2435a293d75d21fd6820fa6a3772864ff`；
REALITY 构建补丁 SHA-256 为 `a28e55298c3aa2efcc4bc66f3fb64e05583333811284d8c9abafe744d1370e30`。
补丁由 feature 控制，原始子模块不修改。Safari Zlib 增加可选 `flate2 1.1.10`
（关闭默认 feature，使用纯 Rust `rust_backend`）；Chrome 保留 `brotli 9.0.0`。
两者及传递依赖必须纳入当前解析图的许可证审查；不新增系统 zlib 链接依赖。
纯内存 ALPS peer 测试直接引用同 revision 的 `boring-sys` 和已锁定的
`foreign-types 0.5.0`（官方 registry 当前稳定版）；它们是 dev-dependencies，
不新增生产 TLS 后端或网络服务端。
原生依赖的构建需要 C/C++、CMake、Perl 和 libclang；目标工具链须独立验证。
Apple 静态库的宿主最终链接需要 libc++（module map 已声明；直接 C 链接需 `-lc++`）。
Android 输出须连同同 ABI、同 NDK 的 `libc++_shared.so` 打包；标准脚本已复制，
许可证审查也必须包含该新增运行库。仅生成 `libvcore.so` 不能证明宿主可加载。
发布须审查 boring 的 MIT/Apache-2.0 及 BoringSSL 随源许可/通知，不能仅检查 Rust crate 的 license 字段。

分支前移不会自动改变 locked 构建。升级必须显式更新 `Cargo.lock`、审查解析 revision，并在同一变更中重新执行验证门禁。

## 验证门禁

在全新目录中执行：

```bash
cargo fetch --locked
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets --no-run
cargo test --locked --all-features --lib security::
cargo test --locked --all-features --lib config::
cargo clippy --locked --all-features --all-targets -- -D warnings
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows
```

同时验证：

- 普通 TLS 与 REALITY 的真实进程数据面；
- 错误 public key、short ID、伪装站证书和 HRR；
- 共享连接器并发、取消重连和运行时停止；
- AnyTLS 继续使用标准 TLS，不继承 REALITY 身份；
- Apple、Android 和 Windows 产物使用同一锁定依赖。

全目标 `--no-run` 只验证编译；外部服务端测试另按[容器隔离规则](testing-isolation.md)运行，不执行尚未容器化的历史宿主监听器测试。

具体执行结果只记录在 [验收矩阵](acceptance.md)。

## 升级与回退

升级 rustls、boring 基线或加密依赖时，单独完成以下变更：

1. rustls 使用官方最新稳定发行版；boring fork 同步上游并先解决普通 TLS 回归；
2. 重新运行全部确定性线上向量；
3. 审查 ClientHello、key share、证书验证器和 provider API 的变化；
4. 重新执行平台构建和产品数据面；
5. boring fork 的变更先发布不可变提交，再更新并审查 lockfile 中的依赖来源、版本、校验值及 Git revision。

回退通过新的 VCore 提交恢复已验证且依赖仍可获取的 lockfile revision；不能回到已退役 fork。VCore 不保留双 REALITY 实现或运行时降级开关。
