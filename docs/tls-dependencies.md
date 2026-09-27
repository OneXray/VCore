# TLS 依赖与发布要求

VCore 通过 GitHub 的 `release` 分支依赖自有 boring 5.2.0 fork，由 `Cargo.lock` 固定已验证的完整提交，承载命名 ClientHello、REALITY（经典默认及显式混合模式）和 JLS。普通无指纹 TLS、QUIC 和共享 WebPKI 验证使用 crates.io 官方 rustls 0.23.45 + tokio-rustls 0.26.5，仅启用 ring provider。生产和四个独立实验工程均不再依赖自有 rustls fork，不保留第二套 REALITY 后端。

## 实现边界

boring fork 提供 Chrome120、Chrome133、Firefox120、Safari16.0 模板及连接级 REALITY 能力：

- 配置构建器接收不可变的服务端公钥、short ID 和客户端版本；
- ClientHello 使用同一 X25519 临时密钥完成 key share、ECDH 和 session ID 封装；
- 证书验证器消费当前连接的认证状态，验证临时证书和 TLS 1.3 `CertificateVerify`；
- 所有失败路径清零秘密并终止连接。

REALITY 扩展不创建线程、异步任务、连接池或全局认证映射。VCore 负责策略和 IO 生命周期；握手字节、认证状态及临时秘密属于 BoringSSL。命名指纹普通 TLS 通过回调复用 VCore 原 WebPKI 验证器，而不是改用系统 OpenSSL 信任。

普通 TLS 与 REALITY 使用不同的不可变连接器，不能热切换身份。默认 classic X25519 REALITY；显式混合模式强制 X25519MLKEM768，不启用 FIPS、RPK、QUIC 或外部预编译 TLS 库。配置与 ALPS 限制见 [TLS 指纹](tls-client-fingerprint.md)，认证线格式见 [REALITY V1](reality-wire-protocol.md)。

## 锁定依赖来源

```toml
boring = { git = "https://github.com/OneXray/boring", branch = "release", version = "=5.2.0", features = ["client-fingerprint"] }
tokio-boring = { git = "https://github.com/OneXray/boring", branch = "release", version = "=5.2.0" }
# dev-dependency for the memory-only native peer tests
boring-sys = { git = "https://github.com/OneXray/boring", branch = "release", version = "=5.2.0" }
rustls = { version = "=0.23.45", default-features = false, features = ["ring", "std", "tls12"] }
tokio-rustls = { version = "=0.26.5", default-features = false, features = ["ring", "tls12"] }
```

要求：

1. boring 三个 crate 必须来自同一 `OneXray/boring` 的 `release` 分支和同一已发布 revision；当前锁定 `d5a5d41850886aef5b269015130ee6d6eb2129ba`。依赖审计同时检查分支来源及已批准的 lockfile revision，拒绝其他分支、Git `rev` 来源或混合提交；rustls/tokio-rustls 只使用官方 crates.io 发行版。不使用本机路径、`references` 依赖、rustls Git patch 或第二个 source；
2. `Cargo.toml` 和 `Cargo.lock` 在同一提交中更新，lockfile 必须包含 registry 校验值和 boring 完整 Git revision；
3. 没有相邻 rustls/boring 目录时，`cargo fetch --locked` 和后续构建仍能成功；
4. rustls 只启用 ring；`outbound-vless` 启用 `boring/reality`、公共 `boring/mlkem` 和 `boring/jls` hook，命名指纹由 `tls-fingerprint` feature 统一拥有。已取消 ShadowTLS 生产目标；锁定 fork 的 JLS feature 仍传递依赖共用的 `shadow-tls-v3` 底层 hook，不代表开放 ShadowTLS；
5. 发布记录保存 VCore/boring revision、rustls/tokio-rustls 版本与 registry 校验值、BoringSSL 子模块和补丁校验值、lockfile hash 及产物 SHA-256。

N7.1 Encryption 复用同一 boring 的公共 X25519、ML-KEM-768、AEAD 和 AES-CTR。
固定文本 context 的哈希/派生使用官方 Rust `blake3 1.8.7`；任意二进制 context
使用获准的私有 `vcore-blake3-raw`，只包装未修改的官方 BLAKE3 1.8.7 C portable
源。来源/逐文件 hash/许可证与符号隔离见 [crate 说明](../crates/vcore-blake3-raw/README.md)。
临时自有密钥材料采用 `zeroize 1.9.0`；不宣称能擦除第三方内部临时副本。
这不新增 TLS 后端，不使用外部研究路径或 build-time 下载。Encryption 随
`outbound-vless` 编译，默认算法根据 CPU 选择；测试用强制 ChaCha 入口只存在于
`interop-test`。原语和 wire 证据不替代公开功能、完整 N7.1 与生产平台构建。

N7.3 静态 ECH 在 `outbound-vless` 下引入官方 crates.io `hpke 0.14.1`
（alloc/aes/chacha/x25519，关闭默认 features），通过 rustls 公开 HPKE trait 使用
X25519/HKDF-SHA256 与三种 AEAD。无需 AWS-LC TLS provider、私有 rustls fork
或新的 TLS 引擎。wire enum 的公开 internal 路径封装在 `security/ech.rs`，升级
rustls 时单独审查。新增官方传递依赖及许可证须纳入 release graph 审计；ECH
配置和失败边界见 [ECH](ech.md)。

旧 rustls fork 已退役，远端计划永久删除，不再作为依赖、回退或重建来源。旧 REALITY 选择实验已从 security spike 移除；纯内存 TLS/record、HPKE/ECH 与官方 binding 接口实验仍保留。历史 N0/N1 验收保留当时的结果与摘要，不追改为官方 rustls 或 boring 的新结果；旧 Git 提交可能无法再重建。当前替换验证见 [fork 退役验收](acceptance/rustls-fork-retirement.md)。

本次 boring revision 内的 BoringSSL 子模块为 `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`，
指纹构建补丁 SHA-256 为 `5d91f9d8a5200df1d8581b5fbbf53ad2435a293d75d21fd6820fa6a3772864ff`；
REALITY 构建补丁 SHA-256 为 `308b0fabbf8651656d4e853e0f789746b4125033dd9bb398903f6bae31ade4da`。
锁定 revision 中由 JLS 复用的 ShadowTLS v3 hook patch SHA-256 为
`0c89bcd209bf40ab9033c1cd7f4e12388c1d44a6684a7c874e772a1ee1fa8138`。
该 hook 仅认证真正的 ClientHello，不包含公开 ShadowTLS 所需的 relay record
认证与受控记录切换。ShadowTLS 目标已取消；保留 JLS 的内部依赖不构成该协议
支持，也不增加当前阶段的开发目标。历史准入和独立 fork 证据见
[N7.4 记录](acceptance/next-protocols/N7-shadow-tls.md)。
当前 JLS hook patch SHA-256 为
`024e6c3724af18b9a714e8da34956e00503055b8c0b3548b600f49f4cc8b2028`；通过上述
`release` 分支及锁文件接入。它认证原生 hello，保留 CertificateVerify/Finished 和
TLS 记录保护，并在首次不可重试握手错误返回前清零原生凭据；非阻塞读写重试仍保留
ServerHello 认证所需凭据。完整接线与证据见 [JLS](jls.md)。Restls 已删除，
JLS 保留；没有本机 path/patch 依赖。历史范围撤回的依赖与消费者验证见
[Restls 撤回验收](acceptance/next-protocols/N7-restls-retirement.md)。
补丁由 feature 控制，原始子模块不修改。Safari Zlib 增加可选 `flate2 1.1.10`
（关闭默认 feature，使用纯 Rust `rust_backend`）；Chrome 保留 `brotli 9.0.0`。
两者及传递依赖必须纳入当前解析图的许可证审查；不新增系统 zlib 链接依赖。
revision `67581195` 另提供既有原生 `SSL_SESSION_get_ticket_lifetime_hint` 的只读
Rust 入口；不修改 BoringSSL。VCore 缓存采用原生超时与非零 ticket hint 的较短期限，
以避免 TLS1.2 票据超过对端公布的有效期后仍被提供。
纯内存 ALPS peer 测试直接引用同 revision 的 `boring-sys` 和已锁定的
`foreign-types 0.5.0`（官方 registry 当前稳定版）；它们是 dev-dependencies，
不新增生产 TLS 后端或网络服务端。
原生依赖的构建需要 C/C++、CMake、Perl 和 libclang；目标工具链须独立验证。
Apple 静态库的宿主最终链接需要 libc++（module map 已声明；直接 C 链接需 `-lc++`）。
Android 输出须连同同 ABI、同 NDK 的 `libc++_shared.so` 打包；标准脚本已复制，
许可证审查也必须包含该新增运行库。仅生成 `libvcore.so` 不能证明宿主可加载。
发布须审查 boring 的 MIT/Apache-2.0 及 BoringSSL 随源许可/通知，不能仅检查 Rust crate 的 license 字段。

分支前移不会自动改变 locked 构建。升级必须显式更新 `Cargo.lock`、审查解析 revision，同步依赖审计中的批准 revision，并在同一变更中重新执行验证门禁。Shadowsocks 2022 使用官方 crates.io `shadowsocks = "=1.25.0"`，不是 Git 依赖；其唯一 AWS-LC 局部例外见 [Shadowsocks](shadowsocks.md)。

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
5. boring fork 的变更先合入并发布至 `release`，再更新并审查 lockfile 中的依赖来源、版本、校验值及完整 Git revision。

回退通过新的 VCore 提交恢复已验证且依赖仍可获取的 lockfile revision；不能回到已退役 fork。VCore 不保留双 REALITY 实现或运行时降级开关。
