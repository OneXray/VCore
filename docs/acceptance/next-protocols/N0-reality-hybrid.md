# N0-E 跟进：自有 rustls 混合 REALITY 入口

日期：2026-09-22。用户已授权在独立分支最小扩展自有 fork。本记录接续 [原始阻塞证据](N0-security.md)，不覆盖其锁定旧 revision 的可复现结果，也不宣称 VCore 已支持 S03/D16。

## 变更边界

- rustls 分支：`feat/reality-hybrid-kx`，起点 `df261c84cbac4f708e63ac8644ce70daa90d771c`（0.23.43）。只本地提交，不 push。
- 实现及独立互通探针提交：`4334fcf00f60188cfdf3c25d2e6cb4a342a01864`，`client: allow explicit hybrid REALITY key exchange`。
- 增加 `RealityClientConfig::with_key_exchange_group`，只接受 X25519 / X25519MLKEM768。默认仍为经典 X25519；builder 与握手使用同一个所选 group，并要求 provider 明确支持 REALITY 密钥复用。
- 混合组的 X25519 component、REALITY 认证 ECDH 与允许提供的经典备选 share 复用同一个临时密钥。没有读取私钥、任意修改 ClientHello/session ID 或新增通用握手 hook。
- 现有证书认证、TLS 1.3 only、ECH/HRR/恢复/0-RTT 限制不变。没有修改其他第三方源码或新增生产密码库依赖；所选生产依赖图仍为 ring，不引入 TLS AWS-LC。
- `reality-tests/` 是 fork 内的独立测试 workspace。它通过公开 provider Interface 接入 RustCrypto `ml-kem 0.3.2`（纯 Rust、Apache-2.0/MIT、显式 zeroize）；该库说明仍标注未审计，此次仅为可行性验证，**不是生产密码实现选型批准**。普通 fork 构建不会依赖这个 crate。
- VCore 的生产 Cargo.toml / Cargo.lock 保持不变，仍锁定原 revision；无相邻仓库 path patch。主锁文件 SHA-256 仍为 `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2`。

## 接口和回归验证

公开测试先以缺少新方法的 E0599 失败，再实现最小入口。sentinel 只验证配置分派/ClientHello，不冒充 ML-KEM 实现；真实密码运算与网络互通另行验证。

在 rustls 仓库执行：

```sh
cargo test --locked -p rustls --no-default-features --features ring,std,tls12,reality --lib --test api --test reality
cargo test --locked -p rustls --no-default-features --features ring,std,tls12 --lib --test api
cargo test --locked -p rustls --no-default-features --features ring,std,tls12,reality --doc
cargo check --locked -p rustls --lib --no-default-features --features ring,reality
cargo check --locked -p rustls --lib --no-default-features --features ring,std,tls12,reality --target aarch64-apple-ios
cargo check --locked -p rustls --lib --no-default-features --features ring,std,tls12,reality --target x86_64-apple-darwin
cargo clippy --locked -p rustls --no-default-features --features ring,std,tls12,reality --lib --test reality -- -D warnings
cargo tree --locked -p rustls --no-default-features --features ring,std,tls12,reality -e normal
cargo fmt --all -- --check
git diff --check
```

REALITY feature 开启时 241 项库测试、217 项既有 API 测试及 9 项新增公共接口测试通过（467 项）；关闭时 227 + 217 项通过（444 项）；doc tests 为 15 通过、5 ignored。无 std 检查及两个 Apple target 的交叉检查通过。上游测试使用 rcgen 等 dev-dependency 时会构建 AWS-LC；这与生产 `-e normal` 依赖图分开记录，不把开发依赖误报为生产 TLS provider。

新增公共测试覆盖默认经典组、显式混合组、缺少/不具备能力的 provider、非法组、低阶公钥、双 share 同一 X25519 公钥、允许经典协商时的真实协商组，以及严格混合模式拒绝经典 ServerHello。ServerHello 测试明确不冒称已完成证书认证。

额外执行 `cargo doc --locked -p rustls --no-deps --no-default-features --features ring,std,tls12,reality` 成功，但有 7 条指向未启用 AWS-LC/FIPS 符号的文档链接警告；同命令加 `RUSTDOCFLAGS='-D warnings'` 为 FAIL。已核对这些链接存在于原始基线，不属于新增 API 链接。本工作包不扩展修复这些上游文档，也不启用 AWS-LC 来掩盖警告。

## 真实 provider 与 Mihomo listener

独立 workspace 的 4 项测试通过：真实 ML-KEM 封装/解封装与 64-byte TLS secret、认证使用同一 X25519、经典 component 完成、错误长度/低阶对端值拒绝。fmt 与 clippy `--all-targets -- -D warnings` 通过；依赖树无 AWS-LC、无第二份 rustls。其锁文件 SHA-256 为 `30285efa415227dd980e50549e95b692c1f84cc25770fa09e02a290300eb3a14`。

原生端通过 VCore 的 `download mihomo` 命令重新解析官方 latest，未调用 GitHub API 或本地编译；实际二进制为 Mihomo v1.19.31 / Go 1.26.8 / darwin arm64，SHA-256 为 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`。伪装 TLS 站点为 OpenSSL 3.6.4，分别限制 X25519 与 X25519MLKEM768。所有端点只监听回环；没有 TUN、系统代理或外部流量目标。

```sh
cargo test --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe
cargo build --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe
cargo clippy --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe --all-targets -- -D warnings
# 以下参数为调用者明确提供的工具路径，脚本不读取相邻仓库。
python3 reality-tests/mihomo_loopback.py --mihomo "$MIHOMO_BIN" --openssl "$OPENSSL_BIN" --probe "$PWD/target/reality-hybrid-probe/debug/reality-hybrid-probe"
```

| Mihomo listener 用例 | 实际结果 |
| --- | --- |
| 经典 REALITY 回归 | PASS，最终 X25519，VLESS 目标连接 1、往返 31 bytes |
| 严格混合 REALITY | PASS，最终 X25519MLKEM768，VLESS 目标连接 1、往返 31 bytes |
| 显式允许经典 component | PASS，初始 hybrid、最终 X25519，VLESS 目标连接 1、往返 31 bytes；不算混合协商 PASS |
| 严格混合客户端面对经典目标 | PASS，预期 HandshakeFailure；目标连接 0、bytes 0 |
| 错误 short ID | PASS，预期 InvalidCertificate；目标连接 0、bytes 0 |
| 错误但有效的静态 X25519 公钥 | PASS，预期 InvalidCertificate；目标连接 0、bytes 0 |

负例检查特定错误类别，超时或任意非零退出码不算通过。原生日志位于 fork 忽略目录 `target/reality-hybrid-probe/mihomo-acceptance.log`，SHA-256 为 `2043b04d60cfc14a3149757402640676a2f9e0e0d66d0430e9e11d474b9a35f7`；对端 debug 日志关闭，不输出认证秘密。各用例退出后清理子进程、监听器和临时配置，并检查没有残留对端进程。

## 签收边界

本工作包只解除“没有公开混合 REALITY 选择入口”的局部障碍。没有完成 VCore 配置字段解析、实际生产 provider、XHTTP 下载腿、Dialer/protect、取消/Stop、资源门槛或跨平台真机互通。N0-E 其他高级安全门禁与 N0 父阶段仍未整体签收。

fork 的新入口选择初始 share，不自动要求服务端最终选择 hybrid；是否允许经典 component 由 provider 控制。严格验收使用仅包含混合组的 provider，并检查最终协商组。允许经典组协商的测试只验证公开 provider 机制，不抵扣矩阵要求的真实混合协商，也不改变当前 VCore 计划的严格策略。

后续生产接入须先获发布授权、把 fork 提交发布到正式依赖分支，再按 [依赖发布要求](../../rustls-reality-release.md) 更新 Git revision 与锁文件、重跑 VCore 门禁。不能提交本机路径依赖或尚不可获取的远端 revision。
