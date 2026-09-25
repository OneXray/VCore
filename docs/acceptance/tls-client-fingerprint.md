# TLS 指纹接线验收（2026-09-25）

> 本页记录首次 boring 接线时的输入，普通 TLS 当时仍锁定旧 rustls fork，但未启用其 REALITY。随后已切到官方 crates.io rustls，并退役旧 fork；原始 hash 与成绩不重写。最新替换回归见 [fork 退役验收](rustls-fork-retirement.md)。

本轮在 `feat/tls-client-fingerprint` 上接入共享 TLS 后端，基线为
`6a6b681006dad5207db330278c30faa4716be59d`，验证的是其后的未提交工作树。
Invoke API 保持 v5，配置 schema 为 19。契约见 [TLS 指纹](../tls-client-fingerprint.md)。

## 已执行范围

| 验证 | 当次结果 | 证明范围 |
| --- | --- | --- |
| 共享 security 纯内存测试 | Debug/Release 各 22 项 PASS | 两条 TLS 路径的证书/签名/ALPN/mTLS、票据预算与隔离、取消、关闭及 Vision record 边界 |
| strict 配置测试 | Debug/Release 各 74 项 PASS | `chrome120`、空串、未知名称/null/错型、证书 pin 独立性、下载腿继承/清除和 H3 拒绝 |
| memory/config 集成测试 | 58 项 PASS | feature/stream foundations、Trojan/VMess/VLESS/XHTTP 配置、codec 与 sing-mux 配置 |
| 全目标测试编译 | PASS（`--no-run`） | 不把编译当作全部测试执行；未运行历史宿主监听器测试 |
| 默认关闭及四种独立出站 feature | PASS | 无默认 feature，以及 AnyTLS/Trojan/VMess/VLESS 各自编译 |
| Python / Ruff / fmt / Clippy / C header / TLS 依赖审计 | PASS；Python 130 项 | 构建、配置、依赖来源和离线 harness 检查 |
| `chrome120` 公开 YAML + 容器业务 | 30/30 PASS | 四协议、TLS/REALITY、Vision direct、XHTTP、mTLS/负例与关闭参照 |
| `chrome120` 启停/自有资源 | 4/4 PASS，共 80 轮 | gRPC TLS、Vision REALITY；每类 20 轮生命周期及 20 轮资源检查 |
| 未设置 profile 的 REALITY | 4/4 PASS | TCP 正例/错误身份、Vision direct、XHTTP stream-one；不继承旧 rustls 成绩 |
| Apple Release | 五目标 PASS | iOS arm64、simulator arm64/x86_64、macOS arm64/x86_64，XCFramework 打包 |
| macOS ARM64 最终链接 | PASS | C 显式链接 libc++、Swift 模块自动链接；各 1,000 次 version/Free，身份 schema 19 |
| Android Release | 两 ABI PASS | arm64-v8a/x86_64；ELF 架构、依赖及同 NDK libc++ 伴随库已检查并打包 |

主机为 macOS ARM64、Rust 1.98.1、Xcode 27.0（27A266a）、CMake 4.4.3；
Android 使用既有 NDK 28.2.13676358 / API 24。全部网络对端与原站都位于独占
Apple Container 1.4.1 host-only 网络，未启动宿主测试对端/原站或修改宿主路由/DNS；
被测 VCore 自身的本机客户端入口不属于参考服务端。

30 项业务用例复用既有容器消费者，节点通过公开 YAML 设置 profile。AnyTLS 与
Trojan/VMess 的 TCP/WS/gRPC 共七组；其余覆盖 VLESS TCP/WS/gRPC 的 TLS/REALITY，
XHTTP 三模式与独立 REALITY 下载腿、Vision TLS/REALITY 及真实内层 TLS 1.3 direct，
错误证书/REALITY 身份/ALPN、gRPC mTLS，以及四组关闭行为参照。
关闭参照客户端使用 Mihomo 当前 `chrome`，这里只比较关闭行为，不宣称 ClientHello 等同。
本轮没有恢复已取消的统一 EOF 后尾包要求。

## 依赖与证据身份

- boring、boring-sys、tokio-boring 5.2.0：远端 Git revision
  `b953b21e689bd2b6c9acb5af2f9cdaa053ce0284`，无本地路径覆盖；fork 功能分支已提交并推送，未合并主分支。
- BoringSSL 子模块：`e2a57cfb4d915b4ba820585aef9fdee7bca13fe5`；classic REALITY patch SHA-256：
  `0b55587d5950d3c35991aa5e37fe294ffea023cc9c9fb8a8478683aa113a55ab`。
- rustls 0.23.45：`bb4092cc32a101869406d0b8242b173372a9d3ea`，仅 ring，REALITY feature 关闭。
- Cargo.lock SHA-256：`1143e34779f2b83beb5e0a78bb0cdeedae29d241d601428b7c49a78e6d696817`。
- Mihomo 每轮重新通过官方 latest 下载，未查 API、固定下载版本或从源码编译。
  本轮得到 v1.19.31 / Go 1.26.8 / Linux ARM64 / with_gvisor；二进制 SHA-256：
  `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`，下载包：
  `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4`。

本地忽略目录中的原始证据（不会随仓库发布）：

- `target/interop/runs/fingerprint-vcore-f5-20260925-01/vless-results.json`：30 项 PASS，
  `source_unchanged=true`、`cleanup=true`；源码树摘要
  `f6764aa5a3ad176c8d203373c2cd1c3737844524c619b4a4499ed64d8520a421`。
- `target/interop/runs/fingerprint-vcore-lifecycle-20260925-02/vless-results.json`：冻结源码后四组
  PASS，`source_unchanged=true`、`cleanup=true`；源码树摘要
  `268490b2ff5d64b20570ca2020583a35cde7cf3dbd2152e4107b583efdf4f657`。
- `target/interop/runs/fingerprint-vcore-default-20260925-01/vless-results.json`：未设置 profile 的
  REALITY 四组 PASS，来源摘要与生命周期 `-02` 相同，快照与清理均通过；最终容器列表为空。
- `target/interop/builds/fingerprint-f5/{apple,android}/`：生产 feature 的 Release 输出，
  不包含 `interop-test`。
- `target/interop/fingerprint-f5-*-build*.log`、`*-package.log`、`*-tests.log`：平台构建与脚本日志。

30 项业务运行后只扩展了构建/打包、模块链接声明、生命周期用例选择及对应脚本测试；
生产 Rust、Cargo.lock 与这 30 项的配置和断言不变。后续运行各自保存新的来源摘要，
不以新的脚本身份覆盖原始证据。

| 交付候选 | SHA-256 |
| --- | --- |
| Apple iOS arm64 静态库 | `dd8790c17b916015d52592f045797ea764c146b8be184be25723b8ad53651857` |
| Apple iOS simulator 双架构静态库 | `fb8fb094c2c9776fcf64fec3191375c6330a0870900087f0a0e633198cfeb677` |
| Apple macOS 双架构静态库 | `9e7a5a2cd939846c4ff090e39089b4cb2fa451fbecdd36274274b9da1d973478` |
| Android arm64-v8a libvcore.so | `488d82bd3abf24613fdee3991fe1574a5603f30e4a8fea27b21b5b9647c0c343` |
| Android x86_64 libvcore.so | `8a4ca67f69cacea67a0dadefac2cd2b41a40299ed4f46ec107bfeddd7aab63a4` |
| Android arm64-v8a libc++_shared.so | `ab4e6c71b96b851de45a8a9bd86369e7dbc2130a44b3b4520564be94847910f2` |
| Android x86_64 libc++_shared.so | `e4cd73c8a3607269f3be58d15c21f78bff112e27f9398d6261e5f965668f8746` |

## 保留的构建失败与修正

Android 初次构建失败：boring-sys 分别构建 ssl/crypto 时执行两次 configure，显式的
`aarch64-linux-android24-clang` 被 NDK 替换成其自身 clang。第二次重新传入包装器触发
CMake 清空缓存，随后混入 macOS `-arch`/sysroot；单独 ARM64 重跑也失败。
用仅声明 C/C++ 工程的两次 configure 在全新目录稳定复现，去掉编译器覆盖即通过。
修正只在自有构建入口：通过自有 toolchain 包装将 ABI/API 交给 NDK；没有修改第三方源码。
旧失败构建缓存移入 `target/interop/fingerprint-f5-android-failed-cmake` 保留，重新构建通过。

链接检查还发现 Android 需要随库交付 libc++_shared，已增加实际复制行为的先失败后通过
回归测试。Apple C 宿主缺少 `-lc++` 的链接失败也保留为日志，显式链接与 Swift module map
自动链接两种路径随后均通过。交叉编译/打包不冒充设备加载或 TUN 运行结果。

首次生命周期补验 `fingerprint-vcore-lifecycle-20260925-01` 的四组业务断言均 PASS、
容器清理通过，但总报告为 FAIL：运行中补正了 `scripts/README.md` 的默认 feature 示例，
该文件属于来源摘要范围，因此 `source_unchanged=false`。没有改判这一轮；完整冻结文件
后另开 `-02` 重跑。两轮都不借用实验客户端或旧后端的资源回收结果。

## 复现与未验收范围

```sh
cargo test --locked --all-features --lib security::
cargo test --locked --all-features --lib config::
cargo test --locked --release --all-features --lib security::
cargo test --locked --release --all-features --lib config::
cargo test --locked --all-features --all-targets --no-run
cargo clippy --locked --all-features --lib --bins -- -D warnings
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint target/interop/runs/<fresh-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_vless_container \
  target/interop/runs/<fresh-default-run> N4-TCP-REALITY-BASE N4-TCP-REALITY-NEG \
  N4-VISION-REALITY-INNER-TLS N4-XHTTP-STREAM-ONE-REALITY-BASE
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
```

尚未验证 Windows 原生构建、远端 CI、Android/iOS 真机、物理 TUN、签名安装、
公网服务兼容范围、性能/包体回归及最终依赖许可证交付。完整 N4/N5/N7 组合门禁未重跑；
不从这些代表性用例推导全部字段组合通过。非空 ALPS、QUIC/H3 指纹、其他命名 profile、
实际 ECH/PQ REALITY 明确不在当前实现范围内。
