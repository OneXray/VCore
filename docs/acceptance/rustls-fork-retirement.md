# 自有 rustls fork 退役验收

日期：2026-09-25。分支 `feat/tls-client-fingerprint`，被测父提交
`6a6b681006dad5207db330278c30faa4716be59d` 加本次工作树变更。
Invoke API v5 / schema19。此报告验证依赖替换，不把历史 N0–N5 或首次指纹接线的
成绩倒填为新锁结果，也不宣称完成整个协议/平台发布门禁。

## 变更与来源

- 主工程及 security/stream/datagram/hysteria2 四个独立 workspace 移除 rustls Git patch，
  锁定唯一官方 crates.io rustls 0.23.45、官方 tokio-rustls 0.26.5。
- 普通无指纹 TLS、QUIC/H3 和共享 WebPKI 验证使用官方 rustls + ring；
  命名 ClientHello 与所有 classic REALITY 使用自有 boring，不保留 rustls REALITY 回退。
- TLS 来源审计拒绝 rustls Git/path/非官方 registry/第二份来源及 REALITY/AWS-LC/FIPS
  feature；boring 的 revision、真实依赖边、features 与 SS 的局部 AWS-LC 边界继续检查。
- security spike 删除两个依赖旧 fork 的 REALITY 选择实验；保留五个普通 TLS record、
  HPKE/ECH 纯内存测试。删除的是退役接口实验，不是把失败用例移出当前协议验收。
- 当前契约迁到 [TLS 依赖](../tls-dependencies.md)，AGENTS、README、脚本和源码索引同步。
  旧 fork 的失效链接移除；通用上游 API 链接与 fork 专有历史描述分开。

旧 fork 已退役，远端计划永久删除。本次不操作远端，不改写 Git 历史；历史提交、
验收摘要和原始失败保留，但不承诺依赖旧 fork 的 Git 提交还能重建。
混合 REALITY 的旧实验不能抵扣当前 boring 的 S03/D16 门禁。

退役修改目前只在本功能分支。本轮只读检查确认本地 `main` 仍声明旧 rustls patch；
必须先将替换变更发布并合入实际使用的分支，再永久删除远端，否则旧分支的干净构建
仍会失去依赖来源。本次不自动 push、合并或删除其他分支。

| 依赖 / 工件 | 固定身份 |
| --- | --- |
| rustls 0.23.45 registry checksum | `0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634` |
| tokio-rustls 0.26.5 registry checksum | `b0c85f2c3ef0b1cd58b36682f4b17aaa995f0e5db534d85692b4903abce21f67` |
| boring / boring-sys / tokio-boring 5.2.0 | `b953b21e689bd2b6c9acb5af2f9cdaa053ce0284` |
| BoringSSL submodule | `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5` |
| REALITY patch SHA-256 | `0b55587d5950d3c35991aa5e37fe294ffea023cc9c9fb8a8478683aa113a55ab` |
| 主 Cargo.lock SHA-256 | `0e8526449ee20749723d9ad522b9720029cb99a8a89e4d348b91289b2508756d` |

rustls / tokio-rustls 的最新稳定、非 yanked 版本已通过官方 sparse registry 核对。
普通 API 的官方源码索引固定在 0.23.45 提交
`2976d90fd1c2db6b518700dd101b714069cfcb17`；不把这个上游提交当成 fork 专有 API 的来源。

## 本轮执行结果

主机 macOS 27 ARM64，Rust/Cargo 1.98.1，Xcode 27.0 / SDK 27，
Android NDK 28.2.13676358 / API 24。纯内存测试不创建宿主服务端；所有网络协议端、
参考客户端入口和原站位于 Apple Container 1.4.1 的 host-only 隔离网络，MTU 1500。

| 范围 | 结果与边界 |
| --- | --- |
| security / strict config / QUIC sniffer | Debug、Release 各 22 / 74 / 18 项 PASS |
| 内存配置/流/codec 集成 | Debug、Release 各 58 项 PASS |
| netstack | 17 项 PASS |
| QUIC pending send / cancel | 1 项纯内存测试 PASS |
| 独立 spikes | security 5、stream 12、datagram 内存 QUIC 1、hysteria2 wire decoder 3 项 PASS；其余历史宿主服务测试未执行 |
| 四个 spikes 的依赖图 | 各一份官方 rustls 0.23.45，无 Git/path rustls |
| 全目标编译 | `cargo test --locked --all-features --all-targets --no-run` PASS，不计为全部测试执行 |
| feature 边界 | 无默认 feature 与 AnyTLS/Trojan/VMess/VLESS 各独立出站 check PASS；精简 feature 的既有 unused/dead-code warning 未隐藏 |
| 脚本与静态检查 | Python 130 项、Ruff check/format、Rust fmt、C header、TLS 依赖审计和 diff check PASS |
| Clippy | 最终 `--locked --all-features --all-targets -- -D warnings` PASS；原始两轮失败见下文 |
| 协议声明目录 | 145 字段 / 69 组合家族 VALID；这是清单检查，不是所有字段行为 PASS |
| 未设置 profile 的容器回归 | 10/10 PASS：TLS TCP/WS/gRPC、mTLS、Vision TLS、classic REALITY 正负例/Vision/XHTTP stream-one |
| `chrome120` 容器回归 | 10/10 PASS：AnyTLS、Trojan WS、VMess gRPC、VLESS TLS/REALITY、Vision、mTLS 与证书/身份负例 |
| XHTTP 双腿安全 | 112/112 PASS：H1 38、H2 38、H3 36；继承/覆盖、证书 pin/name/skip/mTLS 正负例 |
| Apple Release | 五目标及 XCFramework PASS：iOS arm64、simulator arm64/x86_64、macOS arm64/x86_64 |
| Android Release | arm64-v8a/x86_64 PASS；ELF 架构及同 NDK libc++_shared.so 伴随库已核对 |
| macOS ARM64 最终链接 | C 显式 `-lc++` 与 Swift module map 自动链接，各 1,000 次 version/Free PASS，身份 schema19 |

三份容器报告均 `status=PASS`、`source_unchanged=true`、`cleanup=true`，
`owned_remaining=[]`。Mihomo、Xray 每轮重新从官方 latest 获取，未查询版本 API、
编译 Mihomo 或回退旧下载缓存。H3/mTLS 沿用已批准的 xcaddy 构建 Caddy 网关，
在容器内汇合至同一 Xray handler；不冒称 Xray 直接提供所有 mTLS 行为。

实际对端：Mihomo v1.19.31 / Go1.26.8 / Linux ARM64，二进制 SHA-256
`1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`；
Xray 26.3.27 / d2758a0，SHA-256
`c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04`；
Caddy v2.11.4 / xcaddy v0.4.7，SHA-256
`7d31854f54db2b1d0c1fe0dc0055238290b03bc0fd595ecbf3db0d75855d0d41`。
完整下载和隔离身份保存在各次 JSON 中，hash 不是官方签名验证声明。

## 输入与证据

日志目录为 `target/interop/rustls-official-20260925/`，生产产物为
`target/interop/builds/rustls-official-20260925/{apple,android}/`，均不入 Git。
三次网络回归使用同一来源树摘要
`7e256cf76d8c9673fb1b2bdc988906726ead7c60a712f83eb74af29f210efcff`。
之后只修改文档链接、审计负例中的示例 URL 和两处测试 lint；生产 Rust、依赖锁、
容器 fixture 与网络断言不变。静态检查、脚本和受影响内存用例随后重新执行。

| 原始结果（`target/interop/runs/` 下） | SHA-256 |
| --- | --- |
| `rustls-official-standard-20260925-01/vless-results.json` | `e678c3a1e134b96402af097e034a8d6e325936e36aae3774b8d6d56e859843bf` |
| `rustls-official-profile-20260925-01/vless-results.json` | `9d2471ccdf17752390f1f97f22280003afaba46a9c29b16c81b6c8eebd2204ca` |
| `rustls-official-xhttp-security-20260925-01/xhttp-security-results.json` | `51e1fe37cde1ea1646800d336b0f866ce6c17ca360de9ec01238e64e90153d3b` |

| 生产 feature 的交付候选 | SHA-256 |
| --- | --- |
| iOS arm64 libvcore.a | `32b89a64f04cc192b5d416ffc1f3e7fd1586f02adce6fa598cfd7ac33f9b2f30` |
| iOS simulator universal libvcore.a | `5780d301532cc82ea91ac2e87afc5da88875cc3cb71ca91df0297a7849142ece` |
| macOS universal libvcore.a | `c5214c2f18519c65c79866678e7ff6e7f11b6c9e04d12ddd30115d62d1676475` |
| Android arm64-v8a libvcore.so | `2864f28ba5e63d29cb13912bce8ec4dca94500a220bbff61adbeef91604d424c` |
| Android x86_64 libvcore.so | `926383c5fc34501d422c5d190dd4298eb83734dec904b17d2367ac5e7ec0c2ab` |
| Android arm64-v8a libc++_shared.so | `ab4e6c71b96b851de45a8a9bd86369e7dbc2130a44b3b4520564be94847910f2` |
| Android x86_64 libc++_shared.so | `e4cd73c8a3607269f3be58d15c21f78bff112e27f9398d6261e5f965668f8746` |

## 原始失败与未执行边界

### 无相邻源码的独立快照

从暂存 tree `8c8ffc6e275708f25823ba6e5bac7b0c446f4b23` 使用 `git checkout-index`
导出至新临时目录，无 `.git`、相邻 rustls/boring 或研究 checkout。
最终代码输入摘要为 `00b496d1db77f8ae42d56442a04b1986d1ec97f3d9a1b20eea81f8e7e3c718d2`，
对父提交代码 diff SHA-256 为 `1dd8a53e82f86f8055bec3d431507de963f26c63a2612ba0cdeb829549cae452`。
该快照依次通过 `cargo fetch --locked`、offline locked all-features metadata、
offline security 22 项及 TLS 来源审计；rustls 解析为官方 registry，boring 为上述远端 revision。
复用了全局 Cargo 下载缓存和已有 target，**不是空缓存验证**；证明的是无相邻源码/
path patch 的依赖解析和实际编译运行。补写本段及历史链接文案未改变代码输入。
日志单列为 `isolated-fetch.log`、`isolated-metadata.json`、`isolated-security.log`、
`isolated-audit.log`，不将临时快照冒称远端 CI 或已测试的后续 commit。

### 静态检查与保留门禁

全目标 Clippy 首轮因 `vmess_public` 的两个冗余借用失败；移除借用后又发现
`vmess_config` 中 Tungstenite 固定的未装箱 HTTP 错误类型触发 `result_large_err`。
只在该测试 callback 语句上标注附原因的局部 lint 例外，没有修改第三方类型或屏蔽全局
Clippy；最终全目标通过，受影响 duplex 内存测试 Debug/Release 重跑通过。
`clippy.log`、`clippy-recheck.log` 和 `clippy-final.log` 分开保留。

未重跑完整 N4/N5 组合、全部生命周期长测或首次 F0–F4 指纹实验；没有以本轮 132 项
代表全部协议签收。Windows 原生、远端 CI、物理设备/TUN、签名安装、性能/包体、
最终许可证交付仍为 NOT RUN。未开放混合 REALITY、ECH、QUIC 指纹或其他命名 profile。
