# N1：基础库、网络栈与实验依赖更新

日期：2026-09-23。此独立依赖子包已完成下述回归，**不是完整 N1 或新协议签收**。生产仍为 Invoke v5 / schema14、ring、classic REALITY；未开放未来字段，未修改第三方源码、自有 rustls fork 或 Git 依赖 revision。

## 版本与适配

通过当日官方 [crates.io](https://crates.io/) 的 crate API 逐项查询稳定、非 yanked 版本，核对主工程、netstack 和四个实验直接声明的 46 种注册表依赖。兼容传递依赖一并刷新；原始查询与最终锁对应表保存在本轮日志目录。不是所有传递依赖均可脱离其上游的版本约束升级大版本。

| 范围 | 本次锁定版本 / 处理 |
| --- | --- |
| 主工程基础库 | base64 0.23.1、md-5 0.11.0、rand 0.10.3、sha2 0.11.0；随机范围保持原来的开闭区间，仅改用 `RngExt` |
| netstack | smoltcp 0.14.0，原 feature 集不变，无新增 socket 工厂或平台依赖 |
| 测试证书 | 主工程及使用 rcgen 的实验统一为 0.14.10，仍用 ring |
| 流实验 | tokio-tungstenite 0.30.0，仅开启 handshake；日志关闭，不引入第二套 TLS |
| 安全实验 | hpke 0.14.1 / rand 0.10.3；通过公开 `*_with_rng` 接口注入 OS 播种的 StdRng，随机源失败返回脱敏错误；只开启 alloc/aes/x25519 |
| 兼容补丁 | tokio 1.53.1、futures-util 0.3.34、http 1.5.0、serde 1.0.229、regex-automata 0.4.18、socket2 0.6.5、thiserror 2.0.20、uuid 1.26.1、webpki-roots 1.0.9 等；五个锁同步 |
| Windows 局部例外 | 已获明确同意，保留最新 windows 0.62.2 所需的 windows-core 0.62.2 / windows-collections 0.3.2；不混入单独发布的 0.100.0，依据[官方 manifest](https://docs.rs/crate/windows/0.62.2/source/Cargo.toml) |
| 未变的密码学边界 | rustls 0.23.45 / tokio-rustls 0.26.5 / ring 0.17.14；rustls Git revision 仍为 `26f3efe5946dbe96410e85b8541ccf5fe7c244a5`；官方 SS 2022 的既有局部 AWS-LC 例外不扩大 |

升级先暴露公开接口编译失败：HPKE 的 keypair/sender 与 RNG 初始化调用、rand 扩展 trait、测试中的 SHA-256 十六进制格式化。只适配自有调用点，现有认证失败、数据完整性及关闭断言不弱化。安全实验依旧只证明 ECH **Offered**，不代表对端 Accepted。

同时清理之前已复现的 13 项测试 Clippy 告警：10 个重复 trait 导入、3 个固定尺寸 `chunks_exact`；改用 `as_chunks` 时保留奇数字节余项的校验和处理。没有关闭 lint。此前失败记录保留在 [N1 TLS 接入](N1-tls.md)，本轮另记新的全目标通过。

## 被测输入

- 父提交：`40fa8049592e687f6693df485b4d2bf621dc2bde`，加本轮源码与依赖差分。测试发生于提交前，不将父提交单独描述为已测新版本。
- 差分 SHA-256：`0a7c296e5d159255be311ca520ca1bd63e02f80e2d1e517da0bbb9d9edfea234`。重算：`git diff 40fa804 -- Cargo.toml Cargo.lock crates src tests/protocols/spikes | shasum -a 256`；说明文档不在该摘要中。
- 环境：macOS 27.0 ARM64（26A428）、Rust 1.98.1（48a229cea）、Xcode 27.0（27A266a）、Android NDK 28.2.13676358 / API24、Apple Container 1.4.1。
- 本轮在工作目录构建，使用 Cargo 缓存；没有重新做空缓存或无相邻 checkout 的隔离构建，不借用上一轮隔离结果。

| Lockfile | SHA-256 |
| --- | --- |
| 主工程 | `425500945de939af6b81e8a9193612a3a27a205e5d1a700e485f1b73ce764690` |
| security | `3239de18644ab16d7bf3579b8d96138171c04ea5071cba28e29957d13dc6c6a3` |
| stream | `5f2705752dbd85e042388f9e6d598f2eb191dffe906e820e3fc89a1359c53762` |
| datagram | `606078b809934ff5915e612d29e2e892553ef51857d97d2ac37b5778889cb335` |
| hysteria2 | `e21e7bdebcc6e3697ea62aca6373373e2ba08f44bf64cce62c9958826515cbcc` |

## 实际验证

Python 命令均经 `uv run --project scripts --locked` 执行。spike 使用各自 `--manifest-path tests/protocols/spikes/<name>/Cargo.toml` 和仓库内独立 target 目录；所有结果对应上表最终锁，不把更新前的通过沿用到最终输入。

| 命令 / 范围 | 结果 |
| --- | --- |
| `cargo test --locked --all-features --all-targets` 及 `--release` | Debug / Release 各 572 lib + 2 h2 + 4 compatibility + 2 fixture PASS；ignored 不计通过 |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | PASS，包含此前失败的测试目标 |
| netstack `cargo test --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets` 及 `--release` | Debug / Release 各 17 PASS；raw-IP 双栈、TCP/UDP、ICMP、背压和停止回收 |
| netstack all-targets clippy、`cargo check --locked --no-default-features --lib` | PASS；精简构建的既有 dead-code warning 不宣称已全部清理 |
| 四个实验 `cargo test --locked --manifest-path …` 及 `--release` | security 7、stream 12、datagram 4、hysteria2 6，Debug / Release 均 PASS |
| 四个实验 `cargo clippy … --all-targets --no-deps -- -D warnings` | PASS；不包含刻意 compile-fail 的 `missing-session-hook` feature |
| security / stream `cargo check --locked --manifest-path … --lib --target …` | iOS arm64 与 Android arm64 / API24 均 PASS；仅库交叉检查，不是移动设备运行 |
| `vcore-scripts check tls-dependencies`、`check c-header` | PASS；单一公开 fork、官方 binding、ring、SS 局部例外及 C/C++ 头文件 |
| scripts unittest、ruff check/format；主工程/security/stream fmt；shell syntax | 42 项脚本测试 PASS，其余检查 PASS |
| `python tests/protocols/spikes/stream/run.py` | 42 项 PASS：TLS/WS/WSS/gRPC、服务器先发、关闭差分及认证/路径/protect 负例 |
| `vcore-scripts check mihomo-interop --container --extended` | 旧协议基础与扩展 PASS，35.22s；含 100 次生命周期和 100 次 32-flow 重建 |
| 重建 probe 后 `python tests/protocols/spikes/hysteria2/run.py --native-hysteria` | 8 项 PASS；含 Mihomo 与原生 Hysteria 的 UDP-disabled TCP |
| `python tests/protocols/spikes/hysteria2/native_h3.py --compare-mihomo-close` | 11 项 PASS；原生 Xray H3 与官方 Mihomo 客户端同对端关闭对照 |
| `vcore-scripts build apple` | 5 目标 Release 及 XCFramework PASS：iOS arm64、模拟器 arm64/x86_64、macOS arm64/x86_64 |
| `vcore-scripts build android` | arm64-v8a / x86_64 Release PASS；标准生产 features，无 interop-test，产物身份 API v5/schema14 |

100 次 32-flow 重建耗时 17,433ms；清理后 FD=6、在用堆 63,664B、RSS 18,736KiB。只作为本轮短程采样，不推断 1800 秒长测或设备内存结果。自建对端与临时配置已清理，专用网络和镜像缓存保留。

对端重新从官方 latest 下载，不查 GitHub API、不本地编译、不回退缓存。实际 Mihomo v1.19.31，Darwin ARM64 hash `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`，Linux ARM64 hash `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`；Hysteria 和 Xray 的完整身份见本轮结构化报告。内容 hash 不是官方签名证明。

本轮 `dist/` 内交付库摘要（Apple模拟器及macOS为脚本合并的双架构库）：

| Release 产物 | SHA-256 |
| --- | --- |
| iOS arm64 | `5d938f8004aa69c57a1088b2af04a4c7c4e321a3b5cf80c2a3af57591b4d62c7` |
| iOS simulator arm64/x86_64 | `35efc96818d016c916d731f523be4b1319ed3d3cd8af2ea1ff2bd1387b44596a` |
| macOS arm64/x86_64 | `ce0a57a573f6cbe79f4516f4a147a7689e1d4860c1c532ea18da19bcfe7fac2d` |
| Android arm64-v8a | `d7688937104635dc039e415fbf39857e7a9044b99006dff09e5cc4af6d3386a8` |
| Android x86_64 | `16a69b01861a1abfa0d4930db909a168e4f719cfdcbd4e3116fbe2d2408c3df5` |

## 证据与剩余项

原始日志与构建产物位于 `target/interop/runs/n1-latest-20260923/`，下表文件相对该目录，明确注明的除外。保留升级前编译失败及清理前 Clippy 失败，不覆盖成通过；不提交本机路径、合成凭据或原始流量日志。

| 记录 | SHA-256 |
| --- | --- |
| `core-debug-final.log` | `c6b12e7be16a9134cfd1b305270b383161a5a4fa857898d9fa5e605a97e330a2` |
| `core-release.log` | `d40f79abc69f5faa1d79a090378576f474af77affb9b02921bc54691c64c9ab7` |
| `clippy.log` | `5526ec0917b5545a2e9db74b55e2c0102f283fd60b1a2a938f00b3c2ec2db0c7` |
| `mihomo-extended.log` | `05fb899b154aada60cade104d3a1d669bcfc1e8cef40d9453107a3b20b5dcdc3` |
| `hysteria2-result.json` | `9c5a6707d0c952d26972e32404d6d0a29cce97fbf99f3081138801685b720f99` |
| `../n0-stream-20260923T062734Z-pm0bmvw3/report.json` | `a7b0d380705c74eb4c22fda616c437b89db13169a046d2eba631edd58d770545` |
| `target/interop/n0-xray-h3/20260923T062907Z-ac83a087/result.json`（仓库根相对） | `dadbd96a24f1eac572dd05b12c7ae4e789850afa6c7649278fa9a36ced1a9d7a` |

- 自有 rustls fork 的 x25519-dalek 2.0.1 → 3.0.0 仍是独立待评估项。本轮 HPKE 实验经官方依赖使用 3.0.0，不等于生产 REALITY 已升级；不能声称整个依赖图均为最新大版本。
- Windows SDK 配套例外不抵扣 Windows 原生构建；未执行真机、物理 TUN/IPv6、Windows、远端 CI、签名发布或 1800 秒长测。本轮未重跑原生 hopping 或既有半关闭诊断，历史失败不改记为 PASS。
- N1 公共生产 Adapter、resolver/资源观察、配置及覆盖/互通 CLI 仍需后续开发；实验通过不代表 N2–N8 正式协议已实现。
- 本轮只本地提交 VCore，不 push，不改变其他仓库。
