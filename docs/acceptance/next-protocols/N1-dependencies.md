# N1：依赖基线进度

日期：2026-09-23。**依赖升级已收口，[N1公共机制与本阶段门禁](N1.md)全部通过。** 最后一项fork密码依赖升级已获准独立发布，最终锁与复验见[N1-x25519](N1-x25519.md)。最新稳定版原则见开发约定；锁文件用于复现验证，不代表旧版本可永久保留。版本冲突或尚未发布的fork必须明确处理，不能静默回退、换provider或引入本机路径依赖。

## 已完成的独立子包

- [h2 0.4.19 升级与响应关闭回归](N1-h2.md)：VCore 本地提交 `940f18f`，包括全 Debug/Release、原生 Mihomo 流对照及旧协议扩展回归。
- 自有 fork 在 `chore/sync-rustls-0.23.45` 合入官方 `v/0.23.45`，本地提交 `26f3efe5946dbe96410e85b8541ccf5fe7c244a5`；父提交为混合 REALITY 扩展 `4334fcf00f60188cfdf3c25d2e6cb4a342a01864` 和官方 `2976d90fd1c2db6b518700dd101b714069cfcb17`。唯一冲突是 Bogo manifest，保留 REALITY feature，接受上游删除旧 PostQuantum 测试入口。未增加其他 fork 改动。
- fork 普通 TLS 本地 API 回归454项通过；开启 REALITY 时 Debug/Release 各477项通过；独立真实混合 provider 4项、官方 Mihomo 6项互通通过；no-std、iOS arm64、macOS x64、Android arm64检查通过。详细可追溯记录保存在 fork 的 `reality-tests/UPSTREAM-0.23.45.md`，不将这些结果当作 VCore 使用新版依赖的验证。
- 后续获准将同步结果快进合入并推送到 `vcore/reality-0.23`。VCore 主工程及四个实验 workspace 接入 rustls0.23.45 / 官方tokio-rustls0.26.5，仍使用 ring，生产仍为 classic REALITY。新版依赖的独立验证与剩余门禁见 [N1 TLS 接入](N1-tls.md)。
- [基础库、网络栈与实验依赖更新](N1-foundation-dependencies.md)：完成下表 API 适配、兼容传递锁刷新、Windows 配套例外确认和独立回归。全目标 Clippy 的13项既有测试告警已清理并通过，不改写此前失败记录。
- [REALITY x25519-dalek3.0.0](N1-x25519.md)：获准单独分支升级/验证/推送，VCore及四个spike同步公开revision，最终N1门禁重跑通过。

## 正式仓库来源

自有fork的正式来源是[OneXray/rustls](https://github.com/OneXray/rustls)。当前生产依赖为单独获准发布的`chore/x25519-dalek-3`分支，公开revision `bb4092cc32a101869406d0b8242b173372a9d3ea` / rustls0.23.45 / x25519-dalek3.0.0；VCore锁定同一revision，不依赖相邻checkout。`git ls-remote`同时确认原`vcore/reality-0.23`仍保留`26f3efe5946dbe96410e85b8541ccf5fe7c244a5`，没有隐式前移或合并。

以下保留较早来源修正提交 `1cc201c` 的历史证据：该提交同步修正主工程及四个实验 workspace 的 manifest/lock、TLS 来源审计、可执行字段/组合清单的源码链接和现行发布文档，**只改来源地址，版本和完整 revision 不变**，当时远端仍为 `df261c84cbac4f708e63ac8644ce70daa90d771c` / 0.23.43。它的 hash 和通过结果不转记为新版 TLS 的证据。

地址修正实际执行：

| 命令 / 范围 | 结果 |
| --- | --- |
| 主工程 `cargo fetch --locked`，以及 security/stream/datagram/hysteria2 四个 `--manifest-path …/Cargo.toml` | 五个 workspace 均成功从新来源获取锁定依赖 |
| `uv run --project scripts --locked vcore-scripts check tls-dependencies` | PASS：单一 OneXray/rustls0.23.43、官方binding、ring；SS局部AWS-LC例外未扩大 |
| `uv run --project scripts --locked python -m unittest discover -s scripts/tests` | 42项PASS；先保留旧审计拒绝新来源的RED，再修改审计，新来源接受/旧来源拒绝 |
| `cargo test --locked --all-features --all-targets` | 572 lib + 2 h2 + 4 compatibility + 2 fixture PASS；ignored不计通过 |
| scripts ruff check/format、`git diff --check` | PASS |

被测输入为父提交 `940f18f` 加来源修正。manifest/lock、审计与测试、字段/组合清单的 `git diff` SHA-256 为 `5c20eb4f45379105c26835dcf75667e322fef4ab96a17b82af4e2792c69a3472`，不包含说明文档；主锁SHA-256为 `5bc77e3989298bb676521df190c574c7773bbda4d515c1033735f629e5518099`。日志目录 `target/interop/runs/n1-rustls-origin-20260923/`。本次来源修正没有重跑外部互通或Release，不能将h2子包的旧锁hash改写为新锁。

## 最新稳定版审计与兼容边界

通过当日官方[crates.io sparse registry](https://index.crates.io/config.json)和官方发布入口核对。下表保留升级差异及已批准的兼容边界：

| 直接使用的依赖 | 当前版本/系列 → 当日最新稳定版 | 状态 |
| --- | --- | --- |
| rustls fork | 0.23.43 → 0.23.45 | 已发布并接入；验证与门禁见[N1 TLS](N1-tls.md) |
| tokio-rustls | 0.26.4 → 0.26.5 | 已升级；与上述fork共同验证 |
| 流实验 tokio-tungstenite | 0.29.0 → 0.30.0 | 已升级；12项接口测试与42项Mihomo互通通过，不沿用Clash-RS旧pin |
| base64 / md-5 / rand / sha2 | 0.22 / 0.10 / 0.9 / 0.10 → 0.23.1 / 0.11.0 / 0.10.3 / 0.11.0 | 已适配并通过旧协议回归 |
| rcgen / smoltcp | 0.14.8 / 0.13.1 → 0.14.10 / 0.14.0 | 已升级；证书/负例、netstack17项与平台构建通过 |
| 安全实验 hpke | 0.13.0 → 0.14.1 | 已适配公开接口；Debug/Release各7项通过，ECH仍仅Offered |
| fork 的 x25519-dalek | 2.0.1 → 3.0.0 | 已独立升级、验证并发布依赖分支，VCore接入及最终N1复验PASS |
| windows 配套 crates | 最新windows0.62.2要求core0.62.2/collections0.3.2，而后两者单独最新为0.100.0 | 2026-09-23已获明确同意：保留官方兼容配套版本，不混入0.100.0；这是当前SDK组合的局部例外，不是Windows原生构建通过证明 |

其余直接依赖及兼容传递补丁锁已刷新与验证，包括tokio、futures-util、http、serde、regex-automata、socket2、thiserror、uuid、webpki-roots；具体版本/输入/证据见[本轮记录](N1-foundation-dependencies.md)。官方Shadowsocks1.25.0、h2 0.4.19和quinn0.11.12在本次查询时已是各自最新稳定发行。上游库的传递版本约束单独核对，不通过修改第三方源码强行解除，不能把兼容锁刷新描述为全图均升级最新大版本。

Windows 配套例外依据官方 [windows0.62.2 manifest](https://docs.rs/crate/windows/0.62.2/source/Cargo.toml)。未来升级完整SDK时须重新核对其配套约束并验证原生Windows目标，不能永久保留旧组合，也不能把这项批准扩大到rustls/provider或其他旧版依赖。

来源修正轮次没有push；后续TLS/密码依赖轮次仅按各次授权推送rustls依赖分支，VCore仍只本地提交。没有变更Windows依赖。N1覆盖/互通CLI已由[N1公共基础](N1.md)签收；正式新协议、N0其余门禁、真机、Windows原生构建、远端CI与发布不由依赖升级抵扣。
