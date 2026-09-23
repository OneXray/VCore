# N1：已发布 rustls 0.23.45 接入

日期：2026-09-23。TLS 依赖子包已接入并完成下列本机回归；**不代表完整 N1、全依赖升级或正式发布签收**。生产仍使用 ring、classic REALITY 和 Invoke API v5 / schema revision 14，没有新增 YAML 字段或协议功能。

## 来源与版本

在独立同步分支完成验证后，经授权将 `chore/sync-rustls-0.23.45` 快进合入并推送到 [OneXray/rustls 的 vcore/reality-0.23](https://github.com/OneXray/rustls/tree/vcore/reality-0.23)。推送前远端为 `df261c84cbac4f708e63ac8644ce70daa90d771c`；推送后通过 `git ls-remote` 确认完整 revision 为 `26f3efe5946dbe96410e85b8541ccf5fe7c244a5`。没有 force push 或改写提交历史；VCore 本轮只本地提交。

当日查询官方 [rustls registry](https://crates.io/api/v1/crates/rustls)、[tokio-rustls registry](https://crates.io/api/v1/crates/tokio-rustls) 与 [ring registry](https://crates.io/api/v1/crates/ring)，排除预发行及 yanked 版本后分别为 0.23.45、0.26.5、0.17.14。

| 范围 | 本次变化 |
| --- | --- |
| 主工程 | rustls 0.23.43 → 0.23.45，仍通过公开 GitHub 分支 patch；Cargo 解析并锁定已发布完整 SHA |
| 官方异步 binding | tokio-rustls 0.26.4 → 0.26.5；不使用 Watfaq、私有 hook 或 path fork |
| TLS 传递依赖 | 主锁 rustls-webpki 0.103.13 → 0.103.15；四个实验此前已锁定 0.103.15 |
| security / stream / datagram / hysteria2 | 各自 manifest 和 lock 同步到同一公开 fork revision 与 binding 版本，仍为独立实验 workspace |
| 安全边界 | TLS/REALITY 仍为 ring；Shadowsocks 的既有局部 AWS-LC 例外、来源与 feature 限制不扩大 |

fork 的显式混合密钥交换接口已随该 revision 发布，但 VCore 没有启用混合 provider 或对应配置。安全实验继续确认：默认 REALITY 在混合组排在前面时仍发送 classic X25519；缺少所选 classic 组时构建失败。

## 输入与隔离

- VCore 被测父提交：`1cc201c4e73ff5a0d8d6d213232d5bde4f49ecbb` 加本次已暂存修改；验证后提交，不能将父 SHA 单独当成被测新版源码。
- 输入差分 SHA-256：`a89a1ddd50bafb2543a4328c9be0907df35f14c243e9dd1359a4aea6193e1bb7`。重算命令为 `git diff 1cc201c -- Cargo.toml Cargo.lock scripts/src/vcore_scripts/checks.py scripts/tests/test_scripts.py tests/protocols/spikes | shasum -a 256`，不包含本验收文档。
- 平台构建和隔离测试使用 `git checkout-index` 导出的暂存快照，源码树为 `f106a56501f1158e81bc712b7b641e4f5a795365`；安全实验测试/README 更新后同步了对应两文件。快照没有 `.git`、相邻 rustls 目录或研究 checkout；不是全新 Git clone。
- 隔离目录从 `cargo fetch --locked` 开始，独立 target 目录构建；复用本机 Cargo 下载缓存，**未验证空下载缓存**。当前验收文档及进度索引后续编辑不改变被测代码或锁。
- 环境：macOS 27.0 / ARM64（26A428），Rust 1.98.1（48a229cea），Xcode 27.0（27A266a），Android NDK 28.2.13676358 / API 24，Apple Container 1.4.1。

| Lockfile | SHA-256 |
| --- | --- |
| 主工程 | `860e0e918bc3dbb4131f49a262847faa49df8c4de26a4f1d147501697c56f8f5` |
| security | `39f9fe8bd924c2a96c90574aac5f0bca5836206aabe1683673c87a23c2ffd030` |
| stream | `42d53012dbdf1c76d81078d2091892884575e71ec210bd38453edc1cc8825224` |
| datagram | `479425f9694e1ee1b2db0a77f0f8931aafc491e9c32ad95ec69cc7a7df599708` |
| hysteria2 | `7f910732a1b2b613584938d0c4fd00412a09222c77313c5223913d1c7e369a8c` |

## 实际验证

下表中的 Python 命令均通过 `uv run --project scripts --locked` 执行。spike 路径为 `tests/protocols/spikes/<name>/Cargo.toml`，独立 target 目录均在本仓库 `target/interop/` 内；测试未使用 reference 源码。

| 命令 / 范围 | 结果 |
| --- | --- |
| `vcore-scripts check tls-dependencies` | 工作目录与隔离目录均 PASS；唯一公开 fork、官方 binding、ring 和 SS 例外审计 |
| `python -m unittest discover -s scripts/tests` | 42 项 PASS；新版依赖先被旧规则拒绝（RED），更新规则后接受新版并拒绝旧版本、旧来源及违规 provider |
| `cargo test --locked --all-features --all-targets` | 工作目录与隔离目录均 PASS：572 lib + 2 h2 + 4 compatibility + 2 fixture；ignored 不计通过 |
| 同上加 `--release` | 两个目录均为上述计数 PASS |
| 四个 spike 的 `cargo test --locked --manifest-path … --all-targets` 及 `--release` | security 7、stream 12、datagram 4、hysteria2 6；Debug/Release 各通过对应计数 |
| security `cargo check … --features missing-session-hook` | 预期 compile-fail：退出101、E0599；官方 binding 仍无 `connect_with_session_id_generator`，不计成功构建 |
| `cargo test --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets` | 17 项 PASS |
| `cargo clippy --locked --all-features --lib --bins --test h2_stream_regression -- -D warnings` | PASS |
| 四个 spike `cargo clippy --locked --manifest-path … --all-targets --no-deps -- -D warnings`，netstack all-targets clippy | PASS；不代表 VCore 精简 feature 的既有依赖 warning 已清理 |
| 主工程与 security 的 fmt check，scripts ruff check/format，C header 检查，`git diff --check` | PASS |
| `python tests/protocols/spikes/stream/run.py` | 官方 Mihomo 42 项 PASS：TLS/WS/WSS/gRPC、关闭差分、错误目标与 protect 拒绝 |
| `vcore-scripts check mihomo-interop --container --extended` | 基础与扩展 PASS：普通 AnyTLS TLS、VLESS/XHTTP/classic REALITY、SS/SOCKS5/HTTP、组/链、100次生命周期及100次32-flow重建；40.68s |
| `python tests/protocols/spikes/hysteria2/run.py --native-hysteria`（先重建 probe） | 8 项 PASS：Mihomo DIRECT/SOCKS5/认证/证书/protect，原生 Hysteria UDP-disabled TCP |
| `python tests/protocols/spikes/hysteria2/native_h3.py --compare-mihomo-close` | 11 项 PASS：原生 Xray H3 及同对端官方 Mihomo 客户端的响应/整连接关闭对照 |
| 隔离目录 `vcore-scripts build apple` | 五目标 Release 与 XCFramework PASS：iOS arm64、模拟器 arm64/x86_64、macOS arm64/x86_64 |
| 隔离目录 `vcore-scripts build android` | arm64-v8a、x86_64 Release PASS；两种入站/四种出站显式 features，无 interop-test |

扩展互通的100次32-flow重建耗时21,893ms，清理后FD=6、在用堆64,176B、RSS=18,960KiB；这只是短程资源采样，不是30分钟长测或吞吐基准。自建容器/对端及临时配置已清理，专用网络/镜像缓存保留。

### 失败与未执行边界

- security 最初 6/7 PASS，失败仅为旧错误文本 `REALITY X25519 key reuse` 与 fork 新的所选组错误文案不符；拒绝行为本身保留。只更新自有测试文案与默认配置命名后 Debug/Release 7/7 PASS，原失败日志保留。
- **全目标 Clippy 仍 FAIL**：10 个既有测试重复导入警告、3 个 `chunks_exact_to_as_chunks` 警告。用父提交 `1cc201c` 的独立源码导出重跑得到相同13项，错误列表逐项一致；没有屏蔽 lint、清理无关代码或把缩小范围的通过冒充 all-targets 通过。
- 本轮没有重新执行 fork 内部线上向量/HRR/混合 provider 套件；它们属于发布前已验证的同一不可变 revision，详见 [fork 同步记录](https://github.com/OneXray/rustls/blob/26f3efe5946dbe96410e85b8541ccf5fe7c244a5/reality-tests/UPSTREAM-0.23.45.md)。本次 VCore 的公开进程数据面覆盖与 fork 单独测试分开计数。
- 未执行 Windows 原生构建、远端 CI、签名包、物理设备、真实 TUN/IPv6、30分钟长测、原生 hopping 重跑或新的协议功能验收。历史原生半关闭诊断失败不改记为 PASS。
- 其他依赖的最新稳定版升级和 Windows 配套版本决定仍见 [N1 依赖进度](N1-dependencies.md)；本次不是全图最新声明。

## 对端与产物身份

对端均按各入口重新从官方 latest 下载，不调用 GitHub API、不本地编译、不回退旧缓存；实际版本从二进制读取。下面是本次下载内容的本机摘要，不宣称官方签名校验。

| 对端 | 实际版本 | 程序 SHA-256 |
| --- | --- | --- |
| Mihomo Darwin ARM64 | v1.19.31 / Go1.26.8 / with_gvisor | `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090` |
| Mihomo Linux ARM64 | v1.19.31 / Go1.26.8 / with_gvisor | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| Hysteria Darwin ARM64 | v2.12.3 / e1366b173ccf5706e1e4630fe8aa654a4b574085 | `9065dc5dc9cd75f7ba881f481e8cb77e7eae17139460ca09d399682ca6fad443` |
| Xray Darwin ARM64 | 26.3.27 / d2758a0 | `5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404` |

全部构建产物内的身份均经标准构建脚本检查为 API v5/schema14；不等于设备数据面通过。

| Release 产物 | SHA-256 |
| --- | --- |
| iOS arm64 libvcore.a | `4c18e4bf60db3b3087ba6c0885366fbd0bb0e308cd5307774fe0a167bc88d964` |
| iOS simulator arm64 libvcore.a | `1892ae35a263ca0149a45cb3b9ed390e987b925700ac61acf8ec59b29c5923ae` |
| iOS simulator x86_64 libvcore.a | `6ddef654af06b0ff4a5accb4dde7b1d4bfae493a218bca0accfbabca76347dc7` |
| macOS arm64 libvcore.a | `79e9b82329d4476e4c2e2965e9b51110702ad1bfb07d8da4716e3879ff03e26c` |
| macOS x86_64 libvcore.a | `b9047f841fda7e618773d474ef23aacce9b4416588e4161d3fa37eca8d1dfc51` |
| Android arm64-v8a libvcore.so | `14cf34887538e5b5d23e381822ade5f662de35076b6acfd6958e13fef9bc661a` |
| Android x86_64 libvcore.so | `2d8815d4fdf62671285b039e9651595ca886f0b4a08130952fb79254b23d0d1d` |

原始日志保存在被忽略的 `target/interop/runs/n1-tls-20260923/`；不提交带本机路径的日志或临时配置。关键证据摘要：

| 本地记录 | SHA-256 |
| --- | --- |
| `debug.log` | `2026c713362ce36e777219c4ab4526975bb66a909cad6a279788441674f3d682` |
| `release.log` | `ac43f3afe2a86427c626ee20458c03b5c712d04fbfc0c97a2fd6958adef203fe` |
| `isolated-debug.log` | `16e4fd33bac41595f3f8816e4ab79b5a2941986cd760f9c7353c177f9dfbcb5b` |
| `isolated-release.log` | `d8a8dc8beeaeb98e91959c46b07bfe4483ae8090f75670d0d1fdbfbabdb25d07` |
| `mihomo-extended.log` | `a6de8751017c9c5881e7d0cd34b4c6595491f060e31ef1e0a5a1e89fed572068` |
| `../n0-stream-20260923T055555Z-q7as7di4/report.json` | `a7b0d380705c74eb4c22fda616c437b89db13169a046d2eba631edd58d770545` |
| `hysteria2-result.json` | `c034df23960f34488000f2785110d0bbe5e98bc982c771066f00e9f65a527d4b` |
| `target/interop/n0-xray-h3/20260923T055904Z-3e1b2f06/result.json`（仓库根相对路径） | `17188722d95f5ef0698d5cb2e9b269b29928e179573227425e5be0136e87122b` |
| `clippy.log`（新版，FAIL） | `67e8aa3eba5dff9907e5c64a9a31fa62ee88d22f6e508926fd7f88c769a0df80` |
| `clippy-baseline.log`（父提交，FAIL） | `5486138496d1bb9d056b44ab5484191f5afd539531576c457068e355baec7e38` |
