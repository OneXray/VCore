# N0：QUIC / WireGuard 公共接口与依赖预验证

日期：2026-09-22。输入基线：`bbe5100abcf07b1158f86cff39cd835e1f32ccf9`，另加本报告列出的自有 test-only spike。宿主为 macOS arm64；`rustc 1.98.1 (48a229cea 2026-09-01)`、`cargo 1.98.1 (797e8a9bc 2026-08-05)`。

**结论仅限 N0-B/D/G 的公共接口子项。** 已真实编译和执行 packet API / QUIC 注入测试；没有实现生产协议，也没有完成 N0-D 或 N0-G 的官方服务端互通。主 `Cargo.toml`、主 `Cargo.lock`、第三方源码、宿主路由/DNS/VPN 均未修改。

本文保留首轮实验范围。后续 [HY2 受控数据报互通](N0-hysteria2.md) 已完成 Mihomo DIRECT/SOCKS5 UDP auth/stream、protect 拒绝和官方 Hysteria UDP=false 协商，并记录原生半关闭失败；该独立实验也完成 iOS/Android arm64 交叉 check。它不升级本文 WG、原生跳端口、Xray H3 或其他目标平台的未执行状态。

## 状态与边界

| 子项 | 状态 | 本次证据 |
| --- | --- | --- |
| B：候选依赖解析与单一 TLS 来源 | PASS | 独立锁文件；一个 rustls 0.23.43，源码 revision 与 VCore 相同；无 AWS-LC、Watfaq、boring-noise、OS TUN/Wintun 依赖 |
| D：公开 UDP / congestion 注入接口 | PASS | 自有 `AsyncUdpSocket` 上真实 QUIC 握手、证书验证和数据流；自定义 `ControllerFactory` 实际被调用 |
| D：现有 Dialer 的 protect 拒绝 | PASS | 回调只调用一次、返回 PermissionDenied，不把 socket 交给 adapter；受控接收端无数据 |
| D：h3-quinn 与当前 TLS 图类型兼容 | PASS | `h3_quinn::Connection` 接受上述 Quinn connection；不是 HTTP/3 请求互通 |
| D：HY2 auth/stream、DIRECT/SOCKS5 UDP 上游 | NOT RUN | 内存 QUIC 对端不是官方 Hysteria/Mihomo；本次没有完整受控 datagram driver |
| D：Brutal 带宽、原生单状态跳端口、Xray H3 | NOT RUN | 公开 factory 的可注入性不证明算法、流量、端口跳跃或 H3 wire 行为 |
| G：两个官方 Rust 候选的纯 packet / timer API | PASS | BoringTun 双端握手、PSK 与 IPv4 包解密；GotaTun ring 下生成握手并驱动 timer/reset |
| G：官方 Linux / wireguard-go peer 握手与内层 UDP | NOT RUN | BoringTun 自连不是官方 peer，不能抵扣独立服务端验收 |
| G：既有 netstack crate 内主动 TCP 实验 | NOT RUN | 本 spike 没有修改 netstack 或宣称已具备主动 TCP Interface |
| iOS arm64 依赖与测试源码交叉检查 | PASS | `cargo check --target aarch64-apple-ios --tests`；没有链接安装包或在设备运行 |
| Android / Windows / 其他 Apple 架构 | NOT RUN | 不从宿主或单目标 check 外推 |

本报告中的 PASS 都是表内限定子项，**不把 N0-B 全部流传输项、N0-D、N0-G 或整个 N0 标为通过**。

## 可复现的独立工程

源码位于 [tests/protocols/spikes/datagram](../../../tests/protocols/spikes/datagram/Cargo.toml)，使用自己的 `[workspace]` 和 `Cargo.lock`。仅以仓库相对路径依赖 VCore 的 `outbound-socks5` feature，用于调用已有 Dialer；不依赖研究 checkout、用户目录或外部文件布局。产物写到 `target/interop/n0-datagram-build/`。

从 VCore 仓库根目录执行：

```sh
cargo fmt --manifest-path tests/protocols/spikes/datagram/Cargo.toml -- --check
cargo test --locked --manifest-path tests/protocols/spikes/datagram/Cargo.toml \
  --target-dir target/interop/n0-datagram-build
cargo clippy --locked --manifest-path tests/protocols/spikes/datagram/Cargo.toml \
  --target-dir target/interop/n0-datagram-build --all-targets -- -D warnings
cargo check --locked --manifest-path tests/protocols/spikes/datagram/Cargo.toml \
  --target-dir target/interop/n0-datagram-build --target aarch64-apple-ios --tests
cargo metadata --locked --format-version 1 \
  --manifest-path tests/protocols/spikes/datagram/Cargo.toml
cargo tree --locked --manifest-path tests/protocols/spikes/datagram/Cargo.toml \
  --edges features -i rustls
```

最终结果：4 tests PASS，0 failed / ignored；spike clippy 退出码 0；iOS arm64 check 退出码 0。精简 feature 下作为路径依赖编译的现有 VCore 产生 97 条 unused/dead-code warnings；这里没有修改它们或宣称整个主仓库 warning-free。此独立 lockfile 也不替代主仓库 `--locked` 完整构建、依赖审计和回归。

## 依赖来源、feature 与候选选择

| 包 | 解析版本 / 来源 | 本 spike 启用方式 | 元数据许可 / MSRV |
| --- | --- | --- | --- |
| Quinn | registry `quinn 0.11.12`，官方 [quinn-rs/quinn](https://github.com/quinn-rs/quinn) | 禁用默认；`runtime-tokio,rustls-ring`；h3-quinn 另启用 `futures-io` | MIT OR Apache-2.0 / 1.85 |
| Quinn protocol / UDP | registry `quinn-proto 0.11.18`、`quinn-udp 0.5.15` | proto `rustls-ring`；不启用 platform verifier / AWS-LC | MIT OR Apache-2.0 / 1.85 |
| HTTP/3 | registry `h3 0.0.8`、`h3-quinn 0.0.10`，官方 [hyperium/h3](https://github.com/hyperium/h3) | 不启用额外 h3-datagram/tracing feature | MIT / 1.70 |
| BoringTun | registry `boringtun 0.7.1`，官方 [cloudflare/boringtun](https://github.com/cloudflare/boringtun) | `default-features=false`，实际 feature 集为空 | BSD-3-Clause / 未声明 |
| GotaTun | registry `gotatun 0.9.2`，官方 [mullvad/gotatun](https://github.com/mullvad/gotatun) | `default-features=false,features=["ring"]` | MPL-2.0 / 1.95 |
| rustls | 0.23.43，[VCore 既有公开 fork](https://github.com/OneVCore/rustls/tree/df261c84cbac4f708e63ac8644ce70daa90d771c) | 仅 `ring,std,tls12`；spike pin 当前 revision，主仓库 branch/lock 不变 | Apache-2.0 OR ISC OR MIT / 1.71 |
| ring | registry 0.17.14 | TLS 和 WG 可共用；未新增 TLS provider | Apache-2.0 AND ISC / 1.66.0 |

以上来自本次 `cargo info` / `cargo metadata` 实际产物，不将研究 HEAD 当成已发布 crate。两个 WG 候选都没有打开 `device`、`socket`、`tun`、FFI 或 JNI feature。BoringTun 的 ring 与 RustCrypto 密码实现不依赖 TLS；GotaTun 默认 AWS-LC 必须显式禁用。本 spike 同时容纳两个候选只为比较，**生产不得因此同时引入两套 WG 实现**。

后续正式实现优先选 **官方 BoringTun 0.7.1**：packet/timer 接口直接适配现有分层，无 OS 设备所有权；许可证为 BSD-3-Clause，未增加 GotaTun 的 Rust 1.95 下限及额外 packet/pool 类型。此选择已经过本次主机/单个 iOS 目标的编译验证，但正式进入生产仍须官方 peer 与目标平台门禁。保留 GotaTun 作为未采用比较项，不偷偷切换 Watfaq/boring-noise。完整发布仍需对最终解析图作许可证审计，不从顶层 license 字段推导整版授权结论。

## 四个真实测试证明了什么

1. `boringtun_packet_timer_handshake_and_inner_packet`：仅调用公开 `Tunn::new`、`update_timers`、`format_handshake_initiation`、`decapsulate`、`encapsulate`。合成私钥/PSK 的两个独立状态交换 148-byte initiation、92-byte response、确认与加密 IPv4 包，检查完整明文相等及握手状态。数据包不会进入宿主网络。它证明可以把 UDP 和时钟驱动留在 VCore，不证明官方 peer 或完整 UDP/IP 校验。[BoringTun 公共 Tunn](https://docs.rs/boringtun/0.7.1/boringtun/noise/struct.Tunn.html)
2. `gotatun_ring_public_packet_and_timer_interfaces`：公开构造 `IndexTable` / `RateLimiter` / `Tunn`，产生 148-byte initiation，设置/关闭 keepalive、reset，并观察状态；没有借助私有接口或启动其 device 模块。[GotaTun 公共 Tunn](https://docs.rs/gotatun/0.9.2/gotatun/noise/struct.Tunn.html)
3. `quinn_custom_packet_io_and_congestion_with_existing_rustls`：两个自有 packet 队列模拟受控数据报；单队列最多 32 包、单包最多 1400 字节，来源/目的受控，关闭分段和 MTU discovery。由 `new_with_abstract_socket` 注入，不调用 Quinn 自动 bind。使用生成的 localhost 证书与显式信任根，完成 QUIC 握手、单向流和逐字节校验；自定义 controller factory 的实际调用计数至少为 2。随后显式 close 并等待两个 Endpoint idle，全案 10 秒 watchdog。没有开启 `skip-cert-verify`。[AsyncUdpSocket](https://docs.rs/quinn/0.11.12/quinn/trait.AsyncUdpSocket.html)、[Endpoint 注入](https://docs.rs/quinn/0.11.12/quinn/struct.Endpoint.html#method.new_with_abstract_socket)、[ControllerFactory](https://docs.rs/quinn-proto/0.11.18/quinn_proto/congestion/trait.ControllerFactory.html)
4. `existing_dialer_rejects_udp_before_adapter_can_send`：直接调用 VCore 原有 `Dialer::bind_udp_for`，合成保护器拒绝，受控回环接收端 50 ms 内未收到包。它是保护失败的最小探针，不等于 Android VPN 回调/Windows 物理绑定验收，也未证明新的 QUIC→VCore 数据报 driver 已实现。[既有 Dialer](../../../src/dialer.rs)

这些用例为独立自有夹具，没有复制或修改第三方实现。测试使用固定合成材料，不输出凭据、私钥、PSK 或业务目的地。

## 实现时不能忽略的差异

- Clash-RS 的分层可以参考，其 WG 依赖来自 Watfaq/boring-noise，不可直接迁入。上游官方 BoringTun 与 GotaTun API 不是完全同形，应在小 Adapter 内转换。[Clash-RS WG 依赖](https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/Cargo.toml)
- Clash-RS 的 HY2 outbound 当前 `congestion_controller_factory` 安装行被注释，协商后逻辑仍有 TODO；其 Brutal 参考代码以 `as_secs()` 处理 RTT/预算。因此不能将“依赖 Quinn”或参考代码存在写成带宽已正确支持。Quinn 的公开 factory 允许自有控制器，但 Brutal 算法与 pacing 行为仍需原生基准及 N6 带宽用例。[outbound](https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/hysteria2/outbound/mod.rs)、[congestion](https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/hysteria2/congestion.rs)
- VCore 当前 `DatagramTransport` 的 send/receive 共用 `&mut self`，请求只有接收 payload 预算；它不能直接冒充 Quinn 的 Sync / poll 接口。N1 必须补足有界全双工 driver、真实发送预算、来源验证、取消/背压和同步停止，不能持锁等待 receive 阻塞 send，也不能由协议自建旁路 socket。[数据报 Interface](../../../src/dispatch.rs)、[建链请求](../../../src/outbound/connector.rs)
- WireGuard 需要现有 netstack crate 中的主动 TCP/IP 角色与受控 DNS 注入；仅有 crypto `Tunn` 不足以承接普通 TCP/UDP Session。WG 用户态 peer 也不能创建宿主网卡、改默认路由或替换当前平台 TUN。[netstack](../../../crates/vcore-netstack/src/lib.rs)、[资源政策](../../runtime-resource-policy.md)

## 原始失败与最终证据

首次 GotaTun smoke 失败是夹具预期错误：配置 `persistent_keepalive=25` 后立即调用 `update_timers()`，错误地断言必须返回 `None`；真实库允许当场生成握手。修正为先以 `None` 测无动作，再单独验证 keepalive 的设置/关闭；第三方源码不变。原先 2 PASS / 1 FAIL 不被最终 4 PASS 覆盖，也不将该失败报成库缺陷。

最终源码/依赖输入 SHA-256：

| 文件 | SHA-256 |
| --- | --- |
| `tests/protocols/spikes/datagram/Cargo.toml` | `2c214c3ab8d1bf41d671f03c02b1290c8fe78bf0e99f157414ab2184272ef14c` |
| `tests/protocols/spikes/datagram/Cargo.lock` | `f38da9e25bd7a022086878628b48823a802c35073f6af3a82f66a7415ada9057` |
| `tests/protocols/spikes/datagram/src/lib.rs` | `5533e40cb8015e912fdee90c97891b0cb054c4dc0cc7a709377155c1d2c9e4ce` |

最后一轮日志/依赖摘要保留在本地忽略目录；内容包含 Cargo 的本机路径，不能原样上传为公共 artifact：

| 文件 | SHA-256 |
| --- | --- |
| `target/interop/n0-datagram-tests.log` | `095a354bffb02ef9543329521f0351123fa963df46faba6d4a0efb08fc9399e4` |
| `target/interop/n0-datagram-clippy.log` | `96a9a90e1cef26d1576d7dce0598b5c19f3a71f86b111b0d6ac0df4fec7b3035` |
| `target/interop/n0-datagram-ios-check.log` | `51a807c9c99d4c4bafed37c89c323f4cd7dc5d992308eaf8fd69721016ee2fc9` |
| `target/interop/n0-datagram-dependencies.json` | `0aa6225db9fa98dd4c74cb062b6c8c4622c387b914c4146db92d83d3701793d3` |

提交发生在这些测试之后；报告记录被测父 SHA 和输入摘要，不将后续提交 SHA 冒充测试发生时的代码身份。最终源码如再修改，应重跑相应用例并更新上述输入摘要。
