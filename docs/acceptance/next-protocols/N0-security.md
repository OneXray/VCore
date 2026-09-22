# N0-C / N0-E：TLS 与高级安全接口预验证

后续更新：用户已授权独立分支最小扩展自有 rustls fork；公开混合组入口和 Mihomo 数据互通已通过局部验证，见 [混合 REALITY 跟进](N0-reality-hybrid.md)。下文保留对原锁定 revision 的历史实验与阻塞证据；VCore 生产锁定依赖仍未变更，N0-E 未整体签收。

日期：2026-09-22。**结论：部分接口实验通过；N0-C、N0-E 均未整体通过。** 本报告不声明新增协议已实现，不开放任何生产配置。当前明确阻塞为混合 REALITY 的既有握手选择路径；ShadowTLS v3、Restls、JLS 的参考实现依赖本项目没有的握手修改接口，替代路径尚未证明。

## 执行环境与边界

- VCore 基线：`bbe5100abcf07b1158f86cff39cd835e1f32ccf9`。
- rustc `1.98.1 (48a229cea 2026-09-01)`、cargo `1.98.1`，host `aarch64-apple-darwin`。
- 生产锁定依赖：rustls `0.23.43`，`OneVCore/rustls` revision `df261c84cbac4f708e63ac8644ce70daa90d771c`；官方 tokio-rustls `0.26.4`；TLS provider 为 ring。
- 实验已保存为 `tests/protocols/spikes/security/` 独立 Cargo workspace，自带锁文件；产物位于忽略的 `target/interop/n0-security/target/`。未修改生产 Cargo.toml/Cargo.lock、第三方源码、既有 TLS provider；未启动网络服务、修改宿主网络或运行原生协议互通。
- 该实验是可独立复现的 test-only 预验证，不属于生产依赖或已交付的通用 harness；N1 仍须建立完整原生对端编排与证据门禁。

| 工件 | SHA-256 |
| --- | --- |
| 生产 `Cargo.lock` | `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2` |
| 实验 `Cargo.lock` | `4e76a6bb06833667804b4b15054bae419eb6124868b98b055bce76d4f488b789` |
| 实验 `Cargo.toml` | `235c76abfe77cdc901d042005936af5b20b8207a40bfb615af7e71a029ecdac8` |
| 实验 `src/lib.rs` | `143bea3c062bd95005ecf20278ba956a1728d71bac9eb1985b0fe44e34dfae4f` |
| 实验 `src/ech.rs` | `75a7bbba1cf6c75814d22b68f120bd4039d1bc14a936761df0647cc35488efc4` |

## 实际命令与结果

下列命令已从 VCore 根目录执行，使用仓库内独立实验及其锁文件；不是生产协议测试入口。

```sh
cargo test --locked --manifest-path tests/protocols/spikes/security/Cargo.toml --target-dir target/interop/n0-security/target -- --nocapture
cargo check --locked --manifest-path tests/protocols/spikes/security/Cargo.toml --target-dir target/interop/n0-security/target --features missing-session-hook
cargo tree --locked --manifest-path tests/protocols/spikes/security/Cargo.toml -e features -i rustls
cargo tree --locked --manifest-path tests/protocols/spikes/security/Cargo.toml -e normal --prefix none
cargo fmt --manifest-path tests/protocols/spikes/security/Cargo.toml -- --check
```

| 实验 | 实际结果 | 证明边界 |
| --- | --- | --- |
| `public_reader_retains_unconsumed_application_plaintext` | PASS | 本地内存 TLS 1.3 握手后，先读取部分应用明文，再经公开 reader 取回余下明文 |
| `unrestricted_record_read_consumes_raw_tail_and_errors` | PASS（预期错误断言） | 一个 read_tls 输入同时含外层应用记录与模拟直接流记录时，全部被读入，process_new_packets 返回 DecryptError；不能假定之后 into_inner 即可取回尾部 |
| `one_record_owned_input_preserves_raw_tail_without_private_access` | PASS | 将输入严格限制为完整的一条外层记录，可读取标记并把后续 raw 数据保留在自有输入层 |
| `reality_rejects_only_hybrid_group_despite_capability_flag` | PASS（预期拒绝断言） | 提供名称为 X25519MLKEM768、声明 supports_reality 的 sentinel group，builder 仍要求 X25519；没有执行或假造 ML-KEM 运算 |
| `reality_ignores_preferred_hybrid_and_emits_classic_keyshare` | PASS（限制证明） | 把上述 sentinel 放在首位、保留真正 ring X25519 后，解析实际生成的 ClientHello：只有 group `0x001d`、32 字节公钥，没有 `0x11ec` 混合 key share |
| `ech::hpke_public_trait_roundtrip_and_auth_failure` | PASS | 真实 Rust HPKE 实现经 rustls Hpke trait 完成单次与连续 seal/open，并拒绝错误 AAD |
| `ech::ring_client_emits_ech_with_external_rust_hpke` | PASS（仅 ClientHello） | ring TLS + 外部 Rust HPKE 生成 `0xfe0d` ECH 扩展；外层不含合成私有认证名；ech_status 为 Offered，而非 Accepted |
| `missing-session-hook` feature 编译 | 预期 FAIL，exit 101，E0599 | 官方 tokio-rustls 没有 Clash-RS 所用的 connect_with_session_id_generator 方法；正常实验编译不启用这个负例 feature |
| 独立实验依赖树 | PASS（本机图检查） | 一份指定 rustls、tokio-rustls 0.26.4、ring；没有 AWS-LC、Watfaq TLS fork 或第二份 rustls |

最终正常实验结果为 **7 passed / 0 failed / 0 ignored**。负编译错误为：

```text
error[E0599]: no method named `connect_with_session_id_generator`
found for reference `&TlsConnector` in the current scope
```

该错误证明参考调用不可直接复用，不证明所有可能的自有协议实现都不可能。

## N0-C：Vision

公开的 tokio-rustls `TlsStream::get_mut` / `into_inner` 与 rustls `reader` 可访问底层 I/O 和尚未消费的应用明文；无需 Watfaq fork。但 TLS 的入站记录缓冲不是应用明文缓冲，直接绕过 TLS 可能把已预读的 raw 尾部遗留在 rustls 内部，甚至在识别 Vision 标记前误解密并失败。上述两个记录输入实验实际复现了风险及一种可行边界。

实施方向是自有、有界的 record-aware 输入 Adapter，或进一步验证公开 unbuffered API：只在确认协议切换后交还其持有的 raw 字节，发送侧必须先完成外层 TLS flush。不能将 Clash-RS 的“清空明文后直接切底层”视为已完整证明，更不能改私有字段或依赖内存布局。

**仍为 NOT RUN：** Mihomo 原生 Vision listener 上的 TLS 与 REALITY 两条内层 TLS 1.3 direct-mode 数据闭环；真实分片、读前瞻、半关闭与取消；受控 Dialer 接入。上述本地 TLS 实验不是 Vision 互通，也不签收 N0-C。

依据：[锁定 rustls read_tls][R-CONN]、[官方 tokio-rustls TlsStream][T-STREAM]、[Clash-RS splice 参考][CR-SPLICE]。

## N0-E：逐项结论

| 子门禁 / 对应字段 | 当前状态 | 证据与下一步 |
| --- | --- | --- |
| VLESS Encryption / VL06 | NOT RUN | 属于独立协议加密层，不与 REALITY 混合 key share 混淆；本实验未选择 ML-KEM 依赖或完成原生握手，不宣称受 S03 同一限制阻塞 |
| 混合 REALITY / S03、D16 | BLOCKED | 锁定 fork 的 builder 和启动握手均硬选 X25519；已实际验证拒绝混合单组及仍发经典 share。需要上游/fork 提供正式混合 REALITY 入口，或另一个经过证明且符合安全约束的路线；不能靠普通 TLS 的 provider 扩展或经典 REALITY PASS 抵扣 |
| ECH / S04–S06、D17–D19 | 部分接口 PASS；原生互通 NOT RUN | 外部 Rust HPKE 可与 ring TLS 共存；下一步必须取得原生服务端 ECH Accepted + 数据闭环、拒绝/错误配置负例及 bootstrap 隔离，不把 Offered 算通过 |
| ShadowTLS v1/v2 / S07–S08、D20–D21 | NOT RUN | 本实验未证明这两个版本需要 session-ID 定制；不能把 v3 缺口扩大成三个版本都不可行。各版本仍需自己的原生端数据证据 |
| ShadowTLS v3 / 同上 | 直接参考路线 BLOCKED | Clash-RS 明确调用缺失方法，按完整 ClientHello 计算并写入 session ID；普通 stream 包装不是该握手修改接口。其他纯公开 Adapter 路线尚未证明 |
| Restls tls12/tls13 + 脚本 / S09–S11、D22–D24 | 参考路线存在接口缺口；替代路线未证明 | 官方 Go 依赖按实际 key share/PSK/ECDHE 材料生成 session ID，还插入记录认证/密码状态转换；本项目公开客户端构造 API 没有等价协议 hook。未运行原生握手，不把缺一方法的编译失败当成所有 Restls 路线的不可能证明 |
| JLS / S12–S13、D25–D26 | 参考路线存在接口缺口；替代路线未证明 | 原生实现需在完整 ClientHello 序列化后认证并替换 random，服务端认证也关联原始 ServerHello；rustls 现有公开 verifier 不提供等价完整握手修改 hook。未完成原生握手，不能用单纯 skip-cert-verify 代替 JLS 认证 |

### 混合 REALITY 的阻塞细节

锁定实现 `with_reality` 只寻找 `NamedGroup::X25519` 且要求 `supports_reality()`；`client/hs.rs` 再次 `find_kx_group(X25519, TLSv1_3)` 并调用其 `start_reality`。这与普通 TLS 的“provider 首选组”路径不同。ring 本身也没有 X25519MLKEM768 实现。

在这一契约下，仅增加独立 ML-KEM crate 或把自定义 hybrid provider 排在第一位，不会改变实际 REALITY ClientHello。不得用错误的 group 名称伪装另一种算法、生成两份不相干 X25519 密钥，或在线改写 ClientHello 而不维护 TLS transcript。这些不属于已验证的公开扩展方案。[builder][R-BUILDER]、[握手选择][R-HS]、[公开 group 契约][R-CRYPTO]。

本报告没有改动该 fork。是否允许为此扩展 fork 或调整范围，属于需要额外决定的安全/范围变更，不能由阶段自动提交授权推导。

### ECH 的依赖与稳定性

实验使用 crates.io `hpke 0.13.0`，禁用默认 feature，仅启用 `std/x25519`，算法组合为 X25519/HKDF-SHA256/AES-128-GCM；其许可为 MIT/Apache-2.0，公开说明标注未审计。它是本次接口实验候选，**不是生产依赖批准或正式选型**。可继续比较 rustls 自有 provider example 所用的 hpke-rs 路线。

`rustls::crypto::hpke::Hpke` 是公开 trait，`EchConfig::new`、`with_ech`、`ech_status` 也公开。构造 HpkeSuite 所需的枚举/结构由 `rustls::internal` 导出，上游明确不保证该命名空间稳定；自有 Adapter 没有修改第三方，但须固定依赖版本、隔离引用并在升级时重跑编译/互通。不能把“可公开访问”写成“稳定 API 保证”。[rustls HPKE][R-HPKE]、[ECH][R-ECH]、[内部导出说明][R-INTERNAL]、[上游 provider 示例][R-EXAMPLE]、[HPKE crate][HPKE]。

### 为什么不能在流上直接改认证字节

ShadowTLS v3、Restls、JLS 的认证字段依赖已构造的 ClientHello 或密钥交换材料；TLS Finished/CertificateVerify 又依赖双方一致的握手 transcript。公开 SecureRandom 只负责填充随机字节，不是接收完整 ClientHello 后的认证回调。出站 socket 上改 bytes、固定随机源或略过验证不能作为未改第三方的合格替代。

来源：[Clash-RS ShadowTLS v3][CR-SHADOW]、[Restls session-ID 生成][RESTLS-HS]、[Restls record 状态][RESTLS-STATE]、[Mihomo JLS ClientHello 认证][M-JLS]。这些是固定源码推论；尚未执行它们的本机原生端互通。

## 未执行与阶段影响

- Vision TLS/REALITY、Encryption、ECH Accepted、ShadowTLS、Restls、JLS、混合 REALITY 的原生对端数据闭环：**NOT RUN**。
- 新 Adapter 的真实 Dialer/protect、取消/Stop、节点缓存隔离、上游组快照、secret 清理与资源门槛：**NOT RUN**。
- 本次实验的 Apple/Android/Windows 交叉构建与真机：**NOT RUN**；host 编译不可抵扣。
- N0-C 尚未满足进入 N4.3 的全部前置标准；S03/D16 阻塞 N7.2；其余高级安全按各自子门禁签收。不会因此宣称 Trojan/VMess/Hysteria2/WireGuard 的独立工作被同一 TLS 缺口阻塞。
- N0-C/E 未完成，不应提交“阶段完成”的结论；如记录本次发现，应明确为预验证进度/阻塞证据。

[R-CONN]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/conn.rs#L738-L779
[R-BUILDER]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/client/builder.rs#L91-L149
[R-HS]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/client/hs.rs#L179-L193
[R-CRYPTO]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/crypto/mod.rs
[R-HPKE]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/crypto/hpke.rs
[R-ECH]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/client/ech.rs
[R-INTERNAL]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/lib.rs#L466-L470
[R-EXAMPLE]: https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/provider-example/src/hpke.rs
[T-STREAM]: https://github.com/rustls/tokio-rustls/blob/v/0.26.4/src/client.rs
[CR-SPLICE]: https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/transport/splice_tls.rs
[CR-SHADOW]: https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/transport/shadow_tls/mod.rs
[RESTLS-HS]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/handshake_client.go#L176-L233
[RESTLS-STATE]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/restls_utils.go
[M-JLS]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/jls/utls.go
[HPKE]: https://docs.rs/hpke/0.13.0/hpke/
