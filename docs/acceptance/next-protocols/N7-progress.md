# N7 高级安全：当前后端前置验证

2026-09-26。状态：**N7 未完成，N7.1 / N7.2 已完成本地子包签收。** Encryption
的公开/分层/算法/票据门禁与 Apple/Android Release 通过，详见 [N7.1 报告](N7-encryption.md)。
获准的 boring 混合扩展已发布为 `b7639ab7`；S03/D16 的 54 项容器门禁、32 项共享
回归和生产构建证据见 [N7.2 报告](N7-reality-hybrid.md)。当前 schema26 / Invoke v5。
JLS 的 S12–S13 / D25–D26 已签收并继续保留，见 [JLS 记录](N7-jls.md)。
下文保留开发时的原始失败与阶段性状态；N7.3 / N7.4 整体 / N7.5 仍未签收。

最新范围：按用户决定，schema26 仅删除 Restls 配置、实现与专项测试，
自有 boring fork 同步删除 Restls native hook、feature 和探针，恢复并保留 JLS。
Restls 不再是 N7 的交付项或阻塞条件；旧字段严格拒绝，不静默降级为普通 TLS。
最终固定 boring `5ca9ba3e`，JLS 定向互通 10/10、共享回归和 iOS/Android ARM64
生产构建通过；此次收敛的输入、失败与边界见[撤回验收](N7-restls-retirement.md)。
后续 N7.3 动态 ECH、N7.4 ShadowTLS / JLS、N7.5 合法组合与下载腿验收继续保留。
必要 push 已获持续授权，不包含 PR 合并；历史逐提交授权表述不覆盖新授权。

动态 ECH 已获准为 `prepare` / `measureDelay` 增加可选宿主 bootstrap DNS 入口，
不再等待该项范围授权。入口尚未实现，不属于当前 Invoke 支持字段；只服务
动态 ECH，不增加 YAML/global DNS 配置或公共后备。普通 TLS、静态 ECH 不依赖
该入口，动态 ECH 缺安全可用能力失败关闭。后续仍需独立验证受控 Dialer、
平台保护、防环、TTL/节点/传输腿隔离、取消/Stop 和无运行实例的测量。

同日 N7.1 已完成[官方原语和 Encryption wire 纵切](N7-encryption.md)：Debug / Release
各 14 项、18 项独立容器矩阵（含票据/重放/密文篡改）通过并保留初始失败。
该 wire 提交尚未开放公开 YAML / runtime；后续工作区已接入公开 Encryption、UDP、
Vision 和外层传输，schema23 / Invoke v5。新增 ChaCha 18 项、真实票据过期 9 项、
增量公共传输/内层 TLS 互通及 Apple/Android Release 构建通过。随后冻结公开矩阵
59/59 通过，包含真实 Vision direct 关闭差分。最终其余五类 35/35、分层 36/36、
常规/ChaCha 各 18/18、过期 9/9 和最大 padding 2/2 在同一输入下通过，完成 VL06
子包签收；这些结果不抵扣尚未实现的高级安全组合。

## 删除 Restls 之前的历史进度

以下保留删除决定之前的授权、活跃度判断和互通失败，不再构成当前计划。

最新授权与进度：用户已允许后续必要的 push，不必逐提交请求发布授权；下文
未获发布授权的表述是当时边界，不覆盖新授权。Restls 原生 hook `d8d6d929`
已发布并固定接入，公开配置与受控 Adapter 验收进行中，详见
[Restls 记录](N7-restls.md)。该进度不等于 Restls 或完整 N7 签收。
最新冻结验收在 TLS1.2 Restls + Mihomo gRPC 的首字节读取出现偶发 EOF，
后续[专项诊断](N7-restls-grpc-diagnosis.md)已在默认脚本、2 核容器中两次捕获
服务端读写互锁，导致 HTTP/2 SETTINGS 超时。先前官方客户端两组独立对照未
复现的记录继续保留。根因已定位但未修复，当前仍停止 Restls 子包签收，
不提交为已完成阶段；临时诊断 hook 已清理，正式资源门槛不变。
随后按确认方案测试 VCore-only 的 gRPC 启动写入合并，真实默认脚本仍超时，
并再次捕获同类互锁；候选与探针已撤回。此次否定一个客户端兼容候选，
没有修复上游问题或改变 Restls 支持范围，详见同一专项诊断的实验记录。

2026-09-26 范围复核：保留 JLS / Restls。Restls 原作者仓库长期未更新，但 Mihomo
所用 MetaCubeX 分支在 2026-07-05 [新增服务端][RESTLS-SERVER]、2026-07-20
[修复 TLS1.2 回落][RESTLS-FIX]，不据原仓库停更删除现有范围；JLS 也有
[会话恢复认证修复][JLS-RESUMPTION]等近期维护。活跃度不是互通或安全验收，
上述 Restls 偶发错误仍保持未解决，未因本次复核修改实现或降低门槛。

## 最初能力探针的输入和范围

- VCore 基线 `def0e19cb0945614397c884388a9ee561818a19a`，新本地分支 `feat/vless-advanced-security`。
- 生产锁定 boring `67581195fd6388a8bfd42c4e39e945f73c99a2b2`，版本 5.2.0；官方 rustls 0.23.45 / tokio-rustls 0.26.5 + ring 未改变。
- `Cargo.lock` SHA-256：`14a332a4de55c7c026238262b0fd0f5b228ebed3742e8bc3b6c40df631a6f6b3`。
- 新增的[纯内存能力探针](../../../tests/n7_security_capabilities.rs)使用本仓库同一个 lockfile 和公开 TLS 接口，不依赖相邻源码目录。探针 SHA-256：`5e39433ad5767b138d5ae2d8fdd15dad4a27a8ed21b57c87c373bf972f87af0a`。
- 执行环境：Darwin arm64，Rust 1.98.1；2026-09-26 UTC。只记录组号、长度和结果，不保存握手随机数、密钥或原始 ClientHello。

最初接口探针不改生产源码、公开配置、schema21、Invoke v5、依赖锁或第三方源码，不启动任何网络服务端；仅捕获内存中的 ClientHello，因此该探针没有容器、网络或对端清理项。授权后的独立 fork 工作与新增容器证据另见下文，不能反向算作该探针的原生认证、TCP/UDP 数据面、设备或平台通过结论。

## S03/D16 的实际失败

三个对照均使用相同的 Chrome133 模板与锁定后端：

| 路径 | Debug / Release 观测 | 结论 |
| --- | --- | --- |
| 普通 TLS | `key_share = [(4588, 1216), (29, 32)]` | 后端确实能生成 X25519MLKEM768，不是依赖缺少 ML-KEM 实现；未证明对端接受 |
| 调用现有 `set_reality_client` | `key_share = [(29, 32)]` | 经典模式主动裁剪混合 share，不能抵扣 S03/D16 |
| 经典 REALITY 配置后，通过公开 groups / key-share setter 加回混合组 | setter 成功，随后原生握手返回 SSL 错误，发出 0 字节 | 不能只修改 VCore 的 groups 设置来完成新增能力 |

对照与[公开 REALITY 接口说明][BORING-API]及[原生补丁][BORING-PATCH]一致：设置阶段裁剪混合组；`seal_reality_client_hello` 又校验实际 share，仅允许经典 X25519 认证与附加经典 EC share。VCore 无权读取或替换该内部认证状态。该限制在两种构建模式实测，不是将旧 rustls 实验的结论直接套用到 boring。

Mihomo 的显式支持开关保留混合组，认证从实际 X25519 key material 派生；它不是独立的 VLESS Encryption 加密层。VCore 的 N7 合同另外要求显式启用时真实协商混合组、对不支持的对端失败关闭，不能用经典成功代替。[Mihomo 固定参考实现][MIHOMO]

## 可复现命令及结果

均从 VCore 根目录执行，不启动宿主监听器：

```sh
cargo test --locked --all-features --test n7_security_capabilities -- --nocapture
cargo test --locked --release --all-features --test n7_security_capabilities -- --nocapture
cargo clippy --locked --all-features --test n7_security_capabilities -- -D warnings
cargo fmt --all -- --check
git diff --check
```

前两条各 3 PASS / 1 IGNORED，退出 0；Clippy、格式和 diff 检查退出 0。另执行 `cargo test --locked --no-default-features --features outbound-vless --test n7_security_capabilities -- --nocapture`，同样 3 PASS / 1 IGNORED；该精简库构建输出 112 项未使用项警告，不称其为零警告门禁，也不修改无关生产源码。三个 PASS 只验证上表当前边界，不是 N7 支持。显式执行尚未满足的能力要求：

```sh
cargo test --locked --all-features --test n7_security_capabilities n7_requires_hybrid_reality_in_the_actual_client_hello -- --ignored --exact --nocapture
```

实际退出 **101**，1 FAIL / 0 IGNORED，原因 `N7 BLOCKED: current REALITY removes the required X25519MLKEM768 share`。该能力探针被显式隔离，不能把默认跳过计为通过；它记录当前仅有经典入口的缺口。后续新增显式混合模式后，应让此探针调用新入口，保留经典默认不变，并补足真实对端协商/认证。**这个失败不允许通过放宽断言或删除 required 行来消除。**

## 已批准的混合 REALITY fork 子包

用户已批准在自有 boring 的 `feat/reality-hybrid` 分支最小扩展混合 REALITY，保留经典默认，不降低认证、不恢复旧 rustls fork。该授权不包含其他握手 hook、新 TLS 引擎或远端发布。

库侧实现已本地提交为 `b7639ab705076748133d5e8658914e3c3a364cb6`；提交后八个被测输入 hash 与最终容器记录一致，工作区干净。该库门禁结束时尚未 push；后续追加授权与实际发布另记于下文。测试发生在提交前，具体父 SHA 与被测输入见 fork 报告，不倒填测试时尚不存在的提交号。

- 新增显式 `RealityClientConfig::require_x25519mlkem768()`；原 `new` 与旧 C 入口继续是经典模式。混合模式要求实际 ClientHello 和协商结果均为 group 4588，经典选组或 HRR 失败关闭，不静默重试经典模式。
- 保留配置的真实 share；有独立 X25519 时用其认证，否则使用实际混合 share 内的 X25519 分量，与 Mihomo 服务端取值一致。ML-KEM/TLS 密钥交换仍由原生后端完成；REALITY 认证本身不宣称为后量子认证。
- 只有当前 Chrome133 模板包含该混合 share。Chrome120、Firefox120、Safari16 不会被隐式改写成其他模板；VCore 公开配置的默认选择和兼容规则仍待接线验收。
- 原生临时证书 HMAC、CertificateVerify、单连接一次性状态、私钥清理及经典模式回归保留；未导出临时私钥、改写 BIO 或放宽用户证书回调的权限。
- BoringSSL 子模块 `e2a57cfb4d915b4ba820585aef9fdee7bca13fe5` 未修改；扩展位于既有 opt-in build patch。未新增生产依赖或改动 VCore Cargo.lock。

库侧 Debug 33 项、Tokio 17 项、Release 33 项通过；REALITY-only 21 项、fingerprint-only boring 15 / Tokio 16 项及默认 HKDF 9 项通过。包含六项新增混合行为测试、实际内存协商、证书/签名负例和 20 轮重试/取消；Clippy、Rustdoc、格式及 Apple 四个交叉目标检查通过。Android 两 ABI 在显式 API target 下通过；进一步统一 NDK 原生编译器路径后，新目录编译也通过。最初 target 缺 API 级别、API 后缀编译器包装器与 NDK 工具链冲突造成的二次 CMake 配置错误分别保留在 fork 报告中，后者在新目录仍可复现，不能归因于旧目录残留。以上均不等于 VCore 或设备构建签收。

### 隔离对端：13/13 PASS

最终完整运行 `n7-hybrid-fork-20260926-v3` 使用最新官方 Mihomo 下载产物，容器二进制实际版本 v1.19.31 / Linux ARM64 / Go 1.26.8；独立 cover/origin 使用 OpenSSL 3.5.8。两个服务端容器位于 Apple Container host-only 网络、guest MTU 1500，无宿主监听或发布端口。

| 范围 | 本次实际结果 |
| --- | --- |
| 原生混合-only × IPv4/IPv6 | share `(4588,1216)`；选组 4588；双向各 10 MiB 逐字节校验通过 |
| Chrome133 双 share × IPv4/IPv6 | shares `(4588,1216),(29,32)`；选组 4588；双向各 10 MiB 通过 |
| 经典原生 / Chrome133 对照 | share `(29,32)`；选组 29；双向各 10 MiB 通过 |
| 对端经典选组、HRR、错 short ID / 公钥 / SNI、普通证书、TLS1.2 | 七项明确失败，不是超时；业务原站零数据 |

原站独立记录精确字节数，观察器与客户端分别记录实际选组。测试前后八个输入文件、probe 二进制与 lockfile 不变；两个容器及所属进程全部回收。原始结果位于本仓库忽略的 `target/interop/runs/n7-hybrid-fork-20260926-v3/results.json`，SHA-256 `b6c586d8aeb99ba42aafe16680fae1b9f88b5e91d626ef3a5b4fe31d92370fc7`。原生补丁 SHA-256 `308b0fabbf8651656d4e853e0f789746b4125033dd9bb398903f6bae31ade4da`；完整源码/依赖 hash 与命令记于 boring fork 的 `docs/reality-hybrid.md`。

首轮 `n7-hybrid-fork-20260926-v1` 在 cover 启动时失败，尚未执行协议用例，容器清理成功。隔离最小复现确认 Python 的 EC-NID setter 不接受混合组名称；自有夹具改用 OpenSSL 默认组后仍严格检查实际协商 4588，未改第三方或放宽断言。v2 随后 13/13 PASS，最终格式/注释整理后 v3 完整重跑 13/13 PASS，不拼接结果、不追改 v1。

这是独立 fork 客户端到真实 Mihomo 的能力证明，不经过 VCore 的公开 YAML、受控 Dialer、运行时或同步 Stop，不能抵扣 S03/D16 主腿/下载腿及 N7 阶段验收。

## 已获准发布与 VCore 接线

用户追加授权后，`feat/reality-hybrid` 已推送到正式 boring 远端；`git ls-remote`
确认完整 SHA 为 `b7639ab705076748133d5e8658914e3c3a364cb6`。VCore 从该 HTTPS Git
来源锁定三个 crate；仅变更三条 source，保持既有 Windows 配套解析，不使用相邻源码。
schema22 / Invoke v5；经典默认保留，主/下载腿均接受显式混合开关。公开配置和实际
ClientHello 内存探针已通过，非兼容模板在 IO 前拒绝；真实容器子包仍独立验收。

首个 VCore 冒烟 `n7-hybrid-vcore-smoke-v1` 因新增测试的错误类型转换编译失败，未启动
容器；修正自有测试后 v2 的原生 TCP、Chrome H2 双腿和认证/降级负例 3/3 通过，
四个所属容器已回收。`n7-hybrid-vcore-full-v1` 在补齐构建身份/多语言文档前主动中断，
保存 INTERRUPTED 与清理结果；不算完整子包通过，也不拼接其已通过的子集。

完整运行 v2 在 16 个通过用例后因 `none-tcp-security` 的观测门禁失败停止；Rust
认证/拒绝断言通过，源码未变化，四个容器清理通过。保留原始 FAIL，不将它解释为
生产降级成功。隔离对照 `n7-hybrid-vcore-security-diagnostic-v1` 确认：无命名模板只
声明 group 4588，经典/P-384 cover 均返回原生 `NO_SUITABLE_KEY_SHARE`，Mihomo
关闭连接而未生成 ServerHello；Chrome133 则分别收到 group 29 和 group 24 的 HRR。
原观察器门禁错误地要求两种配置都收到这两个 ServerHello。

修正仅位于自有观测夹具和验收谓词：混合-only 必须同时具备实际 groups/share、
原生无共同组错误、零字节服务端 flight 和关闭证据；Chrome 必须捕获经典选组及
HRR，并逐主/下载腿计数。缺失观测、超时或仅“没有 ServerHello”不能记 PASS。
回放回归先红后绿；临时诊断日志已移除，未改变生产 TLS 或第三方代码。另修正
N1 测量配置遗留测试将 N6 已支持的 Hysteria2 当作未来协议的过时断言，保留
WireGuard 拒绝和 Hysteria2 feature admission；不改变运行时行为。

负例复验 `n7-hybrid-vcore-security-v2` 的 `none-tcp-security` 通过，随后独立下载
配置在旧 native 测试构造入口报缺少 prepared download endpoint，尚未进行网络
握手；全部容器回收。通过无网络回归复现后，测试改用已存在的双端点构造入口，
从容器 fixture 的字面 IP 准备下载端点；不放宽生产 prepare 防护。
同类 owned-resources 构造入口也补齐独立下载端点。随后
`n7-hybrid-vcore-security-v3` 的两种指纹 × TCP/H1/H2 六组负例全部通过，源码身份
不变、四个容器回收；该定向运行不替代下面的完整子包验收。

最终完整运行 `n7-hybrid-vcore-full-v3` 在同一生产输入下 54/54 PASS，包含 46 项
功能/认证/公开接线组和八组各 20 轮生命周期/资源检查，四个容器回收，
`source_unchanged=true`。不拼接前面诊断运行的 PASS；共享回归、平台构建和准确
边界在 [N7.2 报告](N7-reality-hybrid.md)单独记录。

## 后续独立授权

- N7.1：用户批准未修改的官方稳定版 BLAKE3 C 源和最小自有 FFI，用于任意二进制
  context 的 DeriveKey；不手写密码算法，不从外部研究 checkout 动态取得生产源码。
- N7.4：用户批准在自有 boring 的独立分支，按 ShadowTLS v3、Restls、JLS 分别
  最小扩展原生握手认证能力并验证；保留完整 TLS 认证，不恢复旧 rustls fork，
  不新增自制 TLS 引擎。这不是对第三方任意修改或远端发布的授权。
- 两项授权解决实施边界，不是功能、下载腿、互通或阶段通过证据。

## 其他子包与下一步

- VL06 Encryption 已完成独立子包；ECH 仍是未签收的独立路线，不受原 share 裁剪直接阻塞，也不因此宣称已实现。
- 三种附加封装的当前公开接口与参考实现核查见[安全封装可行性研究](N7-security-feasibility.md)。有源码实现不等于满足当前认证/生命周期边界；未做原生验证的路径仍未证明。
- 当前最小混合 REALITY 扩展已经获准，库门禁见上文；N7.4 原生扩展依靠新授权，不能从混合模式授权自行推定；TLS 引擎和 AWS-LC 边界不变。
- boring 混合分支发布授权已执行；S03/D16 子包已本地验收。N7.1 冻结验收现已完成，继续 N7.3 / N7.4；N7.4 使用 `feat/n7-security-handshakes` 独立分支。除明确获准的提交外不自动 push，不进入 N8。

N7.4 追加进度：ShadowTLS v3 最小原生 hook 已通过独立 fork 的 25/25 隔离门禁。
用户另行批准后，`de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1` 已推送到正式 boring
分支并核对远端；VCore 在 N7.1 提交后完成固定依赖准入：37 项容器回归、120 轮
生命周期/资源检查、Apple 五目标和 Android 两 ABI Release 通过，schema23 不变。
这不是 VCore ShadowTLS 或 N7.4 签收，也不授权后续 fork 提交自动发布，详见
[ShadowTLS 接线记录](N7-shadow-tls.md)。

JLS 追加进度：用户单独批准的 `a859a66311c82a2f2bf2d0bc392e1475c8615b66`
已发布并固定接入。VCore 生产接线本地提交 `94c05f18`：122/122 容器用例、
80 轮生命周期/资源检查、197/197 所属容器清理及 Apple/Android Release 构建通过。
这只签收 JLS 对应主腿/下载腿字段，不抵扣 ShadowTLS、Restls、ECH 或 N7.5；
未 push VCore，也未进入 N8。完整源码身份和失败记录见 [JLS 报告](N7-jls.md)。

生产子包完成时按既有约定本地提交；全部 N7 门禁未通过前，不创建 N7 完成提交。
进度/研究记录不冒称生产完成。安全封装仍须各自取得前置证据，不能用另一个
协议成功或新授权替代真实认证、下载腿与生命周期验收。

[BORING-API]: https://github.com/OneXray/boring/blob/67581195fd6388a8bfd42c4e39e945f73c99a2b2/boring/src/ssl/reality.rs
[BORING-PATCH]: https://github.com/OneXray/boring/blob/67581195fd6388a8bfd42c4e39e945f73c99a2b2/boring-sys/patches/reality-client.patch
[MIHOMO]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/component/tls/reality.go
[RESTLS-SERVER]: https://github.com/MetaCubeX/restls-client-go/commit/a8fa52c83df7e4feec0d94998fb2729f91b2a34a
[RESTLS-FIX]: https://github.com/MetaCubeX/restls-client-go/commit/61f3272b964b2282a90278174c390cd9afb095f2
[JLS-RESUMPTION]: https://github.com/MetaCubeX/jls-tls/commit/048cc206000261943fdf93f5b3bbe2b81524be77
