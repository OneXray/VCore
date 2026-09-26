# N7 高级安全：当前后端前置验证

2026-09-26。状态：**N7 未完成；已获准在自有 boring 独立分支扩展混合 REALITY，并完成库侧内存/真实对端门禁。VCore 仍锁定原 revision，等待 fork 发布授权后进行 S03/D16 生产接线。** 下文原始接口失败保留，不是已交付经典 REALITY 的回归。N7.1 / N7.3 / N7.4 / N7.5 未签收；不能将一个后端限制推广成所有高级安全实现都不可行。

## 本次输入和范围

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

库侧实现已本地提交为 `b7639ab705076748133d5e8658914e3c3a364cb6`；提交后八个被测输入 hash 与最终容器记录一致，工作区干净。未 push；不能把该提交提前写入 VCore 生产依赖或视为已发布。测试发生在提交前，具体父 SHA 与被测输入见 fork 报告，不倒填测试时尚不存在的提交号。

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

## 其他子包与下一步

- VL06 Encryption 与 ECH 是独立路线，本次未完成其原生互通；不受同一 share 裁剪直接阻塞，也不因此宣称已实现。
- 三种附加封装的当前公开接口与参考实现核查见[安全封装可行性研究](N7-security-feasibility.md)。有源码实现不等于满足当前认证/生命周期边界；未做原生验证的路径仍未证明。
- 当前最小混合 REALITY 扩展已经获准，库门禁见上文；不会将该授权扩大到其他 native hook、TLS 引擎或 AWS-LC。
- 下一步需获得 boring 分支的 push 授权，使不可变 revision 能从正式 Git 来源解析，再接入 VCore 的 S03/D16 和下载腿、跑共享回归及 N7 全矩阵。不能以相邻 `path`、`file://` 或未发布 revision 留下不可复现的生产依赖。

尚无完成的 VCore 生产子包，不创建 N7 完成提交、不自动 push，不进入 N8。已验证的库侧子包按既有约定本地提交，进度/研究记录不冒称生产完成。安全封装若还需其他新 hook 或独立 TLS 引擎，仍须按自己的前置证据和授权边界处理，不从本次混合扩展推定许可。

[BORING-API]: https://github.com/OneXray/boring/blob/67581195fd6388a8bfd42c4e39e945f73c99a2b2/boring/src/ssl/reality.rs
[BORING-PATCH]: https://github.com/OneXray/boring/blob/67581195fd6388a8bfd42c4e39e945f73c99a2b2/boring-sys/patches/reality-client.patch
[MIHOMO]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/component/tls/reality.go
