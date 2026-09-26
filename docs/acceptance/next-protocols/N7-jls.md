# N7.4：JLS 能力与生产接线

2026-09-26。**JLS 公开配置与受控异步安全层已完成本地子包验收，签收
S12–S13 / D25–D26。** 同一冻结输入通过 122/122 容器用例、80 轮生命周期/资源
检查及 Apple/Android Release 构建，197/197 所属容器清理。N7.4 的其余封装、
N7.3、N7.5 和完整 N7 仍未签收。当前为 schema24 / Invoke v5。

## 获准发布的接口

自有 boring 分支 `feat/n7-security-handshakes` 的提交
`a859a66311c82a2f2bf2d0bc392e1475c8615b66` 在已发布 ShadowTLS revision
`de7bf494` 上新增 opt-in `jls` feature，提供
`SslRef::set_jls_client(username, password)`。

连接独占两份有界凭据，原生 SHA-256 / AES-256-GCM（32 字节 nonce）对真正编码的
ClientHello random 封装，并认证完整 ServerHello；实际 TLS 状态和 transcript
同步更新。凭据和临时派生材料按握手阶段或失败/销毁清理，不在 BIO 外改 hello，
不导出私钥或流量秘密，不新增 TLS 引擎、第三方依赖或 lockfile 变化。

成功只允许 TLS 1.3；模板可声明 TLS 1.2，但协商 TLS 1.2、HRR、实际 ECH、
REALITY、ShadowTLS、DTLS/QUIC、服务端、会话恢复与 early data 都失败关闭。
JLS shared-secret 身份替代 WebPKI 身份，**CertificateVerify 和 Finished 仍由
原生 TLS 验证**，VERIFY_NONE/自定义证书回调不能绕过 JLS。对齐 Mihomo named
uTLS 的完整握手证明，不复制普通 jls-tls 分支跳过 CertificateVerify 的行为；
失败后不发送伪装 HTTP 探测或普通 TLS 业务回落。

用户在本地门禁完成后单独批准此提交的 push 和固定 revision 接入，已执行并核对：

```sh
git push origin a859a66311c82a2f2bf2d0bc392e1475c8615b66:refs/heads/feat/n7-security-handshakes
git ls-remote --heads origin refs/heads/feat/n7-security-handshakes
```

远端 `https://github.com/OneXray/boring.git` 返回完整 SHA 一致。该授权不包含
VCore push 或未来 Restls 提交的发布。前一个 ShadowTLS dependency revision 的
冻结回归已完成并本地提交为 `7c9ac4aa`；随后才将三个 boring 包同时固定到 JLS
revision，并增加 `boring/jls` 与对应依赖审计，没有修改 Windows 兼容配套版本。

## VCore 接线与当前验证

主连接和 XHTTP 独立下载连接通过公开 `jls-opts` 配置选择同一个受控安全接口。
凭据成对校验、整对象继承/替换、空对象清除及互斥规则见 [JLS 契约](../../jls.md)。
连接器仅包装调用者提供的流，不另建 socket、resolver 或后台任务；原生
CertificateVerify/Finished、有界关闭、取消与同步 Stop 规则保持不变。

十项配置/内存 IO 测试覆盖 strict 字段、错误脱敏、边界、互斥、下载身份、七值模板、20 轮
取消及普通 TLS1.2/1.3 拒绝。公开容器矩阵包含十五种外层/HTTP 版本、三 UDP
编码和三目标类型、认证负例、下载凭据替换、代理组/IPv6/入口/UDP 隔离，以及
gRPC 与独立下载 XHTTP 的 80 轮生命周期/资源观察。实际完成范围及冻结报告见下文，
不将这些结果推广到其他安全封装或未执行的组合。

### 保留的 Mihomo 对照失败

`n7-jls-default-v1` 在完成十四项后，于 gRPC 关闭对照的 peer-start 阶段 FAIL；
VCore 对应用例尚未运行。独立 `n7-jls-grpc-close-repro-v1` 和带定向日志的
`n7-jls-grpc-close-debug-v1` 均重现同一失败：官方 Mihomo v1.19.31 报
`http2: unexpected ALPN protocol , want h2`，关闭夹具收到 EOF 而非服务端首包。

源码边界是 `gun.NewTransport` 调用 `GetTLSConnectionState`，后者仅识别
metacubex/tls 与 uTLS 的 ConnectionState；普通 JLS 返回 jls-tls 的不同类型，
ALPN 读取为空。仅切换官方对照客户端为 Chrome 指纹，
`n7-jls-grpc-close-chrome-v1` 通过；VCore 无指纹的
`n7-jls-grpc-default-base-v1` 独立通过。没有修改第三方、绕过 ALPN 或改变
VCore 的无指纹实现。

后续无指纹 gRPC 关闭用例明确使用 `jls-grpc-chrome-baseline`，同时记录对照
`client_fingerprint=chrome` 和待测节点的原值，不称为完全同配置差分。仍比较
同一个 JLS listener 上实际尾包与终止行为；其余 JLS 外层和命名模板不套用
该例外。`n7-jls-grpc-close-scoped-v1` 已通过，完整矩阵重新独立运行。
原始 FAIL 保留，不能追改成 PASS；这也不表示 Mihomo 无指纹 gRPC 客户端已修复。

### 凭据错误脱敏修复

随后通过 schema24 的真实 `VCoreInvoke(validateConfig)` 复现：将 JLS 凭据误写为
数字时，Serde 类型错误原样带入该值；直接 `Config::parse_yaml` 同样复现，因此
不是 FFI 新增请求回显。JLS 的对象解码现在沿用原有 strict map，但将输入相关
的类型/未知键错误转换为不含值的 `invalid JLS credential object`。主腿和下载腿
共用这一入口，null、错型、未知字段仍拒绝；完整替换和空对象清除不变。

新增公开配置回归先红后绿，实际 Invoke 复现也已转绿。第二轮完整矩阵
`n7-jls-default-v2` 在 48 项完成、下一项执行期间由开发代理发出 SIGINT 终止；
60/60 所属容器清理。报告的通用原因字符串为 `user interruption`，本次实际
不是用户要求停止；清理期间新增回归测试使 `source_unchanged=false`，该运行
保持 INTERRUPTED、不参与签收。修改后重新冻结输入，完整运行 v3，不拼接旧 PASS。
v1/v2 的本地 `n7_encryption_wire` 命令仅编译并跳过三项 ignored 测试，不计作
Encryption wire 行为通过；v3 本地清单移除此重复编译项，换成实际 ShadowTLS
能力测试，Encryption 组合另通过真实容器消费者验证。

### 第三轮冻结输入与本地门禁

`target/interop/builds/n7-jls-v3/local.json` 已完成 PASS，且
`source_unchanged=true`。父提交为 `7c9ac4aafb96bfe0eb4a49baa1debafe74f1455b`；
CODE_PATHS SHA-256 为
`ff34c4042a318043b5575b109b92250af5c0667be143199294abb2d218d14b2a`；
Cargo.lock SHA-256 为
`61f7f4a4e18f8d95a3f9d4f3225a6093b021a8a5d95422e909e1c710014f3b4a`。
同组容器、组合和平台构建必须保持这一输入，不能用旧输入的结果补齐。

- Debug / Release 各自执行：security 27、config 76、Encryption 单元 18、
  JLS 10、security capabilities 5、ShadowTLS capability 1，以及 VLESS / feature /
  Encryption / hybrid 配置共 21 项，全部通过。
- `outbound-vless` 单 feature 的 JLS 10 + capabilities 5、无默认 feature library
  check、全 targets 测试编译、全 features / targets Clippy `-D warnings` 通过。
- Python 162 项、Ruff 检查与 85 文件格式检查、TLS 依赖审计、C header、Rust fmt
  和 `git diff --check` 通过。
- 此处的全 targets `--no-run` 仅为编译，不算执行其中的外部互通或设备用例。

组合组第一次启动时，主容器矩阵仍占用本机实验室锁；`exclusive_run` 使用非阻塞
互斥锁，立即拒绝，没有启动 peer 或执行行为用例。该记录保留为
`n7-jls-v3/combinations.json` FAIL（source unchanged / cleanup 均 true），不算
协议失败或通过；后续等待主组完成再以独立 `combinations-retry.json` 串行运行，
不修改、绕过互斥锁，不覆盖首次日志。

### 已完成的公共消费者与平台构建

同一 CODE_PATHS 和 lockfile 输入完成下列容器组，均 PASS、source unchanged、
cleanup true；共 104 个用例、157/157 所属容器 join。所有 server / cover / origin /
关闭对照均在 host-only Apple Container 内运行，MTU1500，没有宿主服务端监听。

| 运行 | 通过项 | 报告 SHA-256 |
| --- | --- | --- |
| `n7-jls-default-v3` | 51 | `fb5196da1354c4f770dde22fed1146376d449e2e1f7b2eeea1e6eb1f3f2cfbaa` |
| `n7-jls-chrome-v3` | 7 | `3bfbc2ac4bfb6432f1a5945332b897896a33732533c3e4cbdc84636c8f1a4b11` |
| `n7-jls-chrome120-v3` | 7 | `82e199d4052b7f0f05139d51d029e9c098997c4d1cf3c112ba5b01cddb689878` |
| `n7-jls-firefox-v3` | 7 | `8256c1c8555ab817d3dcca2846914ac473b7f1a44ba6e517c6935f5f143180f4` |
| `n7-jls-safari-v3` | 7 | `1ebf914f8632ab713028019e089bf5af438984d162d41a4e5497031a62102fc5` |
| `n7-jls-regression-none-v3` | 5 | `2cea829436b6a34dc5be380a2d142733a15c8aafca533676e782afcf5fc38615` |
| `n7-jls-regression-chrome-v3` | 5 | `0302b7baae50f95a3a0ad49aaf50ac7436ea88eb699dd09b9085b026ef9f8f8d` |
| `n7-jls-regression-chrome120-v3` | 5 | `a51e22ec9110b888b3a41acfea3b5333ee4aa6579128ed3222ef02cdec6f87c2` |
| `n7-jls-regression-firefox-v3` | 5 | `94118c6d368c2e403bcae6648f59cdcf49fc60162bdd96e5541436a4f28838da` |
| `n7-jls-regression-safari-v3` | 5 | `7b27241a7d6c9ed4a760b6d826dbf6f123a057d57241607524df4f76ba3544d2` |

默认组的 gRPC 与独立下载 XHTTP 各执行 20 轮公开生命周期和 20 轮自有资源观察，
合计 80 轮；每个外层的关闭用例使用实际 Mihomo 对照，只有上述无指纹 JLS gRPC
显式采用 Chrome 参照。四种命名模板组各执行 TCP BASE/AUTH、gRPC BASE/CLOSE、
XHTTP H2 独立下载 BASE/AUTH 及 H1 独立下载 BASE。五种共享回归组各执行标准
TLS BASE/NEG、经典 REALITY BASE/NEG 与 AnyTLS 真实业务消费者。

Apple 五 target 的 Release archive 合成 XCFramework，Android ARM64/x64 Release
库均通过统一构建入口；这只是库构建，不表示设备/TUN 或 Windows 已验收。

| 发布形态 | SHA-256 |
| --- | --- |
| iOS ARM64 `libvcore.a` | `05323eb478a45554e60bb5e9e82f0eb611d08dd2fc9c6d4b2460da4754bb5737` |
| iOS ARM64/x64 simulator archive | `c207abce28557f69e037896a5e37b86c75538697d1e36d5e40bb25b44115a547` |
| macOS ARM64/x64 archive | `a33b036f7097e4070aa3c261d4f7b1f3f4ef1c106db5f1179ed922d51ae872a2` |
| Android ARM64 `libvcore.so` | `38475e8b61ef3a83550ea63b41f2455cc1aaa02a9678cc02af7498730c723c62` |
| Android x64 `libvcore.so` | `cbc45782e78b15f7b4e5657eadc0c89cdcb6dc91bbe0adf7eb64e9f7cb0cd01d` |

聚合报告保存在 `target/interop/builds/n7-jls-v3/`：local JSON SHA-256
`8a15056f71d8df49c14b5a70c455fbf5036a5f9b71c1de801cdc0c0fb2a657db`，
containers JSON `185c31868da1254ec4a3c2f75ac3caa582e22933898223c229124cc0b1266efb`，
platform JSON `a16750c79ee52c4789dd4b88cb5bbbd6e492b9a5c1570c7cc72651e5c9013720`。
平台报告同时记录两个 ABI 的 `libc++_shared.so` hash；完整 CLI、退出码、耗时和
脱敏日志 hash 均保留在各聚合报告中。

### 组合与逐字段签收

主组结束后，独立 `combinations-retry.json` 完成 PASS、source unchanged；六项
混合 REALITY 回归与十二项 JLS+Encryption 用例通过，40/40 所属容器 join。
聚合报告 SHA-256 为
`049b0c8e5729d0a10a1ffa27e18f977288ef2c5af3fb8084be1f32508239163b`。
合并本轮主组实际执行数为 122，不拼接 v1/v2 中断、诊断或独立 fork 用例。

| 运行 | 通过项 | 报告 SHA-256 |
| --- | --- | --- |
| `n7-jls-hybrid-regression-v2` | 6 | `e6bf35640be4ea6cb29cb96ae67bfa16376b5c0a87123fcc638ce1e9fa6d7130` |
| `n7-jls-encryption-native-1rtt-mixed-v2` | 2 | `9311c15f6a209a20ec0f030640a51c34508e655a0d0b83507362296ef96cd83f` |
| `n7-jls-encryption-native-0rtt-mixed-v2` | 2 | `05a72400601b4322caa400e9a0386f4955ffa784182c88b1ee472d5649438430` |
| `n7-jls-encryption-xorpub-1rtt-mixed-v2` | 2 | `1d54d6d74e9382c10f6466a52fcc075df91a490588dbe2974f6c74a3458d7494` |
| `n7-jls-encryption-xorpub-0rtt-mixed-v2` | 2 | `62835aa95a446434d24570be4942bdc63f962c1d083c91084f1d394462c79672` |
| `n7-jls-encryption-random-1rtt-mixed-v2` | 2 | `ca16bf50e3201c6770423f04c7752caf493a531b7f742346563fa54ef4c239a4` |
| `n7-jls-encryption-random-0rtt-mixed-v2` | 2 | `cd2c0e5f318d98ac35cee3d1a68e3dbac90460a96f0aa23b0edc130fc5fee854` |

每种 Encryption 组合均使用 TCP 与 XHTTP H2 独立下载的真实 VLESS 消费者，涵盖
native/xorpub/random × 1rtt/0rtt 的 mixed-key 配置。它们是明确选定的组合，
不是 N7.5 的完整笛卡尔积验收。混合 REALITY 回归为 none/chrome 的 TCP 与 H2
下载 BASE，以及 none TCP / chrome H2 的认证负例。

| 矩阵字段 | 本次证据 | 结论 |
| --- | --- | --- |
| S12 `jls-opts.username` | strict/边界/脱敏；十五种外层 BASE；独立错误用户名且原站零业务 | PASS |
| S13 `jls-opts.password` | strict/边界/脱敏；四模板；独立错误密码且原站零业务 | PASS |
| D25 下载 `jls-opts.username` | 整对象继承、第二有效身份完整替换、错误身份、{} 清除拒绝 JLS-only 对端 | PASS |
| D26 下载 `jls-opts.password` | 不叶级合并、完整替换、独立错误密码、恢复正确配置再成功 | PASS |

可重复入口是 `python -m vcore_scripts.protocol_jls <fresh-output>`；命名模板添加
`--client-fingerprint chrome|chrome120|firefox|safari` 与相应选定 case IDs。
共享回归使用 `protocol_fingerprint`，混合 REALITY 使用 `protocol_reality_hybrid`；
Encryption 组合经 `exclusive_run` 调用 `protocol_vless_container.run(...,
jls=True, encryption=<profile>)`。所有实际参数、退出码和日志 hash 已记录，
不能以只编译测试或只建立 TLS 连接替代这些公共消费者结果。

## 独立 fork 证据

- boring Debug/Release 各 30 项：JLS 3、ShadowTLS 3、REALITY 17、指纹 7。
- Tokio Debug 21 项；Release JLS 2 + ShadowTLS 3。20 轮取消回收只使用内存 IO。
- hook-only 2 项、默认 hash 13 项、默认构建、Clippy/Rustdoc `-D warnings`、
  fmt/Ruff 通过。首次未启用 Tokio 自身 ShadowTLS feature 的零测试不计为通过，
  已另用显式 feature 完整重跑。
- Apple 四交叉目标及 Android ARM64/x64 library check 通过；macOS ARM64 由
  本机测试覆盖。这不是 VCore 生产链接、Windows、设备或远端 CI 证据。

隔离运行 `n7-jls-hook-v1`：**17/17 PASS**，`source_unchanged=true`、`cleanup=true`。
默认加四种模板 × IPv4/IPv6 共十项正例，每项必须真正 TLS 1.3、观察到原生
CertificateVerify/Finished、server-first greeting、双向各 10 MiB 逐字节正确，
独立原站核对字节数。错用户名、错密码、改 ServerHello random、改加密握手 flight
及三个普通 TLS 对照均明确拒绝，业务原站零连接；超时不算认证失败，两项篡改须
实际注入才可通过。

官方 latest Mihomo v1.19.31 / Linux ARM64 / Go 1.26.8 与 OpenSSL 3.5.8 原站/对照
分别位于两个 host-only Apple Container，MTU1500，无宿主监听/发布端口。客户端是
仅客户端、阻塞的 fork probe，不经过 VCore 配置、DNS、受控 Dialer、代理组或 Stop。

| 产物 | SHA-256 |
| --- | --- |
| `n7-jls-hook-v1/results.json` | `7c8ed8dc0a2c5311c4302bb235c64739601ddb1cfef7a5fd78ecafefabf3d23a` |
| native JLS patch | `204879d971b95a30534cea9a3a2b723238857f24884236ab3139da9307761914` |
| probe executable | `085ef86f299b3fef0ad2482004bf6526132fdd97d0f94a93d04f4de8443f727a` |
| fork lockfile | `ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a` |
| Mihomo executable | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |

报告绑定 18 个 fork 输入文件，提交前后这些 hash 与 probe 一致。lab 父提交为
`faa37235ad53b24002a2f1223c2167d2550f3fa2`，CODE_PATHS 摘要为
`f9135c707340340504304b6eea88ffd522e9379a29de15593a8d4875bec1cff8`；此时 lab
只接入前一个已发布 ShadowTLS revision，不能把 fork 客户端结果记作 VCore JLS。
原始报告位于忽略目录 `target/interop/runs/n7-jls-hook-v1/`，独立构建/内存测试日志
在 fork 的 `target/n7-jls-gates/`，完整重现命令见[提交内报告][FORK]。

原始 fixture 错误保留在 fork 报告：零 context patch 无法应用；普通 TLS1.2 对照
group 列表遗漏 P-256 证书曲线。分别修正自有 patch context 和测试组配置，没有
放松第三方原生验证，没有将这些失败追改成 PASS。

本次已完成 JLS 冻结公共消费者、共享回归与生产构建。Encryption 全组合仍属于
N7.5 的单独签收，JLS 成功不抵扣 ShadowTLS、Restls、ECH、完整 N7、Windows
原生、设备/TUN、远端 CI 或发布门禁。

[FORK]: https://github.com/OneXray/boring/blob/a859a66311c82a2f2bf2d0bc392e1475c8615b66/docs/jls-client.md
