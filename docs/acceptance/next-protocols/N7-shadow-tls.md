# N7.4：ShadowTLS 前置能力与接线记录

2026-09-26。**独立 boring v3 hook 门禁与 VCore 固定依赖准入通过，
S07–S08 / D20–D21 与 N7.4 未签收。** v1/v2、异步受控记录流、主腿与下载腿、
运行时资源/Stop 仍须分别完成，不能由 hook 的结果抵扣。

## 已验证并发布的最小接口

自有 boring 独立分支 `feat/n7-security-handshakes` 的提交
`de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1` 新增 opt-in `shadow-tls-v3` feature 与
`SslRef::set_shadow_tls_v3_client(&[u8])`。连接级状态复制并清理密码，在真正编码的
ClientHello 进入 transcript 前生成认证 session ID；原生状态与 wire 同步更新。
非阻塞重试不重复生成，HRR 保留初次 ID。只允许新 TCP 客户端 TLS 1.2/1.3；
与 REALITY、实际 ECH、会话恢复、early data、DTLS、QUIC、服务端模式互斥。

该接口不等于认证成功。调用者仍须验证 relay record、完成原生 TLS 的证书、
CertificateVerify / Finished，再切换业务记录；不接受握手失败后仅凭 HMAC 放行，
不在 BIO 外部改写 hello，不导出私钥或流量秘密。BoringSSL 子模块保持不变，
扩展是自有 fork 的 opt-in build patch；不恢复旧 rustls fork或新增 TLS 引擎。

用户单独批准上述提交的发布及 VCore 固定 Git revision 接入。已执行：

```sh
git push origin de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1:refs/heads/feat/n7-security-handshakes
git ls-remote --heads origin refs/heads/feat/n7-security-handshakes
```

正式来源为 `https://github.com/OneXray/boring.git`；远端返回完整 SHA 与上述提交一致。
N7.1 已验收并本地提交为 `faa3723`；随后才将 VCore 三个 boring crate 一起切到
上述固定 revision，未改其他 lockfile 依赖。`outbound-vless` 启用 native hook，
新增纯内存依赖门禁首先在旧 revision 缺少方法而失败；此后验证新 revision。
尚未开放 ShadowTLS YAML，也不将依赖接入当作运行时封装完成。
这次授权不包含后续 Restls/JLS 提交的远端发布，也不包含 VCore push。

## 独立 fork 门禁

- Debug boring 27 项、Tokio 19 项；Release boring 27 项、Tokio 新 hook 3 项通过。
  包含六份 hello 的认证、密码所有权、重复/过晚/互斥配置、版本下限、完整 TLS、
  四种指纹与默认模板、实际 P-384 HRR、错信任/名称/签名以及 20 轮取消清理。
- hook-only 3 项、默认 hash 13 项及无 feature 构建通过；Clippy `-D warnings`、
  Rustdoc `-D warnings`、fmt、Ruff 通过，无新依赖或 lockfile 变化。
- Apple 四交叉目标和 Android ARM64/x64 library check 通过；macOS arm64 使用
  本机纯内存测试。这不是 VCore Release 链接、Windows 或设备证据。

最终隔离运行 `n7-shadow-hook-v3`：**25/25 PASS**，`source_unchanged=true`，
`cleanup=true`。默认加四种命名指纹 × TLS 1.2/1.3 × IPv4/IPv6 共 20 项，另有
Chrome133 实际 HRR 一项；均读取 server-first greeting、双向各 10 MiB 逐字节
验证，独立原站确认字节数。错密码、错证书信任、错验证名、坏 record MAC 四项
在连接业务原站前明确失败，不以超时算认证拒绝。

客户端 probe 是阻塞、仅客户端的合成能力验证工具，不是 VCore 生产适配器。
两个 Apple Container host-only 容器分别运行官方 latest Mihomo v1.19.31 /
Go 1.26.8 与 OpenSSL 3.5.8 cover/origin；MTU1500，无宿主监听或发布端口。
所有所属容器及日志进程回收。报告绑定 15 个 fork 输入文件、probe 二进制和 lab
输入摘要，测试发生在本地提交前，不将后来产生的提交号倒填为测试时的父提交。

| 产物 | SHA-256 |
| --- | --- |
| `n7-shadow-hook-v3/results.json` | `0dfe4330ad48effaf5b4227a83a46e766ed4b18c9bba7ae3cf5ffa598c2e5b6c` |
| native hook patch | `0c89bcd209bf40ab9033c1cd7f4e12388c1d44a6684a7c874e772a1ee1fa8138` |
| probe executable | `1249d584deb97bec2b3ab693e702f09be87abf742e639dbf5b411eb000c00cd6` |
| fork lockfile | `ee6523543d51017e753350b6a119e986605a7a1c19fc2de74d73f42e9375880a` |
| Mihomo binary | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |

原始报告保留在忽略目录 `target/interop/runs/n7-shadow-hook-v{1,2,3}/`。
v1 因自有夹具错误使用 v1/v2 密码字段而未进入协议用例；v2 完成首个真实数据交换，
但结果谓词将 OpenSSL 的 `TLSv1.3` 与 probe 的 `TLS1.3` 错判不等。v3 用显式两值
映射重跑全部 25 项，保留旧 FAIL；没有修改第三方、放宽认证或数据断言。

更完整的命令与逐文件摘要见 [fork 的提交内报告][FORK]。后续生产适配器继续以
已批准的受控 IO / SecurityClient 接口验证，不从相邻研究 checkout 链接生产代码。

## VCore 固定依赖准入

该切片只准入 `de7bf494`，schema23 / Invoke v5 不变，不开放 ShadowTLS YAML。
冻结输入：父提交 `faa37235ad53b24002a2f1223c2167d2550f3fa2`，CODE_PATHS
SHA-256 `f9135c707340340504304b6eea88ffd522e9379a29de15593a8d4875bec1cff8`，
lockfile SHA-256 `e317c1d1761ba817f34c55327d14d252e61bd68e80d4bcc841003af515407553`。
Cargo 初次更新另行重选了 Windows 传递关系，已恢复原配套选择；最终 lockfile
只改变三个 boring crate 的 Git source，`cargo fetch --locked` 通过。

本地 Debug/Release 各通过依赖能力 6 项、共享 security 27 项、Encryption 18 项；
Debug 另通过配置/feature 32 项。全 feature/all-target Clippy `-D warnings`、
全目标 `--no-run`、C header/TLS audit、Python 160 项、fmt/Ruff/diff 检查通过。
单 `outbound-vless` 能力 6 项及无默认 feature 编译通过，分别保留 112 / 100 项
既有未使用项警告，不称为零警告构建。日志在
`target/interop/builds/n7-shadow-dependency-v2/`。v1 的命令误写不存在的
`n7_security_config` 测试 target，已保留错误输出；v2 用实际能力 target 重跑。

同一冻结输入的容器回归 **37/37 PASS**，所有报告 source/cleanup 均为 true：

| 运行目录（`target/interop/runs/` 下） | 实际范围 | 报告 SHA-256 |
| --- | --- | --- |
| `n7-shadow-dep-chrome120-v1` | TLS/经典 REALITY 数据及负例、AnyTLS，5 项 | `13f05f4ae94bd5f5d617b3e2407858c9b026065b0ebfe1648915a141d99236d1` |
| `n7-shadow-dep-chrome-v1` | 同上及 TLS/Vision REALITY life/owned，9 项 | `b3986099d5e32c425c82b30ed8f713e9042b51bf05d569fba1c2a6dbfdf1ecb1` |
| `n7-shadow-dep-firefox-v1` | TLS/经典 REALITY 数据及负例、AnyTLS，5 项 | `7cc92839b113d24d7cd4c851ed8a422ee333fba954d9680f8d657ac80c1ec82b` |
| `n7-shadow-dep-safari-v1` | 同上，5 项 | `c43f2a2c2755e717dc18506c237c9c78040fba67e96ddeb7ae58d66007d8e1ce` |
| `n7-shadow-dep-hybrid-v1` | 混合 TCP/H2 双腿、认证/降级、经典腿差分、life/owned，8 项 | `24d9b585f07116481fa288fc479f1bf80f295b605b4e4580386999d16a00ead5` |
| `n7-shadow-dep-encryption-v1` | random/0-RTT/mixed：TLS、REALITY、XHTTP 双腿及 Vision 两种 direct-close，5 项 | `785c825df93bfd1c5e4651d297903b70277ba13cb3598a2cc5a8dcf9f2c756b7` |

其中六个 life/owned 用例各 20 轮，共 120 轮；停止后同步归零并安静观察五秒。
这些是新依赖上的既有功能回归，不是新增 ShadowTLS 数据面。所有协议端、观察器、
对照入口和原站均使用隔离容器；官方 latest Mihomo 实际版本为 v1.19.31。

Apple 五目标 Release 合并 XCFramework、Android 两 ABI Release 及配套
`libc++_shared.so` 打包通过。产物在上述 v2 目录，不纳入 Git：

| 产物 | SHA-256 |
| --- | --- |
| iOS ARM64 `libvcore.a` | `6d39f1f34194442bab3b297f4648c6ae80597355b40510b5ae66b30053eb12fa` |
| iOS 双架构 simulator `libvcore.a` | `5fb2d8fe41afee2b27b036c50efcd5102a63168ec3589137eed32acc1d51b2f3` |
| macOS 双架构 `libvcore.a` | `42e213e0631137b143ee28ce11337c1d82738936bd50ab379b5760f7dcae724f` |
| Android ARM64 `libvcore.so` | `e932f460354d8fdb6a99398050aa85dd1e34cb08476375c91d2851f3bbb5a68d` |
| Android x64 `libvcore.so` | `a88a9aecb442bfe872cbf52cd9f809c1633ce4ce430dde05a9423c0296b18092` |
| Android ARM64 `libc++_shared.so` | `7466ed097631a564ed6bff0b47768caa76bf03270d2047b5a65c03f497b824df` |
| Android x64 `libc++_shared.so` | `7918ebd0b8074c312d0c610205d49760b98c008026e6b817cd92103a3e12241b` |

Windows 原生、设备、远端 CI 和完整 N7 未执行/未签收，不从交叉构建推断。
后续 JLS hook 已获单独发布授权，但不混入本切片的依赖或测试输入。

[FORK]: https://github.com/OneXray/boring/blob/de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1/docs/shadow-tls-v3.md
