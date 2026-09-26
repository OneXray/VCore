# N7.4：ShadowTLS 前置能力与接线记录

2026-09-26。**独立 boring v3 hook 门禁通过且已获准发布；VCore 尚未接线，
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
VCore 正在执行 N7.1 冻结验收，暂维持原 `b7639ab7` 锁，结束后单独切换与回归。
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

[FORK]: https://github.com/OneXray/boring/blob/de7bf4943ff9cd4b40e6f1d3ee98939284aa63b1/docs/shadow-tls-v3.md
