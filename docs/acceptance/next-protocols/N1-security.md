# N1.2：共享 TLS 策略与流关闭

日期：2026-09-23。本工作包实现共享安全机制，不开放任何新 YAML 字段或新协议；Invoke v5 / schema14、生产 classic REALITY、ring provider 和锁定 fork revision 不变。完整 N1 尚有传输、数据报/DNS、feature 与验收工具工作。

## 实现范围

- `security::StandardTlsClient::with_options` 接受传入的 `BoxStream`；不会创建 socket、DNS、后台任务或额外的全局缓存。
- 类型化 TLS1.2/1.3 或仅 TLS1.3、ALPN 列表/必须协商的 ALPN、证书策略和可选客户端证书身份。输入错误在建链前失败；ALPN 每项1–255字节、总 wire 长度最多65,533字节，required ALPN 必须在列表中。节点恢复容量不能超过既有总预算4；0禁用。
- 原 AnyTLS pin 验证器成为共享验证器；精确叶 pin 直接决定信任，非叶 pin 验证证书链和名称，错误 pin 不被 skip 覆盖。显式验证名优先于 skip 且不改变 SNI，与 [Mihomo CA 配置](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/component/ca/config.go) 的验证器选择一致。所有分支仍验证握手签名。
- 客户端 DER 证书/私钥在构造时匹配验证，合计大小受既有256KiB配置边界限制；无文件加载、动态 reload 或 SSLKEYLOGFILE。PEM/YAML 消费仍由对应协议阶段实现。每次构造单独分配恢复缓存；身份、验证策略、SNI、ALPN 不可在同一客户端上替换。
- 错误及 Debug 不输出证书中的名称、pin 或密钥；TLS 握手错误保留错误种类但不透传 rustls 的名称诊断。
- TLS `shutdown` 发出 close_notify，并在最多5秒内刷新，不调用底层流的 shutdown；读方向仍可收到对端尾部响应。重复 shutdown 幂等，之后 write 失败，Drop 释放整个流。此行为参考已经独立验证的 [N0 流关闭实验](N0-stream.md)，不改变 XHTTP 的整条逻辑连接关闭契约。
- AnyTLS 继续使用 TLS1.2/1.3、既有 ALPN/pin/skip 默认值；VLESS XHTTP 继续 TLS1.3、强制 h2；REALITY 仍走专用配置和禁用恢复路径。没有第三方源码改动或依赖变更。

## 验证输入与结果

父提交 `ca1f03df28fabb1c1780fa35667be4bdc74f6ded` 加本轮 `src/security` 差分；差分 SHA-256 `6ade71df7f5a460d50111f67a08066647a37250960c34ef9f5d50ec025bb2017`。提交后用 `git diff --binary ca1f03d HEAD -- src/security | shasum -a 256` 核对。说明文档不计入源码摘要。

主 lockfile SHA-256 `425500945de939af6b81e8a9193612a3a27a205e5d1a700e485f1b73ce764690`；rustls0.23.45 / tokio-rustls0.26.5，fork revision `26f3efe5946dbe96410e85b8541ccf5fe7c244a5`。环境 macOS27 ARM64 / Rust1.98.1，平台脚本使用现有 Xcode27 / Android NDK28.2、API24。

原始日志目录：`target/interop/runs/n1-security-20260923/`。

| 本轮实际执行 | 结果 |
| --- | --- |
| `cargo test --locked --all-features --all-targets` | 579 lib + 2 h2 + 4 compatibility + 2 fixture PASS；ignored不计通过 |
| `cargo test --locked --release --all-features --lib security::` | 17项PASS；不是全Release回归 |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | PASS |
| `check tls-dependencies`、`check c-header` | PASS |
| `check mihomo-interop --container --extended` | PASS，34.88秒；旧协议/组/链/100生命周期/100×32-flow全部通过；清理完成 |
| 官方 Apple 构建脚本 | 五目标Release和XCFramework PASS，无interop-test |
| 官方 Android 构建脚本 | arm64-v8a/x86_64 Release PASS，无interop-test |

新测试先复现缺少共享接口、ALPN未校验、名称诊断泄漏，以及默认 tokio-rustls shutdown 关闭底层流，再逐项修复。17项安全测试包括原有pin/签名/缓存回归，以及名称与SNI分离、TLS1.2/1.3 mTLS缺失/错CA/正确身份/票据隔离、密钥不匹配、ALPN/容量输入拒绝、失败零业务字节、close_notify尾包/5秒上界和握手取消释放。

Mihomo互通本次重新获取官方latest，不用旧缓存替代下载。100次32-flow重建耗时17,341ms；结束FD为6，在用堆63,664B，RSS18,416KiB。没有30分钟长测、Windows原生构建、设备、远端CI或push；这些不由本子包抵扣。mTLS/名称覆盖是共享接口的受控TLS测试，不是尚未公开的VLESS/HY2字段互通。

官方下载实际版本为v1.19.31，来源 `https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt`；本轮宿主/容器资产同为解析出的release。Darwin ARM64二进制SHA-256 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`，Linux ARM64为 `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。`debug.log` SHA-256 `6185fb7b9a224cbe91cfa7501cc9f3383e4278eb5927272b29ae94ed49e0c72a`；`mihomo.log` SHA-256 `6137e44c11f16cd20dc58ae56f50763205f226392b6854cad08a1ceee56d9174`。
