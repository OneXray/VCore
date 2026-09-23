# N1.3：共享流传输与 XUDP seam

2026-09-23。本包完成传入IO上的WS/gRPC/HTTP首包伪装/legacy H2，以及XUDP与VLESS响应头解耦。没有新增公开YAML能力，Invoke v5/schema14不变；新协议注册仍留对应阶段。N1的数据报/DNS、限额与观测、独立feature检查和完整manifest执行门禁仍未完成。

## 已实现契约

- 复用自有N0 WS/gRPC实验，生产接口只接受BoxStream与同次绝对deadline，无隐式socket、DNS或连接池。原生测试通过既有Dialer及protect；TLS走生产共享策略和叶pin，没有skip-cert-verify。
- WS支持明确的首包prefix、普通头、默认/自定义early-data头、路径后缀。URL-safe无padding编码先发送early-data，剩余prefix只写一次到WS帧；负例覆盖保留/重复头、非法URI和early-data范围。官方tungstenite要求真正子协议被回显，代理early-data不具备此意义：使用公开generate_request/from_partially_read接口，加有界HTTP升级校验，不修改第三方。状态101/HTTP1.1/Upgrade/Connection/Accept仍验证；拒绝重复Accept、非请求子协议、扩展、截断和超限头。
- HTTP只给显式prefix加一次HTTP请求头；响应头后的预读字节原样保留，之后双向是原始流，不按Content-Length截断业务。method/Host/path/headers由类型化选项构造，拒绝body framing覆盖。
- gRPC为POST和有界Gun records；legacy H2为PUT与原始DATA流。二者共用连接驱动/背压/取消，但不会混用编码。shutdown按Mihomo整体关闭；owner.stop是join屏障，Drop仅兜底。WS/HTTP CloseWrite保留底层允许的读尾包语义。
- XUDP仅处理帧，VLESS包装流自己消费协议响应头；共享port-first地址编码供后续VMess使用。旧XUDP响应帧、取消、空包和大小边界继续测试。
- 新依赖均取官方稳定版：[tokio-tungstenite0.30.0](https://docs.rs/tokio-tungstenite/0.30.0/tokio_tungstenite/)（MIT）及其tungstenite0.30.0、[httparse1.10.1](https://docs.rs/httparse/1.10.1/httparse/)（MIT OR Apache-2.0）。只启用handshake，禁用内置TLS/连接器；TLS仍为既有ring和自有rustls fork。log facade编译关闭，避免第三方trace打印请求/负载。资源数字见[运行时策略](../../runtime-resource-policy.md#共享流传输基础)。

## 本轮验证

父SHA `f26888aa3637e879d41030fa6cb87fc887c85afc`，源码/依赖/脚本差分SHA-256 `028921f48dcb0bde4f0a28d9d5cddbf4fca551098cb5a0e5cbc2fd97339d683f`。验证方式：提交后 `git diff --binary f26888a HEAD -- Cargo.toml Cargo.lock src tests scripts | shasum -a 256`。文档不计入测试输入摘要。Lockfile SHA-256 `dac1715be749f612044022d785aed556556137920cfc8d216e11e2197bdf0b70`。

环境macOS27 ARM64、rustc1.98.1、Xcode27、Android NDK28.2/API24、Apple Container1.4.1。

| 实际执行 | 结果 |
| --- | --- |
| `cargo test --locked --all-features --all-targets` | 580 lib、15 stream、2 h2、4 compatibility、2 fixture PASS；ignored不计通过 |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | PASS |
| fmt、diff、TLS依赖与C header检查 | PASS |
| Python unittest / Ruff | 60项PASS / PASS |
| `check mihomo-interop --container --extended` | PASS 36.80秒；包括旧XUDP、组/链、100生命周期、100×32-flow；清理完成 |
| 官方Apple构建脚本 | 5目标Release和XCFramework PASS，无interop-test |
| 官方Android构建脚本 | arm64-v8a/x86_64 Release PASS，无interop-test |
| `cargo build --locked --example protocol-stream-probe --features interop-test` + `protocol_streams.run_streams` | 下列9项全部PASS，具体调用由后续统一CLI收敛 |

9项原生case：Mihomo WS/WSS/gRPC/gRPC+TLS/默认WS ED；V2Ray HTTP/legacy H2/自定义头ED/路径ED。各自完成一次protect、服务器先发、65,536B增量回显校验、14B末尾响应、原始origin接收量断言以及驱动join/进程清理。测试显式合成VLESS协议前缀，不是未开放YAML的功能验收，不签收完整T/W/G/H字段；真实协议消费由N2–N4补齐。V2Ray legacy/扩展ED的最小N0-F可行性得到证据，其他N0-F codec/组合仍未跑。

最终原生报告 `target/interop/runs/n1-native-stream-qwwn4pqa/native/stream-cases.json`，SHA-256 `6ee06b3897b53865e8dd0de8a2237eb4b080c924436196cf4c84c21363381b55`。官方Mihomo v1.19.31，二进制 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`；官方V2Ray5.53.0，归档 `75d0b4bf571b33aff8fb3eacb4a7ff16061a2d227503d75c5247852ef0958b15`、程序 `2cbac9546e02d732e657cfa415aad222acd7ced5a55c1f7f04313f46c3f5852a`。每批重新下载latest；不查API、不本地编译、不用旧缓存回退。下载器首轮资产名错误导致404，失败记录保留在 `n1-native-stream-3_x8k965/native/stream-cases.json`，没有将它改记成功；修正官方macos-arm64-v8a资产名后另跑两批。

旧扩展互通100×32-flow重建18,798ms；结束FD6、在用堆63,664B、RSS18,496KiB。日志 `target/interop/runs/n1-stream-debug.log` SHA-256 `0a98ea06224ca471fa72464f261014d56758977939db652f8984a08bc2a22144`；`n1-stream-mihomo.log` SHA-256 `77e56f0cd451f296779a85f741e4ddb3be10d94b777794df69bc8d44986e237f`。平台日志为同目录 `n1-stream-apple.log`、`n1-stream-android.log`。

本包不是完整N1/N0、全Release测试、30分钟长测、Windows原生、真机或CI通过；未push。原生编排目前只提供流基础内部入口，完整清单/报告覆盖门禁、失败注入和资源RAII仍由N1后续子包完成，不能用这9项替代它们。
