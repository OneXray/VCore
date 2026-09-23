# N2.1：Trojan 编解码

2026-09-23，N2.1 PASS；N2 整体尚未签收。生产 YAML 仍未开放 Trojan，Invoke v5 / schema14 不变，没有新增或更新第三方依赖。

实现参照 [Trojan 官方 wire 定义](https://trojan-gfw.github.io/trojan/protocol)及 Clash-RS 的认证/数据报分层；自有实现复用 VCore 的 SOCKS 地址 codec，不复制第三方状态机。认证按原始 UTF-8 字节 SHA-224，预计算 token 不出现在 Debug 中。TCP/UDP 命令通过枚举限定，不提供任意命令入口。

数据报保持完整消息边界，发送/接收 payload 上限与调用方预算取交集，最多 8192 字节，对齐 Mihomo 解码上限；不把超限 UDP 拆成多个业务包。帧头最多 263 字节；部分接收状态由关联持有，不因 receive future 取消丢失。取消部分发送后使关联失败关闭。坏地址/长度/CRLF/截断关闭流；合法但超过接收预算的包完整丢弃，不截断、不串入下一帧。该 adapter 没有 socket、DNS、后台任务或接收锁。

测试入口为公开认证请求 Interface 和 `DatagramTransport`，输入来自独立 OpenSSL SHA-224 向量及合成 wire；不是原生服务端互通。

- 首个认证测试先因缺少模块失败，随后通过；数据报测试也记录了首次缺少实现的失败。
- 7 项定向测试：认证/IPv4/IPv6/域名、部分读写、连续帧、取消接收后发送及恢复、取消发送后禁止重放、坏帧、8192/8193 发送界限和超接收预算后的下一帧。
- `cargo test --locked --all-features --all-targets`：581 lib + 53 integration PASS；ignored 不计通过。
- `cargo test --locked --release --all-features --test trojan`：7 PASS。
- `cargo check --locked --no-default-features --features outbound-trojan --lib`、全目标 Clippy `-D warnings`、fmt 通过。首次 Clippy 的固定长度分块建议已在自有代码修正，原始失败保留。

被测输入为父提交 `0cc39856315acad29c8155557be66585dd6eb091` 加本包代码，源码树 SHA-256 `c741bff6e17d26daa53989fd50d5db4bd9feb87eb098a9a069c4440686ec040a`；主锁 SHA-256 `c92520b7c24913e1eff59dbdcd4b7cfb00b964806bfcbc1c4ff399b16d09fd92`。测试在本机 macOS ARM64 执行，报告不冒用后续提交 SHA。

原始日志位于 `target/interop/runs/n2-development/`：

| 文件 | SHA-256 |
| --- | --- |
| `n2-1-header-red.log` | `8f167f1ffd0381370ecc16dcb950130d9f79296ecb777840f89c5040c490b870` |
| `n2-1-regression.log` | `08ccbc9abf41e14b495cbe090cf35b876cdc0060e5be0e5d5fa08dfd89302c3e` |
| `n2-1-release.log` | `7940f6409b64918c98e69707084050e7237474999b7d22abe31f9c94d17de389` |
| `n2-1-clippy-green.log` | `d26b319edd9af5d05c61f85608e3a5076b97e3bec12c6fa9556afc1b6fb3856b` |

N2.2–N2.4 的公开配置、运行时、TLS、WS/gRPC、官方对端、逐字段与 20 轮生命周期仍待执行。没有本包的远端 CI、平台构建或物理设备验收结果。
