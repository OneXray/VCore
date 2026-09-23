# N1：正式 rustls 分支引用与推送前复验

日期：2026-09-23。经明确授权，rustls 的 `chore/x25519-dalek-3` 已快进合入并推送至正式发布分支 `vcore/reality-0.23`；远端完整 revision 为 `bb4092cc32a101869406d0b8242b173372a9d3ea`。没有 force push，也没有删除开发分支。

VCore 的 manifest、锁文件和 TLS 审计恢复使用该发布分支。锁定的 rustls 源码 revision、0.23.45 版本及 x25519-dalek 3.0.0 均未变化；四个独立 N0 实验继续固定同一 revision。GitHub 路由已核实并修正为 `OneXray/VCore`。本记录仅补充发布引用切换，不改写 [N1 依赖验收](N1-x25519.md) 的历史动作和产物。

## 验证输入

父提交 `0c449ce15c3620ee9ad0299945024a8a2688d927` 加本次 manifest/lock/审计变更。文档在验证后补充，不反向冒用后续提交 SHA。环境为本机 macOS ARM64。

- `protocol_inputs.CODE_PATHS` 源码树 SHA-256：`849e06ca811a6f9e5b4403f211b856a5a2ce178747787a002a8e603f2601f036`。
- 对父提交代码 diff SHA-256：`e2ddde2b80c308965db1306d46e8ef1b3bdb5ad7884c9e15bf884c8cb4c0e89e`。
- 主锁 SHA-256：`c92520b7c24913e1eff59dbdcd4b7cfb00b964806bfcbc1c4ff399b16d09fd92`。

## 本轮结果

Python 入口前缀为 `uv run --project scripts --locked`。统一运行目录为 `target/interop/runs/n1-83h8veh8/`，UTC 10:28:50–10:30:52；额外 Release/Clippy 日志在 `target/interop/runs/n1-publish-20260923/`。

| 命令 / 范围 | 结果 |
| --- | --- |
| `vcore-scripts check protocol-interop --stage N1` | 21 组 required / 139 项断言 PASS，source_unchanged、cleanup 均 true |
| `vcore-scripts check protocol-coverage --stage N1 --run-dir target/interop/runs/n1-83h8veh8` | 独立重算覆盖及原始证据摘要 PASS |
| `cargo test --locked --all-features --all-targets`，Debug / Release 各一轮 | 各 581 lib + 46 integration PASS，ignored 不计通过 |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | PASS |
| `vcore-scripts check tls-dependencies` / `check c-header` | PASS；发布分支、真实 x25519 依赖边及零化 feature、ring/SS 例外边界保持严格检查 |
| scripts unittest、Ruff check/format、cargo fmt、git diff 检查 | 80 项脚本测试及其余检查 PASS |
| 最小/四新协议/stream/QUIC 独立 feature 及 default schema | PASS；新协议 YAML 仍拒绝 |

9 项原生 Mihomo/V2Ray 流传输全部 PASS；验证服务器先发、65,536 字节回显、14 字节尾部、protect 一次及资源归零，`close:false` 不改称原生客户端 half-close。旧 Mihomo 扩展回归 PASS：Rust 测试 39.24 秒，100 次 32-flow 重建 20,599ms，结束后 FD 6、在用堆 64,208B、RSS 18,896KiB。自有对端及临时配置均清理。

## 证据摘要与边界

| 原始文件（`target/interop/runs/` 下） | SHA-256 |
| --- | --- |
| `n1-83h8veh8/run.json` | `3f5fdd479734a80d11adaeda21ab5b098c308fc2053e995b83e7a7ba05338555` |
| `n1-83h8veh8/cases.json` | `6264628030f857cb45d2043eff8f45cf95c6a478f576a7d4585e630f2dacceda` |
| `n1-83h8veh8/native/stream-cases.json` | `660c51d4a790b18828090000872d58389ac2aeb29ad91e8a8beb4f808c0e0ace` |
| `n1-publish-20260923/interop.log` | `e0d0f0b43155da1b5cc17d8d322c9d63e5acdb81da1fd83ebbb6b734f99313c6` |
| `n1-publish-20260923/release.log` | `2517c2329a7ac02e93a46db4bdbbcfa126d5421f7e0a7bfee16b2c5867dcefcc` |
| `n1-publish-20260923/clippy.log` | `bc79a46005e61bdd6f08023ea3061a3aa054c671deaf20b5908186cda25d8d71` |

本轮未重新构建 Apple/Android 产物；此前标准/QUIC 构建对应同一 rustls 源码，但其锁文件来源字符串不同，旧产物仍仅归属此前验收。未重跑 fork 全部验收、全部 N0 实验或 WireGuard 原生内核预检。N1 完成不代表 N2–N10、新五协议字段、Windows 原生、真机、远端 CI 或签名发布已通过；WireGuard 环境阻塞仍待 N8 单独解决。Invoke v5 / schema14、ring 和 classic REALITY 边界不变。
