# selected-v1 CF4：VCore 接线与 classic REALITY

2026-09-25，macOS ARM64 / Rust 1.98.1。**本地 CF4 DONE。**
本阶段不继承历史 N4/N5、库测试或平台结果为新的 VCore 互通成绩。

## 来源与接线

- 自有 boring 的 `feat/client-fingerprint-selected` 经授权 push；远端 ref 确认
  `e81c6837a302241d81c0930610b4f34dd4328167`。没有推送 VCore、创建 PR 或合并 main。
- VCore 的两个 Git 依赖及 lockfile 同步锁定该不可变提交，不使用本机 path。
  四模板来自 fork 的真实原生实现；公开名称见 [当前契约](../../tls-client-fingerprint.md)。
- schema20 / Invoke v5；下载腿缺省继承，异模板覆盖，`none` / 空串清除。
  标准无模板 TLS 仍用官方 rustls；REALITY 的 `none` 仍认证，不回退站点证书。

## 当前实际结果

| 检查 | 结果 |
| --- | --- |
| `cargo test --locked --all-features --lib config::` | 75 项通过；含七值、错型/大小写、四模板、下载腿及 H3/明文边界 |
| `cargo test --locked --all-features --lib security::` | 25 项通过；四模板覆盖证书、TLS1.2/1.3、恢复/拒绝、零预算/并发单次消费、节点隔离、ALPS 三种响应、取消/关闭 |
| `cargo test --locked --all-features --test feature_foundations` | 6 项通过；仅 inbound-socks5 及分别增加四个 outbound feature 的五种精简组合各 6 项通过 |
| `vcore-scripts check tls-dependencies` | 通过；boring 三 crate 同源，官方 rustls/ring 不变 |
| 脚本离线单元测试 | 144 项通过；修正依赖变更后失效的旧 revision 负例 |
| fmt、all-target/all-feature Clippy、C header、脚本 Ruff | 通过；Clippy 仅编译历史服务端测试，不在宿主运行它们 |
| 独立容器互通 | 主矩阵 38 项、追加 REALITY SNI 拒绝 5 项全部 PASS；99 个自有容器均清理 |

ALPS 使用内存 TLS 对端：Chrome 按对应新/旧码点协商，非空设置在业务写入及票据准入前拒绝；
Firefox/Safari 不声明 ALPS。并发测试以 0/1/4 预算各发起 8 个握手，实际恢复数等于可消费的
票据数。TLS1.2/1.3 对端更换票据密钥后重新完整认证，错误证书仍拒绝。
测试原先把 AnyTLS 历史的延迟 feature 准入当作解析错误，已修正断言；随后暴露并补齐共享
解析器的 named-profile 后端关闭检查。`none` 保留旧语义，不扩大本阶段协议配置重构范围。

## 容器矩阵

入口为 `python -m vcore_scripts.protocol_fingerprint <fresh-run>
--client-fingerprint <name> <case...>`，使用统一 `uv run --project scripts --locked`。
本轮目录前缀 `target/interop/runs/selected-cf4-20260925-1137-`；每个名称有独立
`vless-results.json`、命令日志、事件序列、源树/lockfile 摘要和清理记录。

四模板每组八项：AnyTLS、Trojan、VMess、VLESS TCP；VLESS TLS/REALITY 认证正反例；
gRPC mTLS/验证名。`firefox120`、`safari16` 各补公开 TCP 数据面；`none` 补 TLS/REALITY
数据面和拒绝认证。公共测试经真实 YAML / Invoke / 入站，校验数据并同步 Stop。

追加目录前缀 `selected-cf4-sni-20260925-1157-`，四模板及 `none` 分别重新执行
`N4-TCP-REALITY-NEG`，包含错误 key、short ID 和 SNI 拒绝。12 份报告均为
`status=PASS`、`source_unchanged=true`、`cleanup=true`；清理后容器列表为空。

主矩阵源树摘要为 `b9833a6bb5f3c7813fe50199b72d49da006c138dcff26c87ef8b3504bdac0e64`。
追加开发测试依赖、内存 ALPS/并发用例、精简 feature 检查和 SNI 负例后，SNI 补验源树为
`d405bab28cba26be6ebae67da5e2ae80a2c189ccbb05b7779d1fcda21b162cdf`，lockfile 为
`b1fc0afac4ccfcc706ff130156337dd83502bf4d7ef91911ea78ae6788efcd5f`。
两个源树的已启用模板映射及 TLS 适配实现相同；不能把先前运行记为后续测试文件的执行。

| 报告名称（上述目录下 `vless-results.json`） | SHA-256 |
| --- | --- |
| 主 chrome120 | `dd77fc9fb0bea663d926d5a1d726010b538af548bc82f3d7d02a61f4a992ec4d` |
| 主 chrome | `8330e87216b825c706fb112fccd5a400fc5bc64977c52d81f8ae9d010a5c7132` |
| 主 firefox | `6f723a4860e81637867e4e604261b9caaea0711f3d90114d30f14ef3b5eef8a0` |
| 主 safari | `b8d5104675a8a26b8b3fa44278876747d3f94c5fb2159f1f32a86bb67aba63ba` |
| 主 firefox120 | `25c2d2be358bb5ceb0346a2d1b8fa39c896da8713d32b5842f44e56b8b0ab49c` |
| 主 safari16 | `b959905defc52acb2bd9da42ba24b42b89df0ea6103413fe28283dcffd461ff3` |
| 主 none | `c9f6fec3d6181b68061374109978a5a48234895d8c9f31abe8c74b17f1726340` |
| SNI chrome120 | `0f4ec3166cc2c78f9747e293777f9347f9c2d5c3d68b4c8df6e4777b056b4279` |
| SNI chrome | `a8433f87e700840a6df00071f14f8632bfa959266bae47c54b94b02eea41bb3b` |
| SNI firefox | `d2c8f69e68dd7b75f926c306afd9a4ef47f41e71ab2b048b0b55e73ecbd3552d` |
| SNI safari | `c72df280de80839d8f2c2d2c4fb5bd035c9018f13686241aaacfe40f835f1870` |
| SNI none | `f14e547bbe3d231eed5dceb243272de8ca8cb6f90885b4057015edf49bcde896` |

对端从官方 latest 下载，实际 Mihomo `v1.19.31`，二进制 SHA-256：
`1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。
这与 CF0 冻结基准一致。服务端、原站与上游都在独占 Apple Container host-only 网络；
不关闭回环保护、不重试业务包、不在宿主运行服务端。镜像 digest 留在各运行报告中。

## 边界与后续门禁

REALITY 的 HMAC、签名、低阶点、HRR 和重复封装属于 fork 原生负例；本节容器成绩不是这些
密码学故障的端到端复现。CF5 的完整传输、结构、平台和独立 checkout 构建尚未执行；Windows、设备、远端 CI、
性能/体积及完整发布许可证审查仍为独立 NOT RUN 门禁。
