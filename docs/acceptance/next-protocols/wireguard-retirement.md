# WireGuard 范围撤回

日期：2026-09-27。本次仅清理被取消的协议目标和脚手架；不是 N8 或 N9 验收。

## 决定与改动

WireGuard 未曾注册为生产出站或公开 YAML 类型。按明确范围决定：

- 删除 `outbound-wireguard` 占位 feature 和对应 runtime cfg 分支。
- 删除专属 inner MTU 方法、常量、两项 limits 登记和仅针对它们的断言。
- 删除原生 W 预检及其内核网卡/工具安装探针，CLI 不再接受 WireGuard/N8。
- 删除独立 datagram 实验中的 BoringTun/GotaTun 用例和依赖；离线刷新实验锁仅
  移除 61 个包，无新包/版本升级，生产 `Cargo.lock` 不变。
- 目录升级为 schema-v4：126 字段 / 65 组合家族 / 72 项限额。
  WG01–WG07、WG-SINGLE-PEER、REJECT-WG-ADDRESSES 退休；
  共用字段/用例去掉 WG 关联，余下 ID 稳定。
- 共享 QUIC 数据报预算、DNS/独立测量 resolver、被动 TUN netstack 保留；
  继续以严格配置测试拒绝 WireGuard，不新增兼容/迁移路径。
- SS 重放窗口的 WireGuard 来源版权和来源链接保留。历史 N0/N1 等报告不追改，
  当时的 WG BLOCKED/NOT RUN 不再是当前依赖，也不变为 PASS。

Invoke API v5 / schema27、七种现有代理出站、TLS 双后端与已签收 N7 能力不变。
不修改第三方代码，不恢复 rustls fork，不改变宿主网络。

## 后续阶段

N8 **取消且不复用编号**。下一步为 N9，随后 N10：

| 工作包 | 目标（尚未执行） |
| --- | --- |
| N9.1 | Trojan/VMess/VLESS/Hysteria2 + SOCKS5/AnyTLS/SS2022 的 7×7=49 个有序两跳组合；合法流量与能力/预算负例、公开入口/组/DNS/测速、全容器回归 |
| N9.2 | 100 次生命周期、100×40-flow 快速重建、取消/故障/Stop 即归零及五秒静默 |
| N9.3 | 1800 秒、20 TCP +20 UDP，四种本版协议各 5+5；HY2 连续跳跃、在用堆/对象/FD 与首尾耗时 |
| N9.4 | 同一冻结输入下的 Debug/Release、netstack、feature/依赖/配置/脚本回归、完整报告与候选 |
| N10 | 最终生产构建、真实设备数据面、远端 CI 和正式交付分别签收 |

N9/N10 的 required 集合/执行门禁尚待实现，空集合仍不能通过。动态 ECH 独立后置，
不因删除 WireGuard 而提前签收或自动加入本次开发。

## 当前验证

环境：macOS ARM64。本轮没有启动协议服务端、原站或测试容器。

| 命令 | 结果 |
| --- | --- |
| `uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only` | VALID，126 字段 / 65 家族；行为仍 NOT RUN |
| `uv run --project scripts --locked python -m unittest discover -s scripts/tests` | 174 项通过，含退休 CLI/feature/peer 防回归 |
| `uv run --project scripts --locked ruff check scripts`、`ruff format --check scripts` | PASS |
| `cargo test --locked --all-features --test feature_foundations --test limit_foundations` | 6+1 项通过 |
| `cargo test --locked --all-features --test datagram_foundations layered_directional_budgets_account_for_ip_headers_and_exact_minima -- --exact` | 1 项纯预算测试通过，未执行旧宿主服务用例 |
| `cargo test --locked --all-features --lib config::measure::tests::measurement_rejects_future_protocols_and_oversized_documents -- --exact` | 1 项通过 |
| `cargo test --locked --no-default-features --test feature_foundations` | 6 项通过 |
| `cargo check --locked --no-default-features --lib`、`cargo check --locked --all-features --all-targets` | PASS |
| `cargo clippy --locked --all-features --lib --bins -- -D warnings` | PASS |
| `cargo check --offline --manifest-path tests/protocols/spikes/datagram/Cargo.toml --tests` | PASS，并裁剪实验锁 |
| `cargo test --locked --offline --manifest-path tests/protocols/spikes/datagram/Cargo.toml tests::quinn_custom_packet_io_and_congestion_with_existing_rustls -- --exact` | 1 项内存 QUIC 实验通过 |
| `uv run --project scripts --locked vcore-scripts check tls-dependencies` | PASS，原 TLS/SS 依赖边界未变 |
| `cargo fmt --all -- --check`、`git diff --check` | PASS |

精简 feature/独立实验构建仍报告未使用代码警告；本轮不做无关清理，不称这些构建零警告。
初次脚本回归因 N1 的三处 WG 字段引用未清理而失败；去掉退休行关联后完整 174 项重跑通过。
没有删掉共用 case 或降低证据检查来规避失败。新测试的格式诊断已修正。

验证时父提交：`79909e6276196f4a54b2fbcf3a953a5dbeb2e9fb`。
自有 `protocol_inputs.source_identity` 的源码树摘要：
`ad8570dd72dca1745918569e83a4ecf65ef514c1b5830bdd74a1596110a0e53c`。
生产 lock 摘要：
`2edfe78b19ac373e00f0fe1be1b3508049495dd8d0f094a1f0f674667b6946b6`。
提交后核对源码树与 lock，不倒填测试时不存在的提交号；文档元数据不计入上述源码摘要。

未重跑 N1–N7 完整原生互通、长测、跨平台产物/设备、远端 CI 或发布。
本地清理通过不扩大先前阶段证据；历史目录需使用其原输入解释，不能套用新目录改写成绩。
