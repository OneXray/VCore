# N2.3：Trojan WebSocket / gRPC

2026-09-23，N2.3 PASS；N2.4 阶段门禁尚未签收。TCP、WebSocket、gRPC 共用已有 Dialer、TLS 安全材料、建链期限和节点生命周期，没有新增依赖或修改第三方源码。

严格配置覆盖路径、Host/附加头、ALPN、gRPC service、默认/自定义头/路径后缀 early-data，拒绝未知、null、跨 network 参数、重复大小写头、保留头、无效 Host、CRLF、禁用时附带 ED header 和超过 2048 的 ED 上限。SNI 默认仍取服务器地址，不从 WS Host 推导。

## 实际执行

- `cargo test --locked --all-features --all-targets`：PASS。
- `cargo test --locked --release --all-features --test trojan --test trojan_config --test trojan_lifecycle`：14 项 PASS。
- 全目标 Clippy、Rust 格式、脚本 Ruff：PASS。
- `uv run --project scripts python -m vcore_scripts.protocol_trojan target/interop/runs/n2-3-acceptance`：16 组 PASS，命令与对端均已 join；运行期间源码未变。

输入源码树 SHA-256：`8ff790b8a0e5cb0b1a6547ed293b41443389277cafd3b3a73509c5102dbafb2c`；Cargo.lock SHA-256：`c92520b7c24913e1eff59dbdcd4b7cfb00b964806bfcbc1c4ff399b16d09fd92`。

| 真实对端与场景 | 结果 |
| --- | --- |
| Mihomo v1.19.31，TCP / WS / gRPC / WS ED=1 / WS ED=2048 | TCP 双栈/域名，各方向 10 MiB hash、服务器先发、分片、上传 EOF 后尾包；UDP 双栈 1/64/512/1200/8192 各 100 包；节点测速、端口回收 |
| Mihomo 三 network 策略 / 组快照 | 认证、信任、pin 负例零源站字节；具体上游与嵌套 select、DIRECT/REJECT、已有流不变、udp/ipv6 门控 |
| Mihomo WS / gRPC / ALPN 负例 | 错 path、错 Host、错 service、实际 ALPN 不匹配均失败，不直连绕过 |
| V2Ray 5.53.0 自定义 ED 头 / 路径后缀 | TCP 双栈/域名与服务器先发，UDP 原生路径上限 2048，节点测速 |
| Xray 26.3.27 三 network 域名 UDP | 域名来源保持、每个长度 100 包、原生路径上限 8166，无截断 |

对端完整版本输出、下载地址、二进制/归档 SHA-256 和每条命令位于该次 `trojan-results.json`。Mihomo 域名 UDP、V2Ray/Xray 缓冲限制及历史失败继续保留在 [N2.2](N2-tcp.md)，没有把补验记为 Mihomo PASS。

## 回归驱动的修正

1. 原有 gRPC adapter 的 shutdown 会关闭整条连接。真实 Mihomo 10 MiB 下载在上传 EOF 后被截断，见 `n2-grpc-half-close-red`。新增仅由 Trojan 消费的 duplex 模式：发送 HTTP/2 END_STREAM 后继续读取，下层 driver 由节点拥有并在 shutdown join；旧 gRPC、legacy H2、XHTTP 关闭语义不变。修正后的原生 BASE 与完整回归通过。
2. 已过期的 `timeout_at` 仍可能先 poll 立即就绪的连接 future。过期建链测试发现额外 protect 调用；Trojan 在任何 I/O 前检查期限，修正后 protect 拒绝和过期上下文均无源站字节。
3. TLS、WS 升级、gRPC 响应头三个受控挂起点分别在 150 ms 期限内取消；节点 shutdown 后资源计数归零、protect 所有者释放。它们是本地取消测试，不冒充原生协议互通。

N2.4 仍须签收默认/独立 feature、公共运行时入口、20 轮且逐轮 5 秒静默的生命周期、机器可检查字段报告。当前结果不代表远端 CI、物理设备或发布通过。
