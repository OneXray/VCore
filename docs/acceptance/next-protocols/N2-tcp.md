# N2.2：Trojan TLS/TCP 纵切

2026-09-23，N2.2 PASS；N2 整体尚未签收。公开 YAML 和 node-only `measureDelay` 已接入 `outbound-trojan` feature，schema 15 / Invoke v5，两处构建身份同步。此包暂仅开放 `network: tcp`；默认 feature 与 WS/gRPC 在后续包签收。没有修改第三方源码或依赖版本。

配置通过严格解析后进入既有混合 DAG 和 `OutboundConnector`。物理连接只由已有 Dialer 创建；TLS 使用运行时共享安全材料及原有总计 4 会话恢复预算，节点隔离。每条连接沿用一次组快照和同一 10 秒建链期限。UDP 使用有界帧 codec，不创建额外 UDP socket；Stop 取消活动流，节点不保留已完成连接历史。密码原样 UTF-8、不 trim、不进入 Debug/错误。

## 真实互通

入口：`uv run --project scripts --locked python -m vcore_scripts.protocol_trojan target/interop/runs/<unique-run>`。脚本使用官方最新二进制，独立私有配置目录、进程组和端口；不依赖仓库外代码或从本地编译对端。

本次 `target/interop/runs/n2-2-acceptance/trojan-results.json` 三组均 PASS，源码未在运行中变化，对端与命令进程均已回收：

| 用例 | 真实观察 |
| --- | --- |
| N2-M-TCP | 公共 YAML → Invoke → SOCKS5 → Trojan → Mihomo；IPv4/IPv6/域名 TCP，各 10 MiB 双向 SHA-256、分片、服务器先发、上传 EOF 后尾包；IPv4/IPv6 UDP 各 5 个长度 × 100 包，最大负载 8192 字节；node-only 测速与停止后端口重绑 |
| N2-M-TCP-POLICY | 错密码、未信任证书、错 pin+skip 均无业务字节到达源站；正确 pin/skip；两个独立 Mihomo 实例的具体上游、嵌套 select、DIRECT/REJECT、新连接采用新选择而已有 TCP/UDP 不变；udp=false、ipv6=false |
| N2-XR-UDP-DOMAIN | 官方 Xray 域名 UDP，1/64/512/1200/8166 字节各 100 包；上/下行无截断，保留域名来源；停止后端口重绑 |

Trojan 没有远端认证 ACK，本地 SOCKS CONNECT 成功不代表远端密码通过；负例检查后续 EOF/错误及源站零业务字节，不能将提前 CONNECT 当成协议认证成功。

## 原生能力缺口及失败记录

- Mihomo v1.19.31 的 `transport/trojan.PacketConn.WaitReadFrom` 调用 `socks5.Addr.UDPAddr()`，后者对域名返回 nil。域名 UDP 首包失败已实际复现于 `n2-udp-domain-minimal`；这不是 hosts/DNS 配置缺失。保留该失败，按原生 listener 能力缺口规则新增 Xray 补验，不把 Mihomo 域名 UDP 标成 PASS。
- V2Ray 5.53.0 的 UDP 原生回包经 2048 字节缓冲，8192 字节回包截断，见 `n2-tcp-base-green` 中的实际失败；未修改它，也未将该结果算通过。
- Xray 的 Trojan writer 使用 8192 字节**总帧**缓冲。受控 18 字节域名的地址头 22 字节，加长度/CRLF 4 字节，实际回包负载上限 8166；8192 失败记录在 `n2-xray-udp-boundary-red`。VCore 自身的 8192/8193 负载边界仍由 codec 与 Mihomo 字面量路径验收，不以较小原生上限降低实现限额。
- 初始链路把同一 Mihomo 实例接回自身，触发其 loopback detector。调整为两个独立进程，各自拥有证书和目录后通过；没有关闭对端的回环防护。
- 首次全目标编译发现旧 Xray fixture 的枚举匹配未覆盖 Trojan，已补全。保留原始失败和通过日志。

配置默认/严格类型/null/未知项/地址/端口/密码/ALPN/pin/DAG 负例、完整 Debug 回归、独立 Trojan feature 编译、全目标 Clippy 与脚本格式检查通过。当前报告不等同于 N2.3 传输、N2.4 20 轮生命周期、跨平台、远端 CI 或设备验收。
