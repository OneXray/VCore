# TUN ICMP 与 DNS

VCore 在 TUN netstack 内回答受支持的 ICMP Echo Request。启用运行时 DNS 后，TUN TCP/UDP 53、选路惰性解析和内部查询共享同一套有界 DNS 实现。

## ICMP Echo

| 地址族 | 请求 | 响应 |
| --- | --- | --- |
| IPv4 | type 8, code 0 | type 0, code 0 |
| IPv6 | type 128, code 0 | type 129, code 0 |

响应会交换源地址和目标地址，保留 identifier、sequence 和 payload，重建最小 IP 头，将 TTL/Hop Limit 设为 64，并重新计算所有校验和。该路径完全位于 netstack 内，不调用 DNS、规则、出站、protect 或物理接口。

输入要求：

- 校验 IP 版本、头长度、声明长度、地址和校验和；
- IPv4 可以携带合法 options，但响应不复制 options；
- 不重组 IPv4 分片或 IPv6 Fragment Header；
- IPv6 base Next Header 必须直接是 ICMPv6；
- 非 Echo、非零 code、截断和非单播地址一律丢弃；
- 单包失败不停止 netstack，也不生成 ICMP error。

smoltcp 负责生成 Echo Reply，VCore 负责更严格的输入分类和运行时门禁。响应直接尝试进入现有原始包出站队列；队列满时只丢当前低优先级响应并更新统计，不创建等待任务或积压队列。

## TUN DNS 入口

当 `dns.enable: true`：

- TUN UDP/53 在普通 UDP 关联建立前进入 DNS 快速路径；
- TUN TCP/53 保留 netstack TCP 状态和两字节 DNS 长度帧；
- 两者与惰性解析和内部查询共享缓存、singleflight 和上游连接。

当 `dns.enable: false` 时，TCP/UDP 53 不做劫持或地址改写，而是保留原目标并作为普通业务流量执行规则。

UDP 读取器只做有界 wire 分类和任务提交，不同步等待上游。合法 DNS 数据报不创建或刷新普通 UDP 关联。

| 查询 | 处理 |
| --- | --- |
| IN/A | 类型化解析和缓存，可生成 TUN 域名提示 |
| IN/AAAA | 类型化解析和缓存；`ipv6: false` 时本地返回 NODATA |
| 其他合法 IN qtype | 原始 wire 转发和缓存，不生成域名提示 |

SVCB、HTTPS、TXT、PTR、MX、SRV、NS、SOA、DNSSEC 和未知 16 位 qtype 都可按原始查询转发。A/AAAA 响应中的可达 CNAME 链继续执行严格地址和 TTL 校验。

TUN 域名提示存储只在启用 TUN 且业务规则包含域名类规则时创建。嗅探域名优先于 DNS 提示，两者都不改写实际目标。

## Nameserver 与出口

```yaml
dns:
  enable: true
  ipv6: true
  nameserver:
    - "tcp://1.1.1.1:53#vless-edge"
  nameserver-policy:
    "geosite:private,cn":
      - "tcp://223.5.5.5:53#DIRECT"
```

### Endpoint

- 主 nameserver 必须有 1–4 项。
- 只接受裸 IPv4/IPv6、`udp://IP[:port]` 和 `tcp://IP[:port]`。
- Endpoint 必须是 IP 字面量，不支持 hostname、system 或 DHCP resolver。
- 无 fragment 时固定使用 DIRECT。
- Fragment 只接受 `DIRECT`、`RULES` 或实际代理名。
- `#RULES` 只按 nameserver endpoint 和传输执行业务规则，不把 DNS question 当作选路域名。
- 规则结果为 `REJECT` 时，当前尝试失败并继续当前组下一项。

### Policy

`nameserver-policy` 是有序映射：

- 最多 16 项；
- selector 只接受 `geosite:<code>[,<code>...]`，同一项内为 OR；
- 同一 code 不能跨项重复；DNS policy 和业务规则合计最多引用 16 个唯一 code；
- value 必须是 1–4 个 nameserver；
- 首项命中后只在该组内顺序故障转移，组内耗尽不查询主组；
- GeoSite 资产不可用时该 policy 不命中，查询主组。

Policy 只决定当前 DNS exchange，不改写后续业务动作。

## Wire 校验

- DNS message 最大 4,096 字节。
- 只接受 opcode QUERY、恰好一个 IN question；query 不能含 answer 或 authority。
- 允许结构合法且受总大小限制的 EDNS additional record。
- 保留原始 16 位 qtype。
- Response 必须匹配 peer、QR、opcode、transaction ID 和完整 question。
- Name compression 最多跳转 16 次，response 最多扫描 64 条记录。
- 类型化缓存和提示最多保留 16 个唯一地址。
- 非法长度、压缩循环、尾随字节或错误帧格式都会失败关闭。
- TCP frame 长度必须为 1..=4,096，非法 frame 关闭当前 DNS 流。

## 缓存与 singleflight

### 类型化缓存

A/AAAA 缓存最多 256 项，从空容量按需增长。TUN 域名提示存储启用时同样最多 256 项，并按 TTL 失效。

### 原始响应缓存

- 最多 64 项，总保留内存 256 KiB，单响应最大 4,096 字节。
- Key 包含规范化 question、qclass、qtype 和移除 transaction ID 后的完整查询语义 SHA-256。
- 命中时恢复调用方 transaction ID 和 RD，并按剩余寿命更新所有可缓存 TTL。
- 正缓存寿命取可缓存记录的最小 TTL，并限制在 30–3,600 秒。
- NXDOMAIN 固定负缓存 30 秒；NOERROR 空 answer 只有在 authority 含 IN/SOA 时才缓存为 NODATA。
- Referral、TTL 0、无可缓存记录和扩展错误码不缓存。
- 原始响应缓存不生成 TUN 域名提示。

### Singleflight

未命中缓存时，以规范化 question 和 wire 语义摘要作为 key：

- Leader 在发起方任务内运行；
- Leader 被取消或释放时，RAII 通知 follower 重新选举；
- 每个调用方恢复自己的 transaction ID 和 endpoint，并独立应用失败策略；
- 不同 key 可以并行。

## 查询、故障转移与连接复用

- 查询总期限 5 秒；单 nameserver 尝试最多 3 秒，并受剩余时间限制。
- UDP 尝试只打开一个传输；首次发送后 1 秒无合法响应时，在同一传输和 ID 上最多重发一次。
- 前两次 peer/ID/question 不匹配只丢当前响应，第三次使当前尝试失败。
- 超时、I/O、格式错误、SERVFAIL、REFUSED、TC 或规则 REJECT 会继续当前组下一项。
- NXDOMAIN 和 NODATA 是终态。
- UDP TC 不自动切换 TCP；只有显式 `tcp://` endpoint 使用 TCP。
- 全部上游失败时生成 SERVFAIL；非法 UDP 查询只丢当前数据报。

显式 TCP nameserver 使用每运行时独立连接池：

- Key 为 endpoint 和最终出口；
- 一条连接同时只处理一个查询，不做 pipeline；
- 活动连接不设固定业务数量上限；空闲连接总数最多 4、同 key 最多 2、超时 30 秒；
- 完成帧和响应校验后才能归还连接；
- 复用连接遇到 EOF、I/O、reset 或响应不匹配时，在原尝试期限内最多新建一次连接；
- 非法、截断或超限响应不重试、不归还连接。

## 队列与生命周期

| 队列 | 容量 |
| --- | ---: |
| TUN DNS 入站 | 128 |
| DNS 响应 | 128 |
| 普通 UDP 响应 | 128 |

DNS 和普通 UDP 响应使用不同队列，但共享 netstack UDP 入站接收器。队列满时只丢当前请求或响应，不阻塞全局 UDP 循环。TUN UDP 响应受 1,452 字节负载上限约束。

运行时停止会取消 open、send、receive、retry 和 response-send，释放全部传输并等待已跟踪任务结束。停止返回后不得再向 TUN 回包。

普通非 DNS UDP 关联不设固定总数，采用代次感知所有权、30 秒空闲超时和 10 秒清理周期。只有成功入队的请求或响应刷新活动时间。

## 不支持

- 真实 ICMP 转发、ICMP error、Traceroute、ICMP 选路规则或 ICMP 测速；
- DoH、DoT、DoQ、hostname/system/DHCP nameserver；
- 代理组、并行 nameserver 竞速、DNS fallback group、fake IP 和 hosts；
- 用户可配置的缓存容量、超时、重试或并发度；
- 使用 DNS question 执行业务规则，或用 DNS 出口改写后续业务动作。

自动化和物理 TUN 覆盖范围见 [验收矩阵](acceptance.md)。
