# TUN ICMP 与 DNS

状态：当前公共契约。VCore 在 TUN netstack 内回答合法 ICMP Echo Request，并为 TUN TCP/UDP 53、惰性解析和内部查询提供同一有界 runtime DNS。

## 1. ICMP Echo

支持：

| Family | Request | Reply |
| --- | --- | --- |
| IPv4 | type 8, code 0 | type 0, code 0 |
| IPv6 | type 128, code 0 | type 129, code 0 |

Reply：

- 交换源/目标地址。
- 保留 identifier、sequence 和 payload。
- 重建最小 IP header；TTL / Hop Limit 固定 64。
- 重算 IPv4 header、ICMP 或 ICMPv6 pseudo-header checksum。
- 完全在 netstack 内完成，不调用 DNS、rules、outbound、protect 或物理接口。

输入边界：

- 校验 version、header length、declared length、地址和 checksum。
- IPv4 允许合法 options，但 reply 不复制 options。
- IPv4 分片和 IPv6 Fragment Header 不重组、不回复。
- IPv6 base Next Header 必须直接是 ICMPv6；当前不遍历 extension chain。
- 非 Echo、非零 code、截断、unspecified source、multicast/broadcast destination 均丢弃。
- 单包失败不停止 netstack，也不生成 ICMP error。

实现使用现有 bounded raw egress queue，不创建 ICMP task、socket、flow table 或 timer。Queue full 时只丢当前 reply；单次分配不超过 1,500-byte MTU。

## 2. TUN DNS 入口

当 `dns.enable: true`：

- TUN UDP/53 在普通 UDP association 创建前进入 fast path。
- TUN TCP/53 保留 netstack TCP state 和 2-byte DNS framing。
- 两者与 routing lazy resolve 和其他内部查询共享 runtime DNS、cache 与 singleflight。
- DNS disabled 时 TCP/UDP 53 都作为普通业务流量执行 rules。

UDP reader 只做有界 wire 分类和 task admission，不同步等待上游。慢查询不能阻塞普通 UDP、QUIC 或其他 source。结构合法的 DNS UDP datagram 不创建或刷新普通 UDP association。

支持：

| Query | 处理 |
| --- | --- |
| IN/A | typed parser/cache，可产生 TUN domain hint |
| IN/AAAA | typed parser/cache；`ipv6: false` 时本地 NODATA |
| 其他合法 IN qtype | opaque wire relay/cache，不产生 hint |

SVCB、HTTPS、TXT、PTR、MX、SRV、NS、SOA、DNSSEC 和未知 16-bit qtype 都可按 opaque query 转发。CNAME question 本身按 opaque query 处理；A/AAAA response 中从原 question 可达的 CNAME chain 继续执行严格地址和 TTL 校验。

TUN domain hint store 只在配置启用 TUN且业务 rules 含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时创建，仅供该 TUN 使用。它与 sniffer 开关独立；sniffed domain 优先于 DNS hint，二者都不改写实际 destination。

## 3. Nameserver 与出口

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

- 主 nameserver 为 1–4 项。
- 只接受裸 IPv4/IPv6、`udp://IP[:port]` 和 `tcp://IP[:port]`。
- Endpoint 必须是 literal IP；不支持 hostname、system 或 DHCP resolver。
- 无 fragment 时固定 DIRECT。
- Fragment 只接受 `DIRECT`、`RULES` 或实际 proxy name。
- `#RULES` 只按 nameserver endpoint/transport 执行业务规则；DNS question name 不作为 routing domain。
- `REJECT` 表示当前 attempt 失败并继续当前组下一项；不隐式回退到其他出口。

### Policy

`nameserver-policy` 是有序 mapping：

- 最多 16 个 entry。
- Selector 只接受 `geosite:<code>[,<code>...]`；一个 entry 内为 OR。
- 同一 code 不能跨 entry 重复；全部 policy 与业务 GeoData rules 合计最多 16 个唯一 code。
- Value 必须是 1–4 个 nameserver 的 sequence。
- 按 mapping 顺序首条命中；命中后只在该组内顺序 failover，组内耗尽不查询主组。
- GeoSite 资产不可用时 policy 暂不命中，查询使用主组。

Policy 选择只决定当前 DNS exchange，不改写后续业务 action。

## 4. Wire validation

- DNS message 最大 4,096 bytes。
- 只接受 opcode QUERY、恰好一个 IN question；query 不得包含 answer/authority。
- 允许结构合法且受总大小限制的 EDNS additional record。
- 保留原始 16-bit qtype。
- Response 必须匹配 peer、QR、opcode、transaction ID 和完整 question。
- Name compression 最多 16 次跳转；response 最多扫描 64 条 resource record。
- Typed cache/hint 最多保留 16 个唯一地址。
- Malformed length、compression loop、trailing bytes 或错误 framing fail closed。
- TCP frame length为 1..=4,096；非法 frame 关闭当前 DNS stream。

## 5. Cache 与 singleflight

### Typed cache

A/AAAA cache 最大 256 项，从空容量按需增长。TUN hint store启用时同样最大 256 项，并按 TTL 失效。

### Opaque cache

- 最大 64 项、总 retained bytes 最大 256 KiB、单 response 最大 4,096 bytes。
- Key 包含规范化 question、qclass、qtype 和排除 transaction ID 后完整 query wire 语义的 SHA-256。
- Cache hit 恢复调用方 transaction ID、同步 RD，并按剩余 lifetime 更新所有可缓存 TTL。
- Positive lifetime 取可缓存 record 的最小 TTL并应用 30–3,600 秒 clamp。
- NXDOMAIN 固定负缓存 30 秒；NOERROR/空 answer 仅在 authority 含 IN/SOA 时作为 NODATA 负缓存。
- Referral、TTL 0、无可缓存 record 和扩展错误码不缓存。
- Opaque cache 永不产生 TUN domain hint。

### Singleflight

Cache miss 以 canonical question + wire semantics digest 为 key进入 singleflight：

- Leader 在发起方 task 内运行。
- Leader cancel/drop 时通过 RAII 通知 followers 重选 leader。
- 每个 caller 恢复自己的 transaction ID/endpoint并独立应用 failure mode。
- Cache hit 不创建 flight；不同 key 可并行。

## 6. Exchange、failover 与连接复用

- Query 总 deadline 5 秒；单 nameserver attempt 最多 3 秒并受剩余时间约束。
- UDP attempt 只打开一个 transport。首次发送后 1 秒无合法 response 时，在同一 transport、同一 ID 上最多重发一次。
- 前两个 peer/ID/question mismatch 只丢当前 response；第三个使当前 attempt 失败。
- Timeout、I/O、格式错误、SERVFAIL、REFUSED、TC 或 rules REJECT 继续当前组下一项。
- NXDOMAIN/NODATA 是终态。
- UDP TC 不隐式创建 TCP；只有显式 `tcp://` endpoint 使用 TCP。
- 所有 upstream 失败时生成 SERVFAIL。Malformed UDP query 只丢当前 datagram。

显式 TCP nameserver 使用每 runtime 独立连接池：

- Key 为 endpoint + 已解析的最终 egress。
- 一条连接同一时刻只处理一个 query，不做 pipeline。
- Active 连接不设业务级固定上限；只保留 idle 总数 4、同 key 2、idle 30 秒。
- 完整 framing 和 response validation 成功后才能归还。
- 复用连接遇到 EOF、I/O、reset 或 response mismatch 时，在原 attempt deadline 内最多 fresh reconnect 一次。
- Malformed、truncated 或 oversize response 不重试、不归还。

## 7. Queue、取消与生命周期

- TUN DNS ingress：128。
- DNS response queue：128。
- Ordinary UDP response queue：128。
- 两类 response queue 独立，但共享 netstack UDP ingress receiver，因此不宣称完整 ingress 隔离。
- Queue full 时只丢当前 request/response，不阻塞全局 UDP loop。
- TUN UDP response 受 1,452-byte payload ceiling；超限 response 只丢当前 query。
- Runtime stop 必须取消 open/send/receive/retry/response-send，释放 transport并 drain/abort tracked task。
- Stop 完成后不得再向 TUN 回包。

普通非 DNS UDP association 不设固定总数，使用 generation-aware ownership、30 秒 idle timeout和10 秒 cleanup。只有成功入队的 request 或 response 刷新 activity；queue-full drop 不刷新。

## 8. 明确不支持

- 真实 ICMP forwarding、ICMP error、Traceroute、ICMP routing rule 或 ICMP 测速。
- DoH、DoT、DoQ、hostname/system/DHCP nameserver。
- Proxy group、interface fragment、fragment 参数或并行 nameserver race。
- DNS fallback group、fake IP、hosts、用户可配置 cache capacity和用户可配置 timeout/retry/concurrency。
- 以 DNS question name 执行业务 rules，或用 DNS egress 改写后续业务 action。

## 9. 验收

自动化覆盖 ICMPv4/v6、checksum、MTU、options、分片、queue full；DNS qtype、framing、compression、cache、singleflight、policy、failover、UDP retry、TCP reuse、取消和 queue isolation。真实代理链、物理 TUN 和 Release iOS footprint 必须按 [`acceptance.md`](acceptance.md) 单独登记。
