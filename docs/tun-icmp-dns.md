# TUN ICMP fake response 与 Mihomo-compatible DNS 扩展

状态：已实现。当前 parser、runtime DNS、routing dispatcher 与 TUN netstack
已经实现本文定义的严格子集和局部有界资源策略；公共配置示例见
[`config.yaml`](config.yaml)。
真实 VLESS DNS 端到端、Release iOS 整进程 footprint 等仍待平台证据的项目
单独列在第 8 节，不能由单元测试代替。第 10 节只保留 TUN UDP DNS 入口与调度
改造的精炼实现记录；当前公共语义以第 3、5、6 节为准。

本文件定义两个当前能力：

1. TUN 对 ICMPv4/ICMPv6 Echo Request 生成本地 fake response。
2. DNS 扩展到非 A/AAAA query，并采用 Mihomo-compatible 的
   nameserver 出口选择语义。

## 1. 兼容边界

- 这是 VCore 的严格有界子集，不声明完整 Mihomo DNS 兼容。
- YAML 不含 `configVersion` 或 `default-proxy`，并且必须至少包含一个字段名与
  嵌套均与 Mihomo 一致的平铺 VLESS、SOCKS5 或 AnyTLS proxy。proxy 数量和链深
  没有独立上限，只受整份 YAML 256 KiB、name 唯一、引用存在和全图无环约束。
  旧 `inbounds/outbounds` 与 Xray 风格嵌套节点直接失败。`rules` 必填，必须恰好
  以一个指向实际 proxy name 的最终 `MATCH` 收尾；该节点及其完整链构成运行配置
  的默认 proxy graph。ICMP fake response 在启用 TUN 时固定打开，不增加 YAML 开关。
- HTTP probe listener 没有 ICMP 或 UDP 数据面；它发往 53 端口的 TCP 连接继续作为
  普通业务流量执行 `rules`，不进入本地 DNS service。
- proxy graph 只有未设置 `dialer-proxy`、直接连接物理网络的根节点服务端才在
  `prepare` 阶段使用 system resolver；链上节点的 domain 原样交给下一跳。
  nameserver fragment 不影响 bootstrap plane。
- DNS 本地命中、DNS upstream 出口和后续业务连接路由是三个独立概念。DNS 经
  DIRECT 或某个精确 proxy name 不决定查询域名之后的业务连接 action。

## 2. ICMP Echo fake response

### 2.1 行为

实现参考 Xray-core：

- `../references/Xray-core/proxy/tun/icmp/packet.go`
- `../references/Xray-core/proxy/tun/stack_gvisor_icmp_handler.go`

只接受以下报文：

| IP family | request | local reply |
| --- | --- | --- |
| IPv4 | ICMP Echo Request，type 8、code 0 | Echo Reply，type 0、code 0 |
| IPv6 | ICMPv6 Echo Request，type 128、code 0 | Echo Reply，type 129、code 0 |

reply 必须：

- 交换源地址和目标地址。
- 保留 identifier、sequence 和全部 payload。
- 重新构造最小 IP header；IPv4 TTL 和 IPv6 Hop Limit 固定为 64。
- IPv4 重算 IP header checksum 与 ICMP checksum。
- IPv6 使用交换后的地址、ICMPv6 长度和 payload 重算 pseudo-header checksum。
- 完全在 TUN netstack 内完成，不调用 DNS、`rules`、DIRECT、任一 proxy、dispatcher、
  Android protect 或任何真实网络接口。

fake reply 只证明 VCore TUN 数据面正在运行，其延迟是本地处理延迟；它不能证明
目标地址、任一 proxy 节点或远端网络可达，也不能用于节点测速。

### 2.2 输入和失败边界

- 必须验证 IP version、header length、declared packet length 和请求 checksum。
- IPv4 允许合法 options，但不把 options 复制到 reply。
- 首版只处理未分片报文；IPv4 MF/非零 fragment offset、IPv6 Fragment Header
  均静默丢弃，不做重组。
- 首版不遍历 IPv6 extension-header chain；base Next Header 不是 ICMPv6 时按不支持
  协议丢弃。
- 非 Echo、非零 code、截断、地址族错误、错误 checksum、unspecified source、
  multicast/broadcast destination 均不回复。
- 单个无效报文或 reply 写回失败不能停止 netstack，也不能产生 ICMP error。

### 2.3 插入点和资源

- 在 `crates/vcore-netstack/src/stack.rs` 的 `Driver::handle_packet` 处理 ICMP，位于
  raw ingress validation 之后、TCP/UDP 分派并列的位置。
- `NetStackConfig` 必须由当前 TUN 配置显式打开 fake echo。
- reply 使用现有有界 raw egress queue；不得增加 ICMP task、专用 channel、socket、
  flow table 或 timer。queue full 时只丢当前 reply。
- 单次最多分配一个不超过当前 TUN MTU 的 reply buffer，并增加 replied/dropped
  计数用于验收。该瞬时分配属于现有 packet budget，不扩大 iOS TUN 队列容量。
- 不增加 `NETWORK,ICMP`，也不扩展通用 `Dispatcher` 的 TCP/UDP 边界。

## 3. DNS query 分类与 TUN 劫持

当 `dns.enable: true` 时，所有 TUN TCP/UDP 目标端口 53 继续在用户
`rules` 之前进入本地 DNS service；不能因为 qtype 非 A/AAAA 就把原始流量放回
客户端指定的 DNS 地址。

TUN UDP/53 使用 pre-association fast path：在普通 source association map 查询、
ingress queue 和 association task 创建之前完成有界 wire 分类并进入 runtime DNS。
因此每个结构合法的 DNS datagram 都不创建或刷新普通 UDP association；iOS resolver
即使连续更换 source port，也只创建由 TUN runtime 跟踪的 request task。UDP reader
不等待 upstream exchange，慢 DNS 不能阻塞普通 UDP/QUIC、其他 source 或已就绪
response。DNS request 不受固定 total-query admission。

TUN TCP/53 仍保留 netstack TCP state 和 2-byte DNS framing；每个 wire query 与
TUN UDP/53、routing lazy resolve 和其他内部 runtime-DNS query 共享同 key
singleflight，但不经过全局 query 或 aggregate live-transport gate。`dns` 省略或
`enable: false` 时不启用任何 TUN DNS fast path；
TUN TCP/UDP 53 与非 TUN 53 一样作为普通业务流量执行 `rules`。

| query | 本地处理 | cache / redir-host | cache miss 的 upstream |
| --- | --- | --- | --- |
| IN/A | 现有 A、CNAME reachability 和地址校验 | 地址 cache；仅启用 TUN hint store 时成功地址可产生 hint | 按第 4 节选择 |
| IN/AAAA | 现有 AAAA 处理；`ipv6: false` 时本地 NODATA | 地址 cache；仅启用 TUN hint store 时成功地址可产生 hint | 按第 4 节选择 |
| 其他 IN qtype | opaque wire relay | 通用有界 response cache；不产生 hint | 按第 4 节选择 |

Mihomo 内部把 IN/CNAME 与 A/AAAA 一起归入 IP-request 分支以参与 fallback；VCore
不支持 fallback，因此 CNAME question 在当前子集中按 opaque query 转发和缓存，不会
单独产生 redir-host hint。A/AAAA response 中从原 question 可达的 CNAME chain 继续
采用现有严格校验，但只有当前 runtime 启用 TUN 且业务 `rules` 含 `DOMAIN`、
`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时，结果才写入仅供该 TUN 消费的
redir-host store。

SVCB、HTTPS、TXT、PTR、MX、SRV、NS、SOA、DNSSEC type 以及未知但 wire 合法的
16-bit qtype 都属于 opaque relay。VCore 没有 fake-ip，因此不复制 Mihomo fake-ip
模式为 SVCB/HTTPS 合成本地 NODATA 的行为。

## 4. Mihomo-compatible nameserver 出口

配置外形为：

```yaml
dns:
  enable: true
  ipv6: true
  nameserver:
    - "tcp://1.1.1.1:53#vless-edge"
  nameserver-policy:
    "geosite:private,cn,apple":
      - "tcp://223.5.5.5:53#DIRECT"
```

`#vless-edge`、`#socks-hop` 等 fragment 是大小写敏感的精确 proxy name，并选择
该节点自己的完整 `dialer-proxy` 链。`#DIRECT` 固定选择内置 direct，`#RULES`
才执行第 4.2 节的业务规则求值。`PROXY`/`#PROXY` 没有默认节点魔法；只有配置
确实存在名为 `PROXY` 的实际节点时，它才按普通精确 name 解析。

### 4.1 语法

- `enhanced-mode` 与 `respect-rules` 不属于当前协议；DNS 启用时 A/AAAA typed cache
  始终正常工作。只有当前 runtime 启用 TUN 且业务 `rules` 含 `DOMAIN`、
  `DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时才维护 redir-host hint。
  没有 route fragment 的 nameserver 固定走 DIRECT。
- nameserver 继续最多 4 项，只支持裸 IPv4/IPv6、`udp://IP[:port]` 和
  `tcp://IP[:port]`，并增加一个可选、大小写敏感的 route fragment。
- `nameserver-policy` 是有序 mapping，最多 16 个 entry。selector 只接受精确小写
  `geosite:<code>[,<code>...]`，不接受 domain、GeoIP、rule-set 或其他 Mihomo
  selector；逗号分隔的 code 为 OR，code 不区分大小写。同一 code 不能在多个
  entry 中重复，全部 policy 合计最多 16 个 GeoSite code。
- policy value 必须是包含 1–4 个 nameserver 的 YAML sequence；不接受单个字符串
  标量。每个 nameserver 与主组使用完全相同的 endpoint、route fragment 和
  无 fragment 时固定 DIRECT 的出口解析。
- route fragment 只接受 `DIRECT`、`RULES` 或任一已配置 proxy 的精确 name。
  `PROXY` 不是特殊 fragment。
- fragment 中的 `REJECT` 本身不合法。未知 proxy/group/interface、空 fragment、
  多个无 `=` token、fragment
  参数和 `h3=true` 等必须在配置校验时明确失败。
- DoH、DoT、DoQ、system、DHCP、hostname nameserver、interface 和任意 proxy group
  仍不支持。

### 4.2 优先级

对每一个需要 upstream exchange 的 query，出口优先级固定为：

1. nameserver 显式 fragment。
2. 没有 fragment：DIRECT。

该优先级统一适用于 A、AAAA 和所有其他 qtype。本地 cache hit 和 `ipv6: false`
的本地 AAAA NODATA 没有 upstream，自然不执行出口选择。

`#RULES` 只以当前 nameserver 的实际 endpoint 和 transport 构建 routing context：

- GEOIP、IP-CIDR/IP-CIDR6、DST-PORT、NETWORK 和 MATCH 可以参与。
- DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD 和 GEOSITE 没有 query-name hint，不能命中。
- DNS question name 不能作为业务 routing domain。
- nameserver 必须是 literal IP，因此 GEOIP 惰性解析不会递归进入 runtime DNS。
- `REJECT` 把当前 nameserver attempt 视为失败，继续配置顺序中的下一个 nameserver；
  不允许从某个 proxy 隐式回退 DIRECT，也不允许从 DIRECT 隐式回退 proxy。

当前 `config.yaml` 示例 nameserver 显式写为 `#vless-edge`，因此固定选择该节点
的完整链。删除 fragment 会把该 nameserver 改为 DIRECT；改成其他精确 name 则只
选择那个节点的完整链。

### 4.3 `nameserver-policy`

VCore 以 canonical DNS question domain 按配置 mapping 顺序检查 policy。一个 entry
中的任一 GeoSite code 命中即选中该 entry，后续 policy 不再求值；没有 entry 命中
时才选择主 `nameserver`。该选择统一适用于 A、AAAA、CNAME question 和所有 opaque
qtype，也不会把 policy 选择结果改写为后续业务 action。

命中 policy 后，当前 query 只在该 entry 的 nameserver sequence 内按顺序 failover。
transport/格式错误、timeout、TC、SERVFAIL、REFUSED 或 `#RULES`/REJECT 可以继续该组
下一项；组内全部失败直接按第 5 节的失败语义结束，绝不能再查询主 `nameserver`。
这样 `geosite:private,cn,apple` 经 `223.5.5.5#DIRECT` 解析时，不会在失败后泄漏到
`1.1.1.1#vless-edge`。未命中的其他域名才使用主组。

policy 引用的 GeoSite code 与业务 `GEOSITE` rules 一并去重并按需从
`dataDir/geodata/geosite.dat` 加载，共享每实例最多 16 个 GeoSite + GeoIP code
和 8 MiB GeoData allocation capacity。即使业务 rules 没有引用某个 policy code，
该分类在资产可用时仍必须完成有界校验；GeoSite 资产缺失或不可用时暂不命中任何
GeoSite policy，query 使用主 `nameserver`，而不是阻塞 `prepare`/`start`。VCore
在后台只经最终 `MATCH` 指向的实际 proxy 及其完整链更新资产，成功热激活后后续
query 使用新 matcher。

## 5. Wire、cache 与失败语义

### 5.1 Query/response validation

- DNS message 上限保持 4096 字节；只接受 opcode QUERY、恰好一个 question、
  qclass IN。query 不得携带 answer/authority；允许结构合法且受总 message 上限约束
  的 EDNS additional record。
- parser 必须保留原始 16-bit qtype，不能把 unknown qtype 当配置或 wire error。
- A/AAAA 继续使用完整 typed parser；opaque response 只做有界结构扫描，并验证
  QR、transaction ID、question name/type/class 与 request 完全一致。
- name compression 继续限制最多 16 次跳转；response 最多扫描 64 条 resource record，
  A/AAAA typed cache 以及启用时的 redir-host hint 最多保留 16 个唯一 IP。
  malformed length、compression loop 和 trailing bytes fail-closed。
- TCP DNS 继续使用 2-byte length framing，同一连接必须能串行处理混合 qtype，
  例如 A -> HTTPS -> AAAA -> TXT。单 frame 为 0 或超过 4096 时关闭该 DNS stream。

### 5.2 Cache

- A/AAAA 地址 cache 始终可用、最多 256 项并从空容量按需增长。redir-host store
  只在 TUN + domain-rule scope 内创建，仅供所属 TUN 消费；启用时同样从空容量增长且
  最多 256 项。非 TUN runtime 或没有上述 domain rule 的 TUN runtime 不创建该 store。
- 新增 opaque response cache：最多 64 项、单个 response 最多 4096 字节；response、
  规范化 question key、完整 query 语义摘要和 TTL metadata 的 retained bytes 合计最多
  256 KiB。达到任一上限时按最早过期项优先淘汰，不得继续扩容。
- opaque key 包含规范化 question name、qclass、qtype，以及除 transaction ID 外完整
  query wire 语义的 SHA-256 摘要，因此 RD/CD、EDNS DO/COOKIE/options 不会跨语义复用。
  cache hit 必须替换 transaction ID、同步 RD，并按剩余 lifetime 更新所有可缓存 RR TTL。
- positive lifetime 取 Answer/Authority/Additional 中可缓存 RR 的最小 TTL；OPT 不参与。
  TTL 为 0 或没有可缓存 RR 时不缓存。VCore 仍可应用现有 30--3600 秒 lifetime clamp；
  这是资源子集差异，不声明与 Mihomo cache capacity/stale-refresh 完全一致。
- opaque NXDOMAIN 采用固定 30 秒负缓存；opaque NOERROR/空 Answer 只有 authority 含
  IN/SOA 时才确认为 NODATA 并负缓存，referral 不缓存。opaque response 的 EDNS
  extended RCODE 参与 effective RCODE，BADVERS 等不误判为 NODATA。opaque cache 永远
  不写 redir-host hint。
- cache 和每次 query 的临时 buffer 分别受前述 item、retained-byte 与 4096-byte wire
  边界约束；不再通过 in-flight admission 或静态 runtime-DNS byte model限制并发 query。

### 5.3 UDP/TCP、failover 与 association

- 主 nameserver 或已命中的 policy 组各自按配置顺序尝试；policy 组失败不跨组回退。
  这是 VCore 子集，Mihomo 更完整的 batch、fallback 和其他 policy selector 不在范围内。
- 每个 query 从进入 runtime DNS 开始计算固定 5 秒总 deadline；建链、发送、接收、
  重发和顺序 failover
  都不得重置它。单个 nameserver attempt 最多 3 秒，并受 query 剩余时间限制。
- UDP nameserver attempt 只打开一个 datagram transport。第一次发送后 1 秒仍未收到
  合法 response 时，最多在同一 transport、同一 transaction ID 上重发一次；禁止为
  retry 新建 socket、XUDP backend 或并行 hedge。peer、QR、opcode、ID 或 question
  不匹配的 response 只丢当前 response 并继续等待；前 2 个 mismatch 可继续等待，
  累计到第 3 个时立即将当前 attempt 判为失败。
- transport/格式错误、timeout、SERVFAIL、REFUSED 和 `#RULES` 得到 REJECT 时继续
  下一个 nameserver；NXDOMAIN/NODATA 直接返回并按对应 cache 规则处理。
- UDP nameserver response 设置 TC 时，当前 attempt 失败并继续下一个 nameserver；
  VCore 不为它隐式创建 TCP transport。只有配置显式写成 `tcp://` 时才使用 upstream
  TCP。该失败不得写入 typed/opaque cache。
- TUN UDP response 必须适配 IPv4/IPv6 共用的 1452-byte payload ceiling。完整
  response 超过该上限时只丢当前 response，不合成本地替代包，也不能向 netstack
  注入超限 datagram；4096-byte internal ceiling 不是 TUN UDP 可发送大小。
- 合法 query 的所有 upstream 均失败时生成 SERVFAIL。UDP 只失败或丢弃当前 query，
  不影响普通 UDP association；TUN UDP DNS 本身不创建 association。malformed TUN
  UDP query 在创建 task 前只丢当前 datagram，不生成 SERVFAIL。
- TUN DNS ingress 固定为 128；DNS response 与 ordinary UDP response 分别使用独立的
  128 项 bounded queue。两类 datagram 仍通过同一个 netstack UDP ingress receiver，
  因此这里只隔离 response-path capacity，不声称完整 ingress 隔离。ingress 在 fast
  path 前已满时只丢当前 request。对应 response queue full/closed 时允许
  request-local drop，不得阻塞全局 UDP loop；UDP 语义不承诺交付。
- malformed TCP framing 关闭当前 DNS stream。取消 TUN session 必须终止 in-flight
  DNS relay；未被 timeout/cancel 中断的 UDP attempt 正常收敛路径显式调用
  `close()`。runtime stop/cancel 必须取消 open、send、receive、retry、TCP fallback
  和 response send，drop 并释放已持有 transport，且 drain/abort 所有
  tracked DNS task；取消路径不承诺 XUDP END 等协议级 graceful close。停止完成后
  不得再向 TUN 回包。

## 6. 资源与生命周期

- 所有 TUN fd target 使用同一个 workload profile，但 TCP session、ordinary UDP
  association、half-open TCP 与 outbound handshake 不设置固定并发总数。仍保留
  256 packet queue、128 event/ordinary UDP response queue、1,500-byte raw-IP packet
  ceiling、32 KiB/TCP direction 和 64 KiB TLS/XHTTP buffers。TUN 最终 proxy UDP
  payload 为 1,452 字节。
- TUN UDP/53、TUN TCP/53、routing lazy resolve 和其他 internal wire query 不经过
  固定 client-request 或 aggregate live-transport admission；cache/local、active 与
  response 阶段都不会仅因某个并发计数到达阈值而生成资源错误。
- A/AAAA typed cache 在所有启用 DNS 的 runtime 中保持正常。redir-host store 仅在
  TUN + domain-rule scope 内启用，从空容量按需增长且最多 256 项；hint 不跨 runtime
  或被非 TUN listener 消费。TUN 路由的 domain 来源优先级固定为
  `sniffed domain > DNS redir-host hint > IP`，任何 hint 都不改变 actual outbound
  destination。
- cache miss 在 upstream exchange 前进入同 key singleflight。key 是 canonical question
  加排除 transaction ID 后 `message[2..]` 的 wire-semantics digest；leader 在发起方
  task 内运行。leader 取消或 drop 时 RAII 广播 Retry，followers 重新选举；每个
  caller 恢复自己的 transaction ID、endpoint，并对共享的 raw result 独立应用自己的
  failure mode。cache hit 不创建 flight。不同 key 可按需并行。
- DNS exchange 继续受 5 秒 query、3 秒 attempt、1 秒单次 UDP resend、cancellation
  和 transport open timeout 约束。outbound handshake 不使用全局 semaphore gate；
  DIRECT、所有 proxy graph、runtime DNS 和本地 HTTP listener 按需建链。旧 iOS
  20-unit user/4-unit DNS weighted pools、cost permit wrapper、协议成本矩阵以及
  128/64/32/16 业务并发档均已删除。
- runtime 保留 TCP、UDP、half-open、handshake 与 DNS current/peak，以及
  singleflight join、cache hit、queue drop 和连接池状态统计；这些统计不触发
  admission。Android TUN 的 DIRECT socket 仍必须在 connect 前执行 protect；
  proxy graph 的物理 socket 使用现有已保护的底层 dialer。
- UDP 继续使用 request-scoped transport。retry 复用当前 attempt 的 transport；
  切换 nameserver/egress 或 query 完成、失败、取消时关闭，不跨 query 复用。
- 显式 `tcp://` nameserver 使用每个 `RuntimeDns` 独立的连接池。key 固定为
  nameserver endpoint + 已解析的最终 egress（`Single`、`DIRECT` 或精确 proxy id）；
  `#RULES` 必须先求得最终 action，不能只按 `RULES` 字面共享。每条连接同时只处理
  一个 query，不做 pipeline 或 response ID demux。
- TCP pool 的 active 物理连接不设置固定 ceiling；默认 idle 总上限为 4、同 key 为
  2、idle timeout 为 30 秒。check-in 达到 idle 上限时按最老 idle 淘汰，reaper 和
  runtime drop 都在锁外释放 stream。expired 回收计入 `idle_expirations`，LRU
  回收计入 `idle_evictions`。
- TCP response 必须先完成 2-byte framing、4096-byte ceiling、question/ID/opcode/rcode
  及 typed/opaque 语义校验，成功后才可 check-in。复用连接发生 EOF、I/O/reset 或
  response mismatch 时，在原 nameserver attempt deadline 内丢弃旧连接并 fresh
  reconnect 一次；malformed、truncated 或 oversize response 不重试且不归还连接。
  SERVFAIL/REFUSED 是合法且可归还的 response，随后仍按 nameserver 顺序 failover。
- 每个普通、非 DNS TUN UDP source association 的 ingress queue 保持有界，full 只丢
  当前 datagram。association map 不设固定项数，并使用 generation-aware completion 和
  child cancellation：idle timeout 30 秒、cleanup 周期 10 秒；cleanup 先从 map 删除
  expired/closed association 再 cancel child。TUN parent 退出时删除并
  cancel 全部 child，drain completion 后才越过 stop barrier。queue-full/drop 不刷新
  activity，成功入队的 inbound 或成功排队的 outbound response 才刷新。
- TUN DNS ingress 固定为 128；DNS response 与 ordinary UDP response 各有独立 128 项
  queue。netstack ingress receiver 仍共享，不能把 response queue 隔离描述为完整 ingress
  隔离。DNS response queue full 时只丢当前 response；普通 response
  queue full 只丢当前 datagram，不停止 UDP loop/TUN runtime。
- ICMP、DNS 和 TUN 仍由明确的 item、wire、cache、queue、per-flow buffer、timeout
  与 idle cleanup 边界约束，
  但不再维护 iOS 静态 post-start byte model。35/45 MiB 是 best-effort telemetry 和
  Release 真机优化目标，不是 fail-closed 门槛；超过目标不改变 VPN 生命周期结果。

## 7. 实现落点

1. `crates/vcore-netstack/src/icmp.rs` 和 `stack.rs` 实现当前 TUN gate、packet builder、
   有界 raw egress 与 replied/dropped 统计。
2. `src/dns/mod.rs` 实现任意 qtype classifier、opaque scanner、canonical SERVFAIL 和
   有界 cache；`src/dns/runtime.rs` 实现 upstream exchange、cache 与 egress selector。
3. `src/config/mod.rs` 实现固定 DIRECT 默认出口、fragment、proxy tag/保留字校验，
   以及有序 GeoSite-only `nameserver-policy` 的 selector、重复 code 和容量校验。
4. `src/dispatch.rs` 为 DIRECT、全部 proxy graph 与 TCP/UDP 提供按需 dispatch；
   `src/runtime.rs` 只接入 activity 观测，不创建 session/handshake semaphore。
   `src/dns/runtime.rs` 维护 active 不限量、idle 有界的显式 TCP nameserver 连接池。
5. `src/tun_runtime.rs` 在普通 UDP association 创建前处理 TUN UDP/53，以 tracked
   task 直接完成 runtime DNS 并向 netstack 回包；`src/routing/dispatcher.rs`
   保留 TUN TCP/53、按需 TUN domain hint、lazy resolve 与普通业务路由，不保留第二套
   TUN UDP DNS 劫持路径。TUN runtime 同时持有 netstack stats handle，每 30 秒及停止
   后输出 TCP/half-open/UDP/handshake/DNS current/peak 与
   reject/drop/invalid/ICMP 固定计数。

## 8. 验收状态

截至 V5 的自动化历史覆盖如下：

- ICMPv4/ICMPv6 正常、奇数 payload、MTU 边界、IPv4 options、checksum 错误、非 Echo、
  分片、IPv6 extension header、queue full；确认 fake reply 从不调用 dispatcher。
- 严格接受当时的 `configVersion: 5`；缺失/其他版本、V2/V3/V4、旧 `inbounds/outbounds` 结构和
  `allowInsecure` 均有拒绝测试。
- A、AAAA、CNAME、TXT、PTR、MX、SRV、SVCB、HTTPS、DNSSEC 和 unknown qtype；
  非 IN、multi-question、compression loop、4096/4097 和 EDNS 边界。
- 无 fragment 固定 DIRECT，fragment `DIRECT`、`RULES`、`PROXY`、两个实际 proxy
  tag、未知 tag、保留字冲突和无效参数；旧 `enhanced-mode`/`respect-rules` 字段
  必须拒绝，`PROXY` 与精确 tag 分别解析到正确的 `ProxyId` 和完整
  `dialer-proxy` graph。
- 对 A/AAAA 与非 A/AAAA 证明同一 nameserver egress 优先级；证明 `#RULES` 匹配
  nameserver endpoint 而不是 query name。
- GeoSite policy 对 typed/opaque query 使用同一选择器；多个分类同时命中时保持
  mapping 首条优先；命中组内可顺序 failover，但 typed/opaque 的组内耗尽均不查询
  主 nameserver。NXDOMAIN 为终态，`ipv6: false` 的 AAAA 仍在 policy 前本地 NODATA。
- 业务 UDP 的 `PROXY`/精确 tag/`DIRECT`/`REJECT` per-datagram 选择，以及 DNS upstream
  egress/failover 分别有独立自动化覆盖。
- 单 source 普通非 DNS TUN UDP association queue 满时按 UDP loss 丢当前 datagram，
  其他 source 仍可完成 round-trip，不产生跨 association 队头阻塞。
- TUN TCP 同连接混合 qtype、partial/pipelined frames，以及 session cancellation。
- opaque cache 的 TTL/ID rewrite、64 项、256 KiB、4096-byte entry、淘汰和不产生
  redir-host hint。
- DIRECT loopback UDP/TCP DNS round-trip、多个 mock proxy dispatcher TCP/UDP 路径，
  以及 UDP TC 只按顺序 failover、不会打开隐式 TCP transport。
- 资源策略重构前的候选覆盖过 TUN 128 client request/8 logical upstream 两级
  admission、bounded singleflight 的
  leader/follower/Retry/ID 恢复、join/cache-hit 固定计数，以及 cache hit 不创建
  flight。
- 64-record response scan、16-unique-address retention、64 项/256 KiB opaque cache
  和 256 项 typed cache；另覆盖非 TUN、TUN 无 domain rule、TUN 含
  `DOMAIN`/`DOMAIN-SUFFIX`/`DOMAIN-KEYWORD`/`GEOSITE` 三类初始化，证明只有最后一类
  创建并消费按需增长、最多 256 项的 redir-host store。
- TUN TCP sniffer 的 domain 优先于 DNS hint；TLS ClientHello extension `0xfe0d`
  位于 SNI 前、SNI 后、分片边界或跨 TLS record 时均丢弃 outer SNI（包括无法区分的
  GREASE ECH），回退到有效 DNS hint，否则使用原 IP；目标 IP 和预读字节回放不变。
- 当时 sniffer 不提供用户开关，只在 TUN + domain-rule scope 内启用；非 TUN 或 TUN
  没有 `DOMAIN`/`DOMAIN-SUFFIX`/`DOMAIN-KEYWORD`/`GEOSITE` 时，80/443 均不预读、
  不分配 sniffer buffer，也不等待 200 ms。
- 历史 V6 新增并已覆盖：省略/关闭 sniffer、启用时至少一个 HTTP/TLS 协议、协议空值或
  mapping 省略 `ports` 分别默认 80/443、显式空列表拒绝、每协议 64 项上限、
  单端口/闭区间边界、HTTP/TLS 重叠拒绝，以及 QUIC、override/force/skip 和旧字段
  拒绝。只有 TUN + `enable: true` + domain-rule scope 才实际预读。
- 历史 V6 关闭 sniffer 时，TUN + domain-rule scope 仍必须独立创建 redir-host store；
  sniffer 永不 override destination，ECH `0xfe0d` 仍回退 DNS hint 或原 IP。
- 当前 V7 将 sniffer 扩展为严格 HTTP/TLS/QUIC；空值或省略 `ports` 分别默认
  80/443/443，仅 HTTP/TLS 互斥，QUIC 可与二者使用相同数字端口。QUIC 只接受标准
  v1/v2 Initial，不支持 Draft-29；UDP/53 fast path 先于 ordinary association 与
  sniffer。
- V7 QUIC Initial 在路由前按 destination 有界缓存：每 association 最多 4 个 state，
  pending 合计 8 个 datagram/32 KiB/500 ms，每 state 的 CRYPTO 为 16 KiB/64 ranges，
  ACK 总计为 64 ranges。满载时 LRU 淘汰 completed state，只有 4 个 state 全 pending
  时新 destination 才直接 fail-open。不同 version/DCID 的 v1/v2 Initial 必须用候选
  Initial keys 完成 AEAD 认证后才替换完成态；pending 先尝试旧 keys，正常 header
  DCID 轮换、0-RTT/Handshake 不重置也不增加等待。解析失败、未知版本、ECH、超时或超限均回退 DNS hint/IP，并把
  每个 flow 已缓存 datagram 按原顺序、原字节且只回放一次；sniffer 不替换目标。
- 资源策略重构前的 V7 候选还覆盖过：两个本地 listener 共享同一个 handshake
  permit/统计；占满 16 个 permit 后先排队
  8 个 internal-DNS handshake，再加入 64 个 TUN handshake churn，释放容量后前 8 个
  获得名额的 caller 均为 DNS，证明后到 TUN 不会使已排队 DNS 饿死。DNS session wait
  与 handshake wait 的次数/毫秒，以及取消 waiter 不占 permit 也有独立自动化。

历史 V6 曾通过 Core 351 passed / 2 个环境依赖项 ignored、netstack 19 passed、
fmt 与全 targets/features Clippy `-D warnings`；其中覆盖的是当时的 TCP sniffer
schema、runtime 三重 gate、redir-host 独立性、ECH fallback、自定义端口和原始目标
保持。2026-07-24 V7 QUIC 候选的 host、App 与 Apple/Android 原生产物门禁已经实际执行并记录在
[验收矩阵](acceptance.md)；物理 iOS/Android TUN 仍未执行。

以下是 2026-07-19 旧实现的历史 host 记录，不代表当前资源档：

- 不同 source port 的 TUN UDP/53 burst 在 association 创建前受 8-slot total
  限制，total overflow 生成 SERVFAIL，并且 DNS 满载不阻塞普通 UDP。
- 当时的 8/32 total 和 2/8 active/logical 档位、pre-admitted query 只消耗一个 total
  slot、lazy resolve 的资源错误、TCP/UDP 合并 logical admission，以及 8 total/2 active
  的并发上限。
- 当时的 DNS-only session/handshake/weighted-pool wait 的释放与 deadline，TUN outbound
  handshake 在既有 open timeout 内的等待，以及本地 proxy/session/weighted admission
  仍为 fail-fast；weighted waiter 不会提前占用共享 handshake permit。
- 同 transport/同 transaction ID 的 1 秒单次 UDP 重发、累计到第 3 个
  mismatch 即 failover、UDP TC 不打开 TCP、malformed request-local drop、超长 TUN
  UDP DNS response drop 和 blocked upstream 下的 stop barrier。
- total permit 随 response 保留到 TCP framing、TUN UDP queue 实际发送或丢弃；queue
  full 会释放 permit，IPv4/IPv6 response 均保持请求 endpoint 方向。DNS-enabled iOS
  ingress burst 为 32，fast-path 精确资源模型为 260,992 字节并通过 256 KiB 子预算断言。

这些数值和测试数量只属于历史快照。当前策略只保留同 key singleflight、UDP idle
cleanup 和队列隔离，不保留 128/8、UDP 64 或 handshake gate；本轮实际命令与结果
统一列在 `acceptance.md`，未由当前工作树执行的项目不写成 PASS。

以下自动化仍待补写或加强，不能归入上述“已通过”集合：

- 超过旧 TCP 128、UDP 64、half-open 32、handshake 16 和 DNS 128/8 阈值时仍按需
  处理、仅由真实网络错误或局部 queue/buffer 边界收敛的集成测试。
- cache/local result、同 key singleflight，以及 5 秒 query、3 秒 attempt、1 秒 resend
  的真实时序边界。
- cancel 分别命中 open/send/receive/retry/response send 的完整
  task/transport 回收计数；现有 stop barrier、queue-full 回收和无 detached task
  覆盖不等于该穷举矩阵。

仍待平台或真实服务端证据：

- 使用真实 VLESS + XHTTP + XUDP/TCP nameserver，并覆盖 SOCKS5 与链式 proxy graph，
  完成 A/AAAA 与 opaque qtype round-trip。
- Release iOS 真机、无调试器条件下记录整个 TUN 宿主进程 cold-start current、
  representative-workload peak 和 plateau；35/45 MiB 只作优化目标，越线不判生命周期失败。

## 9. 明确不支持

- 真实 ICMP forwarding、ICMP error、Traceroute、ICMP route rule 和 ICMP 测速。
- DoH、DoT、DoQ、system/DHCP nameserver、hostname nameserver、出口网卡 fragment、
  任意 proxy group、fragment 参数。
- Mihomo `fallback`、非 GeoSite selector 或标量/无界形式的 `nameserver-policy`、
  `default-nameserver`、`proxy-server-nameserver`、`direct-nameserver`、fake-ip、
  hosts、cache algorithm 和用户可配置 cache capacity。
- 以 DNS query name 执行业务 `rules`，或根据 DNS 出口 action 改写后续业务 action。

## 10. TUN UDP DNS 入口与调度改造记录

状态：本节是 M0–M5 业务优先资源改造的历史实现记录；该阶段本身没有新增 YAML
字段或提升当时的 config version。后续 nameserver policy 曾把公共协议提升为 V4，
当前 HTTP inbound/TUN sniffer 契约已提升为 V7；配置和 DNS 选择语义以第 4、5、6
节为准。非 TUN HTTP listener 的 TCP/53 行为仍未改变。

实现收敛为以下内部结构：

1. `TunRuntime` 持有与 routing dispatcher 相同的 `Arc<RuntimeDns>`；TUN UDP/53 在
   普通 association 之前取得 client-request permit，并以 tracked task 直接完成
   runtime DNS 与 netstack 回包。routing dispatcher 只保留 TUN TCP/53、domain hint、
   lazy resolve 与普通业务路由。
2. TUN runtime 共享 128 个 client-request slots 和 8 个 logical upstream permits；
   total 包含 waiting、cache/local、active 和回包前状态，不能解释为“128 queued +
   8 active”。DNS ingress 和独立 response queue 均显式为 128，不再按 `total × 4`
   推导。
3. cache miss 使用 bounded singleflight。key 为 canonical question 与排除 transaction
   ID 后 `message[2..]` 的 semantics digest；leader 在发起方 task 内运行，取消/drop
   时以 RAII 广播 Retry，followers 重新选举。shared result 按 caller 恢复 ID。
4. runtime DNS 与 TUN flow 使用可取消的 resource wait，本地 HTTP inbound 仍
   fail-fast。query/attempt/
   retry 固定为 5 秒/3 秒/1 秒，同一 UDP transport 最多重发一次，mismatch
   累计到第 3 个即将当前 attempt 判为失败；顺序 failover 与 request-scoped transport
   所有权均保持第 5 节语义，UDP response 的 TC flag 不触发 TCP fallback。
5. DNS disabled、malformed、total overflow、response backpressure 和 stop/cancel 均按
   第 3、5 节 fail-closed：disabled 回普通业务路由；malformed request-local drop；
   已到 fast path 的合法 wire overflow 生成 SERVFAIL，但共享 ingress 或对应 response queue
   backpressure 仍可 request-local drop，不承诺 UDP 必达；正常 UDP attempt 显式
   `close()`，cancel 通过 drop 释放资源且不承诺协议级 graceful END。stop 后不再
   回包且不保留 detached task。
6. response parser 最多扫描 64 条 record，typed cache/hint 最多保留 16 个唯一 IP。
   旧 iOS 8/2 admission、20/4 weighted pools、32-entry ingress、260,992-byte
   fast-path model 和 7,640,960-byte post-start model 均已退役。

设计入口参考 clash-rs 的 pre-dispatch UDP/53 gate，UDP retry ownership 参考 leaf 的
same-transport 重发；当时没有采用在 TUN UDP loop 内同步等待 resolver、每次 retry
新建 transport、并行 hedge、跨 query socket pool 或提前老化普通 association。

后续 2026-07-25 曾实现“显式 TCP nameserver、单连接串行”的 physical=8 有界复用；
当前第 6 节已经取消 active physical ceiling，只保留 idle 4/2/30 秒；这两次变更都不
回写 M0–M5 的历史状态。仍明确延期：跨 query persistent UDP/XUDP transport、
TCP pipeline、DNS ID multiplexer、
DoT/DoH/DoQ、nameserver 并发竞速、健康评分、fake-ip、hostname nameserver、
fallback、其他 policy selector 和用户可调 timeout/retry/concurrency。任何一项进入
实现前都必须评估资源影响、定义必要的局部边界，并先更新当前契约。
