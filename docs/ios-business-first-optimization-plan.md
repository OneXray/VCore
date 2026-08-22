# iOS TUN 业务优先优化计划

状态：第 0 节是 2026-07-25 当前策略；第 1–18 节是历史 M0–M6 及后续候选记录。
旧的 host/互操作/产物与 App 验证只属于对应候选，物理设备项为 `NOT RUN`，不能
作为当前资源策略的验证结果  
制定日期：2026-07-24  
适用仓库：`VCore`  
主要平台：iOS TUN fd；统一 TUN 资源档同时覆盖 macOS/Android TUN fd  
历史阶段配置与 ABI 基线：M0–M6 当时不修改 `configVersion: 3`、Invoke envelope、Android protect 或既有路由语义；后续 DNS nameserver policy 曾提升为 V4、HTTP inbound/TUN TCP sniffer 曾提升为 V6，当前 TUN TCP/UDP sniffer 配置契约为 V7

## 0. 2026-07-25 当前策略（替代后文冲突内容）

本节替代第 1–18 节中关于 TCP 128、UDP 64、half-open 32、handshake 16、DNS
request 128、DNS upstream/physical TCP 8，以及对应 admission、wait、reject、公平
semaphore 和 capacity eviction 的设计。后文保留这些内容仅用于解释历史决策和旧测试，
不得再把它们当作当前契约或当前验收标准。

当前遵循 Leaf 的有限优化思路：

- TCP、UDP 与 handshake 按业务流量按需创建 task，不通过固定总数 gate 正常连接。
- 普通 UDP association map 不设固定项数，使用 generation-aware ownership、30 秒
  idle timeout 和 10 秒 cleanup 回收。
- DNS 不设置全局 query、upstream transport 或 active physical TCP admission；相同
  canonical wire question 仍使用 singleflight 合并。
- 显式 TCP nameserver 的 active 连接按需建立；只保留 idle pool 总数 4、同 key 2、
  idle 30 秒，单连接仍串行处理一个 query 且不做 pipeline。
- bootstrap resolver 最多创建 4 个 worker thread；全部忙时请求在调用方既有 timeout
  内等待可用 worker，不返回资源上限错误。
- 继续硬性约束 bounded channel、每流 buffer、cache/解析和 wire size、MTU、GeoData、
  protocol state、timeout 与 idle cleanup。局部 queue full 仍按对应 TCP 背压或 UDP
  loss 语义处理。
- 保留 TCP、UDP、half-open、handshake 与 DNS current/peak，以及 queue drop、
  singleflight join、cache hit 和 TCP pool 状态观测；观测值不触发业务 admission。
- 公开 lifecycle registry 始终只允许一个实例；`measureDelay` 不进入该 registry，
  外部批量调用不可重叠，单次调用接收 1–5 份配置，Core 固定最多使用 5 路私有
  worker。`validateConfig`
  等无状态方法不受全局 Invoke admission 影响。

这项策略优先保证正常业务可用，再通过局部边界和生命周期回收控制内存；极端负载下允许
iOS 终止 Packet Tunnel Extension。本次改造的 host、Apple/Android build 与产物哈希已
按实际结果登记到 `acceptance.md`；产物未复制进 App，物理 TUN 仍未执行。不得沿用
后文旧候选的测试数量或哈希。

## 1. 历史决策

VCore 的 iOS TUN 优化顺序调整为：

1. 保证 DNS、TCP、UDP、路由和代理链在正常业务负载下可用。
2. 保持协议解析、单对象分配、缓存、队列和生命周期有界。
3. 在不破坏正常业务的前提下优化常态内存。
4. 接受极端压力下 iOS 因进程内存过高终止 Packet Tunnel Extension。

现有 `35 MiB start current` 和 `45 MiB scoped peak` 不再是
`prepare`、`start`、`run` 或 `stop` 的硬性成功条件。它们降级为 Release
真机正常场景的观测和优化目标：

```text
cold-start current footprint: 目标 <= 35 MiB
representative-workload peak: 目标 <= 45 MiB
```

超过目标必须记录和分析，但 VCore 不得因此拒绝启动、主动停止 VPN、覆盖原始业务错误
或让已成功的 `stop` 返回失败。极端压力是否终止进程由 iOS 决定。

这项决策已经替代旧 iOS TUN 35/45 MiB fail-closed、8 MiB post-start modeled
ceiling、2 MiB unmodeled safety 和基于历史 lifetime peak 拒绝进程复用的设计。
公共文档只在带日期的历史快照中保留旧数值，并明确标记为旧实现。

## 2. 证据与参考结论

### 2.1 iOS 真机日志

`/Users/yiguo/Downloads/vcore/01.log` 的一次约 103 秒 VCore 运行显示：

- 143 次 `runtime_dns_total_overload limit=8`；首次发生在 TUN 启动后约 52 ms。
- 至少 431 次普通非 DNS UDP datagram 因 `max_udp_associations=8` 被丢弃。
- 77 次 TUN TCP outbound immediate failure。
- 32 次 TUN UDP association failure。
- 失败时约有 12 条 proxy TCP 和 8 条 proxy UDP 占用，恰好填满当前共享的
  20-unit iOS 用户 proxy transport pool。
- 上游 DNS attempt timeout 只有 2 次；没有 TUN、runtime、panic、OOM 或 footprint
  guard 崩溃证据。
- 两个上游 DNS response 因跨平台 `MAX_ANSWERS=16` 被拒绝。

因此当前首要故障是 VCore 的本地资源策略主动拒绝正常业务，不是 REALITY/XHTTP、
TUN fd 或上游 DNS 普遍不可用。

### 2.2 Leaf

本计划参考 `references/leaf` 的以下思路：

- iOS 只缩小有界 DNS LRU，不设置 iOS 专属 DNS total/active admission。
- TUN 与 netstack channel 使用等待/背压；UDP session 用 idle timeout 回收。
- DNS UDP association 收到 response 后尽快进入清理路径。
- nameserver 优先使用当前首选项，失败后再以有限并发尝试 fallback。

不采用 Leaf 的无上限 TCP task、无上限 UDP NAT map、普通 DNS 无 singleflight、
固定 512-byte UDP response buffer、缺少完整 response identity 校验、每次 DoH
重建 TLS 和无上限 `read_to_end`。

### 2.3 Clash-RS

本计划参考 `references/clash-rs` 的以下思路：

- 复用 persistent DNS client/background task。
- DNS cache、短生命周期 reverse cache 和 iOS 网络切换后的有限重建。
- TCP/UDP egress 分离、per-session queue 和 UDP idle 清理。
- TUN driver 短暂背压时丢当前 IP packet，但保持 runner 存活。
- netstack 在消费输入前先确认输出容量，避免关键 TCP ACK 被错误丢弃。

不采用 Clash-RS 的 TUN UDP/53 inline 串行阻塞、DNS 失败直接无响应、无界
netstack ingress、无上限 active TCP/UDP、约 1 MiB 的每 TCP netstack buffer、
10,000 SYN tracker 和未经移动端验证的 4,096-packet queue。

### 2.4 参考结论

Leaf 和 Clash-RS 都不是严格 iOS 内存模板。可复用的是连接复用、缓存、有限重试、
idle 回收、队列隔离和背压机制，不是它们的具体容量或无界实现。

## 3. 目标与非目标

### 3.1 目标

- 正常 iOS 启动洪峰、网页浏览、Google 服务、QUIC、NTP、DoT 和后台系统流量不因
  VCore 的小容量 iOS profile 立即失败。
- DNS cache miss 支持 burst、同问合并、有限并行和有界排队。
- 已建立 TCP/UDP flow 优先于新建 flow；容量紧张时先清理过期或最老 idle state。
- TUN fd 平台使用同一个按 workload 定义的资源档，删除仅为 35/45 MiB 证明服务的
  iOS 特殊值。
- 内存 telemetry 不影响业务方法结果。
- iOS、macOS、Android、认证 HTTP inbound、单公共生命周期、批量 `measureDelay`
  和 Xray 互操作保持回归覆盖。

### 3.2 非目标

- 不承诺无限并发、恶意流量下不丢包或永不被 iOS 终止。
- 不把 Leaf 或 Clash-RS 直接嵌入 VCore。
- 不修改配置协议、分享格式、App 进程拓扑或 Android protect 语义。
- 不在本轮新增 DoH/DoT 配置、UDP TC 自动 TCP fallback 或新的 outbound 协议。
- 不把 host 单测、交叉编译或模拟器测试写成 iOS Release 真机验收。
- 不继续维护一份声称能够精确证明整个宿主进程峰值的静态 byte model。

## 4. 资源控制原则

### 4.1 继续硬性执行

以下边界用于内存安全、协议安全或所有权正确性，不能因为业务优先而删除：

- 最多两个 proxy、无环且最多两节点的 outbound graph。
- runtime registry 始终最多一个公开 lifecycle 实例；批量 `measureDelay` 的私有
  worker 不进入 registry。
- 每个 runtime 最多一个 TUN lease。
- TUN MTU 1,500 bytes、TUN proxy UDP payload 1,452 bytes。
- DNS name、compression pointer、wire record、message、cache item 和 nameserver 数量上限。
- opaque DNS cache、GeoData source/record/regex 和配置输入的结构上限。
- 每个 channel、每个 session buffer 和每个 cache 的有限容量。
- DNS query/attempt timeout、cancellation、stop barrier 和 fd ownership。
- Android socket protect 的 fail-closed 边界。

### 4.2 从硬失败改为业务友好控制

- TUN 和 internal DNS 取得 handshake/session capacity 时允许可取消等待。
- DNS burst 先进入有界 tracked-request/response queue，不在 8 或 32 个请求时立即拒绝。
- 相同 DNS wire query 使用 singleflight，共享一次 upstream exchange。
- UDP map 满时先清理 expired/idle association，再考虑拒绝新 association。
- TUN driver、UDP packet queue 的瞬时满载只影响当前 packet，不结束整个 runtime。
- 所有 overload、等待、丢包和 high-water mark 使用限频计数日志，不逐包刷屏。

### 4.3 极端场景

达到最后的安全容量后仍允许返回 SERVFAIL、丢 UDP packet、拒绝新 session 或由系统终止
进程，但必须满足：

- 已有 state 不被破坏。
- 不发生 panic、死锁、use-after-free、fd 泄漏或错误复用 response。
- runtime 被取消时仍能正常释放资源；系统直接终止时依赖进程级资源回收。
- App 能识别 Extension 退出并允许用户重新启动 VPN；这属于后续 App 验收，不扩大
  本计划的 VCore API 范围。

## 5. 首版目标资源档

新增平台无关的 `ResourceLimits::tun()`。`for_runtime(has_tun)` 只按 workload 选择
`tun()` 或非 TUN `default()`，不再根据 `target_os = "ios"` 选择小容量档。

首版值如下，后续只能由真机证据调整：

| 资源 | TUN 首版值 | 说明 |
|---|---:|---|
| TCP sessions | 128 | 与当前通用档一致 |
| ordinary UDP associations | 64 | 与当前通用档一致 |
| TUN half-open TCP | 32 | 高于当前通用 8，避免正常 SYN burst |
| outbound handshakes | 16 | DNS active 上限为 8，为用户流量保留正常并发余量 |
| packet queue | 256 | 有界 |
| event queue | 128 | 有界 |
| TUN max datagram | 1,500 bytes | 固定 raw-IP packet 上限 |
| TCP buffer per direction | 32 KiB | 首版回到通用值 |
| TLS sendable buffer | 64 KiB | 首版回到通用值 |
| XHTTP send/upload buffer | 64 KiB | 首版回到通用值 |
| tracked DNS client requests | 128 | 覆盖日志中至少 66-request burst 并保留约 2 倍余量 |
| active/logical DNS upstreams | 8 | DIRECT/全部 proxy/TCP/UDP 聚合 |
| typed DNS cache | 256 | A/AAAA 合并容量 |
| redir-host hints | 启用时最多 256 | 仅 TUN + domain rules，按需增长 |
| opaque DNS cache | 64 entries / 256 KiB | 保持当前结构安全上限 |
| TUN DNS ingress queue | 128 | 与 tracked request 容量匹配 |
| TUN DNS response queue | 128 | 与普通 UDP response queue 隔离 |

现有 `max(event_queue, total_dns_queries × 4)` 的 ingress 推导必须随本计划删除：
`TUN_DNS_INGRESS_BURST_PER_TOTAL_QUERY` 不再存在，TUN DNS ingress 明确取
`max(event_queue, tracked_dns_client_requests) = 128`。否则把 total 从 8 提升到 128
会意外生成 512 深度的队列，违背这里的有界设计。DNS response 另有独立的 128 深度
队列，旧的 260,992-byte fast-path 静态证明直接退役，不按新容量重新包装成硬门槛。

16 个 outbound handshake permit 由 DNS 和用户 flow 共享，必须保持 FIFO 或等价的
有界公平等待。M3 要用持续用户建连叠加 8 个 DNS upstream 的混合负载验证 DNS 不会因
permit 饥饿耗尽 3 秒 attempt deadline；如果现有 semaphore 无法满足，优先修复公平调度，
不得通过降低 DNS 128/8 或恢复 DNS-only weighted pool 规避问题。

这些值不是公开配置，不增加调参字段。VCore 当前只接受 latest-only 协议，内部资源值
随实现整体前进，不保留旧 profile。

## 6. DNS 目标设计

### 6.1 两级 admission

DNS 使用两级控制：

1. `client request admission = 128`
   - 包含 TUN UDP/53、TUN TCP/53、lazy resolve 和其他 internal query。
   - permit 覆盖等待、cache/local、upstream、response framing 和最终有界交付。
   - 达到 128 才允许使用现有 request-local SERVFAIL/结构化错误收敛。
2. `active upstream admission = 8`
   - DIRECT、所有 proxy tag、TCP 和 UDP 共用。
   - 等待受 query/attempt deadline 和 cancellation 约束。
   - 不再叠加 iOS-only 4-unit weighted proxy pool。

保留 5 秒 query deadline、3 秒 nameserver attempt、1 秒同 transport 单次 UDP
重发和第 3 个 mismatch 失败语义。删除 iOS 特有 `8 total / 2 active`。

### 6.2 Singleflight

新增每实例、仅覆盖正在执行请求的有界 singleflight registry：

- 只有结构完全一致的合法 query 才合并。
- key 使用 canonical question，加上排除 transaction ID 后 `message[2..]` 的
  wire-semantics digest；RD/CD、EDNS DO/COOKIE/options 都参与，不能只按域名/qtype
  合并。
- 每个客户端仍保留自己的原始 transaction ID 和 response endpoint。
- leader 完成后为每个 waiter 重写 ID 并走各自有界交付路径。
- leader 运行在发起方 task 内；leader 被取消或 drop 时由 RAII 向 followers 广播
  Retry，followers 重新选举。当前实现不承诺“最后一个 follower 离开时主动取消
  leader”。
- singleflight registry 的总 waiter 仍受 128 个 client request permits 限制，因此
  不引入无限同问等待者。
- cache hit 不创建 singleflight entry。

### 6.3 Response parsing

把当前 `MAX_ANSWERS=16` 拆分为：

- 最多扫描 64 个 DNS answer/resource record。
- 最终 typed cache 最多保留 16 个地址。
- CNAME reachability、loop、compression 和 4,096-byte 当前 message 上限继续独立检查。

这样允许合法的多 answer/CNAME response，同时保持 retained address allocation 不变。
如后续需要扩大 TCP DNS message size，必须另立协议计划，不在本里程碑顺带修改。

### 6.4 Queue 隔离

- DNS response 和普通 UDP response 使用独立 bounded channel；DNS ingress 显式
  bounded 为 128，但两类 datagram 仍经过同一个 netstack UDP ingress receiver，
  因此不把当前实现描述为完整 ingress 隔离。
- 删除 `total_dns_queries × 4` 的 ingress 公式，显式使用 128；后续修改 DNS total
  时必须独立审查 queue 深度，禁止比例联动放大。
- DNS response queue full 只丢当前 response，并释放其 permit。
- 普通 UDP burst 不得耗尽 DNS response capacity；DNS burst也不得阻塞普通 UDP
  association 的 downlink。
- 不采用 Clash-RS 在唯一 UDP loop 中 inline await resolver 的串行模式。

### 6.5 Upstream 复用

首个业务修复版本不以连接复用为前置条件。完成 singleflight、128/8 admission 和队列
隔离后，再评估：

- 每 nameserver/route 复用 UDP transport 并进行 transaction ID demux。
- 显式 TCP nameserver 复用连接。
- 网络切换后使用可取消的有限重建、退避和抖动。

复用实现必须先证明 source/ID/question 校验、并发 response demux、stop cancellation 和
proxy route 隔离正确；否则保留每 attempt 独立 transport。

## 7. TCP、UDP 与 proxy transport

### 7.1 删除 iOS weighted pool

删除：

- 20-unit iOS user proxy transport pool。
- 4-unit iOS runtime-DNS proxy transport pool。
- 仅用于上述 pool 的 cost admission、permit wrapper 和 128 KiB/unit 总预算证明。

最多两个 proxy、最多两跳、128 TCP/64 UDP session、16 handshake 和各 protocol
buffer 仍然提供有限上界。极端两跳 transport 数可能高于旧模型，属于允许由系统内存
压力处理的场景。

不得用一个更大的隐藏 weighted pool 替换旧 pool；如果后续真机证明需要保护，应优先
缩小单 transport buffer、复用连接或回收 idle state，而不是再次在正常并发下 fail-fast。

### 7.2 TCP

- TUN netstack 最多 128 个 TCP session。
- 最多 32 个 half-open；达到容量后保留 bounded SYN state，不为同一 SYN 重复分配。
- outbound handshake 最多 16 个，TUN flow 在原有 15 秒 open timeout 内公平、可取消地等待。
- active session permit 随最终 relay 生命周期持有。
- 已建立 flow 不因新 flow 或内存 telemetry 被关闭。
- local HTTP inbound 保留自己的非 TUN admission 语义；本计划不自动把所有本地
  listener 改成等待。

### 7.3 UDP

- ordinary TUN UDP association 首版上限 64。
- idle timeout 从 60 秒调整为 30 秒，清理间隔不超过 10 秒。
- 每次 association 分配 generation，并持有独立 child cancellation；task completion
  只能删除同 source 的匹配 generation，evict/stop 先从 map 移除再 cancel；parent
  退出时 cancel 全部 child 并 drain completion 后才越过 stop barrier。
- 新 association 到达且 map 已满时：
  1. 同步清理已 expired state。
  2. 回收最久未活动且已经超过 10 秒 eviction grace 的 association。
  3. 仍无容量时才丢当前新 datagram，并增加限频 counter。
- 不得通过丢包刷新 association 活跃时间。
- 已存在 association 的 per-source queue 保持有限；full 只丢当前 datagram。
- DNS UDP/53 继续在普通 association admission 前进入专用 fast path。

## 8. 内存策略

### 8.1 删除控制流中的 footprint 失败

移除：

- prepare-entry lifetime peak 大于 45 MiB 时拒绝 scope。
- prepare/start 中因 task info 读取失败或 footprint 超限返回错误。
- start current 大于 35 MiB 时拒绝启动。
- 运行期每 100 ms 轮询并在大于 45 MiB 时停止 runtime。
- stop 成功后因 footprint 超限覆盖 stop 结果。
- 8 MiB post-start total model 和 35→45 MiB headroom 的硬证明。

### 8.2 保留 telemetry

保留 `TASK_VM_INFO` snapshot 与 `malloc_zone_pressure_relief`，但改成 best-effort：

- `prepare-complete`、`start-complete`、`stop-complete` 记录 current/peak。
- running 最多每 30 秒采样一次。
- 35、40、45 MiB crossing 只按 current footprint 判断，每档在进程内首次跨过时记录一次
  warning；不影响 runtime。
- Mach snapshot 同时记录 current 和 process-lifetime peak；不得把 lifetime peak
  描述为当前 TUN scope peak。单次 VPN 生命周期的 peak/plateau 只由 Release 真机外部
  trace 计算。
- 测量失败只记一次 warning，不影响任何方法结果。
- stop 后继续调用 allocator pressure relief。

telemetry 不增加新的 FFI API，先通过现有 Apple Unified Logging 输出。日志不得包含
目标地址、域名、payload、UUID、密钥或配置。

running runtime 的 pressure relief 只在 engine cancellation domain 完全 drop 后调用
一次；Prepared、prepare 失败或 start 尚未创建 engine 的路径由 controller cleanup
调用一次。telemetry 和 pressure relief 的成功或失败都不能覆盖 prepare/start/stop
的原始业务结果。

### 8.3 后续优化优先级

业务通过后按以下顺序降低常态内存：

1. DNS singleflight、cache hit 和 upstream transport 复用。
2. UDP idle/LRU 回收和短生命周期 state。
3. 减少重复 proxy graph、query wire 和 response buffer。
4. 调整 TCP/TLS/H2/XHTTP buffer，但必须先做吞吐和长肥网络回归。
5. 清理 TLS resumption、过期 cache 和 allocator free pages。
6. 最后才考虑降低并发；任何降低都必须有真机 high-water 证据，且正常场景不得触发。

## 9. 实施里程碑

### 9.1 2026-07-24 实际状态

本表只记录 2026-07-24 当时可确认状态；完整命令、revision、artifact hash 和未执行
边界见 `acceptance.md` 的“V6 历史 M6 host、互操作与产物证据”。这些记录不能作为
当前 V7 或 QUIC sniffer 的验证结果：

| 项目 | 状态 | 说明 |
|---|---|---|
| M0 diagnostics | 已实现 | typed resource error、共享 handshake 统计、DNS wait/join/cache 固定计数与稳定事件 |
| M1 memory policy | 已实现 | 删除 fail-closed/watchdog/activity 独占，保留 30 秒 best-effort telemetry 与 cleanup |
| M2 TUN profile | 已实现 | 平台无关 128/64/32/16 profile、8 MiB GeoData、删除 20/4 weighted pools |
| M3 DNS | 已实现 | 128/8 admission、bounded singleflight、共享 handshake 公平性测试、64-record/16-address、128/128 queue |
| M4 UDP lifecycle | 已实现 | generation/cancel、30 秒 idle、10 秒 cleanup/grace、expired-first/idle-LRU |
| M5 allocation | 已实现/有意暂缓 | XHTTP host/path/session `Arc<str>` 已合入；persistent DNS transport 暂缓 |
| 最终 host 全量 | `PASS` | 320 passed / 1 ignored；netstack 19；fmt、Clippy、header、TLS、shell 通过 |
| Xray 26.7.11 当前互操作 | `PASS` | 固定 revision/binary hash，TLS/REALITY × 两种 XHTTP mode 为 4/4 |
| Apple/Android 当前产物与 App 同步 | `PASS` | 构建、逐文件身份、App integration、iOS Release 与 Android AAB 通过 |
| iOS Release 物理设备 | `NOT RUN` | 已检测到无线 iPhone，但未执行 TUN、流量、30 分钟与 footprint 真机流程 |
| Android 物理设备 TUN/protect | `NOT RUN` | 当前无 physical Android |

当前记录固定 VCore HEAD `14da2d1a047cc5293d23e48a5a0d52027cdb2038`、rustls HEAD
`411fb0278820bbf81ac825b24823f31bed55190e`、App HEAD
`fadcec98ac1a5aa3e0a2c3235d6d910017f431c7` 与 `Cargo.lock` SHA-256
`6a0700beb3cf142364a6a052fcbf91b214ec558d488c69e76842782e9155b8f5`。最终 VCore/App
工作树 content manifest 的算法与 hash 记录在 `acceptance.md`；验收报告自身从 VCore
manifest 输入中排除，避免自引用。`NOT RUN` 不等于失败，也不能被交叉编译、模拟器或
历史结果替换为 PASS。

### M0：基线与回归样例

目标：在行为改变前把已知故障转成可重复测试和计数。

工作：

- 保存不含敏感信息的统计基线，不把原始用户日志提交仓库。
- 新增 80-request DNS burst 测试，证明旧 8/32 total 会拒绝。
- 新增 12 TCP + 8 UDP 单 VLESS 并发测试：用 barrier 保持前 20 个 transport 全部
  存活，再发送第 13 个 TCP，证明旧 20-unit pool 会拒绝第 21 个 transport。
- 新增 9 个普通 UDP source 测试，证明旧 iOS 8 association 会丢第 9 个。
- 为 DNS admission、singleflight、TCP/UDP session、handshake wait、queue drop 和
  association eviction 定义稳定 event/counter 名称；DNS upstream wait 次数/毫秒、
  singleflight join、cache hit 与 core-wide handshake current/peak/wait/reject 进入
  固定字段统计。
- 增加 typed `ResourceLimit { resource, limit }` 诊断，资源失败不得继续被压成通用
  `Other`；HTTP status 和 outbound 协议错误映射等外部 wire contract 保持不变。
- counter 使用随 runtime 销毁的固定字段 atomic，不使用动态 label map；首次拒绝立即
  记录、之后每 30 秒汇总、stop 输出最终 current/peak/reject/drop/eviction 总计。

通过条件：

- 测试能够稳定复现旧行为。
- 不改变发布数据面。

主要文件：

- `src/limits.rs`
- `src/resources.rs`
- `src/dispatch.rs`
- `src/error.rs`
- `src/dns/runtime.rs`
- `src/tun_runtime.rs`
- `src/platform/apple_logging.rs`

### M1：取消内存 fail-closed

目标：内存测量不再影响 VPN 生命周期。

工作：

- 从 `CoreInner` 删除 iOS memory baseline state。
- 从 prepare/start/runtime/stop/panic recovery 删除 footprint error propagation。
- 删除 100 ms memory watchdog。
- 保留 best-effort snapshot、低频 telemetry 和 allocator pressure relief。
- 把 30 秒 telemetry tick 放入既有 engine cancellation domain，不创建独立 shutdown
  task；首次 tick 从 start-complete 之后 30 秒开始。
- 删除 iOS TUN 对其他 active instance 的独占要求，只保留唯一 TUN lease和既有
  6-instance registry 上限。
- 提供平台无关的 telemetry policy 与可注入 snapshot provider，使 macOS host 能覆盖
  measurement error、任意 current/peak 和 threshold crossing；Apple cross-build
  不能替代该行为测试。
- 删除或改写所有 35/45 MiB failure-path tests。

通过条件：

- 任意 mock footprint 和 measurement error 都不改变 prepare/start/run/stop 结果。
- prepare/start 返回原始非内存错误；stop 保持 `transitioned.and(stopped)` 的非内存
  错误顺序；panic 仍返回 panic error。telemetry error 永不写入 `last_error`。
- 同一 registry 仍不能持有两个 TUN lease。
- 非 TUN 多实例、`measureDelay` 和 TUN instance 可遵守既有 6-instance 总上限。
- prepare/start/stop/panic 的所有成功、失败、取消路径继续释放 active count、TUN
  lease、fd 与 task；pressure relief 每条路径最多一次。

主要文件：

- `src/ffi/mod.rs`
- `src/platform/process_memory.rs`
- `src/platform/mod.rs`
- `src/limits.rs`
- `src/error.rs`

### M2：统一 TUN profile 并删除 weighted proxy admission

目标：消除当前日志中 8 UDP、16 TCP、2 handshake、20/4 weighted pool 的本地
业务拒绝源。

工作：

- 新增并启用第 5 节的 `ResourceLimits::tun()`。
- `for_runtime` 只按 `has_tun` 选择 profile。
- TUN MTU/max datagram 固定为独立的 raw-IP packet limit。
- GeoData allocation capacity 删除 iOS TUN 4 MiB 特化，恢复通用 8 MiB 结构安全上限；
  仍然只加载规则实际引用的 category。
- 删除 `ProxyTransportAdmission`、`ProxyTransportPool`、`ProxyTransportPermit` 和仅为
  pool 使用的 weighted cost wrapper。
- 保留 outbound graph 的协议组合与链路构造测试。
- TUN handshake 使用可取消等待；普通 local inbound 行为暂不扩大。

通过条件：

- 12 TCP + 8 UDP 并发不再被 20-unit pool 拒绝。
- 128 TCP/64 UDP 以内不因 VCore session/association admission 被拒绝；真实上游失败
  仍按原始网络错误报告。
- 第 129 TCP、第 65 UDP 等最终安全边界有确定、可观察的收敛行为。
- 单节点与四种 VLESS/SOCKS5 两跳 graph 行为不变。

主要文件：

- `src/limits.rs`
- `src/resources.rs`
- `src/dispatch.rs`
- `src/runtime.rs`
- `src/outbound/`
- `src/tun_runtime.rs`

### M3：DNS scheduler、singleflight 与 parser

目标：正常 DNS burst 不再触发本地 SERVFAIL。

工作：

- 实现 128 client request / 8 active upstream 两级 admission。
- 删除 iOS 8/2 和 4-unit DNS 特化。
- 删除 `TUN_DNS_INGRESS_BURST_PER_TOTAL_QUERY` 与 `total × 4` 推导，DNS ingress 和
  独立 response queue 均显式取 128。
- 实现 bounded singleflight。
- typed cache/hints 统一为 256。
- DNS ingress/response queue 各 128，并与普通 UDP response 隔离。
- 把 16-answer 限制拆成 64-record scan 和 16-address retention。
- 保留现有 timeout、retry、mismatch、failover、TUN TCP/UDP framing 与 lazy resolve
  语义。

通过条件：

- 80 个并发合法 TUN DNS client request 不出现 `runtime_dns_request_overload`。
- 相同 query 的 80 个 waiter 只产生一个 upstream exchange，每个 response ID 正确。
- 80 个不同 query 最多同时使用 8 个 upstream logical transport。
- 持续用户建连与 8 个 DNS upstream 并存时，16 个共享 handshake permit 保持有界公平，
  DNS 不因本地 permit 饥饿触发 3 秒 attempt timeout。
- 第 129 个 request 按稳定 emergency policy 收敛，无 panic、泄漏或永久占用 permit。
- 17–64 answer 的合法 response 可解析；超过结构上限仍被拒绝。
- cancellation、response queue full、stop 和 timeout 后所有 permit/singleflight entry
  归零。

主要文件：

- `src/dns/mod.rs`
- `src/dns/runtime.rs`
- `src/runtime.rs`
- `src/dispatch.rs`
- `src/tun_runtime.rs`
- `src/routing/dispatcher.rs`

### M4：UDP 生命周期与队列隔离

目标：QUIC/NTP/普通 UDP 不再因 8 association 正常触顶。

工作：

- association 上限 64。
- idle timeout 30 秒和至多 10 秒清理周期。
- 实现 expired-first、idle-LRU-second 的回收策略。
- 修正 drop/full 时的 activity 时间更新。
- 分离 DNS response、ordinary UDP response 和 raw packet queue。
- 增加 current/peak/eviction/drop counters。

通过条件：

- 64 个 source association 可并发创建和收发。
- 容量满时优先回收 expired/idle state，不关闭最近活跃 flow。
- queue full 不结束 UDP loop 或 TUN runtime。
- DNS burst 与 QUIC burst 互不耗尽对方保留队列。

主要文件：

- `src/tun_runtime.rs`
- `crates/vcore-netstack/`
- `src/session.rs`

### M5：复用与常态内存优化

目标：在 M1–M4 功能稳定后降低正常场景 footprint。

候选工作：

- DNS UDP/TCP persistent transport 和安全 response demux。
- cache/singleflight wire allocation 去重。
- XHTTP request template 的静态 host/path 与 packet-up session ID 使用 `Arc<str>`，
  每个 request/upload chunk 只 clone `Arc`，不重复分配 `String`。
- TLS resumption 和过期连接状态及时回收。
- 根据真机 trace 调整 TCP/TLS/H2/XHTTP buffer。
- 如果 netstack 支持，避免每连接预分配从未使用的最大 buffer。

通过条件：

- 每项优化独立提交并有功能、吞吐、取消和内存对比。
- 不通过降低正常并发、恢复 fail-fast pool 或关闭合法协议功能换取指标。
- 如果收益不稳定或复杂度过高，可以不合入，不阻塞 M1–M4 的业务修复。

当前决策：静态/会话字符串的 `Arc<str>` 去重已经合入并有 allocation-sharing 测试；
在取得真机 trace 前不宣称 footprint 收益。persistent DNS transport 经评估后暂缓，
原因是 ownership、transaction response demux、route isolation 与 stop cancellation
语义风险较高；暂缓不影响 M5 完成。

### M6：平台构建、App 同步与验收

目标：生成可真机验证的产物，并区分 host、模拟器和物理设备证据。

工作：

- 完成 host 全量验证。
- 构建 Apple XCFramework 和 Android arm64-v8a/x86_64。
- 先运行 App 侧集成检查，再以独立步骤同步产物。
- Android 模拟器只验证 JNI/非 TUN contract；Android TUN/protect 使用真机或明确标为
  未完成。
- iOS 使用 Release 真机、无调试器执行第 11 节场景。
- 保存 VCore/rustls revision、产物 hash、设备、iOS 版本、配置摘要、功能结果和
  footprint trace。
- 同步修改相邻 App 仓库的 `../OneVCore/docs/IOS_MEMORY_ACCEPTANCE.md` 及
  `../OneVCore/tool/ios_memory_acceptance.sh`：35/45 MiB 改为观测目标，脚本不得再把
  越线直接判定为 VPN 生命周期失败；保留原始 trace、PID 过滤和数值报告。

通过条件：

- 所有自动化和互操作通过。
- iOS 正常业务场景不再出现旧的 DNS/UDP/proxy pool 本地过载。
- App 使用的新产物身份与源码 revision 对应。
- 文档只把真正执行过的设备测试写成已通过。

## 10. 自动化验证

每个有代码变更的里程碑至少运行：

```bash
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
./scripts/check_tls_dependencies.sh
sh -n scripts/*.sh tests/run_xray_interop.sh
```

涉及 VLESS、TLS/REALITY、XHTTP、dispatcher 或 transport lifetime 的里程碑还必须运行：

```bash
XRAY_BIN=/path/to/xray tests/run_xray_interop.sh
```

互操作基线固定为 Xray 26.7.11、revision
`50231eaff98ccc31b5cbd247a721c16e97fe5ec1`，并记录实际 binary hash；升级基线必须
另立变更记录。真实 GeoData ignored test 必须携带明确资产单独运行，普通测试输出中的
`ignored` 不能算通过。

M6 还必须执行平台构建和 App 侧产物身份检查：

```bash
./scripts/build_apple.sh
./scripts/build_android.sh

cd /Users/yiguo/work/vpn/OneVCore/OneVCore
./build_scripts/check_vcore_apple_integration.sh
./build_scripts/check_vcore_android_integration.sh
./build_scripts/sync_vcore_apple.sh
./build_scripts/sync_vcore_android.sh
./build_scripts/check_vcore_apple_integration.sh
./build_scripts/check_vcore_android_integration.sh
flutter build ios --release
flutter build appbundle --release
```

同步动作与检查动作分开执行；报告必须记录 VCore/App revision、工作树 diff hash、
`Cargo.lock`、Xray binary、XCFramework、Android `.so` 和最终 App 产物的 SHA-256。
缺少真机、trace 或真实服务端的项目统一标为 `NOT RUN`，不能以交叉编译、模拟器或历史
结果替代。

baseline 与 candidate 必须使用相同设备、系统、服务端、配置、流量脚本和随机种子。
每一道门禁只允许 `PASS`、`FAIL`、`NOT RUN` 三种结果；ignored test、缺失 trace、
只构建未运行或使用旧 artifact 一律不能记为 `PASS`。

覆盖：

- TLS/REALITY × `packet-up`/`stream-one`。
- VLESS TCP/XUDP。
- SOCKS5 outbound CONNECT/UDP ASSOCIATE。
- 四种两跳组合的 graph/lifetime。
- 6 实例与 6 Invoke 并发。
- `measureDelay` 成功、超时、失败和清理。
- Apple/Android TUN fd adapter、Android protect 和重复启停。

## 11. iOS Release 真机验收

### 11.1 正常业务场景

最低场景：

1. 冷启动并启动 VPN。
2. Safari/系统 WebView 连续打开 IPv4/IPv6 网站。
3. Google 搜索、YouTube 或其他同时使用 TCP/QUIC 的服务。
4. 并发触发至少 80 个 DNS query，包含 A、AAAA 和非 A/AAAA。
5. UDP/443、UDP/123、TCP/443、TCP/853。
6. Wi-Fi 与蜂窝切换、断网后恢复。
7. 前后台切换。
8. 连续运行至少 30 分钟。
9. 停止、再次启动，至少循环 20 次。

必须满足：

- DNS burst 不出现旧的 `limit=8` overload。
- 不出现 20-unit proxy pool failure。
- 普通业务不出现 `max_udp_associations=8` drop。
- TUN runner 不因瞬时 queue full 退出。
- VPN 停止后可再次启动，无 lease/fd 泄漏。
- Google、普通网页、QUIC 和显式 TCP 流量可用。

### 11.2 内存观测

- 记录冷启动 current、正常业务 peak、30 分钟 plateau、stop 后 plateau。
- 35/45 MiB 只用于目标对比。
- 正常业务超过 45 MiB 不判功能失败，但 M5 内存优化保持未完成并记录主要占用来源。
- 不得通过恢复 8/20 等低并发上限让数字下降后宣称完成。

### 11.3 极端压力

至少覆盖：

- 超过 128 个 DNS client request。
- 接近/超过 128 TCP、64 UDP 和 16 simultaneous handshake。
- 大量不同 qname/qtype、重复 query、取消和超时。
- 长时间 QUIC/UDP association。
- GeoData 与 DNS/连接压力同时存在。

允许：

- 超过最后安全容量后有明确 SERVFAIL/UDP drop/session rejection。
- footprint 超过 45 MiB。
- iOS 在极端情况下终止 Extension。

不允许：

- 数据错配、DNS response ID/endpoint 错误。
- 已取消 query 占用 permit。
- runtime 死锁、panic 或停止后无法重启。
- 把系统终止伪装成正常 stop 或声称压力测试全部通过。

## 12. Android 与 macOS 回归

统一 TUN profile 会影响所有 TUN fd 平台，因此不能只验证 iOS：

- macOS：TUN TCP/UDP/DNS/ICMP、重复启动停止、HTTP probe/measureDelay 并行回归。
- Android：arm64-v8a/x86_64 构建、JNI、protect、TUN TCP/UDP/DNS/ICMP。
- Android 模拟器通过不代表物理 TUN/protect 通过，验收文档必须分开记录。
- 非 TUN App 进程中的 6 实例测速继续使用非 TUN default profile。
- Windows/Linux 的 unsupported gate 不因本计划变化。

## 13. 可观测性

新增或保留以下稳定限频事件，不增加敏感字段：

- `tun_resource_high_water`
- `tun_tcp_session_rejected`
- `tun_udp_association_evicted`
- `tun_udp_association_rejected`
- `tun_packet_queue_drop`
- `tun_udp_response_drop`
- `runtime_dns_request_overload`
- `runtime_dns_singleflight_reject`
- `runtime_dns_singleflight_join`
- `runtime_dns_cache_hit`
- `runtime_dns_upstream_wait`
- `runtime_dns_response_drop`
- `resource_tcp_session_reject`
- `resource_udp_association_reject`
- `resource_handshake_reject`
- `resource_handshake_wait`
- `resource_stats_periodic`
- `resource_stats_final`
- `tun_netstack_stats_periodic`
- `tun_netstack_stats_final`
- `runtime_dns_tcp_pool_final`
- `ios_memory_snapshot`
- `ios_memory_observation_target_crossed`
- `ios_memory_measurement_failed`

首次事件按对应类型立即输出；`resource_stats_periodic` 最多每 30 秒一次，
`resource_stats_final` 在 stop/drop 收敛时输出。摘要使用固定字段，包含 DNS、
singleflight、TCP、UDP 与 handshake 的 `current`/`peak`/`rejects`/`limit`/wait，
以及 `singleflight_joins`、`dns_cache_hits`、`dns_upstream_waits`/
`dns_upstream_wait_ms`、queue drop 和 association eviction。单个事件只携带适用字段，
不要求每条都同时出现 `current`、`peak`、`limit` 和 `wait_ms`。不得记录目标 IP/域名、
DNS question、payload、UUID、密钥或配置内容。DEBUG/TRACE 的 Apple 日志限流不应吞掉
WARN 级业务拒绝计数；高频事件使用周期聚合而不是逐次 WARN。

## 14. 文档迁移

当前公共文档已迁移到业务优先契约；旧行为只允许保留在明确标记日期与“历史快照”的
段落中。各里程碑对应的迁移范围如下：

### M1

- `README.md`
- `docs/README.md`
- `docs/invoke-api.md`
- `docs/acceptance.md`
- `docs/geodata.md`
- `docs/rustls-reality-plan.md`

删除 35/45 MiB hard gate、历史 peak 拒绝和 100 ms watchdog 的当前契约；改成 telemetry
目标和极端系统终止边界。

### M2

- `README.md`
- `docs/README.md`
- `docs/invoke-api.md`
- `docs/acceptance.md`
- `docs/geodata.md`

替换 iOS 16/8/2、20/4 unit、7,640,960-byte model 和 registry activity 独占描述。

### M3–M4

- `README.md`
- `docs/README.md`
- `docs/config.yaml`
- `docs/tun-icmp-dns.md`
- `docs/invoke-api.md`
- `docs/acceptance.md`
- `docs/geodata.md`

替换 8/2、32 ingress、260,992-byte fast-path、16-answer 和普通 UDP=8 等当前描述。
`config.yaml` 只更新注释，不新增用户配置字段。

### M5–M6

- `docs/acceptance.md`
- 本文状态和实测记录
- App 的 `../OneVCore/docs/IOS_MEMORY_ACCEPTANCE.md`
- App 的 `../OneVCore/tool/ios_memory_acceptance.sh`

只记录实际执行的命令、设备和结果；35/45 MiB 在两个仓库中都必须统一为观测目标，
不能让 App 脚本继续维持已废弃的 hard PASS/FAIL 契约。

## 15. 提交、回滚与风险控制

### 15.1 提交边界

M0–M6 分开提交。行为变更、文档同步和对应测试放在同一里程碑提交中；平台产物同步使用
独立提交，便于回滚二进制而不丢失源码诊断。

### 15.2 回滚原则

- M1 以后不得通过恢复 35/45 MiB fail-closed 解决数据面问题。
- M2 以后不得通过恢复 20/4 weighted pool 解决内存问题。
- M3 以后如果 128-request scheduler 有问题，可单独回滚 singleflight/scheduler，
  但不能无证据恢复 iOS 8/2。
- 内存异常优先回滚最近的 buffer/复用优化，或缩短 idle/cache 生命周期。
- 如正常场景发生系统终止，先定位 retained state 和 per-object buffer；最后才调整并发，
  且必须保留能够通过正常业务场景的下限。

### 15.3 主要风险

| 风险 | 控制 |
|---|---|
| 删除 guard 后正常场景被 iOS 终止 | 真机连续 footprint trace；先优化 retained state 和 buffer |
| DNS singleflight response 错配 | canonical wire key、per-waiter ID、endpoint 与取消测试 |
| 128 request 导致 upstream 放大 | active=8、singleflight、cache、顺序 nameserver failover |
| 删除 weighted pool 后两跳 transport 增长 | session/handshake 上限、per-transport bounded buffer、真机 high-water |
| UDP LRU 误杀活跃 QUIC | expired-first、idle grace、最近活动保护与确定性测试 |
| 统一 TUN profile 影响 Android/macOS | 每个里程碑交叉构建，M6 设备回归 |
| telemetry 影响性能或泄露数据 | 30 秒低频采样、限频聚合、无目标/问题内容 |

## 16. 完成定义

本计划完成必须同时满足：

- M1–M4 实现和自动化全部通过。
- Xray-core 真实互操作保持通过。
- Apple/Android 产物成功构建并通过 App 集成检查。
- iOS Release 真机完成正常业务、30 分钟、网络切换和重复启停。
- 正常业务不再触发旧的 DNS 8、UDP 8、proxy 20-unit 本地拒绝。
- 已记录正常 current/peak/plateau；35/45 MiB 只作为优化结果，不控制业务结果。
- 极端压力的系统终止、拒绝或丢包边界有如实记录。
- 所有公共文档与最终实现一致。
- 本文状态更新为“已实施”，并列出 VCore revision、产物 hash 和仍未完成的真实设备项。

## 17. 首个开发批次（历史顺序）

实际开发的第一批严格限制为 M0 + M1：

1. 添加已知 overload 的回归样例和稳定计数。
2. 移除内存 fail-closed、35 MiB start gate 和 100 ms watchdog。
3. 保留唯一 TUN lease、telemetry 和 allocator pressure relief。
4. 同步 M1 文档。
5. 完成全量 host 自动化与 Apple/Android 交叉构建。

M0 + M1 通过后再进入 M2，避免同时改变生命周期、session admission、DNS scheduler 和
UDP map，确保任何回归都能定位和独立回滚。

## 18. 2026-07-25 历史后续批次：资源观测与 TCP DNS 复用

本节记录 M0–M6 之后、被第 0 节再次替代的候选决定和实现；与前文的历史里程碑
编号无关。

### 18.1 平台边界

- 删除“Apple DIRECT 独立出站/物理接口绑定”阶段。Apple Packet Tunnel 的出站路由由
  Network Extension 处理，VCore 不新增 `IP_BOUND_IF`、`IPV6_BOUND_IF`、interface
  index、网络变化回调或 Apple-only DIRECT 分支。
- 本批不修改 `ResourceLimits::tun()` 数值：TCP 128、ordinary UDP 64、half-open 32、
  handshake 16、DNS client request 128、aggregate live upstream transports 8。
  是否调整这些上限必须以新的 Release iOS 真机 high-water/footprint 证据为依据。

### 18.2 P0：资源可观测性

- netstack stats 新增 active TCP 与 half-open TCP 的 lifetime peak；stop 后 current
  必须归零，peak 保留到 stats owner 释放。
- TUN runtime 持有 stats handle，每 30 秒输出 `tun_netstack_stats_periodic`，在
  netstack stop 和 tracked task drain 之后输出 `tun_netstack_stats_final`。
- 两个事件使用固定字段：active/half-open current/peak、rejected TCP、UDP drops、
  invalid packets、ICMP replied/dropped；不记录目标、域名、DNS question 或 payload。

### 18.3 P1：显式 TCP nameserver 有界复用

- UDP DNS 继续 request-scoped，不做跨 query socket 复用。
- 每个 `RuntimeDns` 独立维护 TCP pool；key 为 nameserver endpoint + 最终解析后的
  `Single`/`DIRECT`/proxy id。`#RULES` 必须先求值，防止不同物理出口错误共用连接。
- 单连接单 query，无 pipeline、无 DNS ID multiplexer。生产物理 ceiling 绑定现有
  aggregate upstream 8；默认 idle 总数/单 key 为 4/2，idle 30 秒。较小 ceiling 使用
  `min(4, ceiling - 1)`，至少为非 idle transport 保留一个名额。
- pool 保留同一份 combined admission；共享 8 路满载时，新 UDP 或 fresh TCP 会先在
  锁内摘除 expired/最老 idle TCP，再在锁外 drop 并释放 permit。expired 回收累计
  `idle_expirations`，压力下的 LRU 回收同时累计 `idle_evictions` 和
  `admission_pressure_evictions`，避免 4 idle TCP + 4 active UDP 造成可避免的超时。
- 只有完整 framing 与 typed/opaque response 校验成功的连接才能 check-in。复用连接的
  EOF/I/O/reset/response mismatch 在原 attempt deadline 内只 fresh retry 一次；
  malformed、truncated、oversize 丢弃且不重试。合法 SERVFAIL/REFUSED 可归还后再执行
  顺序 nameserver failover。
- idle reaper 每个 pool 至多一个 task，使用 weak ownership，并由 pool drop 立即取消；
  过期、LRU eviction、runtime drop 均在 mutex 外释放 stream 和 session permit。pool 释放时输出
  `runtime_dns_tcp_pool_final`，包含 physical/busy/connecting/idle current/peak，以及
  open/reuse/stale-retry/wait/discard/expiration/eviction/admission-pressure-eviction
  计数。

### 18.4 下一验收阶段

Host 单测、Clippy、Apple cross-check 只能证明边界和可构建性。下一步必须在 Release
iOS 实机分别记录：

1. 只有 UDP nameserver、只有 `tcp://223.5.5.5`、UDP + TCP policy 混合三种配置。
2. 冷启动、连续访问 `baidu.com`/Apple/中国域名、30 分钟运行、网络切换和重复启停。
3. `tun_netstack_stats_*`、`runtime_dns_tcp_pool_final` 与既有 resource stats 的
   current/peak/wait/reject/drop，以及 35/40/45 MiB footprint telemetry。
4. DNS 成功率、TCP reuse/stale retry、业务 TCP/UDP high-water 和系统终止情况。

在这些证据取得前，不调整 128/64/32/16/128/8，也不宣称 iOS 数据面或 footprint
问题已经解决。
