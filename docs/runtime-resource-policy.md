# Runtime 资源策略

状态：当前策略。所有Apple/Android TUN fd runtime使用同一组局部结构边界；VCore不以业务flow总数或整进程内存读数拒绝正常业务。本文不记录已退役资源模型。

## 1. 原则

1. 数据正确性、安全边界和同步Stop优先。
2. Queue、buffer、cache、wire/parser size、timeout和idle cleanup保持有界。
3. TCP session、普通UDP association、half-open、outbound handshake和active DNS transport不设置固定业务总数。
4. Queue full按协议语义局部丢弃或失败，不阻塞TUN callback或全局loop。
5. Current/peak统计只用于诊断，不参与admission。
6. iOS内存采样是best effort；读取失败或超过优化目标不改变VPN lifecycle。

## 2. 当前TUN profile

```text
raw packet / MTU                 1,500 bytes
final proxy UDP payload          1,452 bytes
packet queue                     256
ordinary event / UDP response    128
DNS ingress / DNS response       128 / 128
TCP buffer                       32 KiB per direction
TLS / XHTTP buffer               64 KiB
DNS typed cache                  256 entries
DNS opaque cache                 64 entries / 256 KiB
TUN domain hint store            256 entries when enabled
GeoData allocation capacity      8 MiB
```

- DNS response和ordinary UDP response使用独立queue，但仍共享netstack ingress receiver。
- TUN domain hint store只在TUN + domain-rule scope内创建，从空容量按需增长。
- ICMP reply使用现有raw egress queue，不增加task或长期状态。
- 每项扩容前执行checked arithmetic和局部预算检查。

## 3. TCP 与 handshake

- TCP flow按需创建task。
- 每方向buffer固定32 KiB；TLS/XHTTP内部buffer固定64 KiB。
- Half-open、outbound handshake和active session只记录current/peak，不触发资源错误。
- Timeout、cancel、EOF和protocol error负责收敛；Stop必须等待tracked task结束。
- Bootstrap resolver最多4个worker thread；全部忙时在调用方既有deadline内等待，不返回人为资源上限错误。

## 4. UDP

普通TUN UDP association：

- Map不设固定项数。
- 每association ingress queue有界，full只丢当前datagram。
- 使用generation-aware completion和child cancellation。
- Idle timeout 30秒，cleanup周期10秒。
- Cleanup先从map删除，再cancel child。
- 只有成功入队的request或response刷新activity；drop不刷新。
- Parent停止时删除、cancel并drain全部child。

嵌套proxy wire可以为header增加有界余量，但最终解封装payload仍不得超过1,452 bytes。

## 5. DNS

- 不设置固定client-request或aggregate live-transport permit。
- Cache miss使用同key singleflight；leader取消后followers重选。
- UDP transport保持request-scoped，同一attempt重发复用当前transport。
- 显式TCP nameserver按endpoint + 最终egress复用；一条连接只处理一个query。
- Active TCP不设固定上限；idle总数/单key为4/2，idle timeout 30秒。
- Query/attempt/UDP resend deadline固定为5秒/3秒/1秒。
- Response最多扫描64条record，typed cache/hint最多保留16个唯一IP。
- Stop取消open/send/receive/retry和response send，并释放全部transport。

完整语义见 [`tun-icmp-dns.md`](tun-icmp-dns.md)。

## 6. GeoData

- GeoSite与GeoIP共享8 MiB allocation capacity。
- Loader只解析被引用分类，未选分类按wire length跳过。
- Matcher使用紧凑连续存储，运行期匹配不分配。
- Regex source、编译预留和retained DFA均有独立上限。
- Asset缺失或更新失败按种类降级，不阻塞prepare/start。
- Release iOS整进程内存不能由GeoData内部ledger替代。

完整边界见 [`geodata.md`](geodata.md)。

## 7. iOS telemetry

VCore通过Apple `TASK_VM_INFO` best effort记录：

- current physical footprint；
- process lifetime peak；
- current首次跨过35、40、45 MiB的限频事件；
- running期间最多每30秒一次采样。

规则：

- Measurement failure只记录一次warning。
- Telemetry不写入`lastError`。
- 读数不改变prepare、start、running、stop或panic recovery结果。
- Cleanup后的allocator pressure relief同样是best effort。
- 35 MiB cold-start current和45 MiB representative-workload peak是优化目标，不是hard gate。
- 极端压力下允许OS终止extension；VCore不以预测模型提前拒绝业务。

## 8. 日志与观测

Runtime保留：

- TCP、half-open、UDP、handshake和DNS current/peak；
- singleflight join、cache hit；
- queue drop/closed；
- TCP pool idle/expiration/eviction；
- invalid packet、ICMP reply/drop；
- session stop后的final counters。

日志必须有界、脱敏，不记录目标、DNS question、UUID、credential、key、payload或完整配置。

## 9. 验收

Host automation必须覆盖：

- 刚好命中queue/cache/wire上限和下一项失败；
- 超过曾经固定flow阈值后仍按需工作；
- Cancel命中open/send/receive/retry/response-send；
- Repeated prepare/start/stop无task、fd、queue或matcher增长；
- Queue full只影响当前packet/flow；
- Stop后无detached task或回包。

Release iOS真机必须在无debugger条件下记录：

1. Cold start。
2. Representative TCP/UDP/DNS workload。
3. 长时间plateau。
4. Explicit Stop后的回收。
5. 极端pressure下的OS行为。

Android与macOS继续验证TUN、DNS、proxy chain、cancel和重复启停。实际执行状态见 [`acceptance.md`](acceptance.md)。

## 10. 变更规则

新增全局admission、可配置容量或长期缓存前必须：

1. 证明现有局部边界不足。
2. 定义owner、上限、取消和Stop语义。
3. 增加刚好命中上限与越界测试。
4. 记录host与对应物理平台证据。

没有测量证据时，不增加新的资源控制层。
