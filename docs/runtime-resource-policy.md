# 运行时资源策略

所有 TUN 运行时使用同一组局部结构上限。VCore 不根据业务流总数或整进程内存读数拒绝正常流量；容量控制放在包、队列、缓冲区、缓存、解析器和生命周期所有者处。

## 原则

1. 数据正确性、安全边界和同步停止优先。
2. 数据面队列、缓冲区、缓存和解析器保留局部容量边界；空闲资源必须有回收机制。容量界与时间回收不是同一保证。GeoData 不设内存预算，只有 iOS/tvOS 的所选 GeoIP 原始 CIDR 与 GeoSite 原始 Domain 共用 1,280,000 条总保留额度，优先保留 GeoIP。
3. TCP 会话、普通 UDP 关联、半开连接、出站握手和活动 DNS 传输不设置固定业务数量上限。
4. 队列满时按局部协议语义丢当前项目或失败，不能阻塞 TUN 回调或全局循环。
5. 当前值和峰值只用于诊断，不参与 admission。
6. 平台内存采样是尽力而为的遥测，不改变生命周期结果。

长期业务引擎（FFI 的 TUN / 非 TUN 及 Windows Session Host）统一使用
Tokio `new_multi_thread()`，不按 TUN 分叉，不自行读取 CPU 数或设置 worker 数。
worker 数遵循 Tokio 默认行为（包括其 `TOKIO_WORKER_THREADS` 环境覆盖）；
线程栈使用 Tokio / Rust 默认值，不固定为 1 MiB。
短生命周期的 `prepare` / `measureDelay` 保留共用的单线程执行策略，不按 TUN 分叉。
工作线程（含阻塞任务线程）继承 Invoke 重入保护，
Apple 平台另保留线程局部日志作用域；同步停止仍等待子任务与运行时线程退出。
Release 构建优先吞吐（`opt-level = 3`），保留 thin LTO 与现有缓冲、队列边界。

## TUN 结构上限

```text
原始包 / MTU                    1,500 字节
最终代理 UDP 负载               1,452 字节（Windows 1,352）
包队列                          256
普通事件 / TCP accept           128
每关联 UDP 入站                 64
普通 UDP 响应                   4,096
DNS 响应                        128
每个 TCP 方向缓冲区             32 KiB
TLS / XHTTP 缓冲区              64 KiB
DNS 类型化缓存                  256 项
DNS 原始响应缓存                64 项 / 256 KiB
TUN 域名提示                    256 项（按需）
```

Windows L3 接口及其 Session Host netstack 使用 1400 MTU，因此按 IPv6 UDP 头保守计算的响应负载上限是 1352；表中的 1500 是跨平台原始包解析上限和其他 TUN 平台的固定 MTU。

- 普通 UDP 在 reader 同步分流并直接提交到每源关联，不经过 TCP Driver 或共享 UDP 入站队列；DNS 查询独立提交受跟踪任务。
- 每关联请求、普通响应和 DNS 响应使用独立内部容量，不扩大 128 项的 TCP accept，也不增加公开配置字段。
- TUN 域名提示只在 TUN 配置实际包含域名规则时创建，并从空容量按需增长。
- 域名提示的读写使用短同步锁，临界区内不等待 IO 或执行异步操作；新 TUN IP 流读取当前提示，活动 UDP 五元组保持既定 action。
- ICMP 响应复用原始包出站队列，不创建独立任务或长期状态。
- TUN 读写每批最多处理 8 个已就绪包，不等待凑批。复用至多 8 个 1500 字节读缓冲区；
  唯一 writer 公平轮转 TCP/ICMP raw、普通 UDP/DNS 响应三通道，至多暂持 8 包，
  UDP 在复用 MTU frame 中构包，不增加中转队列。非法输出也计入工作预算。批次中途取消或
  失败仍按已完成结果逐包统计；非法包局部隔离，Unix 系统调用保持单包边界。
- 有局部预算的结构在扩容前检查额度；GeoData 保留整数可表示性、实际分配失败检查，以及 iOS/tvOS 的所选原始 CIDR + Domain 总记录计数边界。

## TCP 与握手

- TCP 流按需创建任务，每方向缓冲区固定为 32 KiB。
- rustls/XHTTP 的配置缓冲区为 64 KiB；boring 每次应用写入最多 min(节点缓冲预算, 16 KiB)，原生 TLS 记录有界，命名模板证书消息/解压输出另限 128 KiB。
- 标准 TLS 恢复会话总预算为 4，按节点（含独立下载端点）分配；每个缓存绑定不可变的 SNI、ALPN 和证书策略，绝不跨节点复用。TLS 1.3 票据有界、一次性消费，TLS 1.2 会话占用同一额度；额度为 0 则禁用恢复。REALITY 不参与该缓存。
- 共享 TLS 客户端的显式验证名、协议版本、客户端证书身份和 ClientHello profile 也属于不可变策略，单独构造缓存，不跨身份共享。boring 只保存当前节点/SSL 上下文产生的票据，应用层 ALPN 接受前不发布，失败或取消丢弃临时票据。标准 TLS 和 REALITY CloseWrite 只发送 close_notify，刷新最多5秒，保持读方向和底层传输；Drop 释放整个流。XHTTP 仍以逻辑连接整体关闭为准。
- 半开连接、出站握手和活动会话只记录当前值和峰值，不触发资源错误。
- 超时、取消、EOF 和协议错误负责回收；停止必须等待全部已跟踪任务结束。
- 引导解析器最多使用四个工作线程；全部忙时在调用方既有期限内等待，不返回人为容量错误。

### 物理 socket 初始化

TCP/UDP 共用 Dialer：创建 socket、nonblocking、源地址/Windows 接口绑定与 protect
在当前 Tokio runtime 的受跟踪阻塞任务中完成，避免 FD 表扩容等同步系统调用占满
业务 worker。异步 connect、reactor 注册与收发仍在原 runtime，不新增独立线程池、
CPU 数判断、业务数量配额、FD 预热或 DNS socket 复用。

取消关闭结果接收器并跳过尚未开始的初始化；已开始的系统调用或同步 protect 不能
强制中断，完成后丢弃未交付的 socket。每个 Running Session/测速图拥有独立的
初始化作用域。Stop 先关闭 admission，再取消并等待业务/协议任务，最后等待已登记
初始化任务完成，才释放平台回调租约。测速 runtime 的销毁也使用完整 join，不能
以有限 shutdown timeout 脱离在途初始化。protect 仍必须快速、同步、非阻塞；
线程位置变化不放宽宿主回调契约，也不改变保护失败关闭或 Windows 双绑定策略。

## 共享流传输基础

`stream-transport` 仅包装传入 IO，不创建 socket 或 DNS。WS/HTTP响应首部最多16 KiB、100字段；WS用户请求头最多100字段，额外固定升级头和early-data仍计入16 KiB总预算。WS early-data最多2,048原始字节，头名称/路径后缀由类型化选项区分。WS消息和单帧最多64 KiB，写入切块16 KiB；HTTP首包正文直接写入，不整体复制或持续按HTTP正文定界。

共享的无池gRPC/legacy H2适配器每个实例仅拥有一条底层连接与一个逻辑流，不是全局并发许可；VLESS另有下文描述的节点级gRPC池。流窗口64 KiB、连接窗口128 KiB、最大HTTP/2帧和发送缓冲各16 KiB、解码负载64 KiB。读侧按实际消费量释放窗口；每poll最多处理32个片段/控制消息。原有gRPC和legacy H2的shutdown关闭整个逻辑连接；Trojan使用独立duplex模式，仅发送END_STREAM并保留读取。关闭前已接受的数据须到达所提供IO的flush边界，不能仅排入h2队列后立即reset/abort；每个逻辑写端最多一个待确认数据块，Stop可取消等待。两种模式的owner.stop都等待驱动任务退出；Drop只做取消兜底，不作为同步停止通过证据。WS/HTTP适配器按底层CloseWrite语义工作，协议包装层可以根据Mihomo契约结束整个逻辑流。所有握手使用调用方同一个绝对deadline。

XUDP现在只拥有已认证流上的帧编码；VLESS响应头由VLESS包装层处理。元数据仍最多512字节，单payload仍受调用方预算和u16 wire上限约束，不新增全局会话额度。

## 协议局部预算

协议专用上限与关闭语义只维护在[入站](inbounds.md)、[出站](outbounds.md)、
[VLESS](vless.md)和[XHTTP/sing-mux](xhttp.md)。`tests/protocols/limits.json`
绑定实际常量与越界用例，不是第二套运行时配置或可配置业务准入数。

## UDP

普通 TUN UDP 关联：

- 关联表不设固定项数；
- 每个关联的入站队列最多 64 项，满时只丢当前数据报，不等待慢关联并阻塞其他来源；
- 普通响应队列最多 4,096 项，满时只丢当前响应；没有共享 UDP 入站中转队列；
- reader 拥有关联表和入站分发，唯一 TUN writer 直接、公平消费普通/DNS/TCP raw 三个通道；写回等待不阻塞 reader，不增加逐关联写回任务；
- TCP/ICMP ingress 满时非阻塞丢当前完整 IP 包，避免阻塞 UDP/DNS，记录 packet queue drop；TCP 重传恢复，不引入 pending FIFO；
- 使用代次感知所有权和子取消令牌；
- 空闲超时 30 秒，清理周期 10 秒；
- 清理时先从表中删除，再取消子任务；
- 只有成功入队的请求或响应刷新活动时间；
- 源关联内的 IP 五元组仅保留规则 action、活动时间和可选 QUIC 连接标识，
  不创建逐流任务、队列或 socket；不设流数量上限。各目标独立 30 秒空闲失效，
  关联收发时最多每 10 秒扫描回收并收缩明显过大的表容量；关联关闭释放整个表。
  响应只刷新自身已存在且未过期的目标，不创建状态或复活过期流。
  五元组活动以接收请求或读到匹配出口响应为准；源关联仍只以成功入队刷新，
  响应队列满不会延长源关联所有者的生命周期。
- reader EOF、错误或取消时，先取消其 UDP 子作用域，再删除、取消并等待全部关联和 DNS 任务；父运行时统一取消并等待唯一 writer 与 netstack。UDP 子作用域停止不取消调用者令牌。

### 高吞吐优化边界

普通响应的 4,096 项是所有 TUN 平台共用的内部默认值，用于吸收收包任务与唯一
writer 之间的短时突发。Linux NAT 的无热路径探针 Release 容量对照支持从
1,024 项扩大至此值；它不是逐关联容量、业务并发配额或无损吞吐保证。
相对原值，多出的 3,072 项在 1,452 字节负载下最多多持有 4,460,544 字节
payload，另有元数据与分配器开销；实测 RSS 增量不能作为最坏内存上界。

已采用分类二分定位、TUN UDP 五元组 action 复用、reader 直接分流、单 writer
三通道公平轮转和已就绪批次处理。netstack 每批执行维护，沿用单个待处理 RX 包
和原有 TX 队列，不增加重复中转队列。每关联容量、DNS 保留容量、socket 缓冲、
批次大小和线程策略不随普通响应容量扩大；队列 Full 不等待、重试或刷新源关联活动。

剩余丢包必须分别核对 VCore 队列、内核 TUN、物理出口和客户端 socket，不能以
内部 drop 为零推断端到端无损。2 Gbps UDP 叠加 DNS 的端到端无损目标仍未通过。
Linux TUN `txqueuelen` 属于宿主网络配置，VCore
不修改借用接口的队列长度或 qdisc。扩大宿主队列的实验结果不能直接推广到其他
平台；Linux 吞吐与 RSS 结果也不替代 iOS/tvOS physical footprint 或真机验收。
诊断计时探针、强制让步、Full 后重试和无协作预算发送不属于生产优化策略。

嵌套代理协议可以增加有界帧头，但最终解封装负载仍不得超过调用方按有效 MTU 给出的上限；其他 TUN 平台为 1,452 字节，Windows 为 1,352 字节。

### 定向数据报预算与受控 QUIC

`DatagramBudget` 分别表达当前层的发送和接收 payload 上限。嵌套协议先为下层申请有界 envelope 空间，再按实际协议/地址族开销扣除下层能力，与调用方预算取交集；不能把接收上限直接当作发送能力。DIRECT、SOCKS5、SS 2022、SS/AnyTLS UoT 和 VLESS XUDP 保留对端/地址校验。超出发送预算在写入前失败，超出接收预算丢当前包并有界让出执行权，close 后不能恢复收发。UoT 的流头不从 UDP payload 预算扣除；SS 首包门控、读取任务与单响应队列的局部上限见[出站](outbounds.md#udp-over-tcp-v2)。

`quic-transport` 只把已有 `DatagramTransport` 适配成 Quinn 的受控 UDP 接口，没有内部 bind、DNS 或 DIRECT 回落。每个连接双向各最多32个排队数据报，另允许一个正在发送的包；TX满返回WouldBlock，RX满暂停读取。接收等待不会持有发送队列锁；Pending发送不会重复提交。单逻辑peer/物理peer映射和来源校验独立保留，不接受未请求的目标、GSO或源地址覆盖。物理 socket 仍只能来自 Dialer。

QUIC双向可用payload至少1,200字节；endpoint必须显式把QUIC MTU限制在有效预算内。IPv4/IPv6路径MTU分别先扣除28/48字节IP+UDP头，边界和单字节不足均有定向测试。

QUIC owner.stop先取消并等待驱动，再关闭并释放上游；上游close最多1秒。Driver Drop仅为取消/abort兜底，不能作为同步Stop验收。队列容量是单连接局部界限，不是全局QUIC连接准入数。

TUIC 与 Hysteria2 共用这一接点；TUIC 的独立会话、关联 ID 退役、控制流、分片负载
及交付队列边界见 [TUIC v5](outbounds.md#tuic-v5)。旧池的待建流也持有所有权，
不能在等待 credit 时被当成空闲池回收。TUIC 业务 UDP 队列使用独立观测类别，
旧七协议压力 fixture 中该类别为零不代表 TUIC 压力通过。

## DNS

- 不设置固定的活动请求或活动传输总许可数。
- 相同 key 的 cache miss 使用 singleflight；leader 取消后 follower 重新选举。
- UDP 传输属于单次请求，同一尝试的重发复用当前传输。
- 显式 TCP nameserver 按 endpoint 和配置的 route target 复用；一条连接同时只处理一个查询。
- 活动 TCP 不设固定数量上限；空闲连接总数最多 4，同 key 最多 2，空闲超时 30 秒。
- 查询、单次尝试和 UDP 重发期限分别为 5 秒、3 秒和 1 秒。
- 响应最多扫描 64 条记录，类型化缓存和提示最多保留 16 个唯一 IP。
- 停止取消打开、发送、接收、重试和响应发送，并释放全部传输。

完整语义见 [TUN ICMP 与 DNS](tun-icmp-dns.md)。

IP-only协议接点持有`ResolutionContext`，runtime DNS通过Weak绑定，不形成DNS→dispatcher→connector强引用环。解析继承同次建链绝对期限和runtime取消；同名递归/超过32层解析依赖立即失败，32是单调用依赖深度而非并发请求额度。独立测速的受控bootstrap上下文不创建Running Session或RuntimeDns。

## 代理组与 Controller

- 静态 `select` 组只拥有不可变的有序成员和每组一个可原子替换的当前索引，不拥有协议连接、后台任务、队列、缓存或独立 worker。
- 组数、每组成员数、重复成员数和嵌套深度没有独立固定上限，统一受 256 KiB YAML 上限约束；配置期使用 O(V+E) 的迭代 DAG 校验，运行时也以迭代方式解析当前叶节点。
- 节点上游和全部组成员在同一 DAG 中校验；组连接器只持有声明依赖，按逆依赖顺序释放。建链快照只按需记录本次遇到的组，不成为全局缓存。Hysteria2 的已认证连接为后续端口跳跃保留该快照，直到此物理会话退出；它不再读取实时选择，也不延长原建链期限。
- 同组成功选择是线性化的，不同组独立；选择失败不改变状态，也不创建重试或自动 failover 任务。
- 切换不扫描或迁移现有 TCP、UDP、DNS transport，不刷新 DNS cache/singleflight 或 TCP pool；资源仍由原所有者按既有 timeout、EOF、取消和 stop 语义回收。
- Controller 同时最多跟踪 8 个连接任务。请求 header 和 PUT body 各有 5 秒读取期限，PUT body 最大 1 KiB；超时、超限和解析失败只终止当前请求。

完整接口见 [运行时 Controller](controller-api.md)。

## GeoData

- iOS/tvOS 每份 GeoData 快照的所选 GeoIP 原始 CIDR 与 GeoSite 原始 Domain 共用 1,280,000 条总保留额度。先保留 GeoIP，再将剩余额度交给 GeoSite；GeoIP 自身超限也截断至 1,280,000 条，GeoSite 此时为零。其他平台不设此上限，没有新增 YAML 配置项。
- 同种 code 按 ASCII 大小写归一后合并为唯一集合；业务规则与 DNS policy 共享 GeoSite 集合，重复引用不重复计分类，未引用分类不计数。重复原始 CIDR 以及 Domain/Full/Plain（Substr）/Regex 都逐条消耗额度，不按压缩后的数量计数。
- 同种 code 归一排序，每类按文件 CIDR / Domain（field 2）的原始顺序保留前缀；截断不受配置或资产分类顺序影响。额度耗尽后的所选分类仍是 available 的空分类，未保留记录不再参与 GeoIP/GeoSite 分流和 GeoSite DNS policy 命中。
- 各平台均不设独立 GeoData 分类、引用、文件大小、累计源码/值字节或加载内存预算；DNS GeoSite policy 也不保留独立项数/引用数上限。
- Loader 只解析被引用的分类，其他分类按 wire 长度跳过。
- 匹配器使用紧凑连续存储，运行期匹配不分配。
- 分类按 code 二分定位；TUN UDP 五元组固定规则 action，不保留 GeoData 快照
  或域名。没有全局目的缓存或旧快照引用；各目标独立空闲回收。
  活动流的规则数据更新在新流生效；DNS 查询、域名目标和非 TUN 路径不受此固定策略影响。
- 正则没有独立记录数、源码、编译或保留 DFA 内存预算。单条复杂 Regex 仍可能显著增加加载峰值，GeoData 计数不能约束其内存。容量账本仅作诊断，不涵盖编译器全部临时内存，不能充当进程峰值上界。
- GeoData 超限只截断匹配器，不改写磁盘资产，不视为加载/更新失败；首次可用，合法更新可发布截断快照。截掉记录只检查外层 wire/length，跳过内部 CIDR 解码/压缩、value/Regex 校验和编译；保留前缀仍严格校验，分类 header、外层 wire 和两遍扫描记录数一致性仍检查。截断警告只含数量，不含 code、域名或 IP/CIDR。
- 首次加载缺失、外层损坏或所选保留前缀无效使对应种类不可用且不消耗有效额度，实例以 degraded 状态继续准备/启动；GeoIP 首次不可用时 GeoSite 可用全部额度。更新任一种资产都重新加载两类并重分配额度；GeoIP 增长可减少新快照的 GeoSite 记录。真正的失败重载保留旧整体快照，失败更新保留旧整体快照和资产，不回溯已完成的选路。

1,280,000 是指定的 iOS/tvOS 总 GeoData 工程边界。公开 [benchmark](https://github.com/OneXray/container-benchmark)
的旧 CN 观测只有 111,361 条 GeoSite + 9,648 条 GeoIP，共 121,009 条；该轮 2 Gbps、
1,000 QPS DNS 的 Linux RSS 峰值 26.9 MiB 不代表 1,280,000 条压力负载。
2026-10-06 已执行 1,280,000 条 Linux 原生 TUN 压力：GeoIP 1,054,987 条 +
GeoSite 225,013 条，2 Gbps / 60 秒 / 1,000 QPS DNS 下 RSS 峰值 42,557,440 bytes
（40.59 MiB）。仍有 UDP 丢包和 DNS 超时，本轮 Site 不包含 Plain/Regex，不能
扩展为任意分类、复杂正则或更新叠加的最坏内存保证。完整指标见 benchmark README。
互通和内存压力由 benchmark 的 `interop` / `stress` 执行，并显式指定 `--source vcore=PATH`；
VCore 自有脚本只负责编译。记录边界不是实测数量极限或
50,000,000 bytes 保证，不替代 Apple 真机 footprint 验收。

完整边界见 [GeoData 规则与资产](geodata.md)。

## 当前限制的保留判断

运行时维持 `standard` 行为，不新增 `resourceProfile` API 或活动业务流准入配额。
iOS/tvOS 的 GeoData 1,280,000 条总保留边界在资产加载时执行，GeoIP 优先，适用于
该平台全部运行时，不依赖 low-memory 配置，也不传播到 macOS/Android/Linux/Windows。
GeoData 内存仍无预算。完整 CN 的代表性协议冷/热、双栈入口、取消/重建及资源叠加
短测仍有明显余量；这不是完整矩阵、长期最坏值或正式 Provider 的签收。其他移动
资源策略仍需同一最终候选的完整矩阵与真机结果。局部队列、解析和缓冲继续保持有界。

完整 CN、IPv4、16 条背景 TCP、300 秒、DIRECT/代理各承担一半流量的 1 Gbps 子集
曾测得最坏 7,864,824 bytes；它不覆盖最大并发、DNS 冷查询风暴、UDP、TUN、协议池
或 iOS/tvOS 实机，不能据此删除局部容量边界，也不能承诺任意负载低于 50M。

- 活动 DNS/TCP/UDP/握手已有无总数配额的语义，继续保持；4 个 bootstrap 工作者、
  DNS 空闲 TCP 池 4/2、TUN accept 队列 128 都不是活动业务并发上限。
- 保留队列、缓存、单流缓冲、窗口与解析边界；若出现 VCore 瓶颈，依据队列高水位、
  丢包、背压和峰值测量调整，不通过无界积压掩盖问题。对端 UDP 设施丢包不是核心归因。
- AnyTLS idle 目前只有 30 秒空闲/30 秒扫描，没有数量或字节 cap；后续 churn 应重点
  测量突发后的保留。TUIC 分片重组按关联持有，HY2 按物理会话共享，不能按相同总量估算。
- 普通规则条数和 DNS nameserver 列表数是配置复杂度边界；当前小规则表、高速 TCP
  结果不足以证明可删除，本轮不改。若最终确需业务数量门禁，只在独立 iOS/tvOS
  low-memory 策略中基于实测另行决定，不影响其他平台。

## Apple 内存遥测

iOS/tvOS TUN 通过 `TASK_VM_INFO` 尽力记录当前 physical footprint、进程生命周期峰值和限频阈值事件，运行期间最多每 30 秒采样一次。macOS 不启用该周期任务；平台接入与事件标识见 [TUN 平台层](tun-platform.md)。

- 采样失败只记录一次警告；
- 遥测不写入 `lastError`；
- 读数和阈值越界不改变 prepare、start、running、stop 或 panic recovery；
- 停止后的 allocator pressure relief 同样是尽力而为；
- 固定阈值只是诊断信号，不是产品内存承诺或 admission gate。

## 日志与观测

运行时可记录 TCP、半开连接、UDP、握手和 DNS 的当前值/峰值，以及缓存命中、singleflight、队列丢弃、连接池回收、非法包和 ICMP 统计。

独立 netstack 的 `udp_drops` 只记录通用 UDP endpoint 的入站丢弃；生产 TUN 使用
TCP-only netstack，因此该值为零不代表 UDP 无丢包。运行时记录
`udp_association_queue_drops` 和 `udp_response_queue_drops`，保留两者合计的
`udp_queue_drops`；TCP/ICMP ingress Full 记录 `packet_queue_drops`。这些计数
不包含物理 socket、内核 TUN 或对端设施中的丢包。

日志必须有界且脱敏，不记录目标、DNS question、UUID、凭据、密钥、负载或完整配置。

仅`cfg(test)`/`interop-test`启用的`ResourceProbe`按测试作用域记录RAII当前值/峰值；子任务显式继承作用域，不使用进程全局reset或更换生产allocator。当前接入物理TCP/UDP、共享流/QUIC驱动与session、数据报association、DNS池/等待者及既有运行时活动guard。Hysteria2 的待完成分片通过 `Reassembly` 登记，交付后释放 Packet ID 和重组资源；零计数必须与实际执行过的重组路径一起解释。

生产`ObservedIo`中的观测guard为空类型，不分配共享计数器。同步Stop、5秒静默窗口和真实对端由断言及结构化事件证明，不根据日志中的PASS文字判断。`tests/protocols/limits.json`登记公共限额及继承的`ResourceLimits`，`limit_foundations`直接与Rust常量核对；它不是第二套运行时配置。

## 变更要求

新增全局 admission、可配置容量或长期缓存前，必须：

1. 证明现有局部边界不足；
2. 定义所有者、上限、取消和停止语义；
3. 增加边界值和越界测试；
4. 记录主机和对应物理平台证据。

没有测量证据时不增加新的资源控制层。实际验证范围见 [验收矩阵](acceptance.md)。
