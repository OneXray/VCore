# 独立进程内存测量设施

入口在 VCore 自己的 scripts 中，不依赖仓库外目录。当前支持原生 Apple Silicon macOS；
本机实验包含完整 CN 加载与路由验证，不代表 iOS/tvOS Packet Tunnel Provider 或 VCore 高速转发验收。

## 开发检查与最终验收

各开发阶段只完成实现、相关编译/必要回归和短烟测，不再独立签收内存或吞吐矩阵；
开发完成后可以提交并继续下一阶段。下面的完整 suite、正式重复次数和长测统一在最终
候选验收时执行，开发期间仅按定位需要选择用例，不把每次修改都变成完整复跑。
`--case` 选择范围不会自动缩短正式用例；短诊断必须单列，不能改写正式参数来获取 PASS。

最终验收仍要求完整 CN 分流、1 Gbps、数据正确性与同 PID 全生命周期峰值 ≤50,000,000
bytes 同轮成立，并覆盖全部适用矩阵与真实移动 Provider。单流 UDP 对端容量等设施
问题保留最终待验状态，不阻挡无依赖开发；已发现的正确性、安全和回收错误及时修复。

`accepted`、`cn_compatibility_accepted`、`stage_complete`、`facility_suite_complete`
等字段只表达当轮用例或 suite 的证据范围，不是开发阶段完成开关。不得为提交或继续开发
手工改成 true；开发完成也不等于最终验收通过。边界见[验收安排](../../docs/acceptance.md)。

## 运行入口

```sh
uv run --project scripts --locked vcore-scripts check memory --list
uv run --project scripts --locked vcore-scripts check memory --preflight
uv run --project scripts --locked vcore-scripts check memory
# 定向运行仍只签收所选用例：
uv run --project scripts --locked vcore-scripts check memory --case smoke-1
uv run --project scripts --locked vcore-scripts check memory --case full-cn-loader
# 四个 profile × 五个未插桩进程，随后单独的双规则分配诊断：
uv run --project scripts --locked vcore-scripts check memory --suite cold-start
# 单/16/64 流独立对端容量清单，均不经过 VCore：
uv run --project scripts --locked vcore-scripts check memory --suite peer-capacity --list
# 完整 CN + 16 条 TCP + 300 秒 + 同一 PID 全生命周期峰值，当前为联合子集：
uv run --project scripts --locked vcore-scripts check memory --suite socks-tcp-split
# 扩展 TCP 用例清单；IPv4/IPv6 各自冻结 DNS 夹具，列出不代表已经验收：
uv run --project scripts --locked vcore-scripts check memory --suite socks-tcp-v4 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-tcp-v6 --list
# 明确独立的开发烟测；不改变正式用例参数或签收状态：
uv run --project scripts --locked vcore-scripts check memory --suite socks-smoke-v4
uv run --project scripts --locked vcore-scripts check memory --suite socks-smoke-v6
# TCP/UDP 高速、低速正确性和资源叠加分别列出：
uv run --project scripts --locked vcore-scripts check memory --suite socks-udp-v6 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-correctness-v6 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-overlap-v6 --list
# 保留同一源码、产物、输入和用例集合：
uv run --project scripts --locked vcore-scripts check memory --resume target/memory/<run-id>
```

需要 Rust、Xcode/Command Line Tools、Go、uv、Apple Container 和既有 host-only
`vcore-mihomo-interop` 网络。原站、DNS、Mihomo 都在专属容器中，不发布宿主端口；
宿主仅运行客户端、观察器及被测 VCore SOCKS5 入站。停止只清理本轮拥有的进程和容器。
运行前须移除继承的 `Malloc*` / `DYLD_*` 覆盖项（例如 `env -u MallocNanoZone`），
不更换分配器或把诊断开销算成正式结果。

## 测量边界

- `host.c` 链接生产 feature 集合的 Release `libvcore.a`，通过正式 Invoke API v5 执行
  initialize → prepare → start → 流量 → stop → destroy。没有 `interop-test`、流量生成、
  摘要或 JSON 解析器注入被测进程，也不扣除原生宿主本身的内存。
- `observer.c` 用 SDK 定义读取 `proc_pid_rusage(RUSAGE_INFO_V4)`，约每 20 ms 从外部
  记录 current/lifetime-peak physical footprint、RSS、CPU；PID、启动时间及映像 UUID
  固定。阶段边界与宿主 `TASK_VM_INFO` 自读交叉核验。CPU Mach ticks 转为纳秒；
  内存始终为字节，`wait4` 的 max RSS 单列，不能代替 footprint。
- 内核 lifetime peak 覆盖采样间隙和首次采样前的启动。业务清理、destroy 之后进入最终
  屏障，外部取完峰值才允许宿主 `_exit`；屏障后不再分配或执行业务清理。
  缺读数、PID 不符、崩溃、提前结束或未完成屏障均不可得到内存 PASS。
- 工程门槛是 **50,000,000 bytes**，另给 MiB 和余量。有效超线为 `FAIL_MEMORY`；
  空进程基线不从 VCore 结果中相减。正式移动平台仍须独立实测全 Provider 进程。

## 用例与输入

完整设施集包含 25 项：7 项观测校准、3 次无 GeoData 的独立进程烟测、完整 CN 加载与路由、
负载提前结束及清理失败负例，以及 12 项带宽校准。短时触碰/释放 64 MiB 校准故意避开
实时采样，仍须被内核峰值捕获；持续超过 50M、采样失败、崩溃、缺少最终屏障、错误 PID
也必须产生各自预期的非 PASS。`accepted` 表示设施识别到了预期结果，不改写原始状态。

每个新 run 从官方 latest 下载 Loyalsoldier `geosite.dat` / `geoip.dat` 和 checksum，
要求同一 release、完整 CN，保存分类数量及 hash；Mihomo 使用官方发布二进制，记录其
实际版本与 hash；基础镜像冻结 digest。下载和统计发生在测量前，实际加载发生在被测进程内。
`full-cn-loader` 必须同时满足两类资产 required/available 且无 lastError，不能把 prepare
成功当作加载成功。完整 CN 不得截短或换分类；原 65,536 记录限制的失败证据保持原样。

该用例先在**独立诊断进程**执行 `geodata_cn`：Python 标准库参考使用官方 protobuf
记录、集合/正则和 ipaddress，生成全部 Domain/Full 的精确、子域、非 label 边界、
后缀及大小写/末点见证；全部 Regex 另有隔离单表达式正反例，CIDR 覆盖首/末/邻接
地址和双栈隔离。超 DNS 长度的构造见证验证明确拒绝。上游 Regex 变化要求补充经审阅
的见证，不静默跳过。两份资产、参考输入和结果按 hash 冻结；参考模型不进入被测宿主。

随后同一个生产 ABI 进程执行加载、启动、规则 REJECT、停止/重新准备、真实转发、
TCP/UDP 数据和销毁。CN IP 正例只做 REJECT；CN 域名由容器内白名单 DNS 映射到隔离
原站。SOCKS5 状态 2、零上游 TCP 接受和零 DNS 查询共同证明核心拒绝，不把超时或
对端拒绝当作命中。转发正反例由原站报告实际连接来源，分别核对宿主直连/Mihomo
地址，并校验回显数据；guest-wide PassiveOpens 只作诊断，不当作逐连接 accept 数。
Mihomo 只允许本轮原站地址，拒绝其他目标，不向公网 CN 地址发送验证流量。

`cn_compatibility_accepted` 仅证明完整 CN 与所测路由；账本容量和生产宿主内核峰值分别
报告。有效峰值超线仍为 FAIL_MEMORY，不影响定位，但不冒称移动平台通过。单独复核：

```sh
uv run --project scripts --locked python -m vcore_scripts.memory_geodata <frozen-assets> target/memory/<new-reference>
VCORE_GEODATA_DIR=<frozen-assets> VCORE_GEODATA_REFERENCE=target/memory/<new-reference> cargo test --locked --release --features ffi --test geodata_cn -- --ignored --nocapture
```

每次烟测通过命名代理组连接 Mihomo，验证受控 DNS、1 MiB TCP echo 全量摘要、30 个
64/512/1200 字节 UDP 包、对端所见数据与源地址，以及 Stop 后立即释放 TCP/UDP 端口。

## 冷启动与规则归因

`--suite cold-start` 交错执行 `none/site/ip/both` 四种规则配置，各五个新 PID、空应用
缓存目录和一次生命周期，使用同一个未插桩 Release 产物及冻结资产。没有清空系统页缓存：
校验、参考模型及私有文件拷贝已读取资产，结果只证明**进程/应用冷启动**，不宣称磁盘冷读。
只有启用的资产允许 required/available；prepare 成功但缺失、降级或有 lastError 均 INVALID。

每个进程记录 initialize、prepare、start、首次真实规则命中、30 秒无业务流空闲、stop、
destroy 的墙钟耗时、current footprint、lifetime peak 和 RSS。时间包含 ABI IPC 或
SOCKS5 交换，不作为纯函数耗时。启用类别的 CN 正例只做 REJECT，并核验零上游/零 DNS；
所有配置都转发受控负例域名、IPv4/IPv6 原站，逐条核对 Mihomo 来源和双向 256 字节。
Stop 后立即验证端口释放，destroy 后正常退出最终屏障。完整矩阵必须有 20 个不同 PID，
每个都完整观察且峰值 ≤50,000,000 bytes；最坏值和余量单列，不能用均值掩盖超线。

`geodata_cn` 在另一进程输出四组保留容量/已记账容量峰值（`peak_accounted_capacity_bytes`）。
GeoData 已取消数量和内存预算；账本不再预留正则编译额度，也不观测编译器内部临时分配，
不是加载峰值上界或物理内存。旧结果中的预算预留数与新账本不能直接当作内存优化对比。
20 次正式测量结束后，`diagnose-cold-both` 用独立 PID 开启 Apple `MallocStackLogging=full`，
在 prepare 后、destroy 后捕获 `vmmap`、当前分配和 high-water 调用栈；正常结束也只标为
`DIAGNOSTIC`，绝不成为内存 PASS。该定位步骤失败则本套归因证据不完整，但不阻挡
无依赖的开发；最终矩阵仍需补齐。单独复查可用
`--case diagnose-cold-both`，仍会新建实验轮次、校验冻结输入。追踪改变时序/内存，只用于
区分加载临时对象、保留 matcher、allocator 页和运行时所有者。不可把跨 PID 峰值之差、
文件磁盘大小、阶段 current 值差或 allocation 账本直接当作模块精确 footprint。

低负载基线不签收协议池、TUN、真实 Provider 或 1 Gbps。没有明确收益证据时不修改生产
实现；后续优化的交错 A/B、吞吐/延迟防退化和未插桩完整矩阵统一在最终候选验收。
开发期可做必要的最小对照实验，不提前声明优化收益已经签收。

`traffic.go` 是独立标准库驱动与隔离原站，不是代理实现。带宽校准不经过 VCore：
direct / 独立 SOCKS5 客户端经 Mihomo × TCP / UDP × 上行 / 下行 / 双向。
每项 16 流、10 秒、聚合应用有效载荷 1 Gbps，双向为各 500 Mbps；TCP 64 KiB 记录与
SHA256，UDP 1200 字节、逐序列/内容/源校验及有界 bitset。UDP 使用进程级单发送循环，
按单调时钟轮转等速流，最多积累 16 个报文的发送时序额度；超额延迟不集中补发，
但不减少规定包量，实际窗口或 goodput 不达标仍失败。接收端用值类型地址校验，
不逐包分配/格式化地址字符串。TCP 保留逐记录 pacing。
必须完成全部工作、各发送端实际持续 9.9–10.1 秒且接收 goodput ≥ 990 Mbps；
不能把提前完成的突发流量除以名义时长过线，也不允许丢包、重发、扩缓冲或降低负载。
保存逐流/逐秒收发量、pacing 滞后、CPU、外部驱动样本、容器 UDP/TCP/网卡计数。
带宽原站 4 vCPU、Mihomo 8 vCPU，均 256 MiB；轻量正确性/DNS 原站 1 vCPU、256 MiB。
UDP 多流校准使用单个官方 Mihomo 进程的 16 个独立 SOCKS5 监听端口，每流一个；
TCP 和低速烟测仍用单监听端口。命令、manifest 和结果保存实际端点数量，数量不符不签收。
不修改默认 socket 缓冲或回环保护。
原单监听器的接收队列溢出和进程内转发丢包保留为失败证据；分散监听不证明单监听器或
单流 1 Gbps 通过。后续 VCore 多流对照必须保持同拓扑，单流场景须重新独立校准。
对端或驱动不能提供负载时是 `INVALID`，不是 VCore 的 `FAIL_BANDWIDTH`；10 秒校准也不能
替代后续 300 秒 VCore、完整 CN、内存与带宽同轮验收。

## 联合 SOCKS5 负载

`socks-tcp-split` 只覆盖 IPv4、16 流的上行/下行/双向，每种三次新 PID；最高档为
300 秒、聚合名义 1 Gbps，双向为各 500 Mbps。完整两类 CN 实际决定路由：
GeoSite 正例 DIRECT、负例经过不带 `no-resolve` 的 GeoIP 判断后走 Mihomo。
两分支各接收一半字节，原站逐条连接核对实际来源；每分支和聚合窗口均验收速率、
全量 TCP 摘要及工作量。它只验收所测 SOCKS5 **入站**联合负载，不把半数 DIRECT
解释为 SOCKS5 出站独立承载 1 Gbps，不签收整套负载矩阵。

先以相同两条隔离路径同时进行各 500 Mbps、10 秒容量校准。两驱动的所有连接就绪后
由一个共同屏障放行，墙钟分别记录准备与传输；不得把串行两次 500 Mbps 相加。
正式 VCore 的内存观测先于 initialize，连接建立、规则加载和准备仍计入生命周期峰值，
绝不在吞吐屏障重置峰值。对端、驱动、DNS 和正文处理不进入被测 PID。

300 秒窗口内固定在 35/70/105/140/175/210/245/280 秒新建选路见证，覆盖 Domain、
Full、Regex 正例及负例、私有 IPv4 转发、CN IPv4/IPv6 REJECT。新 DNS 夹具只响应
冻结白名单，返回隔离原站地址并按 case ID / 查询类型 / 核心或代理来源计数；不记录
业务 DNS 名称。保留核心的最小 30 秒 DNS TTL，不关闭缓存来制造压力；各轮必须真的
观察到核心查询。CN IP 拒绝同时核验无上游连接和无 DNS，不向公网 CN 目标转发。
REJECT 和不发送应用正文的建链见证不计入吞吐。主高速数据面目前仅 IPv4。

`socks5_joint_subset_accepted` 只说明本轮所选联合子集通过，`stage_complete` 仍为 false。
该旧子集不包含后续新增的单/64 流、速率阶梯、IPv6 高速、全 SOCKS5 出站、UDP 和资源叠加；
这些不能由本子集推定通过。专属 DNS 夹具不同，
不得在同一 run 混用该子集与旧设施/冷启动用例。

`socks-tcp-v4/v6` 扩展清单包含 `split` 和 `proxy` 两种拓扑。16 流覆盖
250/500/750/1000 Mbps，低三档 120 秒各一次，最高档 300 秒各三次；1 / 64 流仅列最高档。
`proxy` 的正负分支连接两个不同隔离容器内的同版 Mihomo，全部正文经过 SOCKS5，
原站逐连接核对对应来源，不能用 DIRECT 分支充数。IPv6 同时使用 IPv6 SOCKS5 入站、
代理端点和原站数据 socket；控制统计/DNS 可用 IPv4，不将其字节计入吞吐。
DNS 仅返回所选地址族；命中 GeoSite 后交给 SOCKS5 服务器解析的正例记录 peer 查询，
未命中后经 GeoIP 触发的负例仍必须记录核心 DNS 查询，不把远端 DNS 当核心压力。
Mihomo 测试配置只为这些受控域名添加精确白名单；其余目标保留隔离 IP 白名单和 REJECT。
仅有 `no-resolve` IP 规则会提前拒绝委托解析的域名，不得因此误判 VCore 的 CN 路径。
同一次 run 不能混用两种 DNS 地址族。最高档持续新选路，低档同样覆盖窗口三个区段。
单流分别选 `cn` / `miss` 主路径承担全部速率，期间仍执行两类路由见证；不把一个
连接拆成正负两个并发分支。单流 `both` 是同一个 TCP socket 内并发收发，独立种子、
摘要和读写 deadline，每向 500 Mbps；报告必须证明一条数据连接和两个完整方向。
多流 `both` 仍为半数上行、半数下行，报告中的方向记录数不冒充单流的连接数。
外部原站容量为 128 个任务，容纳 64 背景流和新选路见证；没有扩大 VCore 缓冲或改第三方。
新增用例只有对应实际运行的 `accepted`、来源/数据/速率、同 PID 峰值及清理全部通过才成立。

`socks-udp-v4/v6` 使用相同速率、方向、流数和重复矩阵；逐序列、长度、内容、源地址及
双向数量必须全部一致，没有 UDP 重传、允许丢包或扩大缓冲。多流 proxy 路径配置每流
独立的 Mihomo 监听节点，由认证 Controller 串行选择并完成该流建链，再放行共同屏障；
旧流固定原上游，不用运行中切组迁移报文。报告核对实际选择列表及对照端点数。
单流双向只有一个 UDP association，同时收发不同种子的完整数据。

`socks-correctness-v4/v6` 是固定低速 300 秒、三次新 PID 的正确性基线，不套用 1 Gbps
速率门槛。1 TCP / 1 UDP 分别覆盖 cn 和 miss；16 / 64 mixed 各半 TCP/UDP，每条连接
同时双向：TCP 每向 64 KiB/s，UDP 每向 20 pps，循环 64/512/1200 字节。接收端按序列
推导长度与内容，校验规定总量，不把变长包填充到 1200 字节或把上下行算成两条连接。

`socks-overlap-v4/v6` 在完整 CN、64 流、300 秒、聚合 1 Gbps 期间执行以下事件；
对应低速 mixed 也有独立用例。报告要求事件开始/结束时背景仍在运行，事件字节不计吞吐：

- DNS：1,024 个经独立 CN 参考确认未命中的冷域名，32 并发分批执行；随后 32 个热域名
  重复八轮。以受控 DNS 的核心来源计数增量证明真实冷查询；热集合在生产 30 秒缓存窗口
  内不再产生查询。精确白名单、地址族和实际代理来源同时验证，不关闭缓存制造压力。
- 建断连：100 轮各新建 32 TCP + 32 UDP、双向非空探针并关闭；另用同一组连接复用 100 次
  作为热控制。报告逻辑连接及时间线，不把协议可复用的物理会话自动认定为全新 TLS 握手。
- 背压：64 条背景流中八条 TCP 接收端每十秒暂停两秒，恢复后全量排空和校验。
  暂停窗口与稳定 1 Gbps 窗口分开解释，不能用积压突发或降低数据量过线。

TCP 驱动在 SOCKS CONNECT 请求后发送一个固定非空握手字节，原站在就绪前消费；它不计
业务 goodput。这是 client-first 测试，不改变或宣称解决 SS 官方 server-first 例外。

`socks-smoke-v4/v6` 单列 5–8 秒、低速的 TCP/UDP、分散监听、DNS、建断连/热控制、
慢读和 mixed 检查。结果只能是 `DIAGNOSTIC`，`final_matrix_accepted` 始终为 false。
每次仍下载冻结完整官方资产、生成独立参考、真实 CN 分流并测全 PID；仅此开发集合可
跳过单独的全量 Rust CN 穷举，报告明确记为 NOT RUN。正式套件仍要求全部 CN 参考通过。
`socks-smoke-udp-pair-v6` 保留双分支并发的 GeoSite 热点回归入口。

历史 UDP 失败 attempt 原样保存，包括旧线性 GeoSite 扫描造成的明显丢包和其后偶发少量
缺包；一次短诊断完整接收不等于稳定容量通过。单流及多流 1 Gbps、正式重复、全部负载
叠加和真实移动 Provider 都留到最终候选验收。

`peer-capacity` 是不经过核心的 10 秒容量诊断，1/16/64 流、上/下行及多流双向各三次。
UDP 仍是同一官方 Mihomo 进程的每流独立监听；该历史容量集合未覆盖的单流双向不能由
多流结果替代。`--udp-pacing-credit 0` 和 `--peer-cpus 2` 可冻结单变量实验；未指定仍为 16 包
时序额度及 8 vCPU，origin 固定 4 vCPU。它们不改变 socket 缓冲、数据量和任何验收阈值。
原始单流 UDP 对照及实验的 INVALID 必须保留，不能反复重跑直至一次 PASS 就签收。

## 证据与恢复

`target/memory/<run-id>/` 保存 manifest、源码/本地 boring 身份、构建命令、正式产物
及冻结输入 hash、用例阶段时间线、self/external/final/退出取证、容器身份与清理、
原始结果和 `summary.md`。`target/memory/progress.json` 指向最新运行和下一条命令。
物理设备、正式 Provider/签名权限、设备可达的隔离网络和生产可信 TLS/更新身份缺失时
单列 `BLOCKED`，不借用测试信任放行。

SIGINT/SIGTERM 会清理并保留已完成用例；每个用例使用独立 attempt。恢复时严格校验
源码、二进制、输入及已封存证据；只复用已通过设施判定的完整 attempt，失败/中断项另开
attempt，绝不覆盖旧失败。修改源码或准备阶段未完成须新建 run；不要编辑 manifest 绕过校验。
只跑子集不会置 `facility_suite_complete`；完整 CN 子集只证明该次兼容性范围，不独立
签收开发阶段。全套任一必需校准或所选 CN 检查失败仍以非零退出；调度到最终验收
不改变运行器的校验、退出码、时长或阈值。最终结果不能拼接不同中间源码的 PASS。

必要回归：

```sh
uv run --project scripts --locked python -m unittest discover -s scripts/tests -p 'test_memory*.py'
uv run --project scripts --locked ruff check scripts tests/memory/guest_metrics.py
go vet tests/memory/traffic.go
```
