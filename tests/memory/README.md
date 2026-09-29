# 独立进程内存测量设施

入口在 VCore 自己的 scripts 中，不依赖仓库外目录。当前支持原生 Apple Silicon macOS；
本机实验包含完整 CN 加载与路由验证，不代表 iOS/tvOS Packet Tunnel Provider 或 VCore 高速转发验收。

```sh
uv run --project scripts --locked vcore-scripts check memory --list
uv run --project scripts --locked vcore-scripts check memory --preflight
uv run --project scripts --locked vcore-scripts check memory
# 定向运行仍只签收所选用例：
uv run --project scripts --locked vcore-scripts check memory --case smoke-1
uv run --project scripts --locked vcore-scripts check memory --case full-cn-loader
# 保留同一源码、产物、输入和用例集合：
uv run --project scripts --locked vcore-scripts check memory --resume target/memory/<run-id>
```

需要 Rust、Xcode/Command Line Tools、Go、uv、Apple Container 和既有 host-only
`vcore-mihomo-interop` 网络。原站、DNS、Mihomo 都在专属容器中，不发布宿主端口；
宿主仅运行客户端、观察器及被测 VCore SOCKS5 入站。停止只清理本轮拥有的进程和容器。

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

## 证据与恢复

`target/memory/<run-id>/` 保存 manifest、源码/本地 boring 身份、构建命令、正式产物
及冻结输入 hash、用例阶段时间线、self/external/final/退出取证、容器身份与清理、
原始结果和 `summary.md`。`target/memory/progress.json` 指向最新运行和下一条命令。
物理设备、正式 Provider/签名权限、设备可达的隔离网络和生产可信 TLS/更新身份缺失时
单列 `BLOCKED`，不借用测试信任放行。

SIGINT/SIGTERM 会清理并保留已完成用例；每个用例使用独立 attempt。恢复时严格校验
源码、二进制、输入及已封存证据；只复用已通过设施判定的完整 attempt，失败/中断项另开
attempt，绝不覆盖旧失败。修改源码或准备阶段未完成须新建 run；不要编辑 manifest 绕过校验。
只跑子集不会置 `facility_suite_complete`；完整 CN 子集可单独完成其兼容性阶段。
全套任一必需校准或所选 CN 检查失败均以非零退出。

必要回归：

```sh
uv run --project scripts --locked python -m unittest discover -s scripts/tests -p 'test_memory*.py'
uv run --project scripts --locked ruff check scripts tests/memory/guest_metrics.py
go vet tests/memory/traffic.go
```
