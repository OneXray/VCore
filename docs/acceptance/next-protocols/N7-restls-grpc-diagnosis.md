# N7 Restls / TLS1.2 / Mihomo gRPC 首字节 EOF 诊断

> 范围更新（2026-09-26）：仅 Restls 从 VCore 与自有 boring fork 撤回，JLS 保留；
> Restls 不再属于 N7 交付或验收门槛。下文为历史记录，不代表当前支持；
> Restls 的旧命令不适用于 schema26。

2026-09-26。**已定位到 Mihomo 所用 Restls 服务端的读写互锁；未修复，
不签收 Restls 或完整 N7。** 本次是诊断，不修改第三方，不修改生产默认脚本、
HTTP/2 超时或业务重试策略。此前失败记录继续保留。

## 实际输入与边界

- macOS arm64 客户端；Mihomo、cover TLS 和业务原站均在 Apple Container
  host-only 网络，MTU 1500，无宿主服务端或端口发布。
- 每轮从官方 latest 入口重新下载 Linux arm64 Mihomo；实际均为 v1.19.31，
  revision `ab405bad5beeeac8b003bb01f60f134f6df54471`。
- 二进制 SHA-256：`1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。
  `go version -m` 确认内含 `restls-client-go v0.1.9`、`metacubex/http v0.1.7`。
- 最小消费者为 `runtime::repeated_first_byte`：每次新建 VLESS/Restls/gRPC
  outbound，只做一条 TCP 流的一字节回显，然后正常 shutdown。
  不需要第二条业务流、UDP、ResourceProbe 或五秒 quiet 才能失败。
- 起止 CODE_PATHS SHA-256 均为
  `c0ce0b2bd4f792a62c9d88593959a59f2da951afdcdebc17c034c75e3563aab8`；
  Cargo.lock 为 `e3b76e026d6fb32f9a1afa0dcd500a55d97bf309c5a63d2b3decc11e26f98ac7`。
  临时探针不计为生产更改；带完整探针的独立输入摘要为
  `30087cc6b62e789b3c5628f94d3ae21f38847d2aebe843ea9fcd0a9e336a09fc`。

## 复现与单变量对照

运行目录均位于忽略的 `target/interop/runs/`，前缀为
`n7-restls-grpc-diagnosis-`。表中序号从 1 开始；快照文件里的 iteration 从 0 开始。

| 目录后缀 | 服务端 / 观察方式 | 实际结果 |
| --- | --- | --- |
| `baseline-v1` | 1 核、双方默认脚本、无探针 | 1000 次计划循环中失败；首字节 `UnexpectedEof`，服务端 SETTINGS 超时；测试耗时 12.81 秒 |
| `snapshot-v1` / `snapshot-v2` | 1 核、默认脚本、延迟快照观察 | 分别 1000 / 10000 次通过，无慢连接快照；不能抵扣原 FAIL |
| `small-record-v2` | 1 核，仅服务端脚本改为 `100<1,1<1,100,100,100` | 第 45 条失败；两份非致命 goroutine 快照均捕获互锁 |
| `default-trace-v1` | 1 核、默认脚本、状态与长度日志 | 1000 次通过，未捕获故障 |
| `default-cpus2-v1` | 恢复双方默认脚本；服务端改为 2 核，无 IO 日志 | 第 7 条失败；两份快照捕获相同互锁 |
| `default-cpus2-trace-v1` | 同上，追加单调时间 / 状态 / 长度日志 | 第 95 条失败；相同互锁与自然 EOF，再次捕获 |
| `no-wait-v1` | 2 核，仅移除服务端默认脚本前两行的 `<1` | 1000 次通过；这是机制对照，不是正式修复或默认配置验收 |
| `clean-cpus2-v1` | 移除全部客户端探针，源码恢复起始摘要；2 核、双方默认脚本 | 3.28 秒再次出现首字节 EOF / SETTINGS 超时；未启用快照钩子 |

`small-record-v1` 因诊断 Python 包装器形参遮蔽而在配置阶段退出，协议用例
未执行，报告保留 NOT RUN；修正包装器后另开 v2，不追改旧报告。
上述各轮报告均记录 `source_unchanged=true`、`cleanup=true`。

快照使用仅监听服务端容器 loopback 的官方 `/debug/pprof/goroutine?debug=2`。
测试在首字节等待超过 500 ms 时记录标记，**继续等待同一个读 future**；
独立观察器获取两份快照，不发送 SIGQUIT、不提前关闭连接、不改变两秒超时。
调试路由启用后将普通日志调回 warning，避免大量成功连接日志干扰观察。

无探针的原始复现入口仍为：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_restls \
  target/interop/runs/<new-directory> N7-RESTLS-GRPC-STARTUP --version-hint tls12
```

这是概率复现，不保证单次必失败。2 核提高了本次观察到的触发概率，不能把
失败轮号视作确定性的概率估计。

诊断包装器仅保留在忽略目录；清理后执行以下命令得到上表 `clean-cpus2-v1`。
它仍使用未修改的 1000 次消费者和官方二进制，只配置容器 CPU 与 loopback
调试路由。临时 Rust 钩子已移除，因此不再提供每轮编号或自动快照：

```sh
uv run --project scripts --locked python \
  target/interop/diagnostics/restls-grpc-snapshot.py \
  target/interop/runs/<new-directory> --iterations 1000 --server-cpus 2
```

## 根因与 EOF 因果链

默认脚本的两份故障快照指向**同一条 Restls 连接和同一份 state**：

1. HTTP/2 写协程正在写 13 字节数据，进入 `writeRestlsRecords`，持有
   `writeMu`，在 `waitToClientWritable` 的 `sync.Cond.Wait` 等待客户端记录。
2. HTTP/2 读协程已进入 `restlsServerConn.Read`，完成记录认证与
   `noteClientRecord`，但为处理客户端的 `ActResponse`，调用
   `writeRestlsRecords(inbound, nil)`，阻塞在同一 `writeMu.Lock`。
3. 读协程不能返回已解码数据，也不能读取后来到达的客户端回复；写协程则要靠
   后续 `Read` 才能解除等待。`Cond.Wait` 释放的是 `awaitMu`，不是 `writeMu`。
4. HTTP/2 未从读协程收到首个 SETTINGS，约两秒后关闭连接，VCore 首字节读取
   才表现为 `UnexpectedEof`。[读方][READ]、[写方 / 等待状态][WRITE]、
   [HTTP/2 超时][TIMEOUT]

从源码和上述同连接快照可以推导触发它的竞态：写方先 `inbound.Write(record)`，
之后才 `maybeAwaitClientRecord`。早到的客户端记录可能先执行
`noteClientRecord`，随后等待标志又被写方设置；HTTP/2 的下一次写入若先取得
写锁，就在持锁状态等待，读方的脚本回复随即无法取得写锁。这同时存在
等待登记晚于发送的时序窗口，以及持写锁等待读方的循环依赖。
这是源码 / 快照推导的交错顺序，不冒称每一次锁操作都经过动态跟踪。

`default-cpus2-trace-v1` 的失败连接还显示：

- 58 微秒：24 字节 HTTP/2 前导对应记录已写入底层；
- 338 微秒：124 字节后续启动数据对应记录已写入底层；
- 384 / 607 微秒：脚本回复已写入底层；客户端认证收到 39 字节服务端数据；
- 655 微秒：额外九字节数据已写入底层；发送缓存与记录队列均为空；
- 约 1 秒：仍能发送 17 字节数据；约 2.002 秒才收到对端 EOF。

因此本次捕获的故障不是客户端两秒内未调度发送，不是 TLS 握手未完成，
也不是记录认证失败。移除服务端 `<1` 后的对照支持同一因果解释；但不代表
通过更改用户脚本即可作为正式兼容策略，更不将所有 TLS1.2 EOF 都归为此因。

## 为什么之前的官方客户端对照可能通过

Mihomo 的 HTTP/2 客户端把前导、SETTINGS、WINDOW_UPDATE 写进同一个缓冲后
统一 flush；VCore 使用的 h2 0.4.19 先单独写 24 字节前导，之后才构造并驱动
帧 codec。[Mihomo 所用 HTTP 客户端][GO-CLIENT]、[h2 客户端][H2-CLIENT]

这种合法的写入边界差异会改变 Restls 脚本和服务端并发读写的交错，是此前
Mihomo → Mihomo 两轮成功而 VCore 路径失败的合理解释；不是本轮已执行的
官方客户端同配置失败证明。本轮未修改 h2、Mihomo 或 Restls 上游源码。
故障在 TLS1.2 外观下捕获，不据此宣称 TLS1.3 在所有配置下都不受影响。

## 收尾与下一步边界

临时 500 ms 标记、循环次数入口、状态日志全部撤回；起止源码内容摘要一致。
诊断脚本 / 快照仅保留在忽略的 `target/interop/diagnostics/` 和运行目录，
不是新的生产依赖或已签收测试目录。原正式 OWNED 的 20 轮、Stop 归零与
五秒 quiet 门槛不变。清理后安全层 33 项测试、fmt 通过。
`git diff --check` 通过，临时标记搜索无残留，所属容器全部回收。
清理后的原始协议源码仍可复现故障；没有用一次通过把问题改判为已修复。

后续需要单独决定兼容处置：上游服务端应消除等待登记竞态及持锁等待读方；
若坚持不修改第三方，需要评估客户端兼容策略或明确支持边界，并重跑默认配置
与完整矩阵。延长超时、重试首字节或静默删除脚本等待都不能作为本次根因修复。
当前只完成诊断，没有完成修复、阶段提交、远端 CI 或设备验证。

## 客户端启动合并实验：未通过，已撤回

同日按用户确认的下一步，只在 VCore 的 Restls + gRPC 建链处测试一次性
写入合并：将 h2 前导和首批帧暂存在最多 16 KiB 缓冲中，首次 flush 后释放
缓冲并透传；读取不隐式 flush 前导。不新增 socket、任务、休眠或重试，
不改脚本、认证和期限，也不修改 Mihomo、h2、Restls 上游或 boring fork。

先用真实 `GrpcPool` 和 h2 的纯内存消费者检查接线前的写入边界，断言首个
底层 write 必须同时包含 24 字节前导、完整 SETTINGS 与 WINDOW_UPDATE。
原样透传时失败（`preface was sent in isolation`），加缓冲后通过，并完成
gRPC 回显。这只证明批次形成，不能替代真实 Restls 服务端回归。

隔离测试仍采用双方默认脚本、TLS1.2 hint、2 核 Mihomo 服务端及 1000 次
新连接首字节消费者。每轮重新下载官方 latest，实际版本与上文摘要一致。
运行目录前缀为 `target/interop/runs/n7-restls-grpc-coalesce-`：

| 目录后缀 | 改动 | 实际结果 |
| --- | --- | --- |
| `baseline-v1` | 未改协议源码 | 3.69 秒 FAIL，首字节 `UnexpectedEof`，服务端 SETTINGS 超时 |
| `candidate-v1` | 只加入启动合并，无临时 IO 探针 | 10.85 秒 FAIL，首字节 `TimedOut`；未记录 SETTINGS 超时 |
| `candidate-snapshot-v1` | 同一候选，仅增加 500 ms 慢读标记 | 第 92 条连接首字节 `TimedOut`，测试耗时 11.66 秒；两份非致命快照捕获同类互锁 |

快照中的写方在写入 22 字节 HTTP/2 数据时，持有 `writeMu` 停在
`waitToClientWritable`；读方对同一连接 / state 的 `Read` 已认证客户端
记录，为发送脚本回复进入 `writeRestlsRecords(nil)`，等待同一写锁。
两次快照均为此状态。没有 SETTINGS 超时日志本身不能证明每个帧的内部
处理顺序，但与原 EOF 不同的超时及同连接互锁足以否定该候选的修复效果：
改变启动写入边界没有消除服务端的锁依赖，不能把故障变晚当作兼容通过。

该轮标记只在读 future 挂起超过 500 ms 时写入循环编号，随后继续等待
同一个 future，不重建连接、不重发业务；快照观察线程正常 join。
三轮 `source_unchanged=true`、`cleanup=true`，所有所属容器均已回收。

本次输入身份（同一父提交和 Cargo.lock；见上文）：

| 输入 | CODE_PATHS SHA-256 | tracked patch SHA-256 |
| --- | --- | --- |
| 原基线 / 撤回后 | `c0ce0b2bd4f792a62c9d88593959a59f2da951afdcdebc17c034c75e3563aab8` | `e45b5e8104400f7fc8c1c71db6a1701e4c1e8aa17f50f13849fd36ae2cd4c329` |
| 无探针候选 | `f81bca9fe482017d8962c3ce548508ab8b930337b4a36f70969056b392fe3490` | `5c358900002364246385c391537a25834cb0b41d2fafad1fbdd21744402c15eb` |
| 候选 + 慢读标记 | `9ee4066bc2535dcc7f0f415e993873678860e73f8acca3f88c854eb75cbe279e` | `17ceca1b90c8368d46cb1a7a398ca1cc4d621c546655524b9c7b5d485e144217` |

候选 Adapter、其生产接线、候选专用内存测试及临时标记全部撤回；候选副本
仅保存在忽略的 `target/interop/diagnostics/grpc-startup-rejected.rs`，相关
说明在同目录 README。撤回后内容摘要精确恢复基线，已有未提交工作保留。
基础默认组合已失败，因此未继续候选的小记录脚本、完整数据和资源矩阵，
这些项目是 NOT RUN，不从此前阶段继承通过。没有创建阶段完成提交。

结论：**这个 VCore-only 方案不成立**，不是所有客户端策略均被证明不可能。
若继续坚持不改第三方代码，应由用户明确选择改变服务端脚本（移除等待会
改变流量时序），或验证独立官方 Restls 前置到 Mihomo gRPC handler 的拓扑。
此前原生前置的 H1 通过不自动证明 gRPC；两条路线都不能静默作为原默认
Mihomo listener 的成功，Restls 子包与完整 N7 保持未签收。

[READ]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/restls_server.go#L1047-L1100
[WRITE]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/restls_server.go#L1266-L1319
[TIMEOUT]: https://github.com/MetaCubeX/http/blob/v0.1.7/h2_bundle.go#L4983-L5031
[GO-CLIENT]: https://github.com/MetaCubeX/http/blob/v0.1.7/h2_bundle.go#L8179-L8184
[H2-CLIENT]: https://github.com/hyperium/h2/blob/v0.4.19/src/client.rs#L1315-L1355
