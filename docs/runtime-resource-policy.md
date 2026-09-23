# 运行时资源策略

所有 TUN 运行时使用同一组局部结构上限。VCore 不根据业务流总数或整进程内存读数拒绝正常流量；容量控制放在包、队列、缓冲区、缓存、解析器和生命周期所有者处。

## 原则

1. 数据正确性、安全边界和同步停止优先。
2. 队列、缓冲区、缓存、wire 大小、解析大小、超时和空闲清理必须有界。
3. TCP 会话、普通 UDP 关联、半开连接、出站握手和活动 DNS 传输不设置固定业务数量上限。
4. 队列满时按局部协议语义丢当前项目或失败，不能阻塞 TUN 回调或全局循环。
5. 当前值和峰值只用于诊断，不参与 admission。
6. 平台内存采样是尽力而为的遥测，不改变生命周期结果。

## TUN 结构上限

```text
原始包 / MTU                    1,500 字节
最终代理 UDP 负载               1,452 字节（Windows 1,352）
包队列                          256
普通事件 / UDP 响应             128
DNS 入站 / DNS 响应             128 / 128
每个 TCP 方向缓冲区             32 KiB
TLS / XHTTP 缓冲区              64 KiB
DNS 类型化缓存                  256 项
DNS 原始响应缓存                64 项 / 256 KiB
TUN 域名提示                    256 项（按需）
GeoData 分配容量                8 MiB
```

Windows L3 接口及其 Session Host netstack 使用 1400 MTU，因此按 IPv6 UDP 头保守计算的响应负载上限是 1352；表中的 1500 是跨平台原始包解析上限和其他 TUN 平台的固定 MTU。

- DNS 响应和普通 UDP 响应使用不同队列，但共享 netstack UDP 入站接收器。
- TUN 域名提示只在 TUN 配置实际包含域名规则时创建，并从空容量按需增长。
- ICMP 响应复用原始包出站队列，不创建独立任务或长期状态。
- 每次扩容前执行 checked arithmetic 和局部预算检查。

## TCP 与握手

- TCP 流按需创建任务，每方向缓冲区固定为 32 KiB。
- TLS/XHTTP 内部缓冲区固定为 64 KiB。
- 标准 TLS 恢复会话总预算为 4，按节点（含独立下载端点）分配；每个缓存绑定不可变的 SNI、ALPN 和证书策略，绝不跨节点复用。TLS 1.3 票据有界、一次性消费，TLS 1.2 会话占用同一额度；额度为 0 则禁用恢复。REALITY 不参与该缓存。
- 共享 TLS 客户端的显式验证名、协议版本和客户端证书身份也属于不可变策略，单独构造缓存，不跨身份共享。标准 TLS CloseWrite 只发送 close_notify，刷新最多5秒，保持读方向和底层传输；Drop 释放整个流。XHTTP 仍以逻辑连接整体关闭为准。
- 半开连接、出站握手和活动会话只记录当前值和峰值，不触发资源错误。
- 超时、取消、EOF 和协议错误负责回收；停止必须等待全部已跟踪任务结束。
- 引导解析器最多使用四个工作线程；全部忙时在调用方既有期限内等待，不返回人为容量错误。

## 共享流传输基础

`stream-transport` 仅包装传入 IO，不创建 socket 或 DNS。WS/HTTP响应首部最多16 KiB、100字段；WS用户请求头最多100字段，额外固定升级头和early-data仍计入16 KiB总预算。WS early-data最多2,048原始字节，头名称/路径后缀由类型化选项区分。WS消息和单帧最多64 KiB，写入切块16 KiB；HTTP首包正文直接写入，不整体复制或持续按HTTP正文定界。

共享gRPC/legacy H2每个实例仅拥有一条底层连接与一个逻辑流，不是连接池或全局并发许可。流窗口64 KiB、连接窗口128 KiB、最大HTTP/2帧和发送缓冲各16 KiB、解码负载64 KiB。读侧按实际消费量释放窗口；每poll最多处理32个片段/控制消息。gRPC和legacy H2的shutdown关闭整个逻辑连接，owner.stop等待驱动任务退出；Drop只做取消兜底，不作为同步停止通过证据。WS/HTTP按底层CloseWrite语义保留读方向。所有握手使用调用方同一个绝对deadline。

XUDP现在只拥有已认证流上的帧编码；VLESS响应头由VLESS包装层处理。元数据仍最多512字节，单payload仍受调用方预算和u16 wire上限约束，不新增全局会话额度。

## HTTP 代理入站

HTTP 代理入站不是 TUN 转发缓冲区的使用者：请求 / 响应各使用 8 KiB 预读与复制缓冲区，头部 32 KiB / 100 字段、chunk 行 1 KiB、trailer 8 KiB / 100 字段。正文不整体缓存，不设全局业务连接准入数；先绑定后启动，Stop 取消并等待所有入站连接任务。读头、正文空闲和临时响应数量边界见 [HTTP 代理入站](http-proxy.md)。

## SOCKS5 代理入站

TCP 每方向复制缓冲区 4 KiB，握手 10 秒。UDP 控制连接拥有授权、单关联 16 包队列及 relay；全局接收不等待建链或发送。空闲 30 秒、每 10 秒清理，满队列与非法包不刷新时间。UDP wire 上限 65,507 字节，回包负载保守预留最大头部为 65,245 字节，出站继续逐层核算预算；不复用 TUN MTU。Stop 等待全部任务退出，无全局关联数准入。完整语义见 [SOCKS5 入站](socks5-proxy.md)。

## UDP

普通 TUN UDP 关联：

- 关联表不设固定项数；
- 每个关联的入站队列有界，满时只丢当前数据报；
- 使用代次感知所有权和子取消令牌；
- 空闲超时 30 秒，清理周期 10 秒；
- 清理时先从表中删除，再取消子任务；
- 只有成功入队的请求或响应刷新活动时间；
- 父运行时停止时删除、取消并等待全部子任务。

嵌套代理协议可以增加有界帧头，但最终解封装负载仍不得超过调用方按有效 MTU 给出的上限；其他 TUN 平台为 1,452 字节，Windows 为 1,352 字节。

### 定向数据报预算与受控 QUIC

`DatagramBudget` 分别表达当前层的发送和接收 payload 上限。嵌套协议先为下层申请有界 envelope 空间，再按实际协议/地址族开销扣除下层能力，与调用方预算取交集；不能把接收上限直接当作发送能力。DIRECT、SOCKS5、SS 2022、AnyTLS UoT 和 VLESS XUDP 保留原来对端/地址校验。超出发送预算在写入前失败，超出接收预算丢当前包并有界让出执行权，close 后不能恢复收发。

`quic-transport` 只把已有 `DatagramTransport` 适配成 Quinn 的受控 UDP 接口，没有内部 bind、DNS 或 DIRECT 回落。每个连接双向各最多32个排队数据报，另允许一个正在发送的包；TX满返回WouldBlock，RX满暂停读取。接收等待不会持有发送队列锁；Pending发送不会重复提交。单逻辑peer/物理peer映射和来源校验独立保留，不接受未请求的目标、GSO或源地址覆盖。物理 socket 仍只能来自 Dialer。

QUIC双向可用payload至少1,200字节；endpoint必须显式把QUIC MTU限制在有效预算内。WireGuard公共计算接点扣除32字节数据包开销和16字节padding对齐，最终inner MTU至少1,280字节；这不是WireGuard协议已实现。IPv4/IPv6路径MTU分别先扣除28/48字节IP+UDP头，边界和单字节不足均有定向测试。

QUIC owner.stop先取消并等待驱动，再关闭并释放上游；上游close最多1秒。Driver Drop仅为取消/abort兜底，不能作为同步Stop验收。队列容量是单连接局部界限，不是全局QUIC连接准入数。

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
- 节点上游和全部组成员在同一 DAG 中校验；组连接器只持有声明依赖，按逆依赖顺序释放。建链快照只按需记录本次遇到的组，随建链结束释放，不成为全局缓存或长生命周期状态。
- 同组成功选择是线性化的，不同组独立；选择失败不改变状态，也不创建重试或自动 failover 任务。
- 切换不扫描或迁移现有 TCP、UDP、DNS transport，不刷新 DNS cache/singleflight 或 TCP pool；资源仍由原所有者按既有 timeout、EOF、取消和 stop 语义回收。
- Controller 同时最多跟踪 8 个连接任务。请求 header 和 PUT body 各有 5 秒读取期限，PUT body 最大 1 KiB；超时、超限和解析失败只终止当前请求。

完整接口见 [运行时 Controller](controller-api.md)。

## GeoData

- GeoSite 与 GeoIP 共享 8 MiB 分配容量。
- Loader 只解析被引用的分类，其他分类按 wire 长度跳过。
- 匹配器使用紧凑连续存储，运行期匹配不分配。
- 正则源码、编译预留和保留 DFA 内存都有独立上限。
- 资产缺失或更新失败只使对应种类不可用，不阻塞准备或启动。

完整边界见 [GeoData 规则与资产](geodata.md)。

## Apple 内存遥测

Apple 目标通过 `TASK_VM_INFO` 尽力记录当前 physical footprint、进程生命周期峰值和限频阈值事件，运行期间最多每 30 秒采样一次。

- 采样失败只记录一次警告；
- 遥测不写入 `lastError`；
- 读数和阈值越界不改变 prepare、start、running、stop 或 panic recovery；
- 停止后的 allocator pressure relief 同样是尽力而为；
- 固定阈值只是诊断信号，不是产品内存承诺或 admission gate。

## 日志与观测

运行时可记录 TCP、半开连接、UDP、握手和 DNS 的当前值/峰值，以及缓存命中、singleflight、队列丢弃、连接池回收、非法包和 ICMP 统计。

日志必须有界且脱敏，不记录目标、DNS question、UUID、凭据、密钥、负载或完整配置。

仅`cfg(test)`/`interop-test`启用的`ResourceProbe`按测试作用域记录RAII当前值/峰值；子任务显式继承作用域，不使用进程全局reset或更换生产allocator。当前接入物理TCP/UDP、共享流/QUIC驱动与session、数据报association、DNS池/等待者及既有运行时活动guard。`Reassembly`是预留类别，后续协议拥有重组对象时再登记；没有所有者的零值不证明未来协议已无泄漏。

生产`ObservedIo`中的观测guard为空类型，不分配共享计数器。同步Stop、5秒静默窗口和真实对端由断言及结构化事件证明，不根据日志中的PASS文字判断。`tests/protocols/limits.json`登记N1公共限额及继承的`ResourceLimits`，`limit_foundations`直接与Rust常量核对；它不是第二套运行时配置。

## 变更要求

新增全局 admission、可配置容量或长期缓存前，必须：

1. 证明现有局部边界不足；
2. 定义所有者、上限、取消和停止语义；
3. 增加边界值和越界测试；
4. 记录主机和对应物理平台证据。

没有测量证据时不增加新的资源控制层。实际验证范围见 [验收矩阵](acceptance.md)。
