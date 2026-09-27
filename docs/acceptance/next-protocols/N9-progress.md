# N9 开发记录

日期：2026-09-27。状态：**进行中，N9 未签收**。本阶段只验证保留的七种代理
协议，不恢复 WireGuard/N8、Restls/ShadowTLS 或动态 ECH。Invoke v5/schema27 不变。

## N9.1 两跳消费者入口

- `protocol-interop --stage N9 --list` 冻结 49 个有序两跳组合和 16 个其他必需组。
  两跳协议为 SOCKS5、AnyTLS、SS2022、Trojan、VMess、VLESS、Hysteria2；
  同协议两跳仍是两个独立节点/容器，不是图自环。
- 新入口不回退到历史 N1 的宿主服务执行器。尚未实现的 required gate 显式
  NOT RUN；完整 coverage 不能因仅有两跳子集通过而签收。
- 每个两跳 case 通过公开 YAML/Invoke/SOCKS 运行四个路径：具体/嵌套 select
  上游 × IPv4/IPv6 外层；各有三种 TCP 目标、双向各 10 MiB、服务器先发与
  客户端先发，IPv4/IPv6 UDP 各四种包长、每种 100 包，Stop 后入站端口可重绑。
- 主对端仍为当轮 fresh official latest Mihomo。每个组合独占 origin、首跳、末跳
  三个 host-only 容器；镜像与二进制同轮冻结，不发布宿主端口或修改第三方。
- 原始结构化断言、每条路径的流量统计、版本/hash、源身份和清理记录分开核对；
  缺路径、重复路径、包数不足、错误映射和丢失断言均不能通过。

## 当前已执行

`n9-pair-tracer-20260927-v1` 三项先导检查通过：SOCKS5→VLESS、
Hysteria2→VMess、VMess→Hysteria2。每项四条实际路径；9 个所属容器回收，
`source_unchanged=true`。仅证明这三个先导组合，不是 49 组合或阶段签收。

当前离线脚本 176 项通过；N9 新测试 target 的 Clippy 通过。初次新增清单测试
因 N9 没有 required 集合失败，新增消费者因缺少隔离 fixture 失败；补齐目录与
隔离驱动后先导消费者通过。没有以空测试集、宿主服务或修改第三方绕过失败。

完整 49 组合开发轮次 `n9-all-pairs-20260927-v1` 在第 25 项 SS→SS 的
TCP bulk 回包超时而失败，之前 24 项留有完整原始观察；整轮不是 PASS。
单组合复跑及 50 次 bulk 诊断未稳定重现时序，但公开 connector 的有界内存
背压测试稳定复现：调用方在 Pending 后扩充缓冲，官方 codec 按新长度计数，
8192 字节被确认而实际只交付 4096 字节。自有 SS 适配器新增最多 16 KiB 的
待写块，固定重试内容与长度；第三方源码/锁均未改动。三算法确定性回归、
原有两项空首写/半关闭测试和 `n9-ss-pair-fixed-20260927-v1` 实际两跳通过。

`n9-entrypoints-20260927-v1` 已执行七协议 HTTP forward/CONNECT、合成 TUN
TCP/UDP/DNS。`n9-graph-dns-20260927-v2` 的 graph 消费者和
`n9-dns-measure-20260927-v3` 已执行七协议组切换/旧流快照、冷启动 REJECT、
未选环拒绝、失败不回落、代理 DNS/IP 规则、node-only 测速与组配置拒绝。
先前 AnyTLS 活动会话复用和末尾 MATCH,REJECT 两项夹具假设被现有契约拒绝；
修正夹具，不修改产品行为。上述仍是开发子集，不是完整 N9.1 签收。

`n9-resource-tracer-20260927-v1` 打通同步 Invoke 与运行线程的独立资源域；
`n9-resource-task-red-20260927-v1` 明确暴露旧观测未覆盖运行时任务。
为运行时/入站/Controller/TUN/AnyTLS 自有任务接入同一测试用 RAII 观察后，
`n9-resource-task-green-20260927-v1` 七协议活动任务/socket 与 Stop 归零通过。
异步和同步观测均按 scope 隔离，不添加生产 ABI、全局重置或测试计数器。

`n9-lifecycle-tracer-20260927-v1` 的 20 次先导通过：四种新协议各含正常停止、
活动流停止、握手中停止、监听启动回滚及单流取消/兄弟存活；逐轮在 Stop 返回
时检查资源/FD、重绑端口，再观察 5 秒静默。正式 100 次仍未签收。

`n9-queue-tracer-20260927-v1` 七协议队列观测先导通过。SOCKS UDP、HY2 UDP、
QUIC 收发队列记录每类单队列占用高水位（含已保留发送许可），不是跨队列
累加，也不冒充当前存活对象。生产容量和非阻塞丢弃策略不变。

`n9-pressure-tracer-20260927-v2` 的 3×40-flow 重建及 65 秒短测通过（四种新
协议各 5 TCP +5 UDP）。首次冷进程 FD 4→6 被独立空 Tokio IO driver 复现，
是进程级 Unix 信号管道；因此先初始化空 driver，固定 6 FD 空闲基线。
不以协议预热掩盖泄漏，不允许 Stop 后清理宽限。先导 Stop 后 FD=6、自有计数
为零，短测不是正式 1800 秒门禁。

`n9-ss-native-20260927-v1` 的三算法 Mihomo 消费者通过；同轮官方 ssserver
EIH 在 4096 字节 UDP 失败。`n9-ss-eih-diagnostic-20260927-v3` 的真实日志明确
为 `Message too large`：官方服务端默认禁止 UDP IP 分片。启用官方已有的
`outbound_udp_allow_fragmentation` / `inbound_udp_allow_fragmentation` 后，
`n9-ss-eih-fragmentation-20260927-v4` 的 AES-128/AES-256 EIH 终结端 TCP/UDP、
双外层/目标地址族、错误身份/用户拒绝通过；网络仍为 1500 MTU、第三方未改。
此原生证据不延伸为任意多层 EIH relay 声明。

## 最终候选进度

`n9-final-20260927-v1` 已启动完整最终轮（不是对开发子集拼接）：
49 个两跳消费者追加 Trojan 域名 UDP 原生终结端、实际双向调用方预算、
业务 UDP 与上游载体能力的区分及拒绝后无旁路。七协议故障先导
`n9-failures-tracer-20260927-v1` 已验证 protect/身份/pin 拒绝、外来 UDP 来源、
超长包、单关联取消与兄弟存活，正式轮仍会重跑。

验收脚本新增原始曲线重算与失败注入单元测试；当前 180 项脚本测试通过。
资源登记新增 SS 16 KiB 待写块（共 73 项）；三算法两种首次写入长度的内存
回归覆盖调用方扩充缓冲和大于块上限的输入。全目标编译发现 Cargo 自动发现
辅助模块问题后，将模块移到既有公开消费者子目录，Clippy 全目标重新通过。
独立 feature 测试只建图，不创建物理 socket，七个单 feature 分别验证全部
已启用/禁用协议；Debug/Release 另有真实结构化断言。

该轮五个本地门禁全部通过，但第7个两跳 AnyTLS→VMess 的 carrier 小流
首响应超时，整轮 FAIL、source_unchanged/cleanup 均为 true。此前同组合的
12项大流量及预算/业务UDP检查通过。最小 `carrier_tracer` 在新容器重复
相同10秒超时；仅为直接 AsyncWrite 调用补齐 `flush` 后恢复，生产 VMess
原本允许有界缓冲，公开 relay 已负责刷新。该失败属于测试调用契约，未改
协议源码；red/green分别保留 `n9-carrier-anytls-vmess-red-20260927-v1` 与
`n9-carrier-anytls-vmess-flush-20260927-v1`。后续最终轮必须从头重新执行。

`n9-final-20260927-v2` 在五个本地门禁和45组两跳后，于第46组 VMess→SS
的服务器首包读取失败。`n9-vmess-ss-red-20260927-v1` 在新容器再次得到10秒
EOF；三算法公开 connector 的内存回归缩小为缓冲上游与空首写，2秒超时。
仅去掉缓冲立即通过，恢复后再次超时。自有 SS 层在空首写之后显式刷新并
保存 Pending 刷新状态后，内存回归、原空首写/半关闭检查和原始组合通过。
VMess 与第三方实现未修改；该最小回归进入 Debug/Release required 事件。
v2 所属容器回收、源码保持不变，但整轮仍为FAIL；后续v3重新执行全部门禁。

`n9-vmess-tail-green-20260927-v1` 的 VMess→SS/Trojan/VLESS/VMess 四组均通过，
源码不变、清理完成；随后完整 `n9-final-20260927-v3` 重跑。五个本地门禁、
49组两跳、100次生命周期、100×40-flow重建、官方SS EIH及1800秒压力均通过，
数值保留在该轮原始记录中。但独立 IPv6 明文随机HOP在sequence=732、size=4066
的UDP回包超时，另三组HOP通过；所属容器全部清理，整轮仍FAIL。
该轮共享回归未执行，后续原始记录保留。

独立普通窗口先后通过多轮，不能消除原失败。追加定向分片日志后，
`n9-hy2-v6-fragment-dense-20260927-v1/attempt-3` 在更密集的大包窗口复现：
sequence=1189 的请求到达原站，同一回包的四个分片均被 VCore 的
completed-ID 缓存拒绝，随后超时。该缓存把已完成的16位 Packet ID屏蔽5秒，
而当轮官方 Hysteria `e1366b173ccf5706e1e4630fe8aa654a4b574085`
在 `core/server/udp.go::sendMessageAutoFrag` 随机生成ID；当前 Mihomo 使用的
sing-quic `1c242664697a` 在交付后清空分片，不保留此类屏蔽。

公开 connector 的纯内存 QUIC 夹具用17/18/17/17的ID和四种不同载荷，旧实现
稳定只交付前两包；带日志回归明确记录第三包被同一路径拒绝。初版夹具将
客户端专用 QUIC adapter 用作被动端，握手超时，不算根因证据；修正为独立
内存 AsyncUdpSocket 后的有效 red/green 记录分别为
`n9-hy2-fragment-id-red-20260927-v2.log` /
`n9-hy2-fragment-id-green-20260927-v1.log`。删除自有完成ID缓存后四包交付通过，
未完成分片去重/冲突、来源、容量及过期检查不变。无第三方、跳跃间隔、
网络MTU或超时阈值修改。该公开回归加入 N9 Debug/Release required 断言。

`n9-hy2-v6-fragment-dense-green-20260927-v1` 五个全新原生窗口均PASS，
每轮1500个大包往返、持续60秒、同一认证连接多次跳端口，源码不变且容器
清理完成。该诊断只提高分片密度，不替代正式四组原始大小分布窗口。
`n9-shared-preflight-20260927-v1` 九组/81个共享原生用例均通过，执行器的
独立重建检查、源码不变与清理检查通过；这只是 N9-SHARED 子集。
随后移除全部定向日志与大包强制开关，正式 HOP 输入与期限恢复原样。
完整最终轮 `n9-final-20260927-v4` 从本地门禁重新执行，不继承v3或预检成绩。

v4 的五个本地门禁/68条命令全部通过（Debug/Release各261项，脚本180项），
但在官方Hysteria已下载后的防火墙工具包准备阶段中止；尚未启动49组合。
`package-preparation.json` 记录准备容器started/joined均true、未得到包清单，
实际剩余容器为零；整轮仍FAIL。原始内部异常只留下RuntimeError类型，不能
推测为某种确定网络错误。`n9-package-preparation-repro-20260927-v1` 的全新
官方下载/隔离包准备成功并清理；未改源码、镜像策略或退回缓存。
随后新建 `n9-final-20260927-v5`，完整重跑，不拼接v4的本地成绩。

## 最终签收

`n9-final-20260927-v5` 于UTC 06:48:43–08:34:46完成同一输入全部65组：
五个本地门禁/68条命令、49组两跳、九个运行时门禁、四个独立HY2窗口和
九组/81项共享原生回归全部PASS。Debug/Release各261次定向测试、脚本180项、
netstack17项、Apple五目标/Android两ABI Release构建通过。

100次生命周期最长Stop1,004ms；100×40-flow重建最终Stop85ms。长测
1800.002秒、12,733轮数据交换、1,799次切组和29次断连/新建，正常窗口零
损坏/错投/非预期丢失；堆中位数增长174,416字节≤1MiB，Stop91ms，自有资源
归零且FD回到6，随后5秒静默通过。共享回归另外完成120轮资源检查。

291/291个唯一所属容器回收，实际容器列表为空。源码/lock未变化；从仓库内
相对路径、仓库外绝对路径分别执行独立coverage均退出0。v1–v4保留原FAIL，
没有用其局部PASS抵扣v5。详细输入、数值和595份artifact索引摘要见[N9报告](N9.md)。

所有服务端测试继续容器化。历史成功不拼接成本轮成绩；N10 的平台、设备、
远端 CI、签名与发布仍独立。
