# N7.4：Restls 生产接线与验收进度

> 范围更新（2026-09-26）：仅 Restls 从 VCore 与自有 boring fork 撤回，JLS 保留；
> Restls 不再属于 N7 交付或验收门槛。下文为历史记录，不代表当前支持；
> Restls 的旧命令不适用于 schema26。

2026-09-26。当前为 schema25 / Invoke v5。**S09–S11 / D22–D24 尚未完成子包
签收，完整 N7 仍未完成。** 本页记录真实开发失败，不用 fork 门禁替代公开消费者。

## 依赖与生产路径

用户已追加后续必要 push 的持续授权。自有 boring 的独立分支
`feat/n7-restls-handshake` 已发布 revision
`d8d6d92912a5e6bd1c43f4c8e1c78fd4a2d74544`；VCore 的三个 boring crate
固定到该不可变 revision。普通 TLS / QUIC 的官方 rustls + ring 路线不变。
没有修改第三方源码，没有恢复旧 rustls fork。

主连接与独立下载连接使用相同的安全接口，仅包装调用者 IO。配置、认证、脚本、
有界记录/缓存与关闭规则见 [Restls 契约](retired-restls-contract.md)。原生握手仍验证证书
策略和 TLS 签名/Finished；Restls 握手后迟到的 cover 记录继续交给原生 TLS
验证，明文不交给业务。原生 fork 验收与 VCore 验收是两个独立边界。

## 已保留的失败

初始公开配置测试因不识别 `restls-opts` 失败；接入后配置测试通过。
纯内存关闭测试发现脚本等待发生在关闭计时开始之前，导致退出上限失效；关闭
期限改为覆盖整个 flush/脚本等待过程，回归先红后绿。

`n7-restls-transports-smoke-v1` 的独立下载 XHTTP 基础用例完成全部 TCP 与三种
UDP 编码断言后，在 5 秒 `measureDelay` 超时，整项保持 FAIL。最小公开复现
`n7-restls-measure-repro-v1` 同样失败，未增大超时或放宽成功断言。

定向诊断 `n7-restls-measure-cover-trace-v2` 只记录阶段/单调时间：第一条 cover
TLS 于 14.418 秒就绪，第二条到 19.416 秒才被接受。夹具串行接受连接，第一条
等待应用数据使第二条独立下载连接排队；不是 UDP 丢包或生产关闭语义差异。
夹具改为最多八个并发 cover，仍保留每条五秒上限；生产协议未因该失败修改。
临时诊断日志已移除，`n7-restls-measure-concurrent-v1` 重新执行最小复现与完整
基础用例，两项均 PASS，源码不变、清理完成。

前一次短日志没有落入运行报告，是读取尚未结束的 follow 进程缓冲所致；VLESS
运行器现在在清理前抓取有界容器日志快照。原始空日志与 FAIL 不追改。

`n7-restls-tls13-full-v1` 的 H1 `stream-one` BASE 出现另一失败：第一条
10 MiB TCP 双向传输完成，第二条 IPv6 literal 连接等待五字节首包时于 10 秒
收到 `UnexpectedEof`；同模式 CLOSE 对照通过。整轮最终为 **51 PASS / 1 FAIL**，
source unchanged / cleanup 均 true；不能拼接单独重跑的成功把本轮改为通过。

### 官方 Mihomo 的 H1 stream-one / Restls 服务端阻塞

`n7-restls-h1-original-repro-v1` 原样单独重跑通过，故保留偶发性。新增公开
消费者 `public_restls_server_first_repeated` 去掉大流量、UDP、DNS，仅循环读取
五字节服务端 greeting 和四字节回显。`n7-restls-h1-server-first-repro-v1`
第三条连接失败；纯 IPv4 的 `n7-restls-h1-server-first-ipv4-v1` 首条连接即失败。
原来的 IPv6、先前连接复用和大流量不是必要条件。

`n7-restls-h1-server-first-trace-v{1,2}` 仅记录状态和长度，证明原生认证成功、
请求与脚本响应已写到受控底层，HTTP 响应首段已交给 H1；未触发接收缓存背压。
`n7-restls-h1-server-stacks-v1` 在用例已失败后，对所属容器的已核实 peer 进程
发送 SIGQUIT 留取 Go 栈，再按原所有权清理。栈停在
`restlsServerState.waitToClientWritable` → `writeRestlsRecords` →
`restlsServerConn.Write` → `ResponseController.Flush` → XHTTP `ServeHTTP:478`。

官方 `restls-client-go v0.1.9` 服务端在持有写锁时等待下一条客户端记录来解除
脚本暂停；解除发生在 `Read`。但 Mihomo 的 H1 `stream-one` 处理器先同步刷新
响应头，随后才启动读取请求体的 `connHandler`。当响应头落入仍带 `<1` 的脚本行，
且该次 HTTP 请求头已经完整时，写方等待尚未启动的读方。客户端增加超时或多发
padding 不能保证解除这一服务端调用顺序形成的阻塞。[服务端脚本实现][M-SCRIPT]、
[XHTTP 处理顺序][M-H1]

独立 `n7-restls-h1-mihomo-client-repro-v1` 使用**官方 Mihomo 客户端到官方
Mihomo 服务端**，客户端设有效 `restls-script: "4096<1,4096<1"`，服务端仍为默认
脚本。同样在读取 greeting 时十秒超时，服务端栈停在相同位置。该运行在
`peer-start` 的对照阶段失败，VCore 协议消费者未执行；不称为双方默认配置的
完全同配置复现，但足以独立证明该服务端组合的缺陷。源码未变、所属容器清理完成。

临时状态日志和 SIGQUIT 钩子已移除。`protocol_restls --restls-script` 保留为
明确记录自定义客户端脚本的正常夹具入口。旧 FAIL / 栈证据保留，不修改第三方，
也不通过改变默认脚本或 padding 隐藏问题。

独立官方 `3andne/restls` 的 latest 发布资产已接入**单独编号**的容器拓扑：
原生 Restls 前置层 → 单个明文 Mihomo XHTTP handler。cover 也在容器中，使用
原生 CLI 固定要求的 443 端口。服务端保留原生默认脚本，不修改第三方。发布标签
为 v0.1.1，但包内 `--version` 为 `basic 0.1.0`；同时记录下载 URL 与二进制摘要。
`n7-restls-h1-native-smoke-v1` 的 20 次公开 server-first + ping 全部通过，
源码不变、清理完成。此结果只证明该原生分层拓扑，不把 Mihomo 的失败改判。

### 客户端脚本回复顺序

对照官方 Go 客户端还发现独立的回复顺序差异：先恢复被脚本暂停的应用发送，
随后仍应发送每一条被请求的 padding 回复。恢复发送不能抵扣回复数量，因为
其 `Write(empty)` 接收的新数据长度为零。新增行为断言在原实现下超时失败；
调整发送顺序后，`n7-restls-script-response-v1/green.json` 的五项纯内存安全流
回归全部通过。它不修复上述服务端死锁，也不替代真实网络验收。

随后增加“最后一次 Read 返回后调用方不再执行任何 IO”的一字节背压用例，
`n7-restls-read-reply-v1/red.json` 真实失败：应用数据已返回，但随该记录请求的
脚本回复仍留在客户端队列。Read 现在按官方客户端顺序完成回复后才交付该段
数据，保留有界输入和原写背压；同目录 `green.json` 六项回归通过。新冻结运行
在此修正和 Windows 依赖恢复之后开始，不能借用旧源码的通过结果。

## 已完成的独立检查

`n7-restls-native-tls13-v1` / `n7-restls-native-tls12-v1` 各四项通过：分层 H1
stream-one 的 BASE、CLOSE、20 次 SERVER-FIRST 与 AUTH。两轮 source unchanged /
cleanup 均 true；不抵扣原 Mihomo 服务端缺陷。

`n7-restls-tls12-tickets-v1` 四项均通过：TCP BASE、SCRIPT、真实 TLS1.2
票据隔离，以及 XHTTP 独立下载 `measureDelay`。票据测试通过同一客户端
full → resumed、独立客户端 full、原客户端 resumed 的四条真实 TLS 连接，
逐条检查 ServerHello / Certificate / NewSessionTicket 元数据与数据回环，
不保存随机数或票据内容。运行源码不变、所属资源清理完成。

`target/interop/builds/n7-restls-v1/local.json` 记录 Debug / Release 各 32 项
安全层、76 项配置、18 项 Encryption 单元测试和 46 项配置集成回归通过；
单 feature Restls 八项、无默认 feature 库检查、全 feature / 全 target Clippy、
格式、diff、162 项 Python 测试、Ruff、TLS 依赖及 C header 检查均退出 0。

同目录 `platform.json` 记录 Apple Release XCFramework 与 Android arm64-v8a /
x86_64 Release 构建通过、五份产物摘要及前后源码身份相同。这是构建证据，
不等同于设备、Windows 原生或远端 CI 验证；也不消除前述真实互通失败。

`n7-restls-v2` 的本地与 Apple/Android 检查也通过，但随后依赖 diff 复核发现：
boring 更新同时让 Cargo 将 errno、quinn-udp、rustix、socket2、tempfile 的五条
Windows 依赖关系重新选到旧版。这不是本切片所需变更。已对本任务独占运行器
发送 SIGINT，`n7-restls-frozen-v2/tls13-mihomo` 保留 **INTERRUPTED**（31 PASS，
当前一项 NOT RUN），source unchanged / cleanup true；没有剩余容器。
报告的通用中断原因字段写 `user interruption`，实际是代理为依赖审计主动中止，
不是用户取消，也不是把未完成的 wire 用例改判成功。五条关系恢复到原基线的
`windows-sys 0.61.2`，lockfile 现在仅含三个 boring crate 的 revision 变更；
最终冻结验收须在该修正之后重新执行，不能继承上述构建/网络结果。

### 第三轮冻结输入与本地构建

`target/interop/builds/n7-restls-v3/local.json` 和 `platform.json` 均为 PASS，
各自 `source_unchanged=true`。这是本轮新执行的结果，不继承 v1/v2：

| 输入 | SHA-256 / revision |
| --- | --- |
| 父提交 | `9ec0d5ab96f2916588e8d1dcc7f6dce1ed97c083` |
| CODE_PATHS 内容 | `f4db7b68ba6a74e2cc237cd90e702f85c12a962fefbef28ff837099686ecbb88` |
| tracked patch | `177812fbcd5f1984e13e834078c6d4f620e0a1efc3bfbcd8240b622f9d7a99b1` |
| Cargo.lock | `e3b76e026d6fb32f9a1afa0dcd500a55d97bf309c5a63d2b3decc11e26f98ac7` |

Debug / Release 各自执行 security 33、config 76、Encryption 18 和配置集成
46 项，全部通过。单 feature Restls 八项、无默认 feature library check、
全 features / targets Clippy、fmt、diff、163 项 Python 测试、Ruff 检查/格式、
TLS 依赖审计及 C header 检查也通过，18 条命令全部退出 0、所属进程清理完成。

Apple 五目标 Release XCFramework、Android arm64-v8a/x86_64 Release 库构建
通过。产物相对于同一构建目录的摘要如下；不等同于设备或 Windows 原生验收。

| 产物 | SHA-256 |
| --- | --- |
| `apple/LibVCore.xcframework/ios-arm64/libvcore.a` | `81489c8176a7c9d32c7d81b202a5a1f8a9884da043b6a40f6542712941044e26` |
| `apple/LibVCore.xcframework/ios-arm64_x86_64-simulator/libvcore.a` | `4e3a5e8932c261906cebf3ed96cf939fab6a9eb86ab066147b70b8bd27101b00` |
| `apple/LibVCore.xcframework/macos-arm64_x86_64/libvcore.a` | `b36a46454f1832c3a85d74764977c5c62c0e57e1e2b6e027f856258fc2ea5d37` |
| `android/arm64-v8a/libvcore.so` | `ed0350fd61e71ddc54bfbde230cf8fc274e42469de11fd7676df670a10aa8b79` |
| `android/x86_64/libvcore.so` | `5e5f86a8986831dc036f49960f5aae8f180b9b3e77b352698624cc022789e336` |

同一输入的 `n7-restls-frozen-v3` 原计划 40 个独立运行、243 项用例，未完成。
TLS1.3 的 Mihomo 50 项、独立原生 Restls 四项通过。TLS1.2 在
`N7-RESTLS-GRPC-OWNED` 第四轮、首字节读取时 `UnexpectedEof`，此前三轮
Stop/quiet 资源均归零；Mihomo 同时记录等待 HTTP/2 SETTINGS 超时。代理为
最小复现主动中断后续矩阵，TLS1.2 子报告保留 INTERRUPTED 和已发生的 FAIL，
总报告 FAIL；三份子报告 source unchanged / cleanup 均 true。

`n7-restls-grpc-owned-repro-v1` 原样单独重跑 20 轮通过，故该错误仍视为偶发，
不能抵扣原 FAIL。随后增加去掉 UDP 与五秒 quiet 的反复首字节消费者；
`n7-restls-grpc-startup-repro-v1` 因测试误用不存在的 `stop` 接口编译失败，
并未执行网络用例。更正为既有 `begin_shutdown` / `shutdown` 接口后继续复现。

精简的单流首字节用例分别执行 100 / 1000 次通过，恢复原 gRPC 用例顺序也通过；
这些成功未消除原 FAIL。`n7-restls-grpc-owned-fast-trace-v1` 保留原双流、UDP
与 ResourceProbe 作用域，仅跳过每轮五秒 quiet，在第 546 轮再次出现相同
首字节 EOF / 对端 SETTINGS 超时。此诊断不替代正式 OWNED 的 20 轮与静默门槛。
临时状态/长度观测表明该连接的 HTTP/2 前导、124 字节后续输入和脚本回复均已
写到底层，随后收到对端 EOF；未观测到客户端认证错误或残留发送缓存。
`n7-restls-grpc-official-client-repro-v1` 的官方客户端到官方服务端默认脚本
独立对照 1000 轮通过。因此尚不能将 VCore 原始失败归因为确定的上游缺陷。

`n7-restls-grpc-official-client-split-v1` 再把官方客户端脚本首段显式设为
`24<1`，其余沿用默认段，服务端仍为默认脚本；1000 轮也通过。两次对照均不经过
VCore，source unchanged / cleanup true；不能用其成功把 VCore 的失败改判。

随后仅在首字节等待超过 500 ms 时才请求所属 Mihomo 容器的栈快照。诊断启动器
v1 因重复创建输出目录在网络执行前失败；更正后的 v2 完成 1000 轮，没有触发
快照。扩大次数的 v3 记录到 9671 轮完成、没有触发快照，但汇总时事件文件超过
既有 4 MiB 上限，报告为 FAIL / case NOT RUN，不能记为完整通过。
两轮观察线程均已 join，source unchanged / cleanup true；没有实际发送 SIGQUIT。

临时 IO 日志、500 ms 标记和跳过 quiet 的诊断消费者已移除，正式 OWNED 仍为
20 轮、Stop 后归零及至少五秒静默，不放宽超时或增加业务重试。保留独立的
1000 次新连接首字节用例，不能替代原 OWNED。历史诊断脚本和失败证据仅留在
忽略的 `target/interop/`；抓栈脚本依赖已移除的临时 hook，不是生产验收入口。

清理后重新运行安全层 33 项测试、公开 VLESS 测试编译、163 项 Python 测试、
fmt / Ruff 检查与格式、diff 检查，全部通过。另按报告中的精确所有权名单复核
128 个容器，无残留。这些基础检查不抵扣互通 FAIL；未新增 VCore 提交。
此时 CODE_PATHS SHA-256 为
`c0ce0b2bd4f792a62c9d88593959a59f2da951afdcdebc17c034c75e3563aab8`，
保留的新首字节用例使其不同于第三轮冻结输入，不能声称整轮新矩阵已通过。

上述 Mihomo 矩阵明确排除三个 H1 stream-one case 并保留原始失败，另用官方
原生 Restls 分层用例验收，不覆盖或改判旧结果。计划数不计为通过数。

## 未签收范围

TLS1.2 Restls + Mihomo gRPC 的偶发首字节 EOF 已通过默认脚本下的非致命
goroutine 快照定位为服务端读写互锁：写方持有写锁等待客户端记录，读方却为
发送脚本回复等待同一写锁，最终触发 HTTP/2 两秒 SETTINGS 超时。
2 核容器两次分别在第 7 / 95 条连接捕获；仅移除服务端脚本等待的 1000 次
对照通过。完整输入、原始失败与推导边界见[专项诊断](N7-restls-grpc-diagnosis.md)。
**已定位不等于已修复**；没有修改第三方、默认脚本或超时，当前仍停止子包签收，
也不提交为已完成阶段。上文“尚未查明”的段落保留当时的证据边界。

按用户确认追加的 VCore-only 启动合并实验也未通过：内存消费者确认前导、
SETTINGS 和 WINDOW_UPDATE 已合并，但 2 核 / 双方默认脚本下两次真实运行
仍首字节超时；第 92 条连接的两份快照捕获同类服务端互锁。候选与临时探针
已全部撤回，协议源码摘要恢复原基线；实验与失败证据见上述专项诊断的
“客户端启动合并实验”节。未改第三方或默认脚本，未因此签收任何新组合。

完整两 hint / 命名模板 / 主下载腿矩阵、共享回归、资源/生命周期以及上述
构建尚未汇总成完整通过的冻结验收输入；H1 `stream-one` 的官方服务端缺陷仍须保留，
不能用其他模式或单次成功抵扣其对端边界。
当前通过的定向测试不抵扣未执行项，设备、远端 CI 和 N8 也不在本次结论中。

[M-SCRIPT]: https://github.com/MetaCubeX/restls-client-go/blob/v0.1.9/restls_server.go#L1266-L1319
[M-H1]: https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/xhttp/server.go#L470-L489
