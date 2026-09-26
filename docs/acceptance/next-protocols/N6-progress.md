# N6 Hysteria2 开发记录

2026-09-26，分支 `feat/hysteria2`，基线 `a9495fc5cea061d208780619fd9bf6c82480bae5`。

**N6 已完成本地阶段签收。** 最终完整结果见 [N6 验收](N6.md)；下文保留开发期的增量证据与真实失败，不将旧 FAIL 改记 PASS，也不以子集拼接签收。

## 复用决策

用户要求先调查 Rust 实现，并允许在第三方库不能满足需求时内部实现。已核验 `rsteria2 0.1.1`、`hysteria2 0.1.6`、`crapthings/hysteria-rust`、其他应用内实现及 clash-rs/meow-rs/shoes。没有发现可原样满足完整 N6、受控 socket/上游组、共享 TLS/mTLS 和同步 Stop 的稳定库。

- `rsteria2` 的公开客户端入口自建 socket/TLS；公开 BrutalFactory 没有独立 wire pacer，不能以窗口近似直接证明固定线速。
- clash-rs 是内部 Quinn/h3 实现，带宽控制接入仍有 TODO；meow-rs 是内部 quiche 实现；shoes 的 Hysteria2 是服务端。
- 因此保留现有官方 Quinn/h3/rustls 和 VCore 的 Dialer、TLS、数据报、生命周期接口，内部实现 Hysteria2 薄协议层；不修改第三方、不引入另一套网络核心，不使用 references 路径作为生产依赖。
- 2026-09-26 通过官方 sparse index 核验 Quinn 0.11.12、quinn-proto 0.11.18、h3 0.0.8、h3-quinn 0.0.10 为当前非撤回稳定版。

参考：[官方协议](https://v2.hysteria.network/docs/developers/Protocol/)、[rsteria2 发布源码](https://docs.rs/crate/rsteria2/0.1.1/source/src/lib.rs)、[clash-rs](https://github.com/Watfaq/clash-rs/tree/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/hysteria2)、[meow-rs](https://github.com/meow-rs/meow-rs/tree/22705030e880a82c84b24a2a3bca6365ef077a2a/crates/meow-proxy/src/hysteria2)、[shoes](https://github.com/cfal/shoes/blob/60ed3838b346268615c81e4eace4e15e717da23e/src/hysteria2_server.rs)。仅源码调查不构成候选运行结果。

## 开发期增量验证

所有原生服务端和原站均在本次独占 Apple Container host-only 容器内，guest MTU 1500；无宿主服务端、端口发布或宿主网络修改。每次重新下载官方 latest Mihomo，本轮实际版本 `v1.19.31`，二进制 SHA-256 `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。

| 增量 | 本轮证据 | 结果 |
| --- | --- | --- |
| 配置入口 | `cargo test --locked --features outbound-hysteria2 --test hysteria2_config` | 从未知协议 RED 到基础/组合字段 GREEN；尚不是完整拒绝矩阵 |
| TCP wire | `cargo test --locked --all-features --lib outbound::hysteria2::wire::tests` | 固定协议帧、边界、响应不吞目标首包，通过 |
| 原生 TCP 基线 | `target/interop/runs/n6-tcp-green2/report.json` | IPv4/IPv6/域名双向各 10 MiB、client-first、measureDelay 通过，源码未变、清理完成 |
| 原生 UDP 基线 | `target/interop/runs/n6-udp-green1/report.json` | 三类目标，各 1/64/512/1200/4096 字节各 100 包，共 1500 包，包含真实分片往返；源码未变、清理完成 |
| 带宽纯逻辑 | `cargo test --all-features --lib outbound::hysteria2::bandwidth::tests` | 协商分支与确定性 token-bucket 测试通过 |
| 真实带宽专项 | `target/interop/runs/n6-bandwidth-first/report.json` | 10 个样本通过；每样本预热 10 秒 + 测量 30 秒；源码未变、清理完成，命令 435.832 秒 |
| Salamander 向量 | `cargo test --locked --all-features --lib outbound::hysteria2::salamander::tests` | 与独立 Python hashlib BLAKE2b-256 固定向量相符；拒绝 ≤8 字节短包 |
| Salamander TCP | `target/interop/runs/n6-salamander-tcp-green/report.json` | 三类目标双向各 10 MiB、client-first、测速通过；源码未变、清理完成 |
| Salamander UDP | `target/interop/runs/n6-salamander-udp-green/report.json` | 三类目标、1500 包（含 4096 字节）通过；源码未变、清理完成 |
| 安全矩阵 | `target/interop/runs/n6-security-serial/report.json` | 23 项真实 Mihomo 证书/pin/mTLS/ALPN/认证/混淆正负组合及非法 identity 配对通过；源码未变、清理完成 |
| 官方 H 固定 IPv4 跳跃 | `target/interop/runs/n6-hopping-green1/report.json` | 60 秒 TCP/单个 IPv4 UDP 关联、至少 8 次新受保护 socket、单次认证、三个实际端口及资源清理通过；仅此增量，不抵扣后续完整矩阵 |
| 官方 H 随机 IPv6 + 混淆 | `target/interop/runs/n6-hopping-ipv6-obfs-random-serial/report.json` | 60 秒 TCP 双向各 93.75 MiB、三类 UDP 目标共 1500 包、实际最大值 + 1 的对端丢弃、至少 8 次新 socket、单次认证及 5 秒静默通过；源码未变、清理完成 |
| 自有资源生命周期 | `target/interop/runs/n6-owned-life-first/report.json` | 20 轮并行流/UDP、取消未完成握手、过期 deadline；每轮 Stop 立即归零且静默 5 秒，通过 |
| 跳跃时 protect 拒绝 | `target/interop/runs/n6-hop-protect-first/report.json` | 新 socket protect 失败使现有连接失败关闭，无新认证/业务重放；Stop 后资源归零且静默 5 秒，通过 |
| Mihomo 关闭对照 | `target/interop/runs/n6-mihomo-close-green/report.json` | 同配置官方客户端与 VCore 的逻辑流关闭尾包均为空；修复前的差异单独保留 |

带宽样本原始每秒桶、RTT、cwnd、丢包及 QUIC UDP 字节量保留于 `n6-bandwidth-first/bandwidth.jsonl`。无上限上传/下载基线约 55.1/91.6 MB/s；1/2 Mbit/s 的双向实测业务载荷分别约 122,334/244,668 B/s，服务端较低的 1 Mbit/s 上限均约 122,334 B/s。上传测量来自容器原站收到的字节，不取客户端写入缓冲区速度。Mihomo 在 `down=0` 时返回 RxAuto，因此 `up=2,down=0` 仍按 BBR；`ignore-client-bandwidth` 独立样本也按 BBR 连续传输。每个流的双方 SHA-256 一致。上述是无人工丢包的受控本机容器实验，不等于真实 WAN 或设备性能。

开发期定向命令为 `uv run --project scripts --locked python -m vcore_scripts.protocol_hysteria2 <fresh-run-dir> [test-name]`；早期尚未接入统一阶段 runner/catalog，不将这个增量入口标为 N6 完成。

## 真实失败与修复

`n6-tcp-red` 确认 Runtime 尚未实现；`n6-tcp-green1` 的三组 server-first bulk 通过，但 client-first 超时。`n6-client-first-red` 在全新连接单独复现，排除前三条流的复用/关闭影响。Mihomo 的 serverConn 可以将成功响应和目标端首批数据合并发送，客户端也采用首读解析响应。VCore 不再在返回可写业务流前阻塞等待响应；响应解析仍有界，并保留原建立期限。完整原始基线 `n6-tcp-green2` 通过，不抹去此前失败。

UDP 载荷上限暂按 Mihomo 与官方 Hysteria 的共同 4096 字节边界实现，`udp-mtu` 是分片消息预算；仍需补实际最大值 + 1、重组/来源/取消等独立门禁。

`n6-salamander-red` 用真实开启混淆的 Mihomo 复现旧实现超时；当前补充 RustCrypto `blake2 0.11.0`（2026-09-26 官方最新稳定版）与独立 Salamander Adapter。混淆只改变每包内容和 8 字节预算；pacer 计入 salt，socket 仍由共享 Dialer 创建。

原生 Hysteria latest 实际为 `v2.12.3` / `e1366b173ccf5706e1e4630fe8aa654a4b574085`。`n6-hopping-red`/`red2` 在夹具观察规则加载阶段失败；规则结束括号缺少换行，已修正，没有改动容器外防火墙。`red3` 发现官方 `correctnet` 将 `[::]` 明确绑定为 IPv6-only，改用各用例的具体地址族。`red4` 认证、TCP 与较小 UDP 成功，但 4096 字节 UDP 回包超时：官方 `core/server/udp.go` 的 `msgBuf` 为 4096，`udpIOImpl.SendMessage` 在包含协议头的序列化长度超限时直接静默丢弃，尚未进入自动分片分支。Mihomo 的完整 4096 业务载荷 PASS 保留；官方 H 跳跃用例按实际回包上限 `4096 - UDPMessage头长度` 验收，不修改第三方、不把这个限制伪装成 VCore 的已修复问题。所有这些失败均已清理容器。

`n6-hopping-red5` 在第 9 秒明确断言没有创建第二个受保护 socket。当前使用公开 Quinn rebind 接口和受控数据报路径，每次实际新 socket 均经过 Dialer，旧路径最多保留 1 秒；修复后 `n6-hopping-green1` 通过。`n6-security-first` 在容器 IPv6 就绪检查失败，`n6-hopping-ipv6-obfs-random-first` 在准备容器下载 nftables 包时失败，均未进入协议验收；容器已清理，串行新运行通过，不替换原记录。

`n6-public-graph-first` 的上游 UDP 超时；最小 TCP 上游用例通过、`n6-concrete-upstream-udp-red` 对 IPv4 UDP 复现，排除业务域名因素。同一 Mihomo 同时承担 SOCKS5 上游和 HY2 服务端时，解封装业务 UDP 的源 tuple 命中其 DIRECT loopback detector；将上游放入独立容器后该问题消失，不改第三方或 VCore 协议实现。`n6-public-graph-isolated-hop` 随后指出测试误将业务 `udp:false` 当作 raw carrier 不支持；保留正确的路由/connector 区分后，`n6-public-graph-carrier-contract` 通过具体上游、嵌套 select、跨两次物理跳跃的旧连接快照、新会话 REJECT/DIRECT、未选中环及坏成员不回落。原失败与容器清理记录均保留。

`n6-mihomo-close-first` 复现 VCore 在上传 EOF 后仍收到原站尾包，而同配置官方 Mihomo 客户端得到空尾包。VCore 改为关闭整条逻辑流的双向通道，不关闭共享 QUIC；原生对照及内存测试 GREEN。进一步以挂起的 read 复现漏唤醒，关闭时显式唤醒该读操作后回归通过。

统一入口的 `n6-local-gates-first` 在脚本测试发现旧指纹 CLI 参数测试重复获取套件互斥锁；独立运行 154 项均通过。该参数测试改为真实的独立临时锁，正常原生测试互斥不变，`n6-remaining-first` 的脚本门禁通过。该轮同时通过 UNIT、共享 10 秒期限/调用方 UDP 预算、HTTP/SOCKS/模拟 TUN、IPv6 开关及跳跃中 Stop，随后在 UDP 极限夹具失败，没有标记整轮通过。

`n6-udp-boundary-minimize` 确认 `udp-mtu=64` 与较长 IPv6 authority 时不能假设 4096 字节都可编码，必须相交 255 片上限。修正后 `n6-udp-boundary-budget`/`trace` 在 255 片极限仍有未到达原站的失败；不能据此断言为第三方缺陷。`n6-udp-fragments-trace` 的大小/片数观测显示 255 片可成功，但后续测试误在自身刚发送超限包、已终止的 SOCKS 关联上验证“兄弟存活”。当前测试分开这两条契约，发送大量分片时每 32 片主动让出调度，与接收侧公平性预算一致；不重放业务、不修改第三方、不放大验收容差。所有原失败记录保留，诊断日志代码已删除，仍须完整新运行。

内存用例 `a_client_first_write_does_not_steal_a_pending_read_wakeup` 进一步稳定复现：已挂起的 reader 与 client-first writer 共用响应 future，最后一次 write poll 覆盖底层唤醒地址，导致业务 response 到达后 reader 仍未运行。当前响应使用读/写唤醒扇出；该用例从 100ms 超时 RED 到 GREEN，三个 TCP 并发/关闭内存回归均通过。

`n6-integration-second` 六个完整增量门禁通过：带混淆的 Mihomo 关闭对照、Xray H3 三模式 TCP/三 UDP 编码回归、20 轮公开生命周期、23 项结构化安全子项、UDP 极限/来源隔离及官方 H 的 UDP-disabled。该子集不替代完整 N6。首个全量运行 `n6-complete-20260926-first` 在全测试编译检查发现旧 Xray 测试漏匹配新枚举；修正后还清理了 future-feature 单元素循环。全目标 Clippy 已通过，随后重新运行完整阶段，不拼接之前的子集结果。

## 完整运行与收尾

`n6-complete-20260926-v2` 完成所有本地门禁、带宽、安全、八组跳端口、两套生命周期共 40 轮、关闭/入口/图/期限和 H3 回归，随后 `N6-TCP` 被证据验收器判 FAIL。真实 Rust TCP 测试成功且退出 0，但清单只期望外层事件，漏登记 IPv4/IPv6/域名三次 `tcp_10mib_both_directions` 内部断言；独立 `n6-tcp-final-red` 同样复现。按真实嵌套事件写回归先得到两个 RED，再要求恰好三次 bulk 后 GREEN；缺少、多出、重复和错 suite 仍失败，未放宽校验或修改协议代码。该轮不改记 PASS，随后复验余下基线并启动新的完整运行。

`n6-remaining-catalog-green` 的八组定向复验全部通过：154 项脚本、普通/Salamander TCP 和 UDP、UDP 边界、原生 UDP-disabled、具体上游。之后启动 `n6-complete-20260926-v3`，冻结源码树 `a9ad301f19a4fa6541fbe6e89cced857f1223da2d0ba3e3f5c9fa806befe37db`；整个新运行与独立 coverage 完成之前不签收。

`n6-complete-20260926-v3` 在随机 IPv4、不带混淆的跳端口组失败：UDP sequence=673、size=4041 等待回包超时。源码未变，容器已清理；该轮仍为 FAIL。相同原生场景的 `n6-hop-random-loss-repro` 独立复跑通过，说明原始症状与时序有关，不能把一次重跑通过当作修复证明。

随后在已批准的受控数据报 seam，`a_new_path_packet_does_not_end_the_old_receive_window` 稳定复现另一条直接相关的接收窗口契约缺口：Quinn 0.11.12 会在新 socket 收到连接包后停止轮询自己的 previous socket，原实现仅延迟旧 driver 销毁，不能保证完整一秒内接收旧路径的迟到包。测试 50ms 超时 RED；VCore 的当前 Adapter 显式同时公平轮询新旧路径、只经新路径发送，期满再回收旧路径后 GREEN，并检查了双侧 pending reader 唤醒。未修改 Quinn 或重放业务包。这证明并修复了窗口缺口，尚不能单凭该内存测试认定它是 sequence=673 原生超时的唯一原因；仍需完整原生重跑。

当时剩余门禁包括完整八组跳端口矩阵、native UDP-disabled、跳跃中 Stop、公开入口/20轮生命周期、UDP 边界、最终源码下带宽/安全/关闭复验、feature/跨平台/共享 QUIC 回归、统一阶段覆盖报告与契约文档；在它们全部通过前没有签收 N6 或进入 N7。

`n6-handover-window-regression` 九组定向复验全部 PASS：12 项 N6 行为断言、完整静态检查、154 项脚本、代理图/快照、protect 拒绝、跳跃中 Stop、随机 IPv4 无混淆、随机 IPv6 带混淆，以及 20 轮自有资源生命周期。两个持续跳跃场景各完成 60 秒、TCP 双向各 93.75 MiB、1500 个 UDP 往返、单次认证与资源清理。之后启动全新 `n6-complete-20260926-v4`；本定向子集不抵扣新完整运行。

最终 `n6-complete-20260926-v4` 在源码摘要 `01918e339d489e09f5cf2e26d9055c3f6d9993223f86534a44effe47d8e7500a` 下完整通过 36/36 组 required、20/20 字段；相对/绝对路径的独立 coverage 均 PASS，运行全程源码未变。32 条本地门禁命令退出 0，69/69 个所属容器回收。10 个带宽样本、八组持续跳跃、23 项安全、40 轮公共/自有生命周期、共享 H3、既有纯逻辑回归和 Apple/Android 生产构建全部通过。最终输入、产物与原始报告摘要已写入 [N6.md](N6.md)；本阶段仅本地提交，N7、设备与发布仍是独立门禁。
