# 验证范围与发布边界

核心离线测试见 [tests](../tests/README.md)，平台编译入口见 [scripts](../scripts/README.md)。
容器互通、压力与性能比较由公开的
[container-benchmark](https://github.com/YuanDevTeam/container-benchmark) 的
`interop` / `stress` / `compare` 分别执行，通过 `--source vole=PATH`
显式指定被测 checkout；Vole 编译入口不执行网络或压力验收。
本文定义证据边界，不是随源码自动续期的“全部通过”证明。
文中统一使用当前工程名称；改名前的实验保留原始源码与产物身份，原始命令以独立
benchmark 的历史记录为准，名称更新不构成重新验收。

2026-10-08 工程更名验证在 macOS 执行：`cargo fmt --all -- --check`、
`cargo test --locked --all-features --all-targets --no-run`、
`cargo clippy --locked --all-features --lib --bins -- -D warnings`，以及
`cargo build --locked --no-default-features --features cli,ffi --lib --bin vole` 均通过。
CLI、共享 Invoke、配置、平台、TUN、路由、两个本地 crate 的纯内存回归通过；
新 CLI 的文件、标准输入、环境默认和输出验证通过，实际加载 `libvole` 调用
`VoleInvoke` / `VoleFree`，核对新构建身份与旧导出移除。构建脚本 41 项、benchmark
146 项 Python 回归及离线 Go 分类回归通过；Windows 四个 backend 依赖图检查通过。
本轮不重跑容器压力、原生 Windows 构建、设备或正式发布。

## 核心压力测试

独立 benchmark 的 `stress` 面向指定 Vole 的原生 Linux TUN，默认 2 Gbps /
60 秒 / 1,000 QPS DNS，与 `compare` 一样固定只加载增强 DAT 中完整的
`geosite:cn` / `geoip:cn`。原件下载和更新不裁剪、不扩展匹配器分类范围。
当前 Vole CLI 压力入口尚无运行中的 GeoData 状态采样，显式拒绝
`--geodata-update`，不以旧 C ABI 采样或离线 probe 替代运行中更新的证据。
`compare` 执行 Vole/Mihomo 1/1.5/2 Gbps 对比。两者分别记录混合 TCP/UDP 与 DNS 负载
及指定内核 PID 的内存峰值，实际输入和门槛以 benchmark README 为准。
50,000,000 bytes 为宿主工程目标；报告实际吞吐、丢包/错误、CPU、RSS 和 DNS 完成数。
未达到目标负载不能宣称该档内存通过，数据损坏、崩溃、观测或清理失败不能隐藏。

压测不以候选冻结、全协议/规则语义矩阵、对端零丢包容量校准、平台构建或真机准备
作为前置。协议正确性、发布和物理设备验收保持独立，宿主结果不证明 iOS/tvOS
Network Extension 实机内存。当前保持 standard，不新增生产业务数量配额。

参数和范围由独立 benchmark README 维护；记录实际命令、源码身份、测量和失败，
结束清理本轮产物，仅保留脱敏文字结论与共享公共依赖。复验重新运行，旧结果不续期。

GeoData 属性/反选、真实 Regex 编译、合成 Plain 和双快照重叠由独立 builder probe
记录；它不包含生产 TUN/DNS 运行时，不能拼成更新与满速流量叠加验收。真实 DAT
没有的类型明确报告为零，不把合成记录计入真实压力规模。最新完整 CN 结果与历史
128 万无 Regex 基线分别见 benchmark README；均不代表任意输入内存保证或
iOS/tvOS 实机验收。

2026-10-08 CLI / Invoke 重写后，使用显式指定 checkout 的 `stress` 入口执行
2 Gbps / 60 秒压力：生产 CLI 通过
`-d data -f config` 启动，从 `tun.file-descriptor` 借用原生 Linux TUN。
Rust 1.99.0、GNU ARM64 Release、Ubuntu 26.04.1 LTS、NAT、5 CPU / 8 GiB，
TUN 与 eth0 队列为 4096；builder 在施压前停止。
完整 CN DAT 为 GeoSite 111,400 / GeoIP 9,648 条，64 条混合 TCP/UDP 流、
1,000 QPS DNS。实际吞吐 1,991.176 Mbps，CPU 141.662%，RSS 峰值
26,075,136 bytes（24.867 MiB）；负载、DNS 和内存门槛通过，case 为 PASS。
UDP 上行零丢包，下行丢失 197 包，合计 197 / 6,249,984（0.003152%）；
16 条下行接收超时，`driver_complete=false`，没有内容损坏。
DNS 成功 60,000 / 60,000。真实 TUN 就绪、拒绝见证、fd/MTU 保持和测量有效；
CLI 响应 SIGINT 正常退出，容器、采样器和 scratch 均已清理。
源码在本轮构建与压力期间未变；完整源码、锁文件、二进制和输入身份见独立
benchmark 的 `conclusions/20261008T090052384923Z-run-3qibok_7.md`。
该结果不等于全部流完成、零丢包、运行中 GeoData 更新或物理设备验收。

本轮 macOS 离线检查执行了 `cargo fmt --all -- --check`、
`cargo test --locked --all-features --all-targets --no-run` 和
`cargo clippy --locked --all-features --lib --bins -- -D warnings`；
CLI、配置、共享 Invoke、路由、平台适配器、TUN 和 netstack 的显式纯内存回归通过。
Windows x64/ARM64 的 backend 依赖图及内存设备替身已检查；原生 Windows 构建、
外置 Wintun DLL / 真实设备、UWP 设备和六平台正式 tag 发布本轮均为 NOT RUN。
相关 CI 门禁已配置，不将配置存在计为执行通过。

2026-10-06 切换常规 `regex::bytes::Regex` 后，执行两轮完整 CN 原生 Linux TUN
复测：`compare` 单内核模式、显式指定 checkout、2 Gbps / 60 秒，
仅加载 `geosite:cn` / `geoip:cn` 共 121,009 条，正常 Release + 生产 FFI，
Ubuntu 26.04.1 LTS、NAT、5 CPU / 8 GiB、1,000 QPS DNS，线程/队列保持默认。
RSS 峰值为 28,008,448 / 30,543,872 bytes，低于 50,000,000 bytes；分流与
观测有效、进程正常退出，容器和 scratch 已清理。
实际带宽仅 1,966.61 / 1,959.93 Mbps，**两轮均未达到 2 Gbps 的 99% 负载门槛**；
发送速率也低于门槛，不能把差额全部归因于正则替换。UDP 丢包为
7,077 / 28,190 包（每轮发送 6,249,984 包），DNS 成功 59,790 / 59,585 次
（各计划 60,000），仍有超时和跳过；不宣称整体 2 Gbps、零丢包或全部查询通过。
完整输入身份与两次文字证据见 benchmark README。本次未复跑完整资产或双快照
probe，Linux RSS 不替代 Apple 实机 footprint，也不是任意输入的内存保证。

以下全分类资产与双快照数据仅为 2026-10-06 旧 dense DFA 历史记录，不属于固定 CN 场景：
完整增强资产共 1,572,166 条（GeoIP 1,054,987、GeoSite 517,179），
未截断的 60 秒 / 2 Gbps / 1,000 QPS DNS 混合压力取得有效观测：实际吞吐
1,993.88 Mbps、CPU 154.06%、指定 Vole 进程 RSS 峰值 53,542,912 bytes。
50,000,000 bytes 内存目标 **未通过**；UDP 丢包 2,911 / 6,249,984，DNS 成功
59,843 / 60,000 次计划查询。负载门槛通过不等于零丢包或全部查询完成。
同轮离线双快照 probe 峰值 64,045,056 bytes，也超出该目标；它不是运行中更新
叠加满速压力的结果。所有容器已正常退出并清理，不据此恢复条数截断。

## 必须保留的验证

| 层次 | 验证内容 | 不能证明 |
| --- | --- | --- |
| 离线 / 纯内存 | 严格配置与 feature、DAG/组快照、协议向量、TLS 身份/签名/pin、取消与局部上限、FFI 所有权 | 网络互通、设备 |
| 容器互通 | 公开配置和消费者、真实认证及负例、传输关闭、UDP 来源与边界、受控 DNS/上游 | 任意字段组合或公网服务 |
| 集成 / 压力 | 八出站 64 有序两跳、SS v3/UoT/TUIC 强耦合链、运行时切组、Stop/回滚/测速、混合重建与长测 | 无扰动吞吐基准或整机内存保证 |
| 平台构建 / ABI | 同一锁文件、产物架构/身份/hash、打包依赖；原生 C/Swift 消费者另行验证 | 物理 TUN、签名安装；delivery 不执行原生消费者 |
| Apple 模拟器 | 生产库的 C ABI、生命周期、容器原站 SOCKS5 TCP/UDP、合成 utun TCP/UDP、fd 借用和错误路径 | 真机 Packet Tunnel、完整协议矩阵、整进程 50M / 1 Gbps 验收 |
| 设备 / 发布 | 真机网络、protect/物理绑定、正式宿主生命周期、签名安装及商店门禁 | 其他平台或后续 revision |

保留独立 ClientHello golden、Encryption 密码向量、H2 完整响应后 RST、SS 背压/读先于写的刷新、
HY2 已完成分片 ID 重用等确定性回归。单纯复用实现生成期望值、声明字段数量或找到 PASS
文本，不能替代行为验证。ignored、未运行、基础设施失败和清理失败均不得计为通过。

## 当前容器互通入口

默认编排 64 个代表用例：Mihomo 26、Xray-core 20、Hysteria2 5、V2Ray 10、
Caddy/Xray H3/mTLS 3。具体配置由 benchmark 的 `interop --list` 和源码定义，
可按 `--backend` / `--protocol` 筛选；命令存在或离线通过不等于当次互通通过。
消费者统一使用生产 Invoke ABI；每轮构建一次，再顺序运行各组的三个 Linux
隔离容器（NAT、5 CPU / 8 GiB）。编排已移至独立 benchmark，Vole 只提供被测源码；
原入口的历史通过不能作为迁移后本轮重新运行的证明。

2026-10-06 迁移后仅重新执行 Mihomo SOCKS5 TCP/UDP 短测并通过：TCP 双向
各 1,024 bytes、UDP 双向各两包（64 / 1,200 bytes），来源见证、正常 Stop 和
容器清理通过。其余 63 用例本轮 **NOT RUN**，不继承旧完整矩阵的通过状态。

正例核对双向 payload 和原站所见实际协议对端来源；SS2022 是非空 client-first。
Trojan 的域名 UDP 经 Xray TCP/WS/gRPC 补验；XHTTP H3 的四模式、独立下载腿和
静态 ECH 由 Xray 补验，下载腿必须汇入同一个 handler。Hysteria2 的 mTLS 正/负例、
16 端口跳跃、跳跃叠加 Salamander 与禁用 UDP 使用官方原生服务端；跳跃须保持
同一关联至少 16.5 秒且观测至少两个实际目的端口。认证拒绝和禁用 UDP 负例必须
有被拒绝业务的原站零交付证据。VMess/VLESS 的 HTTP 首包伪装、legacy H2 和
扩展 WS ED 由 V2Ray 补验；H3/mTLS 由 Caddy 的真实 `require_and_verify` 终结后
H2C 转发到同一 Xray handler，并验缺身份及错误 CA 拒绝；不宣称原生 Xray 支持 mTLS
或 legacy H2。AES EIH 对 Xray 验两算法正例及错误 identity/user 的 TCP/UDP 零交付；
H3 packetaddr 与三种 sing-mux 使用 Xray XHTTP 透传到同容器的回环 Mihomo 解码端。

Encryption、REALITY/JLS 等额外配置不在本入口覆盖内。这套代表入口不代表历史
完整字段、代理链、切组/重建长测、ClientHello golden 或
设备矩阵全部恢复或重新执行。独立密码/ClientHello 输入与纯内存回归继续保留，
不得由单协议短探测拼成完整验收。所有声明以当次源码/锁文件/对端 hash、容器内
版本、实际业务及清理结论为准；历史完整矩阵与标准仅在下方链接查阅。

## 对端与已知限制

- 所有协议端、原站、DNS 和提供入口的对照客户端遵守[隔离规则](testing-isolation.md)。
  优先 Mihomo listener；当前代表缺口由官方 Xray、V2Ray、Hysteria 与 Caddy 网关补验。
  历史官方 Shadowsocks 补充对照不意味着当前入口已恢复相同覆盖。
- 关闭行为按 Mihomo 的实际传输包装链验证；不要求所有传输在上传 EOF 后仍收到尾包。
- WS + REALITY 的数据/认证对 Mihomo listener 验证；关闭使用同种 WS 的标准 TLS 分层参照。
  无指纹 JLS/gRPC、Safari ECH/gRPC 的官方对照缺口使用明确标注的 Chrome 关闭参照。
  这些不是完全同配置的客户端差分。
- XHTTP H3/mTLS 使用获准的 Caddy 网关；packetaddr/sing-mux 等分层拓扑明确标注
  网关、会话处理器和解码端，不能宣称单个原生服务端直接支持全部能力。
- 官方 Hysteria 回包缓冲包含协议头；V2Ray 部分 VMess 返回路径也有更小缓冲。
  原生夹具上限不改变 Vole 的协议预算。
- SS 原样上游 padding 未初始化风险及空首包随机零 padding 被严格服务端拒绝的限制
  仍未修补。裸 SS、EIH 与 SS v3 TCP 的空首包/server-first 明确不在必过正例内，
  不计作互通成功；保留确定性拒绝负例。TCP 改验非空首段的 client-first，仍须三地址族、
  双向各 10 MiB 摘要、认证和关闭；其他协议的 server-first 与 SS UoT 首写门控不变。
  codec 级刷新回归不证明 server-first 互通。官方 ssserver 单层 EIH 终结与自有
  1/2 层身份中继是不同证据，不能据此宣称任意多层原生 EIH。详见[出站](outbounds.md#shadowsocks-2022)。
- ShadowTLS 只支持 SS2022 的 strict v3/TLS1.3 TCP 包装，原生 UDP 单独验证。
  主对端为 Mihomo，官方 ShadowTLS + 原样 ssserver 为补充对照；内存中的 cover
  server-first 不代表官方 SS 空首包限制已解决，额外四字节记录特征仍存在。
- SS UoT 仅 v2，裸流/v3 与三算法分别验证 TCP-only Mihomo listener，包含
  TCP-only SOCKS5 上游、切组、零长度包与 UDP 旁路观测。当前 Mihomo 的 UoT 接收
  缓冲为 16 KiB；原样 ssserver 只作不支持 UoT 的负例。Vole u16 codec 边界、
  调用方双向预算和该对端实际包上限分别取证，不相互替代。
- 静态 ECH、JLS、Encryption 与混合 REALITY 是选定能力集；动态 ECH、Restls、
  ShadowTLS v1/v2、WireGuard 不在当前范围。
- TUIC v5 的 native/quic、三算法、身份拒绝、三地址族与上游组合对 Mihomo 验证；
  认证没有 ACK，不以本地 SOCKS 成功当作密码通过。独立内存 QUIC 验 u16、分片/ID
  退役、credit、窗口和同步 Stop，网络包大小以实际链路为准。TUIC suite 包含
  Hysteria2 和 XHTTP H3 受影响回归，不代表新的八协议完整压力或设备验收。

## 当前证据如何使用

精简前的[冻结验收索引](https://github.com/YuanDevTeam/Vole/blob/b7c0100602e188bf28b9fa5370e11120069b54f7/docs/acceptance.md)
保留各次运行、原始失败、环境和适用 revision；[完整阶段记录](https://github.com/YuanDevTeam/Vole/tree/b7c0100602e188bf28b9fa5370e11120069b54f7/docs/acceptance)
可在 Git 历史查阅。它们不再复制到当前文档。

该基线记录过本地协议集成、持续压力与 Apple/Android 构建通过；随后 boring release /
Shadowsocks registry 接入只做了定向 JLS、SS 和离线回归，没有重签全部组合及长测。
平台交付仍未完整签收。这些是历史记录范围，不代表当前 checkout、远端 CI 或发布候选
已经重新执行。后续生产构建结果放当次 PR、CI artifact 或发布记录；容器实验仅保留脱敏文字结论，
绑定源码、锁文件、对端、命令、结果及清理状态，不在本文累计包哈希和阶段流水账。

## 尚需独立签收

- iOS/tvOS 无 debugger 的 Release Packet Tunnel 生命周期、宿主 raw-fd/packetFlow 接入及
  整进程内存；tvOS 以 17.0+ ARM64 为平台边界，模拟器与构建不证明真实扩展可交付。
  Android 真机 TUN/protect、
  DNS/TCP/UDP、重复启停；macOS system extension 正式宿主安装和生命周期。
- Windows 10 20H2、原生 x64、真实物理 IPv6、物理网卡禁用、多用户/远程会话；
  session backend 包路径/argv/退出与 Job 清理、正式宿主 UI。
- production-signed MSIX、WACK、Partner Center identity/publisher 与受限能力、
  ARM64/x64 Store bundle、提交及安装。
- 干净 checkout、同一 lockfile 的平台产物、原生运行库和完整许可证审查。

Windows 11 ARM64 历史开发包曾覆盖数据面、policy 和生命周期；loose-package、
单个 LAN peer、合成 utun 或交叉编译均不能抵扣上述门禁。记录遵守隐私规则，不含
真实凭据、UUID、密钥、完整用户配置或私有目标。
