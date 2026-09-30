# 验证范围与发布边界

测试入口见 [tests](../tests/README.md)，命令见 [scripts](../scripts/README.md)。
本文定义证据边界，不是随源码自动续期的“全部通过”证明。

## 内存专项的开发与验收安排

内存专项采用分阶段开发、最终候选统一验收。开发阶段只要求相关编译、必要正确性回归、
短烟测与问题定位，不以完整压力矩阵、重复新进程或长测作为阶段提交和继续开发的门禁。
实现及必要检查完成后可以提交；开发完成与验收通过分开记录。

最终阶段集中执行冻结候选的全部适用矩阵：完整增强 CN 实际分流、两入口/双栈、
TCP/UDP、协议组合、DNS/建断连/背压、更新/生命周期/长测，以及 iOS/tvOS 正式 Provider。
50,000,000 bytes 全生命周期峰值、1 Gbps、工作量、数据正确性和正式重复次数不变。
设施容量或设备/证书缺口不阻挡无依赖开发，但必需项未通过时不能完成最终验收。

历史结果及产物字段不改写，不拼接不同候选的 PASS；改动后的受影响矩阵必须重验。
本安排不免除已发现的正确性、安全、取消或资源回收错误，也不改变其他协议/平台发布
门槛。运行范围和证据字段见[内存设施](../tests/memory/README.md)。
`check memory-matrix` 提供清单、冻结和按组恢复。FROZEN_NOT_ACCEPTED 只表示候选
准备完成；即使 `local_matrix_accepted` 成立，也不能代替正式 iOS/tvOS Provider、
平台/共享回归、外部容量和交付依赖来源审查。当前保持 standard，不新增业务数量配额。

## 必须保留的验证

| 层次 | 验证内容 | 不能证明 |
| --- | --- | --- |
| 离线 / 纯内存 | 严格配置与 feature、DAG/组快照、协议向量、TLS 身份/签名/pin、取消与局部上限、FFI 所有权 | 网络互通、设备 |
| 容器互通 | 公开配置和消费者、真实认证及负例、传输关闭、UDP 来源与边界、受控 DNS/上游 | 任意字段组合或公网服务 |
| 集成 / 压力 | 八出站 64 有序两跳、SS v3/UoT/TUIC 强耦合链、运行时切组、Stop/回滚/测速、混合重建与长测 | 无扰动吞吐基准或整机内存保证 |
| 平台构建 / ABI | 同一锁文件、产物架构/身份/hash、原生 C/Swift 消费者与打包依赖 | 物理 TUN、签名安装 |
| Apple 模拟器 | 生产库的 C ABI、生命周期、容器原站 SOCKS5 TCP/UDP、合成 utun TCP/UDP、fd 借用和错误路径 | 真机 Packet Tunnel、完整协议矩阵、整进程 50M / 1 Gbps 验收 |
| 设备 / 发布 | 真机网络、protect/物理绑定、正式宿主生命周期、签名安装及商店门禁 | 其他平台或后续 revision |

保留独立 ClientHello golden、Encryption 密码向量、H2 完整响应后 RST、SS 背压/读先于写的刷新、
HY2 已完成分片 ID 重用等确定性回归。单纯复用实现生成期望值、声明字段数量或找到 PASS
文本，不能替代行为验证。ignored、未运行、基础设施失败和清理失败均不得计为通过。

integration 另含 TUIC 双模式到 SS v3 三算法的六条链，复跑 TCP-only SOCKS5 到
SS UoT/v3、SS UoT 到 TUIC 等既有消费者。100 次生命周期覆盖基础协议及扩展组合；
100 轮重建和至少 1800 秒长测每轮保持 20 TCP + 20 UDP，TCP 使用 SOCKS5、SS v3、
TUIC、HTTPUpgrade 四组，UDP 使用 SS UoT、SS UoT+v3、TUIC、HTTPUpgrade 四组，
每组五条并轮换算法/模式。原七协议和 HY2 连续跳端口回归仍保留。
Stop 返回时资源必须归零、FD 回基线，后续五秒静默不作清理宽限。预热五分钟后，
逐分钟独立记录堆、RSS、活对象和队列；后十分钟堆中位数增长上限为 max(1 MiB, 5%)，
建链中位数上限为首次两倍。短 tracer 或单协议 suite 均不能替代整轮验收。

## 对端与已知限制

- 所有协议端、原站、DNS 和提供入口的对照客户端遵守[隔离规则](testing-isolation.md)。
  优先 Mihomo listener；缺少的能力由官方 Xray、V2Ray、Hysteria 或 Shadowsocks 服务端补验。
- 关闭行为按 Mihomo 的实际传输包装链验证；不要求所有传输在上传 EOF 后仍收到尾包。
- WS + REALITY 的数据/认证对 Mihomo listener 验证；关闭使用同种 WS 的标准 TLS 分层参照。
  无指纹 JLS/gRPC、Safari ECH/gRPC 的官方对照缺口使用明确标注的 Chrome 关闭参照。
  这些不是完全同配置的客户端差分。
- XHTTP H3/mTLS 使用获准的 Caddy 网关；packetaddr/sing-mux 等分层拓扑明确标注
  网关、会话处理器和解码端，不能宣称单个原生服务端直接支持全部能力。
- 官方 Hysteria 回包缓冲包含协议头；V2Ray 部分 VMess 返回路径也有更小缓冲。
  原生夹具上限不改变 VCore 的协议预算。
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
  缓冲为 16 KiB；原样 ssserver 只作不支持 UoT 的负例。VCore u16 codec 边界、
  调用方双向预算和该对端实际包上限分别取证，不相互替代。
- 静态 ECH、JLS、Encryption 与混合 REALITY 是选定能力集；动态 ECH、Restls、
  ShadowTLS v1/v2、WireGuard 不在当前范围。
- TUIC v5 的 native/quic、三算法、身份拒绝、三地址族与上游组合对 Mihomo 验证；
  认证没有 ACK，不以本地 SOCKS 成功当作密码通过。独立内存 QUIC 验 u16、分片/ID
  退役、credit、窗口和同步 Stop，网络包大小以实际链路为准。TUIC suite 包含
  Hysteria2 和 XHTTP H3 受影响回归，不代表新的八协议完整压力或设备验收。

## 当前证据如何使用

精简前的[冻结验收索引](https://github.com/OneXray/VCore/blob/b7c0100602e188bf28b9fa5370e11120069b54f7/docs/acceptance.md)
保留各次运行、原始失败、环境和适用 revision；[完整阶段记录](https://github.com/OneXray/VCore/tree/b7c0100602e188bf28b9fa5370e11120069b54f7/docs/acceptance)
可在 Git 历史查阅。它们不再复制到当前文档。

该基线记录过本地协议集成、持续压力与 Apple/Android 构建通过；随后 boring release /
Shadowsocks registry 接入只做了定向 JLS、SS 和离线回归，没有重签全部组合及长测。
平台交付仍未完整签收。这些是历史记录范围，不代表当前 checkout、远端 CI 或发布候选
已经重新执行。后续结果放当次 PR、CI artifact 或发布记录，绑定源码、锁文件、对端、
命令、结果及清理证据，不在本文累计包哈希和阶段流水账。

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
