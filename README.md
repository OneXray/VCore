# VCore

VCore 是独立的 Rust 客户端代理 core。配置只接受字段名和嵌套与 Mihomo 一致的严格当前子集；YAML 不包含 `configVersion` 或 `default-proxy`，也不解析或迁移旧 `inbounds/outbounds`、Xray 风格嵌套 proxy 或历史 VCore 配置。Invoke API v5 的 `version.configVersion` 与 `buildIdentity` 使用内部 schema revision 11，它不是 YAML 字段。当前实现包括可独立选路或组成任意长度无环链的 VLESS/SOCKS5/AnyTLS proxy、全 qtype runtime DNS、基础/GeoData rules、TUN ICMP fake response 和路由数据面。TUN 流量查询采用独立的 Mihomo 外形 loopback Controller：`GET /traffic` 返回一次 `up/down/upTotal/downTotal` snapshot，可选 `secret` 使用 Bearer 鉴权，且不进入 Invoke API。VLESS + XHTTP + TLS/REALITY 的协议基线已通过真实 Xray-core 互操作验证。Invoke API v5 只允许一个公共生命周期实例，并把最多五路节点测速收进单次批量 `measureDelay` 内部。

## 范围

- proxy outbound：必须配置至少一个平铺 Mihomo 节点；支持简化 VLESS + XHTTP + TLS/REALITY、SOCKS5 CONNECT/UDP ASSOCIATE，以及 AnyTLS TCP/UoT。节点可由 `rules`/DNS 按精确 name 独立选择，也可通过 `dialer-proxy` 组成任意长度、任意协议组合的链。proxy 数量和链深没有独立上限，只受整份 YAML 256 KiB、name 唯一、引用存在和全图无环约束。
- 链式语义：节点 A 设置 `dialer-proxy: B` 时，选择 A 会执行完整链，物理路径为 `client -> B -> A -> target`；数组顺序没有出口或链路语义。
- UDP：VLESS proxy 使用 XUDP，不实现普通 VLESS UDP；SOCKS5 proxy 使用 UDP ASSOCIATE；AnyTLS `udp: true` 使用 sing UoT v2 datagram mode。链式 UDP 由同一个 outbound graph 组合，不隐式回退 DIRECT。
- listener：可选顶层 `port` 只启动绑定 `127.0.0.1` 的 HTTP CONNECT/forward listener，且必须同时提供恰好一条 Mihomo 形式 `authentication: ["user:password"]`；它只供宿主在公共实例启动后自行探测，不再提供 SOCKS5 inbound。批量 `measureDelay` 不创建或使用这个 listener。TUN 由独立 `tun` 配置与 Invoke 的 TUN fd 启动参数控制。
- 配置：宿主先通过 Invoke API v5 调用 `initialize({dataDir})`，再把 UTF-8 YAML 文本放入 `validateConfig`/`prepare` 的 `configYaml` 字段；VCore 不接收或读取宿主配置路径。`dataDir` 仅承载 VCore 自己管理的运行数据与 GeoData，App 可独立持久化最终配置用于日志和恢复。运行配置不含 YAML 版本与默认节点字段；顶层使用配对的 `port`/`authentication`、仅限 TUN 的 loopback `external-controller` 与依附于它的可选非空 `secret`、`tun`、可选 `sniffer`、`proxies`、`dns` 和必填 `rules`。配置必须至少包含 `port` 或启用的 TUN，且至少包含一个 proxy；name 大小写敏感且唯一。`mixed-port`、`socks-port`、未知引用、自引用、环、旧 `inbounds/outbounds`、Xray 风格 `settings/streamSettings`、`allowInsecure` 和未知字段均失败。
- 路由：`DIRECT`/`REJECT` 是内置动作，proxy action 必须精确使用实际 name；`PROXY` 不再是魔法别名。支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`GEOSITE`、`GEOIP`、`IP-CIDR`、`IP-CIDR6`、`DST-PORT`、`NETWORK` 和最终 `MATCH`。`rules` 必填且必须恰好以一个指向实际 proxy name 的 `MATCH` 结束；该节点及其完整链也是运行配置的默认 proxy graph。
- DNS：支持固定 IP 的 UDP/TCP nameserver 与 `#DIRECT`/`#RULES`/`#<name>` egress；没有 fragment 时固定走 DIRECT。`#PROXY` 没有魔法含义，只有存在同名 proxy 时才是精确 name。A/AAAA 始终使用 typed cache；只有 TUN runtime 的业务 `rules` 含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时，才从空容量按需维护仅供该 TUN 使用的有界 redir-host hint，256 项是启用上限。`nameserver-policy` 是严格有界的 Mihomo 子集：只接受有序 `geosite:` selector，按配置顺序首条匹配；命中后仅在该 policy 的 nameserver 组内顺序 failover，组内全部失败不回退主 `nameserver`，未命中才使用主组。还包括其他 qtype 的有界 opaque relay/cache、同 key DNS singleflight、SERVFAIL 收敛，以及固定 5 秒 query/3 秒 attempt/1 秒 same-transport 单次重发；前 2 个 mismatch 只丢当前 response，累计到第 3 个即判当前 attempt 失败。UDP nameserver 返回 TC 时只判当前 attempt 失败并继续当前组的下一个 nameserver，不隐式创建 TCP transport。显式 `tcp://` nameserver 在每个 runtime 内按“endpoint + 最终 egress”复用连接：同一连接串行请求、无 pipeline；active 物理 TCP 不设固定上限，只保留最多 4 个 idle、同 key 最多 2 个，idle 30 秒，完整校验成功后才归还池，复用连接的 EOF/I/O/response mismatch 只允许一次 fresh reconnect。
- TUN：Apple/Android TUN fd 不再设置 TCP session、普通 UDP association、half-open TCP 或 outbound handshake 的固定并发上限；流量按需建立 task。每个 TUN session 在 raw-IP packet I/O 边界维护上传/下载的一秒窗口与累计 byte 计数，session 重启清零；配置 `external-controller` 后可查询单次 snapshot。仍保留 256 packet queue、128 event/ordinary response queue、每流缓冲、协议解析大小、超时和空闲回收等局部边界。顶层可选 `sniffer` 默认关闭；`enable: true` 时必须在 `sniff` 中至少配置大小写敏感的 `HTTP`、`TLS` 或 `QUIC`。协议使用空值或 mapping 省略 `ports` 时分别默认 HTTP 80、TLS 443、QUIC 443，显式空列表失败；每个协议最多 64 个单端口/闭区间项。只有同属 TCP 的 HTTP/TLS 端口集合不得重叠，QUIC 是 UDP，可与二者使用相同数字端口。只有 TUN runtime、sniffer 已启用且业务 `rules` 含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时才实际预读。
- sniffer 数据面：HTTP/TLS flow 沿用 200 ms/32 KiB 有界前缀和精确回放；TLS 扫描完整 ClientHello extension 列表。QUIC 只接受标准 v1/v2 Initial，不接受 Draft-29；UDP/53 runtime-DNS fast path 先于 sniffer。QUIC 在选择 route 前按 destination 缓存 Initial：每个 ordinary UDP association 最多 4 个 destination 状态，全部 pending 合计最多 8 个 datagram/32 KiB、500 ms，每个状态的 CRYPTO 最多 16 KiB/64 个 range，ACK 总计最多 64 个 range。满 4 个状态时 LRU 淘汰 completed state，只有全部为 pending 时新 destination 才直接 fail-open。不同 version/DCID 的候选 Initial 只有 AEAD 认证成功后才替换完成态；pending 先尝试原 Initial keys，同一连接的 header DCID 轮换以及 0-RTT/Handshake 不会误触发重置或额外等待。成功提取 SNI 后按 `sniffed domain > DNS redir-host hint > IP` 选择 route；解析失败、未知版本、ECH、超时或任一上限触发时回退 DNS hint/IP，并把每个 flow 已缓存的 datagram 按原顺序、原字节且只回放一次。TCP/UDP sniffing 都不替换实际 destination；redir-host hint 是否创建仍只由 TUN + domain-rule scope 决定，与 sniffer 开关独立。启用 DNS 时，UDP/53 在 ordinary association/sniffer 创建前进入 tracked runtime-DNS fast path，TUN TCP/53 继续使用 framed stream path；两者与 lazy resolve 共享同 key singleflight，但没有全局 DNS query 或 upstream transport gate。DNS ingress 与独立 DNS response queue 各为 128；普通 UDP response 仍使用自己的 128 项队列，但 netstack ingress 仍是共享入口。netstack 本地回答合法 ICMPv4/ICMPv6 Echo Request；fake reply 不经过 DNS、rules 或 outbound。TUN runtime 的 resource/netstack 统计共同保留 TCP、half-open、UDP、handshake 与 DNS current/peak，以及 TCP reject、UDP drop、invalid packet 与 ICMP 计数。
- GeoData：VCore 自行管理 `dataDir/geodata` 中的 Xray-compatible `geosite.dat`/`geoip.dat`，采用有界 wire scanner 和紧凑 matcher。下载配置由成组出现的 `geox-url`、`geo-auto-update`、`geo-update-interval` 显式声明；`geox-url` 仅接受 `geoip`/`geosite` 两个 HTTPS domain URL，interval 当前仅接受 24 小时。缺失时 GeoSite 与 GeoIP 各自独立降级，首次启动不阻塞；只有唯一公共实例已 start、auto-update 为 true 且实际存在对应需求时，VCore 才只经最终 `MATCH` 所选 proxy graph 后台更新，不允许 DIRECT fallback。`measureDelay` 和 `validateConfig` 都不注册或下载 GeoData。文件提交仍保留跨进程 update lock、原子替换和崩溃恢复，但下载调度不再聚合多个业务实例。
- ABI：Invoke API v5 提供一个 JSON 业务入口和一个配套的响应释放函数；`initialize({dataDir})` 建立固定数据目录，Android `protect(fd)` 作为平台回调单独注册。TUN 流量通过当前 TUN 进程内的 HTTP Controller 查询，不新增 Invoke method、跨 runtime 查询或平台 FFI getter。
- 产物身份：`version` 返回 `engine: rust`、Invoke API 5、内部 schema revision 11 和稳定 `buildIdentity`；revision 11 不写入 YAML。Apple/Android 构建及 App 同步在复制前核对该身份，源码 revision 与产物 hash 由发布记录单独保存。
- 实例：当前 VCore runtime 最多存在一个公共生命周期实例。`instanceId` 只作为不可复用的 generation token；同实例生命周期请求 fail-fast。纯 `validateConfig` 不受全局 Invoke busy 配额影响。
- 平台：iOS、macOS、Android 使用宿主提供的 TUN fd，fd/packet I/O 由固定版本的 `rust-tun` adapter 实现；Linux 暂不实现。Windows 已通过 `Windows.Networking.Vpn` + `windows-rs` 的 ARM64 IPv4 tracer，以及 Phase 2 的双栈本地 ICMP、DNS namespace、物理 source/interface 配对绑定、网络变化 fail-closed 与 lifecycle slice；完整代理/平台矩阵和正式 App/MSIX 接入尚未完成，公共 FFI TUN `start` 仍明确失败。Windows 不使用 `rust-tun` 的 Wintun backend。
- Apple 日志：iOS/macOS 的 VCore `tracing` event 直接写入 Apple Unified Logging，固定使用 `net.yuandev.log`/`vcore`，不增加 Swift 回调或 FFI；iOS 为确保 Packet Tunnel Extension 的事件出现在 Xcode Console，统一使用 Apple Error 传输级别并在消息中保留真实 tracing level，macOS 保留原生级别映射。单条事件最多 2 KiB，Debug/Trace 合计最多 64 条/秒并报告抑制数，不使用后台队列或 span 缓存。日志覆盖 runtime、TUN 首包、TCP/UDP session、route、physical/TLS/REALITY/XHTTP 建链阶段和 relay 结果，不记录目标 IP/域名、payload、UUID、密钥或配置内容。
- 集成：相邻 OneVCore App 已通过独立的薄适配层接入 Apple XCFramework；VCore 仍不依赖其 Dart、Pigeon、JNI 包名或构建目录。
- 宿主边界：VCore 不识别 App、TUN、Extension、Service 或 daemon 等进程角色，也不实现跨 runtime/跨进程实例计数或 IPC；宿主自行决定进程拓扑。
- 节点测速：提供批量内置 `measureDelay`。payload 只接受 `configYamls`、`timeout` 和 `url`；一次接收 1–5 份严格的 node-only YAML 文本，Core 固定最多启动五个私有 worker，实际 worker 数不超过配置项数。测速 YAML 顶层只允许 `proxies`，并从未被任何 `dialer-proxy` 引用的唯一节点推导链头；该链必须覆盖全部节点。VCore worker 直接准备 outbound graph 并执行 TCP、可选目标 TLS 和 HEAD，不创建 listener、公开实例或 GeoData registration；结果与输入严格等长同序，单项失败不取消其他项。同一 runtime 同时只允许一个批次。

## 文档

- [Invoke API](docs/invoke-api.md)：FFI envelope、method、状态机、所有权与 Android protect 契约。
- [配置](docs/config.yaml)：唯一当前 Mihomo 外形配置、DNS 与 rules 契约和示例。
- [AnyTLS outbound](docs/anytls.md)：v2/v1 协商、TCP/UoT、标准 TLS、session/padding 和显式停止生命周期。
- [TUN 流量 Controller API](docs/controller-api.md)：`external-controller`/`secret`、Bearer 鉴权、单次 `/traffic` snapshot 与 session 计数边界。
- [GeoData rules](docs/geodata.md)：当前 `GEOSITE`/`GEOIP` 实现的语义、资产和资源边界，以及仍待完成的验收。
- [TUN ICMP 与 DNS](docs/tun-icmp-dns.md)：ICMP fake response、Mihomo-compatible DNS 语义、资源边界和验收状态。
- [TUN 平台层](docs/tun-platform.md)：`rust-tun` fd adapter、所有权/分配约束与 Windows UWP 后续边界。
- [Windows UWP TUN 接入调研](docs/UWP_TUN_RESEARCH.md)：已确认的 Win10/Win11、Store MSIX、packet callback、物理出口绑定与 fail-closed 基线。
- [自有 rustls REALITY 实现计划](docs/rustls-reality-plan.md)：fork 分支规则、连接级安全状态、迁移阶段、验收门槛与回滚策略。
- [iOS TUN 业务优先优化计划](docs/ios-business-first-optimization-plan.md)：取消内存 fail-closed、移除业务并发硬门、保留有限资源优化和真机验收的演进记录。
- [验收](docs/acceptance.md)：当前自动化证据与仍待真机完成的验收项。
- [第三方参考与许可证](THIRD_PARTY_NOTICES.md)：参考角色、版本和许可证边界。

`config.yaml` 定义唯一配置公共契约，Invoke API 与 TUN Controller API 分别定义生命周期和流量查询边界；README 只提供入口和实现状态摘要。

## 当前实现状态

当前实现包括：

- 严格 latest-only parser、至少一个平铺 Mihomo VLESS/SOCKS5/AnyTLS proxy、必填且最终指向实际 proxy name 的 rules、精确 name 与任意长度有向无环 `dialer-proxy`、一个可选且强制 Basic 认证的 loopback HTTP `port`、最多一个启用的 `tun` 和可选 Mihomo 外形 `sniffer` 严格子集；不包含旧协议分流或兼容 DTO。
- 统一 `VCoreInvoke`/`VCoreFree` C/JNI 边界、两阶段生命周期、borrowed TUN fd duplicate、`rust-tun` packet I/O 和同步 stop。
- VLESS TCP/XUDP、XHTTP `packet-up`/`stream-up`/`stream-one`、可选独立 download-settings TLS/REALITY 下行腿、SOCKS5 outbound CONNECT/UDP ASSOCIATE、AnyTLS TCP/UoT 与协议无关的任意长度链，以及 TUN 和带认证的 HTTP inbound。
- 全 qtype runtime DNS、Mihomo-compatible nameserver egress、TUN UDP/53 pre-association fast path、同 key singleflight、active 不限量且 idle 有界的显式 TCP DNS 连接池、顺序 rule engine、精确 proxy name/`DIRECT`/`REJECT` action、TCP/UDP 路由、ICMP fake response、惰性 DNS 固定目标和有界 `GEOSITE`/`GEOIP` loader/matcher。
- Android 独立 UTF-8 `byte[]` Invoke、runtime-local protect controller 和 TUN outbound 的 fail-closed socket protect；非 TUN `prepare`/`measureDelay` 不要求 controller。
- VCore 自身的 Apple XCFramework 与 Android arm64-v8a/x86_64 构建输出。

当前生命周期实现包含顶层 `instanceId`、`createInstance`/`destroyInstance` 和单个公共 controller。第二次 `createInstance` 在旧实例销毁前失败；销毁后生成更高且不复用的 ID。批量 `measureDelay` 使用独立私有 worker pool，不进入公共实例表。不同 VCore runtime 之间不共享生命周期状态，VCore 不协调跨进程实例总额。

单 runtime 公共单实例和并发纯配置校验已有自动化证据；当前 Invoke API v5 的单批次 1–5 份配置、固定最多五路测速边界以 [验收](docs/acceptance.md) 中的独立状态为准。TUN fd runtime 采用平台无关的业务优先资源档；iOS 的 35/45 MiB 数值只作为 best-effort telemetry 和 Release 真机优化目标，不再影响 `prepare`、`start`、运行或 `stop` 的业务结果。Android 真机 binding 验收与 Release iOS 真机数据面/footprint 证据仍按范围定义延期。

当前配置已完成运行配置 parser、node-only 测速 parser、认证 HTTP listener、TUN TCP/UDP sniffer、DNS/routing/ICMP 数据面和 GeoData 实现。DNS 不再使用 client-request 或 aggregate upstream transport admission；同 key singleflight 以 canonical question 与排除 transaction ID 后 `message[2..]` 的 wire-semantics digest 为 key。leader 在发起方 task 内运行，取消/drop 时以 RAII 广播 Retry 让 followers 重选 leader。response 最多扫描 64 条 record，typed cache 以及启用时的 redir-host hint 最多保留 16 个唯一地址，opaque cache 继续受 64 项和 256 KiB retained-byte 双重限制。UDP transport 仍为 request-scoped；显式 TCP nameserver 使用 runtime-local pool，连接 key 包含 endpoint 和解析后的最终 egress；active 物理连接不设固定上限，只保留 idle 总数/单 key 上限 4/2 和 30 秒过期。连接仅在完整 framing 和 typed/opaque response 校验成功后归还；复用连接遇到 EOF、I/O 或 response mismatch 时在原 attempt deadline 内 fresh retry 一次。outbound handshake 也不再通过全局 semaphore gate。普通 TCP/UDP flow 按需启动，UDP association 使用 generation-aware cancellation、30 秒 idle 和 10 秒 cleanup，不再因达到固定数量而拒绝新 flow。runtime 保留 TCP、UDP、half-open、handshake 与 DNS current/peak，以及 singleflight join、cache hit、queue drop 和 TCP pool 状态统计。bootstrap resolver 最多创建 4 个 worker thread；全部忙时请求在调用方既有 timeout 内等待可用 worker，不返回资源上限错误。XHTTP request template 的静态 host/path 与 packet-up session ID 使用 `Arc<str>`，每个 request/upload chunk 只复制引用；这只证明 allocation 去重，不宣称真机 footprint 收益。历史测试结果与本轮实际状态分开记录在验收文档。

## 验证命令

```bash
cargo fmt --all -- --check
cargo test --all-features --all-targets
cargo clippy --all-features --all-targets -- -D warnings
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
sh -n scripts/*.sh tests/run_xray_interop.sh tests/run_anytls_interop.sh
```

安装 Xray-core 后可运行协议互操作测试：

```bash
XRAY_BIN=/path/to/xray tests/run_xray_interop.sh
```

本地存在 `references/anytls-go` 且安装 Go 后，可运行默认 ignored、只随
`interop-test` 编译的 AnyTLS 真实互操作测试：

```bash
tests/run_anytls_interop.sh
```

生成独立平台产物：

```bash
./scripts/build_apple.sh
./scripts/build_android.sh
```

2026-07-15 与 2026-07-19 的旧实现历史基线，以及当前业务优先资源档的验证状态，均记录在
[验收](docs/acceptance.md)。

## TUN 有限资源策略与 iOS 内存观测

所有 Apple/Android TUN fd runtime 使用同一组非配置化局部边界：

```text
packet queue 256; ordinary event/UDP response queue 128
TUN raw packet ceiling/MTU 1,500; final proxy UDP payload 1,452
TCP buffer per direction 32 KiB; TLS/XHTTP buffers 64 KiB
explicit TCP DNS active unbounded; idle total/key 4/2; idle timeout 30 s
typed cache 256; TUN redir-host hints 256 when enabled
TUN DNS ingress 128; independent DNS response queue 128
```

TUN DNS 和普通 UDP response 使用独立的 128 项 channel，避免一类回包直接耗尽另一类的保留容量；两类流量仍从同一个 netstack UDP ingress receiver 到达，所以这是 response-path 隔离，不是完整 ingress 隔离。TUN packet ceiling 为完整 raw-IP packet 的 1,500 字节；最终 proxy UDP payload 仍受协议头扣除后的 1,452 字节限制。

旧的 iOS 16/8/2 session 档、后续 128/64/32/16 业务并发档、20/4 weighted proxy pools、DNS 128/8 admission、DNS `total × 4` queue 公式和启动后静态 byte model 均已删除。VCore 不再以 TCP session、UDP association、TUN half-open、outbound handshake、DNS query 或 DNS upstream/physical TCP 的固定总数拒绝业务；这与 Leaf 的按 flow spawn、UDP idle cleanup、无全局 DNS/handshake gate 策略一致。资源优化集中在有界 channel、每流 buffer、cache/解析与 wire size、timeout、idle cleanup 和同 key DNS singleflight；current/peak 统计继续用于真机诊断，而不是 admission。

iOS 仍通过 Apple `TASK_VM_INFO` best-effort 记录 current footprint 和进程 lifetime peak，并在 current 首次跨过 35、40、45 MiB 时输出限频告警。运行期采样至多每 30 秒一次，测量失败只记录一次；这些数据不写入 `lastError`，也不改变 `prepare`、`start`、运行、`stop` 或 panic recovery 的业务结果。清理后的 allocator pressure relief 同样是 best-effort。

35 MiB cold-start current 与 45 MiB representative-workload peak 只适用于 Release iOS 真机的优化对比；超过目标不等于生命周期失败，极端压力下允许系统因内存终止 Extension。公共生命周期本身始终为单实例；测速 worker 是独立的非 TUN 私有批次，不参与 TUN 内存门控。

2026-08-09 的 revision 11 host 验收为 471 passed / 1 ignored；两个外部 integration harness 默认各自 ignored，fmt 与全目标全特性 Clippy `-D warnings` 通过。本机 Xray 26.3.27 与 OpenSSL 3.6.3 的 TLS/REALITY × `packet-up`/`stream-one`/split `download-settings` 六组真实进程互操作全部通过，split 分别覆盖 TLS auto→packet-up 与 REALITY auto→stream-up。该结果证明单 VLESS 的当前 wire 基线，但不替代任意长度真实代理链、AnyTLS 或物理 iOS/Android TUN/protect 验收。当前命令、产物与未完成实机项目见[验收](docs/acceptance.md)。
