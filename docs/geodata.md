# GeoData rules

状态：当前公共契约。YAML 不含 `configVersion` 或 `default-proxy`，使用字段名与
嵌套均与 Mihomo 一致的平铺 proxy 子集；Invoke API v4 单独报告内部 schema
revision 10。rule engine、runtime DNS 与 routing dispatcher 继续使用有界 Xray
GeoData loader/matcher，固定数据目录、单公共生命周期和 VCore 自管更新。业务
规则与 DNS nameserver policy 引用的 GeoSite code 统一按需加载。GeoSite 与
GeoIP 资产缺失时分别降级跳过，不能阻塞首次启动；可用资产仍执行完整校验和
资源边界。`measureDelay` 与 `validateConfig` 都不注册需求或下载数据。物理 TUN
与真实公网更新仍需实机验收。

## 1. 范围

当前 GeoData 消费者包括业务 `rules`，以及只按 DNS question domain 匹配的
`dns.nameserver-policy`。业务规则包含两个 Mihomo 风格类型：

```yaml
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,cn,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,vless-edge
```

严格语法为：

```text
GEOSITE,<code>,<target>
GEOIP,<code>,<target>[,no-resolve]
```

- 每段移除前后 ASCII 空白；rule type 与 `code` 不区分大小写，`target` 继续区分大小写。
- `target` 可以是 `DIRECT`、`REJECT` 或任一已配置 proxy 的精确 name。精确
  name 选择该节点及其完整 `dialer-proxy` 链，target 区分大小写。
  `PROXY` 没有默认节点魔法；只有配置确实存在名为 `PROXY` 的实际节点时才按普通
  精确 name 解析。
- `code` 必须匹配 `[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}`。首字符不能是 `!`；
  数据文件内的 code 按 ASCII case-fold 后判重和查找。资产可用时，未找到被引用
  code 会使该实例的资产快照不可用；后台任务仍遵守该 source 已成功检查后的
  24 小时周期，不能因源中缺少某个 code 每 15 秒重复下载。首次缺少资产时不阻塞
  配置验证。
- `GEOSITE` 必须恰好三段，不接受 `no-resolve` 或其他参数。
- `GEOIP` 只接受可选的第四段、大小写敏感的固定字面量 `no-resolve`，不能出现重复或未知参数；`NO-RESOLVE` 不接受。
- 首版不支持 Mihomo 的 `!code` 反选、`code@attribute`、一条规则引用多个 code、`SRC-GEOIP` 或 `LAN` 伪分类。`geolocation-!cn` 中间的 `!` 是数据文件 code 的普通组成部分，不属于反选语法。
- 规则仍然从上到下匹配，第一条命中生效；`rules` 必填，必须恰好以一个指向
  实际 proxy name 的 `MATCH` 结束。该节点及其完整链是 GeoData 下载使用的运行
  配置默认 proxy graph。

## 2. GeoData 资产

只接受 Xray GeoData protobuf wire/schema 的严格子集：

| 规则 | 固定文件名 | 顶层消息 | 分类内容 |
| --- | --- | --- | --- |
| `GEOSITE` | `geosite.dat` | `GeoSiteList` | `GeoSite.code` 与 `Domain` |
| `GEOIP` | `geoip.dat` | `GeoIPList` | `GeoIP.code` 与 IPv4/IPv6 `CIDR` |

- 宿主先通过 Invoke API v4 调用 `initialize({dataDir})`。VCore 固定使用
  `dataDir/geodata/geosite.dat` 与 `dataDir/geodata/geoip.dat`；YAML 只能位于
  `dataDir/configs`。不接受 YAML 内的资产路径或环境变量；下载 URL 只能通过
  下述严格 `geox-url` 配置提供。
- App/宿主只负责原子写入 `dataDir/configs`，不得投放、更新或删除
  `dataDir/geodata`。GeoData 的下载、校验、状态和替换统一由 VCore 管理。
- GeoData 下载配置由三个顶层字段组成，必须全有或全无：

  ```yaml
  geox-url:
    geoip: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat
    geosite: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat
  geo-auto-update: true
  geo-update-interval: 24
  ```

  `geox-url` 必须含且仅含 `geoip`、`geosite` 两个 key；两项都必须是 host 为
  domain name（不能是 IP literal）、不含 userinfo/fragment 的绝对 HTTPS URL。
  `geo-auto-update` 必须是 bool；`geo-update-interval` 单位为小时，当前只接受
  整数 `24`。省略整组时仍可加载本地已有资产，但该配置不启动后台更新。
- 唯一公共实例的业务 rules 或 DNS `nameserver-policy` 引用 GeoSite 时声明 `geosite.dat` 需求；
  业务 rules 引用 GEOIP 时注册 `geoip.dat` 需求。缺少 GeoSite 只使 `GEOSITE`
  与 `geosite:` nameserver policy 暂不生效；缺少 GeoIP 只使 `GEOIP` 暂不生效。
  两类资产互不连带，基础规则、DNS 和数据面继续启动。
- 只有公共实例已经 `start`、`geo-auto-update: true`，且配置实际使用对应 GeoData
  时才启动后台任务。缺失资产立即安排下载；已有资产按配置的 24 小时周期检查。
  失败按 1 分钟、5 分钟、15 分钟、1 小时退避，之后保持 1 小时上限；不能让
  `prepare`/`start` 失败，也不能缩短已成功检查后的 24 小时周期。
- VCore 使用当前配置 `geox-url` 中对应资产的 URL。Simple Config 固定写出上例
  MetaCubeX `meta-rules-dat` latest release 两个 URL、`geo-auto-update: true`
  与 `geo-update-interval: 24`。VCore 按 GeoSite/GeoIP 分别保存 source URL、
  ETag、hash 与下一次检查时间；只有 source 未变化、当前 matcher 仍可用，
  且磁盘文件 SHA-256 与状态一致时才发送 `If-None-Match`。URL 变化、状态首次
  增加 source、文件缺失或损坏时进行无 ETag 检查；合法 304 只推进下一次检查
  时间，不重写资产。
- 所有 GeoData HTTPS 请求必须使用当前配置最终 `MATCH` 指向的实际 proxy 及其
  完整 `dialer-proxy` 链，绕过业务 rules；不允许 DIRECT、system proxy 或失败
  后的 DIRECT fallback。下载器不能因此递归依赖尚未生效的 GeoData rule。
- 下载写入 VCore 管理的 staging 文件，完成大小、hash、protobuf、分类与当前需求
  校验后才原子替换正式文件；失败保留上一份有效资产。调度只读取唯一公共实例的
  demand 和 source，不聚合多个业务实例。跨进程 update lock、staging、原子
  rename、持久状态与崩溃恢复仍用于保护共享数据目录；这些是文件一致性措施，
  不是多实例调度协议。
- 不支持 MMDB、MetaDB、MRS、超出上述严格子集的 Mihomo `geox-url` 或 Leaf 的
  `site:FILE:CODE`/`mmdb:FILE:CODE` 外部路径语法。
- 可用文件必须校验 outer protobuf framing、分类 code 语法和按 ASCII case-fold
  后的唯一性；未引用分类的内部 payload 按已验证的 message 长度跳过。被引用分类
  还必须完整校验内部 protobuf、CIDR 和 Regex。非普通文件、格式损坏、目标 code
  不存在、记录非法或任何资源超限，使该类资产保持不可用并触发后续更新重试；
  不得替换上一份有效 matcher，也不得把错误分类伪装成有效空分类。

## 3. `GEOSITE` 语义

`GEOSITE` 使用路由上下文中已经存在的 domain：

- HTTP inbound 的 domain 目标直接参与匹配。
- redir-host store 仅在 TUN 的业务 `rules` 含 `DOMAIN`、`DOMAIN-SUFFIX`、
  `DOMAIN-KEYWORD` 或 `GEOSITE` 时创建，并且只供该 TUN 消费；该条件与 sniffer
  开关独立。TUN TCP/UDP sniffer 还必须由顶层 `sniffer.enable: true` 显式启用；
  没有这些规则或 sniffer 关闭时，即使端口已经配置也不预读、不分配 buffer、
  不引入 TCP 200 ms 或 QUIC 500 ms 等待。HTTP/TLS/QUIC 协议空值或省略 `ports`
  时分别默认 80/443/443，显式空列表失败；每协议最多 64 个单端口/闭区间项。
  仅 HTTP/TLS 端口互斥，QUIC 可与二者使用相同数字端口。
- 启用后，TUN TCP 的已配置 HTTP/TLS 端口提取 HTTP Host/TLS ClientHello SNI；
  TUN UDP 的已配置 QUIC 端口只解析标准 v1/v2 Initial，不支持 Draft-29。UDP/53
  fast path 先于 sniffer。QUIC 在 route selection 前按 destination 有界缓存：
  每 association 最多 4 个 state，pending 合计 8 个 datagram/32 KiB/500 ms，
  每 state 的 CRYPTO 为 16 KiB/64 ranges，ACK 总计为 64 ranges。满载时 LRU
  淘汰 completed state；候选新 Initial 只有 AEAD 认证成功后才替换完成态，pending
  先尝试原 Initial keys，因此正常 header DCID 轮换和 0-RTT/Handshake 不误重置。
  routing domain
  优先级固定为 `sniffed domain > DNS redir-host hint > IP`，不改变 actual
  outbound destination。
- TLS 与 QUIC sniffer 都扫描完整 ClientHello extension 列表；出现
  `encrypted_client_hello` (`0xfe0d`，包括无法区分的 GREASE ECH) 时不得采用
  outer SNI。解析失败、未知 QUIC 版本、ECH、超时、超限或未配置端口都回退有效
  DNS hint，否则使用原 IP；每个 flow 已消费的 TCP prefix/QUIC datagram 按原顺序、
  原字节且只回放一次。
- `GEOSITE` 不触发正向或反向 DNS，也不会从目标 IP 猜测域名。没有 domain 时该条规则不匹配并继续下一条。

目标 domain 在进入路由器时只规范化一次：先移除一个末尾的 `.`，优先使用 UTS #46 non-transitional 处理生成 ASCII A-label，再转为 ASCII 小写。为兼容 Xray 真实 GeoData 中少量不能由 IDNA 库反解、但 wire 上仍是合法 ASCII DNS name 的 `xn--` label，UTS #46 失败后允许一个受限 fallback：输入本身必须是 1–253 字节 ASCII DNS name，每个 label 为 1–63 字节、只含字母/数字/连字符且不能以连字符开头或结尾，然后按 opaque ASCII 小写接受。该 fallback 不对非法 Unicode、空 label、下划线或其他字符放宽校验，也不把该 label 解释回 Unicode。

两条路径都失败时拒绝该 session/datagram，不能拿未经校验的原始字符串继续匹配。规范化结果存入有长度上限的 routing context，后续规则复用，不为每条规则重复转换或分配。

数据文件内四种 `Domain.type` 都必须支持。`Plain` value 必须是非空 ASCII 并在 `prepare` 时转为小写，其他字符和末尾点保持不变；`Domain`/`Full` value 使用与目标 domain 相同的 UTS #46 优先、严格 opaque ASCII DNS fallback、小写和末尾点规范化；`Regex` pattern 保持原文：

| 类型 | 匹配语义 |
| --- | --- |
| `Plain`/`Substr` | domain 包含 value |
| `Domain` | domain 等于 value，或是 value 的子域名 |
| `Full` | domain 与 value 完全相等 |
| `Regex` | 在规范化后的完整 domain 字符串上执行不自动锚定的 search |

数据记录携带的 attribute 可以存在，但当前不提供 attribute 过滤语法；没有 `@attribute` 时所有记录均参与分类匹配。Regex 只接受 ASCII source 以及 Go `regexp` 与 Rust regex-automata 共有的 RE2-class 语法，不支持 look-around、backreference 或 Rust-only `u`/`x`/`R` inline flag；pattern 不自动小写，默认大小写敏感，并且只有 pattern 自带 `^`/`$` 时才锚定。由于 routing domain 已经规范化为 ASCII，Regex 固定以 ASCII byte mode 编译；Unicode 字符类不会扩张到运行期不可能出现的 Unicode haystack。每条 Regex 在 GeoData 快照加载/更新校验时独立编译为有大小上限且关闭 accelerator 的 dense DFA，避免 multi-pattern DFA 的状态乘积和额外 accelerator capacity。routing context 构建后的 Plain/Domain/Full/Regex 规则求值不再分配堆内存，非法或超限 Regex 使候选资产快照不可用，不采用 Leaf 静默忽略 Regex 的行为。

## 4. `GEOIP` 与 `no-resolve`

`GEOIP` 使用目标 IPv4/IPv6 地址匹配数据文件中的 CIDR：

- 路由上下文已经包含目标 IP 时直接匹配，不进行 DNS；此时有无 `no-resolve` 不影响结果。
- `no-resolve` 只禁止当前 IP 类规则在尚无目标 IP 时主动触发 runtime DNS；它不是连接级或全局 DNS 开关。
- 目标只有 domain、尚无目标 IP，且当前规则带 `no-resolve` 时，该条规则不触发 DNS、不匹配，并继续后续规则。
- 后续未带 `no-resolve` 的 IP 类规则可以触发 runtime DNS；解析完成后，结果可供该规则及它后面的 `GEOIP`/`IP-CIDR`/`IP-CIDR6` 规则复用，包括带 `no-resolve` 的规则。解析前已经跳过的规则不回头重新求值，保持 Mihomo 的单向规则顺序。
- 目标只有 domain、规则未带 `no-resolve` 且 runtime DNS 已启用时，当前路由决策最多触发一次惰性解析。VCore 在有界结果集中先按 A response 内部顺序、再按 AAAA response 内部顺序检查，第一个位于该 code CIDR 集合中的有效地址使规则命中；这是在 Mihomo 按规则抑制 `ResolveIP` 语义之上的 VCore 多地址扩展。`dns.ipv6: false` 时不请求或采用 AAAA 结果。
- runtime DNS 未启用或解析失败时，该条规则不匹配并继续后续规则。不得改用 `prepare` 阶段的 system resolver。
- runtime DNS 按 nameserver fragment 选择 DIRECT、任一精确 proxy name 的完整链
  或 `#RULES`；没有 fragment 时固定 DIRECT。`PROXY`/`#PROXY` 没有默认节点
  魔法。`#RULES` 只使用
  literal nameserver endpoint 与 transport，不注入 query name，也不需要再次解析
  endpoint，因此 GeoIP 惰性解析不会递归进入 runtime DNS。
- 后续规则最终选择 `DIRECT` 时，为建立连接而进行的必要解析不受 `no-resolve` 禁止；`no-resolve` 只控制 IP 类规则的匹配阶段。
- `GEOIP` 不执行反向 DNS。首版不支持数据内的 `reverse_match: true`，遇到该字段必须在校验阶段明确失败。

同一次路由决策得到的解析结果可供后续 `GEOIP`/`IP-CIDR` 规则复用，不得为每条
规则重复解析。因 `GEOIP` 命中而选出的 IP 必须固定为该 TCP session 或 UDP
datagram 的有效目标；除 `REJECT` 不建立连接外，`DIRECT` 和精确 proxy name
action 都使用这个 IP，不能再次解析或把原 domain 交给远端重新解析。原 domain
只保留为日志/协议元数据。TCP 每个 session 决策一次；UDP 继续按每个 datagram
的目标独立决策，但共享现有有容量和 TTL 上限的 runtime DNS cache。

## 5. 加载、共享与生命周期

- `validateConfig`（包括 App 的 `testXray`）只完成 YAML schema、三项下载配置的
  组合与值域、GeoData code 语法、去重和引用资源上限校验；不读取资产、不发生
  网络访问或修改文件，因此首次启动没有资产也可以验证成功。
- `prepare` 向进程内 GeoData manager 注册按 code 去重后的需求，并且只读取本地
  当时已验证可用的 matcher，不启动或等待下载。缺失或不可用的资产返回显式
  unavailable 状态，而不是让整个实例准备失败。所有 target/workload 统一使用
  8 MiB GeoData allocation capacity；不再按 iOS TUN 缩小为 4 MiB。
- manager 只消费当前唯一公共实例引用的 code，并生成一个有界 matcher 快照；
  停止/销毁时释放需求与快照。更新成功后仅在新快照不会降级当前需求时原子切换。
- 加载器必须按 protobuf wire format 有界扫描。第一遍只建立 code 到文件范围的有界索引，未选中分类按 message 长度跳过；第二遍只逐条解析选中分类。不得把整个文件或完整分类先解码成 protobuf object graph。
- matcher 使用连续字节区、紧凑索引、压缩 CIDR 数组和 dense DFA；不为每条 domain/CIDR 建立独立 `Box`。运行期 domain、CIDR 和 Regex 匹配不进行堆分配。
- manager 使用不可变 matcher 快照。后台下载完成并通过完整校验后原子切换快照；
  后续新 TCP session、UDP datagram 和 DNS query 使用新 matcher，已经完成的路由
  决策不回溯，也不重启或重配实例。
- `start` 先启动业务数据面；只有 `geo-auto-update: true` 且配置存在实际
  GeoData 需求时，才运行长期后台更新任务。首次下载和 24 小时检查不能位于启动
  关键路径。公共实例停止后，更新任务和需求必须释放；磁盘资产与全局更新时间
  状态保留给下一代实例复用。
- iOS TUN `prepare` 与其他平台使用相同的 GeoData 加载顺序和 8 MiB allocation capacity。Apple memory snapshot 只是 best-effort telemetry；读数或测量失败不改变 GeoData、`prepare` 或 `stop` 结果，也不要求 registry activity 独占。
- App 的 `measureDelay` writer 顶层只写 `proxies`。Core 使用独立 node-only
  parser，拒绝 GeoData、port/authentication、TUN、DNS、rules 与 sniffer；它从
  没有被其他 `dialer-proxy` 引用的节点推导唯一链头，并要求该链覆盖全部节点。
  测速 worker 不创建 GeoData registration 或 updater。

## 6. 硬性资源边界

下列限制是当前实现的内部常量，不开放为 YAML 配置项：

| 项目 | 上限 |
| --- | ---: |
| `geosite.dat` 文件大小 | 16 MiB |
| `geoip.dat` 文件大小 | 32 MiB |
| 每个文件的顶层分类数 | 4,096 |
| 每实例引用的 GeoSite + GeoIP 唯一 code 总数 | 16 |
| 所有选中 GeoSite 分类的 Domain 记录总数 | 65,536 |
| 所有选中 GeoSite value 总字节数 | 2 MiB |
| GeoSite Regex 记录数/源文本总量 | 512 / 64 KiB |
| 所有选中 GeoIP 分类的原始 CIDR 总数 | 320,000 |
| 每实例 GeoData 同时存活 allocation capacity | 8 MiB |
| 编译后 Regex matcher 在适用 GeoData 预算中的份额 | 512 KiB |
| 单条 Regex 的 DFA + determinization 预留 | 最多 3 MiB，且不得超过当时剩余 GeoData 预算 |

每次扩容前必须先做 checked arithmetic 和预算检查；超限在分配前失败。CIDR 编译时删除重复及被其他前缀完全包含的项，并且只能递归合并对齐、前缀长度相同的 sibling CIDR；不能无损合并的相邻前缀必须保留。合并不能作为绕过原始记录数上限的手段。

表中记录数、文本量和 allocation capacity 是同时生效的累计限制，不保证其他单项未超限就一定可加载。统一 8 MiB 预算由同一实例的 GeoSite 与 GeoIP 共享。当前 allocation ledger 精确核算 VCore 自有 Vec 的实际 capacity、I/O scratch、索引、规范化临时区、紧凑 matcher 和 dense DFA 报告的 retained memory，并在扩容前失败；不能解释成“最终 matcher 达到上限后，构建时还可以额外翻倍”。

`regex-automata` 没有公开短生命周期 parser/HIR/NFA builder 的精确 allocation capacity，也只公开 dense DFA 的 reported memory 而非其内部 `Vec` capacity，因此无法逐个读取这些分配的真实 capacity。当前实现对每条 Regex 独立编译，在调用 compiler 前先从同一 GeoData ledger 保守预留最多 3 MiB，并把 DFA 与 auxiliary determinization 的配置上限之和限制在这份预留内；DFA accelerator 被关闭，编译后所有 DFA 的 reported retained memory 合计仍不得超过 512 KiB。512 条/64 KiB source 上限同时约束 parser 输入。

GeoData 预算只证明加载器和 matcher 自身有界，不再拼接成整个 iOS 进程的静态 byte model。TUN workload 不设置 TCP session、UDP association、half-open 或 handshake 的固定并发总数；仍受 256 packet queue、128 event queue、32 KiB/TCP direction、64 KiB TLS/XHTTP 等局部边界约束。旧 iOS 16/8/2 profile、后续 128/64/32/16 profile、20/4 weighted proxy pools 及 7,640,960-byte growth model 均已删除。runtime DNS 不设置 client request、aggregate live upstream transport 或 active physical TCP 总数上限，继续保留 256 typed cache、64 项/256 KiB opaque cache 和 128/128 TUN DNS ingress/response queue；显式 TCP nameserver 只保留 idle 总数/单 key 4/2 与 30 秒 idle timeout。按需 TUN redir-host store 启用时最多 256 项且从空容量增长。

ICMP fake response 只瞬时分配一个不超过 1,500-byte TUN MTU 的 reply 并复用 raw egress queue，不新增常驻预算。iOS 的 35/45 MiB 只是 best-effort telemetry 和 Release 真机优化目标；超过目标或无法读取 snapshot 都不改变 GeoData、VPN 启停或路由结果。不得用 mmap 或“文件页可被系统回收”作为内存安全证明。

## 7. 失败与验收

YAML 中非法的 GeoData rule/policy 语法、超过 code 数量上限或无效 target 仍使
`validateConfig`/`prepare` 失败。磁盘资产缺失、损坏、下载失败或检查超时不属于
实例生命周期错误：GeoSite 与 GeoIP 各自保持 unavailable 或继续使用上一份有效
快照，相关规则按顺序跳过，其他规则和数据面继续运行。不可用 GEOIP 规则不得为了
匹配而触发惰性 DNS；它必须直接继续下一条规则。

`state.json` 仅保存每种资产的 source URL、ETag、hash、下一次检查时间等更新调度
元数据，不是业务配置。旧状态缺少 source URL 时视为需要一次无条件检查。状态损坏
时 VCore 在跨进程更新锁保护下重置调度状态，不能因此拒绝 `initialize` 或 VPN
启动；另一个更新进程异常退出后遗留的 `updating` 状态也必须在锁已释放时自动
恢复并继续重试。

V5 自动化历史覆盖如下：

- 当时严格 V5 schema/rule/policy 正负矩阵、`PROXY` 到 `default-proxy`、精确 tag 到完整链、默认 `MATCH,PROXY`、认证 HTTP listener、DIRECT TCP/UDP 和 UDP 每 datagram 跨 action 路由。
- nameserver policy 单独引用 GeoSite 时仍加载 `geosite.dat`；与业务 rule 重复引用共享
  一份分类；缺失分类和 rule + policy 合计超过 16 个唯一 code 都 fail-closed。
- runtime DNS 的任意 16-bit qtype、UDP/TCP framing、DIRECT/PROXY/精确 tag/RULES egress、顺序 failover、SERVFAIL 收敛、typed/opaque 正负缓存、`redir-host`、`ipv6: false` AAAA NODATA、A→AAAA、UDP TC 不打开隐式 TCP、超长 TUN UDP DNS response drop、CNAME reachability/loop/TTL、32 查询并发和合并 upstream session admission；TUN DNS TCP relay 取消、malformed UDP request-local drop 与同源 burst 也有回归测试。
- 当前 TUN ICMP gate、ICMPv4/ICMPv6 checksum、MTU、options、分片/extension-header drop、raw egress backpressure 和实际 TUN reply 有回归测试。
- `GEOSITE` Plain/Domain/Full/Regex、attribute wire 校验、UTS #46 与严格 opaque ASCII DNS fallback、Regex 失败、大小写和 domain/subdomain 语义。
- `GEOIP` IPv4/IPv6、CIDR sibling 合并、family 隔离、非法 CIDR 和 `reverse_match` 拒绝。
- 未选择分类只扫描 header、选择分类损坏失败、code 缺失/重复、outer protobuf 损坏、16 code 上限和小 allocation budget 分配前失败。
- 当时旧契约曾要求 `validateConfig` 对缺失 GeoData 资产 fail-closed；该行为现已由
  “验证成功、运行期按资产种类降级”替代。matcher 的 `Send + Sync` 要求继续保留。

历史 V6 曾通过 Core 351 passed / 2 个环境依赖项 ignored、netstack 19 passed、
fmt 与全 targets/features Clippy `-D warnings`；其中包含当时的 TCP sniffer schema
与 domain-rule gate 回归。该计数不覆盖 V7 QUIC sniffer，也不能替代 V7 原生产物、
真实 GeoData、真实 Xray 或物理 TUN 的独立门禁。

2026-07-19 的 8/32、2/8、32-entry ingress 和 260,992-byte 断言，以及后续
128/8 scheduler，均属于旧实现历史快照，不再描述当前资源策略。同 key
singleflight、64-record scan/16-address retention、UDP association idle cleanup
和本轮命令与结果由 `acceptance.md` 统一登记；host 证据不声明固定 Xray DNS
互操作或物理 iOS 已验收。

仓库还提供一个默认忽略的真实 Xray 资产兼容测试；只有显式提供资产并运行后才能把它作为本机证据：

```bash
VCORE_GEODATA_DIR=/path/to/assets/dat \
  cargo test real_xray_geodata -- --ignored --nocapture
```

2026-07-24 已对当前工作树显式执行该测试，结果 `1 passed`。allocation ledger 记录：

| 样例 | retained bytes | construction ledger peak | 统一 capacity |
| --- | ---: | ---: | ---: |
| baseline | 423,252 | 3,385,312 | 8,388,608 |
| documented | 459,844 | 3,421,904 | 8,388,608 |
| real Xray assets | 1,962,020 | 4,935,888 | 8,388,608 |

这些数字证明本次 host 加载在当前 8 MiB ledger 内收敛，不代表 Release iOS 整进程
footprint、真实 VLESS DNS 数据面或边界 fixture 已通过。

历史记录：2026-07-15 曾对 OneVCore 随 App 保存的真实 Xray 资产执行该测试；`GEOSITE,CN`、`GEOSITE,GEOLOCATION-!CN`、`GEOIP,CN`、`GEOIP,PRIVATE` 的组合在当时的 iOS TUN 4 MiB 旧预算内通过，reported retained memory 为 1,962,020 字节，construction ledger peak 为 4,194,304 字节。当前实现统一使用 8 MiB；该历史结果只证明资产兼容，不是当前 host 回归或 Release iOS 真机证据。

仍待补齐的验收项：

- 使用真实 VLESS + XHTTP 上游并覆盖 SOCKS5/链式 proxy graph，完成 runtime DNS、TUN TCP/UDP 53 劫持、DNS failover 和 GeoData 惰性解析/固定 IP 的端到端互操作。
- 为 `no-resolve` 的已有 IP 等价匹配、domain-only 不主动解析、后续规则复用解析
  结果但不回溯、`DIRECT` 建连仍可解析，以及多 A/AAAA 结果、`redir-host` 过期
  提示和同一普通业务 UDP association 混合多个精确 proxy name、`DIRECT`/
  `REJECT` 增加完整 netstack 级组合测试；当前这些语义主要由分层单元/dispatcher
  集成测试覆盖。
- 对每一项记录数、文本量、文件大小和 Regex size limit 生成刚好命中上限与下一次扩容失败的 fixture。
- 验证多条规则重复引用同一 code 只保留一份 matcher，并用多个真实 runtime 证明实例隔离和停止/销毁后的资源回收。
- 构造接近文件上限的巨大未选中/选中分类，记录扫描时间和峰值，而不只验证小型损坏 fixture。
- 至少 20 次 `prepare -> start -> stop` 循环，验证 fd、task、matcher 与预算不增长。
- 为统一 8 MiB allocation capacity 生成距上限不足一个分配量子的边界 fixture，并生成下一次分配必定越界的负例。
- Release iOS 真机使用 8 MiB 边界 fixture 完成 TUN 启动、混合 TCP/UDP 和停止，记录 cold-start current、representative-workload peak 与 plateau；35/45 MiB 只作优化对比，越线不判生命周期失败。

## 8. 参考边界

- 规则外形与 `no-resolve` 的逐规则 `ResolveIP` 抑制语义参考 Mihomo；有界 A 后 AAAA 多地址求值与命中 IP 固定属于 VCore 扩展。
- protobuf 数据结构参考 Xray-core 的 `GeoSiteList`/`GeoIPList`。
- Leaf 的逐分类流式读取和所有权移动可作为实现参考，但不采用其完整解码当前分类、每条域名一个动态 matcher、Regex 静默跳过或 MMDB mmap 方案。
