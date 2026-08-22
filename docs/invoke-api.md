# VCore Invoke API

状态：当前公共契约；YAML 使用字段名与嵌套均与 Mihomo 一致的严格平铺
VLESS/SOCKS5/AnyTLS 子集，不包含 `configVersion` 或 `default-proxy`。Invoke API
v4 的 `version` 与 `buildIdentity` 单独报告内部 schema revision 10。公共生命周期
保持单实例；内置批量 `measureDelay` 使用独立的 node-only 配置并由 Core 推导唯一
完整链头。平台无关 TUN 资源档和 iOS best-effort 内存 telemetry 已实现。物理
iOS/Android TUN 仍需实机验收。

## 1. C ABI

C ABI 只包含一个业务入口和一个配套释放函数：

```c
char *VCoreInvoke(const char *request_json);
void VCoreFree(char *response);
```

- `request_json` 必须是 NUL 结尾的 UTF-8 JSON。
- `VCoreInvoke` 为每个非空响应分配独立字符串。
- 调用方必须使用 `VCoreFree` 释放响应，不能使用宿主 allocator。
- 除灾难性分配失败外，非法输入、未知 method、状态错误和内部 panic 都必须返回合法 failure JSON，而不是 `NULL`。
- Invoke request 和 response 不得完整写入日志，避免泄漏 UUID、REALITY key、short ID 或配置路径。
- TUN 流量不增加 Invoke method。启用 TUN 的运行配置通过顶层
  `external-controller` 启动 Mihomo 外形 loopback HTTP Controller；可选非空
  `secret` 启用 Bearer 鉴权，省略时采用 Mihomo 无鉴权语义。App 的 Simple
  Profile 启用 TUN 流量统计时写入随机 secret，并查询单次 `GET /traffic`
  snapshot；该请求不携带 `instanceId`，也不进入 Invoke command admission。完整语义见
  [TUN 流量 Controller API](controller-api.md)。

## 2. Envelope

请求固定为：

```json
{
  "apiVersion": 4,
  "method": "getState",
  "instanceId": "1",
  "payload": {}
}
```

约束：

- `apiVersion` 必填且只能为 `4`；旧 Invoke payload 不做兼容。
- `method` 必填且必须来自本文白名单。
- `instanceId` 是 VCore 生成的 runtime-local opaque identifier。实例 method 必须携带，registry 级 method 必须省略；不接受 `null`、空字符串、宿主自定义值或放在 `payload` 中的副本。
- `payload` 必须是 object；没有参数时使用空 object。
- 未知顶层字段和未知 payload 字段都失败。

响应固定为：

```json
{"success":true,"data":{},"error":""}
```

或：

```json
{"success":false,"data":null,"error":"invalid configuration: ..."}
```

无业务数据的方法成功时返回空 object，不使用 `null`。

## 3. VCore runtime registry 与状态

### 数据目录初始化

- 每份已加载的 VCore runtime 必须先调用一次 registry 级
  `initialize({"dataDir": "/absolute/path"})`，再执行 `validateConfig`、`prepare`
  或 `measureDelay`。`version`、`initialize` 与轻量实例表操作不读取配置。
- `dataDir` 必须是可写绝对路径。VCore 创建并规范化固定布局
  `dataDir/configs` 与 `dataDir/geodata`；同一 runtime 以同一路径重复初始化幂等，
  改用其他路径失败。VCore 不根据 App、Extension 或 Service 角色推断目录。
- App/宿主只负责把完整 YAML 原子写入 `dataDir/configs`（允许其下的 generation
  子目录）。所有 `configPath` 都必须是绝对路径，且规范化后仍位于该子树；符号链接
  不能逃逸。节点校验与 `measureDelay` 的临时 YAML 也必须先完成 `initialize`，
  再写入该子树内的隔离临时目录，不能使用 application cache。
  `dataDir/geodata` 由 VCore 独占管理，宿主不得投放、更新或删除资产。

每份已加载的 VCore runtime 最多存在一个公共生命周期实例。这个约束覆盖从
`createInstance` 到 `destroyInstance` 的完整周期，而不只是 `running` 状态；
第二次 `createInstance` 必须失败。`instanceId` 是不可复用的 generation token，
用于拒绝旧异步命令误伤后来创建的新实例，不表示并行实例能力。约束是
runtime-local 的，不做跨进程计数或 IPC。状态机为：

```text
stopped -> preparing -> prepared -> starting -> running
   ^                                      |
   +------------- stopping <-------------+

任一关键数据面提前退出 -> 仅该实例进入 failed
```

- Invoke 不再设置会改变业务结果的全局六路 fail-fast admission。不同宿主线程可以
  并发执行纯校验；同一配置文件内容的 `validateConfig` 结果不能因为其他 Invoke
  是否并发而变成 busy。
- 公共实例保留独立的 fail-fast command admission。同一 `instanceId` 同一时刻只
  执行一个生命周期 method；并发操作立即返回该实例 busy。
- `measureDelay` 使用独立的单批次 admission 和私有 worker，不进入公共生命周期
  registry，也不占用公共实例名额。
- `stop` 在目标实例为 `stopped` 时幂等成功；在 `prepared`、`running` 或 `failed`
  时同步释放全部资源并回到 `stopped`。
- 不支持实例内热重载。切换某个实例的配置必须完整 `stop -> prepare -> start`。
- panic recovery 只清理当前公共实例；销毁完成后才能创建下一代实例。

### TUN lease

- 每份配置最多通过 `tun.enable: true` 启用一个 TUN。由于公共生命周期已经是单实例，
  TUN lease 只负责保护该实例的 fd 与 Android protect callback 生命周期。
- `prepare` 解析出 `tun.enable: true` 后必须先取得 runtime-local TUN lease；lease 从该实例的 `preparing/prepared/starting/running/failed/stopping` 生命周期持有到 `stop` 或 `destroyInstance` 完成。`prepare` 失败时必须释放尚未提交的 lease。
- 批量测速 worker 永远不包含 TUN，也不取得 TUN lease 或 Android protect controller。

### 宿主无关边界、TUN 资源档与 iOS 内存观测

- VCore 只根据 target、配置是否含 TUN 以及生命周期状态执行契约；宿主自行决定各次调用位于哪个进程。任何 App/Extension/Service/daemon 拓扑都不属于本 ABI。
- 所有 TUN fd target 使用 `ResourceLimits::tun()` 中相同的局部资源边界：256 packet queue、128 event/ordinary UDP response queue、1,500-byte TUN raw packet ceiling、32 KiB/TCP direction，以及 64 KiB TLS/XHTTP buffers。TUN 最终 proxy UDP payload 限制为 1,452 字节。TCP session、ordinary UDP association、TUN half-open TCP 与 outbound handshake 不设置固定并发总数；新 flow 按需创建 task。
- TUN TCP/UDP sniffer 只使用 YAML 顶层可选 `sniffer`，不增加 Invoke 开关。该段一旦出现就必须显式包含 `enable`；省略该段或 `enable: false` 表示关闭，关闭时可省略或保留合法 `sniff`。`enable: true` 时 `sniff` 至少包含大小写敏感的 `HTTP`、`TLS` 或 `QUIC`。协议空值或 mapping 省略 `ports` 时分别默认 80/443/443，显式空列表失败；每协议最多 64 个单端口/闭区间项。只有同属 TCP 的 HTTP/TLS 端口不得重叠，QUIC 是 UDP，可与二者使用相同数字端口。只有 TUN runtime、sniffer 已启用且业务 `rules` 含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时才实际预读。
- HTTP/TLS 单 flow 使用 200 ms 总 deadline 和 32 KiB retained-prefix ceiling。QUIC 只接受标准 v1/v2 Initial，不接受 Draft-29；UDP/53 runtime-DNS fast path 先于 ordinary UDP association 和 sniffer。QUIC Initial 在 route selection 前按 destination 缓存：每 association 最多 4 个 destination state，全部 pending 合计最多 8 个 datagram/32 KiB、500 ms；每 state 最多保留 16 KiB CRYPTO 与 64 个 CRYPTO range，ACK 总计最多 64 个 range。满载时 LRU 淘汰 completed state，只有 4 个 state 全 pending 时新 destination 才直接 fail-open。不同 version/DCID 的 v1/v2 Initial 必须通过候选 Initial keys 的 AEAD 认证才可替换 completed state；pending 先尝试原 Initial keys，同一连接的 header DCID 轮换、0-RTT 与 Handshake 均不得误触发重置或额外等待。TLS 与 QUIC 内的 ClientHello 都扫描完整 extension 列表；发现 `encrypted_client_hello` (`0xfe0d`，包括无法区分的 GREASE ECH) 时，即使已经读到 SNI 也必须丢弃 outer SNI。routing domain 优先级固定为 `sniffed domain > DNS redir-host hint > IP`。超时、EOF、超限、畸形/未知协议、未知 QUIC 版本、ECH 或未配置端口均 fail-open 到 DNS hint/IP；每个 TCP/QUIC flow 已消费的数据按原顺序、原字节且只回放一次。sniffer 永不 override destination，outbound 始终收到原始 IP destination；redir-host hint 仍由 TUN + domain-rule scope 独立控制。
- TUN runtime DNS 不设置 client-request 或 aggregate live upstream transport permit；A/AAAA typed cache 固定最多 256 项。只有 TUN 配置的业务 `rules` 含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时才创建 redir-host store；它仅供该 TUN 消费、从空容量按需增长且最多 256 项。opaque cache 保留 64 项/256 KiB。UDP transport 保持 request-scoped；显式 `tcp://` nameserver 在当前 runtime 内按 endpoint + 最终 egress 复用，active 物理连接不设固定上限，默认只保留 idle 总数/单 key 4/2，idle 30 秒且每条连接只串行处理一个 query。DNS ingress 与独立 DNS response queue 各为 128；ordinary UDP response 另有 128 项队列。两类 datagram 仍通过共享 netstack UDP ingress receiver，所以这里只是 response-path 隔离。
- DNS cache miss 使用同 key singleflight：key 为 canonical question 与排除 transaction ID 后 `message[2..]` 的 semantics digest。leader 在发起方 task 内运行；leader 被取消或 drop 时 RAII 广播 Retry，followers 重新选举。共享 raw result 按 caller 恢复 transaction ID/endpoint 并独立应用 failure mode；cache hit 不创建 flight。response 最多扫描 64 条 record，typed cache/hint 最多保留 16 个唯一 IP。
- runtime DNS 保留 5 秒 query/3 秒 attempt deadline 和 cancellation；outbound handshake 不再通过全局 semaphore admission。TCP 连接只有在完整 framing 与 typed/opaque response 校验成功后才能归还 idle pool；复用连接发生 EOF、I/O 或 response mismatch 时最多 fresh reconnect 一次，其他错误丢弃连接。UDP 首次发送 1 秒未收到合法 response 时最多在同一 transport 上重发一次；前 2 个 mismatch 只丢当前 response，累计到第 3 个即判当前 attempt 失败。bootstrap resolver 最多创建 4 个 worker thread，全部忙时在调用方既有 timeout 内等待可用 worker，不返回资源上限错误。
- 普通 TUN UDP association 不设固定总数，使用 generation-aware task ownership 和 child cancellation。idle timeout 为 30 秒、cleanup 周期为 10 秒；cleanup 先从 map 删除再 cancel child，TUN parent 退出时删除/cancel 全部 child 并 drain completion。只有成功接收/排队的入站 datagram 或成功排队的 outbound response 刷新 activity，queue-full drop 不刷新。
- 旧 iOS 20/4 weighted proxy pools、128/64/32/16 业务并发档、DNS 128/8 admission、`total × 4` DNS queue 推导、静态 8 MiB/7,640,960-byte growth model 和 activity 独占已经删除。VCore 仍通过 bounded channel、每流 buffer、cache、GeoData、wire/parser size、timeout 和 idle cleanup 提供结构安全边界；TCP/UDP/half-open/handshake/DNS current/peak 只用于观测，不作为业务 admission。
- iOS 通过 Apple `TASK_VM_INFO` best-effort 记录 current footprint 和进程 lifetime peak；current 首次跨过 35、40、45 MiB 时每档只记录一次，running 至多每 30 秒采样一次，测量失败只记一次 warning。telemetry 不写入 `lastError`，也不改变 `prepare`、`start`、运行、`stop` 或 panic 的原始结果。allocator pressure relief 在对应 cleanup 路径 best-effort 执行。
- 35 MiB cold-start current 和 45 MiB representative-workload peak 是 Release iOS 真机优化目标，不是 ABI hard gate。超过目标必须记录分析，但 VCore 不拒绝启动、不主动停止 VPN，也不把成功的 stop 改为失败；极端压力下允许 iOS 终止 Extension。
- `instanceId` 和状态只属于创建它的当前 runtime registry；其他 runtime 即使持有同名字符串也不能访问。跨 runtime 状态传播由宿主负责，VCore 不定义 IPC。

### 节点测速边界

- `measureDelay` 是 registry 级批量 method。一次调用接收 1–5 份节点配置；
  Core 固定最多并发执行五个私有 worker，实际 worker 数不超过配置项数。结果数量
  和顺序与输入严格一致，调用方不提供并发参数。
- 同一 VCore runtime 同时只允许一个 `measureDelay` 调用。第二个重叠调用立即返回
  `measureDelay is busy`；App 负责用进程内 FIFO dispatcher 串行提交批次。
- 每个 worker 只准备独立 outbound graph。Core 从没有被其他节点的
  `dialer-proxy` 引用的节点中推导唯一链头，并通过该节点对目标执行
  TCP、可选目标 TLS 和 HTTP/1.1 HEAD。它不创建 HTTP listener、公开实例 ID、
  DNS runtime、rules、sniffer 或 GeoData registration。
- 测速 YAML 是独立严格子集，顶层只允许 `proxies`。每份配置至少包含一个平铺
  Mihomo VLESS、SOCKS5 或 AnyTLS 节点；推导出的唯一链头必须通过
  `dialer-proxy` 路径覆盖全部节点。没有链头、存在多个独立链头或包含未被该链
  使用的节点都失败。
- 单项配置、连接、TLS、HTTP、timeout 或 worker panic 只使对应 result 失败；
  其他项继续。payload 非法、未初始化或 batch busy 才使整个 Invoke 失败。

## 4. Methods

### 4.1 `initialize`

```json
{
  "apiVersion": 4,
  "method": "initialize",
  "payload": {"dataDir": "/path/to/vcore"}
}
```

成功数据返回规范化后的目录：

```json
{"dataDir":"/path/to/vcore"}
```

- `initialize` 是 registry 级 method，必须省略 `instanceId`。
- payload 只接受非空绝对路径 `dataDir`。调用会创建固定的 `configs` 与 `geodata`
  子目录，并拒绝非目录或逃逸到根目录外的子目录。
- 同一路径重复调用幂等成功；当前 runtime 已绑定后不能切换到其他路径。

### 4.2 `getGeoDataState`

```json
{"apiVersion":4,"method":"getGeoDataState","payload":{}}
```

成功数据按资产种类分别返回：

```json
{
  "geosite": {
    "required": true,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": "failed to access .../geosite.dat: ...",
    "etag": null,
    "hash": null
  },
  "geoip": {
    "required": false,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": null,
    "etag": null,
    "hash": null
  }
}
```

- 这是 registry 级只读 method，必须省略 `instanceId`，且要求已经调用
  `initialize`。它不创建实例、不发起下载，也不改变业务规则。
- `required` 来自当前唯一公共实例的需求；没有 prepared/running 实例时为
  `false`。`available` 是对应资产能否满足当前需求，两种资产独立报告。
- `lastSuccess`/`nextCheck` 是 Unix 秒；`hash` 是最近一次成功提交文件的
  SHA-256 小写十六进制。尚无对应状态时这些字段为 `null`。

### 4.3 `createInstance`

```json
{"apiVersion":4,"method":"createInstance","payload":{}}
```

成功数据：

```json
{"instanceId":"1"}
```

- `createInstance` 是 registry 级 method，必须省略 `instanceId`。
- 成功只创建一个状态为 `stopped` 的轻量实例记录，不读取配置、不解析域名、不创建 runtime 或 listener。
- 在该实例销毁前再次调用必须失败；`stopped` 或 `prepared` 状态也不会释放公共槽。
- ID 由 VCore 生成，在当前 runtime 生命周期内不复用；它不是指针、跨 runtime handle 或可持久化后在下次加载时继续使用的标识。

### 4.4 `destroyInstance`

```json
{
  "apiVersion": 4,
  "method": "destroyInstance",
  "instanceId": "1",
  "payload": {}
}
```

- `destroyInstance` 是实例的最终同步清理屏障。目标处于 `prepared`、`running` 或 `failed` 时，必须先执行与 `stop` 等价的资源清理。一旦请求取得该实例的 command admission，无论清理成功、返回错误或 panic，实例都会 tombstone 并从实例表移除；只有在取得 admission 前因同实例 busy 被拒绝时实例仍保持有效。
- 返回成功后该 ID 永久失效，该实例的 task、fd、listener、session 和 Android protect callback 均不得继续存在。
- 未知或已经销毁的 ID 返回 failure；同一实例正在执行其他 method 时立即返回 busy。

### 4.5 `validateConfig`

```json
{
  "apiVersion": 4,
  "method": "validateConfig",
  "payload": {"configPath": "/path/to/vcore/configs/config.yaml"}
}
```

- 从已初始化的 `dataDir/configs` 读取、限长、解析并完成 schema/组合校验。
- 这是 registry 级 method，必须省略 `instanceId`。
- 不创建或修改实例，不解析远端域名，不建立网络连接，也不等待或触发 GeoData
  下载。App 的 `testXray` 使用这一 method，因此即使 Simple Config 固定写出
  GeoData 下载配置，测试配置也只校验、不下载。
- 该方法是可重入的纯校验；并发调用或同时存在其他 Invoke 不得将合法结果改成
  busy。调用期间宿主仍需保证目标文件内容不被原地改写。
- GeoData 文件尚不存在时配置仍可通过；这里只校验 `geox-url`、
  `geo-auto-update`、`geo-update-interval` 三项全有全无及其值域，以及规则语法
  与引用资源上限。对应 matcher 会在可用资产上加载，缺失资产按 GeoSite/GeoIP
  分别降级。

### 4.6 `prepare`

```json
{
  "apiVersion": 4,
  "method": "prepare",
  "instanceId": "1",
  "payload": {"configPath": "/path/to/vcore/configs/config.yaml"}
}
```

- 只允许目标实例从 `stopped` 调用。
- 配置文件最大 256 KiB。
- `configPath` 必须是位于已初始化 `dataDir/configs` 内的绝对路径。
- `prepare` 只读取本地已有 GeoData，不启动、等待或执行下载。GeoData 缺失或
  后台更新失败不使 `prepare` 失败：缺少 `geosite.dat` 时跳过
  `GEOSITE` 与 GeoSite nameserver policy，缺少 `geoip.dat` 时跳过 `GEOIP`；
  两类资产互不连带，其他规则与数据面继续准备。
- 在系统 VPN 默认路由安装前，只对未设置 `dialer-proxy`、直接连接物理网络的 proxy 节点完成 bootstrap DNS 解析，并缓存有界数量的结果；链上节点的 domain 交给下一跳。
- 成功后进入 `prepared`；失败必须释放临时资源并回到 `stopped`。
- 配置含 TUN 时取得该公共实例的 TUN/protect 生命周期 lease。
- Android 仅在配置实际包含 TUN 时要求已注册 protect controller；非 TUN `prepare` 不检查 controller。

### 4.7 `start`

业务 runtime 启动后，只有配置完整写出 `geox-url`、`geo-auto-update: true`、
`geo-update-interval: 24`，且业务 rules 或 DNS policy 实际引用对应 GeoData 时，
VCore 才启动后台更新；所有请求只使用运行配置最终 `MATCH` 指向的实际 proxy
及其完整 `dialer-proxy` connector graph。该任务不在 start 的关键路径。省略整组
或设置 `geo-auto-update: false` 时仍可读取本地资产，但不启动后台下载。

设置 `tun.enable: true` 时：

```json
{
  "apiVersion": 4,
  "method": "start",
  "instanceId": "1",
  "payload": {
    "tunFd": 23,
    "tunFraming": "utun"
  }
}
```

Android 使用 `rawIp`：

```json
{"apiVersion":4,"method":"start","instanceId":"1","payload":{"tunFd":23,"tunFraming":"rawIp"}}
```

- 只允许目标实例从 `prepared` 调用。
- 配置设置 `tun.enable: true` 时，`tunFd` 与 `tunFraming` 必填；否则二者必须省略。
- `tunFd` 是 borrowed。宿主必须在调用前把它设为 nonblocking；`start` 会先验证该状态再 duplicate，且 VCore 不修改与原 fd 共享的 file-status flags。
- VCore 不关闭宿主原 fd；core-owned duplicate 会转交给 Unix `rust-tun` adapter，并在 adapter drop 时关闭。
- VCore 不使用 `rust-tun::AsyncDevice`，而是在已经 nonblocking 的同步 device 外包装 Tokio `AsyncFd`，避免第三方 async constructor 对共享 file-status flags 再执行 `F_SETFL`。
- Apple 的四字节 packet-information header 由 `rust-tun` 剥离/补齐，Android 始终为 raw IP；进入 netstack 的统一边界只有 raw IPv4/IPv6 packet。`tunFraming` 继续作为严格宿主协议字段，不因内部迁移而删除或兼容猜测。
- Apple 只接受 `utun` framing；Android 只接受 `rawIp` framing；其他 target 的 TUN `start` 明确返回 unsupported failure。
- Windows 后续的 `Windows.Networking.Vpn` 接入不复用此 fd payload，也不把 `VpnChannel`/COM 对象塞进 Invoke JSON；在 Windows plugin API 完成前仍明确 unsupported。
- iOS TUN `start` 在 duplicate fd 前可 best-effort 记录 current/lifetime-peak snapshot；读取失败或跨过 35/40/45 MiB 观测档位都不阻止数据面启动，也不覆盖原始 fd、framing 或 runtime 错误。
- 全部 listener 和关键数据面成功启动后才进入 `running`。
- 首次缺少 GeoData 时 `start` 不等待网络下载。只有完整下载配置启用自动更新且
  实际存在对应需求时，VCore 才使用 `geox-url` 中的 URL，并只经配置的
  最终 `MATCH` 实际 proxy 及其完整链在后台补齐/检查资产，不允许 DIRECT
  fallback；成功更新后的 matcher 热激活给后续新 flow，已完成的路由决策不回溯。

### 4.8 `stop`

```json
{"apiVersion":4,"method":"stop","instanceId":"1","payload":{}}
```

- 只同步取消并等待目标实例的 TUN、netstack、inbound、session、outbound 和 runtime task。
- 返回前关闭 core-owned duplicate fd。
- iOS TUN 清理完成后 best-effort 记录 current/lifetime peak 并执行 allocator pressure relief；telemetry 或 pressure relief 失败不能让成功的 `stop` 变为 failure，也不能覆盖原始停止错误。
- 返回后目标实例不得再调用 Android protect callback。

### 4.9 `getState`

```json
{"apiVersion":4,"method":"getState","instanceId":"1","payload":{}}
```

成功数据：

```json
{
  "state": "running",
  "lastError": ""
}
```

异步数据面失败时状态为 `failed`，`lastError` 保存可展示但不包含密钥的错误摘要。

`getState` 只查询当前 runtime registry 中与 `instanceId` 精确匹配的实例。它不是跨 runtime 状态查询接口；宿主系统 VPN 状态和 IPC 不属于 VCore 契约。

### 4.10 `version`

成功数据固定包含：

```json
{
  "apiVersion": 4,
  "buildIdentity": "OneVCore/VCore;engine=rust;coreVersion=0.1.0;invokeApiVersion=4;configVersion=10",
  "configVersion": 10,
  "engine": "rust",
  "version": "0.1.0"
}
```

`version` 是 registry 级 method，必须省略 `instanceId`。`buildIdentity` 是稳定的
宿主兼容性身份，用于阻止 App 混入旧 engine、旧 Invoke 或旧配置协议产物；源码
revision 和产物 hash 由发布清单单独记录，不能从该字段推断。响应中的
`configVersion: 10` 是内部 schema revision，不是允许写入 YAML 的字段。

### 4.11 `measureDelay`

```json
{
  "apiVersion": 4,
  "method": "measureDelay",
  "payload": {
    "configPaths": [
      "/path/to/vcore/configs/measure/node-a.yaml",
      "/path/to/vcore/configs/measure/node-b.yaml"
    ],
    "timeout": 5,
    "url": "https://cp.cloudflare.com/"
  }
}
```

成功数据：

```json
{
  "results": [
    {"success":true,"delay":123,"error":""},
    {"success":false,"error":"measureDelay probe failed: TLS handshake failed"}
  ]
}
```

- `measureDelay` 必须省略 `instanceId`。`configPaths`、`timeout` 和 `url`
  三个 payload 字段都必填且拒绝未知字段。`configPaths` 接受 1–5 个非空路径；
  `timeout` 是 1–30 秒。
- 同一 runtime 同时只能有一个批次。重叠调用不排队，返回
  `invalid state: measureDelay is busy`。Core 固定最多并发执行五个私有 worker；
  实际 worker 数不超过 `configPaths` 的项目数。
- 每个路径必须位于已初始化的 `dataDir/configs` 内，文件最大 256 KiB，并只接受：

  ```yaml
  proxies:
    - name: exit
      type: socks5
      server: 192.0.2.1
      port: 1080
      udp: true
  ```

- 测速 parser 严格拒绝 `port`、`authentication`、`tun`、`sniffer`、`dns`、
  `rules`、GeoData 下载字段及其他未知字段。它复用运行配置的
  VLESS/SOCKS5/AnyTLS 平铺节点和 `dialer-proxy` 图校验。Core 必须推导出恰好
  一个没有被其他
  节点引用的链头，且从它出发的完整链覆盖所有节点；多链头、无链头或 unused
  proxy 都失败。
- 每个 worker 直接准备自己的 proxy graph，通过推导出的唯一链头连接目标；不创建
  loopback HTTP listener、公开实例、TUN lease、Android protect、GeoData matcher
  或 updater。App 不再分配端口或生成 HTTP Basic 凭据。
- `url` 必须是无 userinfo、无 fragment 的绝对 `http` 或 `https` URL。目标域名以
  domain destination 交给被测 outbound graph；HTTPS 使用 bundled WebPKI roots
  验证目标证书并通过 HTTP/1.1 HEAD 探测。
- 计时从 outbound connect 前开始，到收到完整 HTTP/1.0 或 HTTP/1.1 response head；
  配置读取、bootstrap DNS、proxy graph 构建和最终资源释放不计入 `delay`。目标返回
  任意合法 HTTP status 都表示探测成功；不跟随 redirect、不读取 body。
- `results` 与 `configPaths` 严格等长同序。成功项包含非负毫秒 `delay` 和空
  `error`；失败项省略 `delay` 并包含非空、有界 `error`。单项失败不取消其他项，
  也不使用 10000/11000 哨兵。
- payload、初始化或 batch admission 错误使用普通顶层 failure envelope。方法返回
  前所有 worker、stream、connector 和 runtime task 都已经释放。

## 5. Android protect

Android protect 是 Invoke 之外唯一允许的平台注册边界，因为 JSON 无法携带回调能力。

- Android wrapper 必须在含 TUN 配置的实例调用 `prepare` 前注册一个 runtime-local `ProtectFd(int) -> bool` controller。`measureDelay` worker 不要求 controller，也不会调用它。
- Rust runtime 线程调用 Java 前必须安全附着 JVM；controller 使用 JNI global reference 保持存活。
- 含 TUN 实例的每个 outbound TCP/UDP socket 在 connect 前同步调用 `protect(fd)`。
- TUN `prepare` 时没有注册 controller 必须立即失败；运行时返回 `false`、抛出 Java exception 或 controller 失效必须使该次连接失败。
- `protect(fd)` 必须快速、同步、非阻塞地返回，且不得直接或间接重入 `nativeInvoke` 或 controller 注册接口；native binding 会拒绝从任意 VCore runtime 线程重入，防止 callback 调用实例生命周期 method 后等待自身退出。
- 只保护 outbound socket，不注册 listener controller。
- 只有当前 registry 没有实例持有 TUN lease 时，才能替换或注销 controller；非 TUN 实例不会阻止该操作。TUN 实例的 `stop`/`destroyInstance` 是释放 global reference 前的同步屏障。
- Android binding 使用稳定 namespace `com.onevcore.vcore.NativeVCore`，不硬编码 OneVCore App package。
- 业务入口为 `nativeInvoke(byte[]) -> byte[]`；protect controller 通过 `nativeRegisterProtectController`/`nativeUnregisterProtectController` 注册和注销。

## 6. 大小与编码边界

- Invoke envelope 上限为 1 MiB（1,048,576 个 request bytes，不计 C 结尾 NUL）；
  C 入口执行有界 NUL 扫描，Android 在复制前检查 `byte[]` 长度。Invoke 不设置会让
  第七个纯校验返回 busy 的全局业务 admission；配置文件另受每次 256 KiB 上限。
- 配置通过位于 `dataDir/configs` 的 `configPath` 读取，不把 YAML 嵌入 Invoke JSON，以减少临时内存和敏感数据复制；iOS 35/45 MiB 观测目标不是 Invoke 大小或生命周期限制。
- TUN 最终 proxy UDP response payload 在分配前限制为 1,452 字节；嵌套 SOCKS5/XUDP 只可为各层 wire header 增加有界余量，解封装后仍执行该最终上限。HTTP inbound 不提供 UDP。
- Android binding 已使用 UTF-8 `byte[]` 收发 Invoke JSON，不依赖 Modified UTF-8，并由测试覆盖中文与 emoji 输入。
