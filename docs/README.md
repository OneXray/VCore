# VCore 文档

状态：VCore 只接受当前严格配置协议。YAML 使用字段名和嵌套与 Mihomo 一致的平铺 VLESS/SOCKS5/AnyTLS 子集，不含 `configVersion` 或 `default-proxy`；Invoke `version` 和 `buildIdentity` 单独报告内部 schema revision 10。运行配置必须至少包含一个 proxy，以及恰好以实际 proxy name 的最终 `MATCH` 收尾的 `rules`。proxy 数量和 `dialer-proxy` 链深没有独立上限，只受整份 YAML 256 KiB、name 唯一、引用存在和全图无环约束。Invoke API v4 要求宿主先用 `initialize({dataDir})` 建立固定的 `configs`/`geodata` 布局；App 只写配置，GeoData 由 VCore 管理。公共生命周期始终单实例；`measureDelay` 单次接收 1–5 份顶层仅含 `proxies` 的 node-only 配置，Core 推导唯一完整链头并固定最多五路并发。全 qtype runtime DNS、Mihomo-compatible nameserver egress/有序 GeoSite nameserver policy、rules、TUN ICMP fake response、TUN TCP/UDP sniffer、路由数据面和有界 GeoData loader/matcher 属于当前契约。启用 TUN 的配置还可通过顶层 `external-controller` 提供单次 `GET /traffic` snapshot；可选 `secret` 使用 Bearer 鉴权，省略时采用 Mihomo 无鉴权语义。iOS 35/45 MiB 只作为诊断观测与 Release 真机优化目标，任何读数或测量失败都不改变 VPN 生命周期结果。物理 iOS/Android TUN 数据面仍需按验收矩阵单独登记。

阅读顺序：

1. [Invoke API](invoke-api.md)
2. [配置协议](config.yaml)
3. [AnyTLS outbound](anytls.md)
4. [TUN 流量 Controller API](controller-api.md)
5. [GeoData rules](geodata.md)
6. [TUN ICMP 与 DNS 当前契约](tun-icmp-dns.md)
7. [TUN 平台层与 Windows UWP 边界](tun-platform.md)
8. [REALITY V1 客户端协议基线](reality-wire-protocol.md)
9. [自有 rustls REALITY 实现计划](rustls-reality-plan.md)
10. [iOS TUN 业务优先优化计划](ios-business-first-optimization-plan.md)
11. [验收矩阵](acceptance.md)
12. [第三方参考与许可证](../THIRD_PARTY_NOTICES.md)

实现目标对应关系：

1. `src/config/` 实现严格的 JSON-compatible YAML 预校验，只接受配对的 `port`/`authentication`、仅限 TUN 的 `external-controller` 与依附于它的可选非空 `secret`、独立 `tun`、可选 `sniffer`、至少一个平铺 Mihomo `proxy`、`dns` 和必填 `rules`；YAML 无版本/默认节点字段，旧顶层或 Xray 嵌套 proxy、未知字段、无效 name/引用/环都失败。proxy 数量和链深没有独立上限，整份 YAML 最大 256 KiB。`rules` 必须恰好以指向实际 proxy name 的最终 `MATCH` 收尾；`PROXY` 没有魔法别名。`authentication` 必须恰好包含一条 `user:password`。`sniffer` 默认关闭，只接受 `enable` 与大小写敏感的 `sniff.HTTP/TLS/QUIC.ports`；启用时至少配置一个协议。
2. `src/ffi/` 负责 Invoke API v4、`initialize({dataDir})`、单公共两阶段生命周期、generation `instanceId`、runtime-local TUN/protect lease、fd 所有权和 Android protect 边界；`src/ffi/measure_delay.rs` 负责单批次 admission、1–5 份配置、固定最多五路 HEAD 测速和同序逐项结果，payload 只接受 `configPaths`、`timeout` 与 `url`。`configPath` 必须位于 `dataDir/configs`，App 不写 `dataDir/geodata`。`validateConfig` 是不受全局 Invoke busy 配额影响的纯校验。同一公共实例的生命周期命令仍 fail-fast。VCore 不识别宿主进程角色，也不做跨 runtime 配额。
3. `src/outbound/`、`src/xudp.rs`、`src/transport/xhttp.rs` 实现 VLESS/XUDP/XHTTP、SOCKS5 CONNECT/UDP ASSOCIATE、AnyTLS TCP/UoT 和协议无关的任意长度链。节点 A 的 `dialer-proxy: B` 表示物理路径 `client -> B -> A -> target`。AnyTLS 使用标准 TLS、v2/v1-compatible session 协商、单 active stream 的 idle reuse 和显式 shutdown；完整边界见 [anytls.md](anytls.md)。
4. `src/inbound/http/`、`src/tcp_sniffer.rs`、`src/quic_sniffer.rs`、`src/dns/`、`src/routing/`、`src/tun_runtime.rs` 与 `src/outbound/direct.rs` 实现认证 HTTP probe listener、TUN TCP/UDP sniffer、全 qtype runtime DNS、按 nameserver fragment 选择的 `DIRECT`/`RULES`/精确 proxy name egress（无 fragment固定 DIRECT）、有序 `geosite:` policy、顺序业务 rules 以及精确 proxy name/`DIRECT`/`REJECT` action。`PROXY`/`#PROXY` 不具有默认节点魔法含义。TUN raw-IP packet I/O 同时维护当前一秒窗口与 session 累计 byte，并由 loopback Controller 暴露单次 `/traffic` snapshot。
5. `src/geodata/` 管理 `dataDir/geodata` 内的 Xray-compatible `geosite.dat`/`geoip.dat`，只加载唯一公共实例的业务规则或 DNS nameserver policy 引用分类，执行有界 protobuf wire 扫描、紧凑匹配和统一 8 MiB allocation capacity 预算。下载由成组出现的 `geox-url`、`geo-auto-update`、`geo-update-interval` 显式配置；缺失的 GeoSite/GeoIP 各自降级跳过。只有公共实例 start 后 auto-update 为 true 且有实际需求时，才经最终 `MATCH` 指向的 proxy graph 后台检查，不允许 DIRECT fallback。
6. `scripts/build_apple.sh` 与 `scripts/build_android.sh` 只向 VCore 自身的 `dist/` 输出平台产物。
7. `ResourceLimits::tun()` 只保留 256 packet queue、128 event/ordinary response queue、1,500-byte TUN packet、32 KiB/TCP direction、64 KiB TLS/XHTTP、cache/wire/parser 等局部边界，不再包含 TCP、UDP、half-open、handshake 或 DNS 并发总数。runtime DNS 保留 256 typed cache、64 项/256 KiB opaque cache、128/128 TUN DNS ingress/response，以及按需启用且最多 256 项的 TUN redir-host store。显式 TCP pool 的 active 物理连接不设 ceiling，默认只保留 4 个 idle、同 key 2 个，idle 30 秒。bootstrap resolver 最多 4 个 worker thread，忙时等待可用 worker，而不是以资源上限错误拒绝。runtime 继续记录 TCP、UDP、half-open、handshake、DNS current/peak、singleflight join、cache hit、queue drop 与 TCP pool final stats。旧 iOS 20/4 weighted pools、128/64/32/16 业务并发档、DNS 128/8 admission、静态 byte model 和 `total × 4` queue 推导均已删除。
8. iOS `TASK_VM_INFO` 与 allocator pressure relief 只提供 best-effort telemetry/cleanup：current 首次跨过 35/40/45 MiB 时限频记录，running 至多每 30 秒采样一次；measurement failure、current 或 lifetime peak 都不能影响任何 Invoke 结果。35/45 MiB 是优化目标，不是 hard gate。
9. `measureDelay` 是 registry 级批量 method。同一 runtime 只允许一个外部调用；payload 只接受 `configPaths`、`timeout` 和 `url`，单次接受 1–5 份配置，Core 固定最多使用五个私有 worker，实际数量不超过配置项数。测速 YAML 顶层只允许 `proxies`；未被其他节点 `dialer-proxy` 引用的唯一节点是链头，且该链必须覆盖全部节点。worker 直接准备 outbound graph，不创建 listener、公共实例、TUN/protect、DNS/rules/sniffer 或 GeoData registration。

## 文档规则

- `invoke-api.md`、`config.yaml`、`anytls.md`、`controller-api.md`、`geodata.md` 与
  `tun-icmp-dns.md` 是当前公共契约；实现和文档不一致属于缺陷。
- `acceptance.md` 必须分开“已执行的 host 自动化”、“尚待补写或加强”与
  “需要真实服务端/真机/宿主”；只有已记录日期、命令和结果的自动化才能写成已通过。
- Xray 配置形状不等于完整 Xray 功能兼容；未实现能力必须明确拒绝。
- 配置协议只向前演进，不保留旧字段、旧顶层结构或版本迁移分支。新增协议、配置字段、无界资源或 App 耦合前，必须先更新契约和验收矩阵。
