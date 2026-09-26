# VCore 验收矩阵

本文记录验证范围与发布门禁，不把历史开发包结果当作当前 release 保证。
源码 revision、lockfile/产物 hash、签名、环境、命令和结果保存在当次 PR 或发布记录中。

## 证据规则

- 后续服务端和测试原站必须遵守[容器隔离规则](testing-isolation.md)。历史宿主测试仅为历史证据，未迁移的用例不得回退宿主执行。
- 主机测试、交叉编译、模拟器和虚拟网络不能替代对应物理 TUN 或安装包证据。
- x64 模拟不能替代原生 x64；VPN 双栈接口不能替代真实物理 IPv6。
- 外网吞吐与进程间通信基准各自独立，不能相互替代。
- 未执行或缺少可复现记录的项目保持未验证；不从旧产物继承通过结论。
- 记录不得包含 secret、UUID、密钥、完整用户配置或私有目标信息。

## 自动化覆盖

2026-09-25 [精选指纹 CF0](acceptance/client-fingerprint-selected/CF0.md)完成七值/四模板的独立官方参考基线、116 组原始观测检查与冻结门禁。它只签收 `selected-v1` 的采样设施，不扩大生产名称、不抵扣新模板业务互通或平台验收；后续 CF1–CF5 独立记录。

同轮 [fork 库阶段记录](acceptance/client-fingerprint-selected/library-progress.md)完成 CF1–CF3 及 CF4 的本地 REALITY 子包，组合测试 43 项通过。[本地 CF4](acceptance/client-fingerprint-selected/CF4.md)锁定获准发布的 `e81c6837`，完成四模板/七值及 schema20 接线，43 项独立容器互通、共享内存安全及 feature 门禁通过。

[CF5 本地签收](acceptance/client-fingerprint-selected/CF5.md)完成四模板各 57 项、合计 228 项完整容器互通，520 个所属容器全部回收；168 组公开配置 ClientHello 和 24 组真实恢复/期限观测通过，下载腿身份/票据隔离与受影响检查通过。锁定已授权发布的 `67581195`，修正命名 REALITY 的 TLS1.2 声明保留及票据 hint 期限；实际 REALITY 协商仍仅允许 TLS1.3。独立 checkout、Apple 五目标和 Android 两 ABI 的 Release/打包/最终链接通过，macOS arm64 C/Swift 各 1,000 次 ABI 调用通过。记录保留首次 H3 夹具失败与收尾 Windows 锁文件修正的证据边界；Windows 原生、设备/TUN、远端 CI、性能/体积及完整发布许可证审查不因此通过。

2026-09-25 [TLS 指纹接线](acceptance/tls-client-fingerprint.md)接入 boring 的 `chrome120` 和经典 REALITY，schema19 / Invoke v5。随后[退役自有 rustls fork](acceptance/rustls-fork-retirement.md)：普通无指纹 TLS、QUIC、WebPKI 改用官方 crates.io rustls；最新替换回归为 132 项容器检查及 Apple/Android 构建通过。旧 fork 将永久删除，以下 N0–N5 记录保留当时的依赖摘要，不保证历史版本重建，也不计为当前后端的新增能力。现行依赖见 [TLS 依赖](tls-dependencies.md)。

下一版协议从独立 N0 基线开始，进度见 [N0 基线与可行性门禁](acceptance/next-protocols/N0.md)。2026-09-22/23 的新基线与接口实验不继承本页历史通过状态，也不代表新五协议或平台交付已经完成。当时的混合 REALITY fork 局部实验不等于生产能力；当前实现另见下文 N7.2。[N0-D QUIC 原生入口](acceptance/next-protocols/N0-quic-entries.md)已验证，原生半关闭失败和 N0 其余门禁仍保留。

2026-09-23 追加的 [XHTTP 关闭对齐](acceptance/next-protocols/XHTTP-close.md)修正了既有生产 H2 的三种模式：应用上传 EOF 结束整条逻辑连接，不再保留下行半关闭。独立 H3 实验与官方 Mihomo 客户端完成同一 Xray 对端的行为对照；当时 H3 尚未接入生产，后续接入见 N5。历史 request-EOF/尾包失败不改记为成功，也不再作为 XHTTP 的客户端契约。

同日 [N0-B 公共流接口实验](acceptance/next-protocols/N0-stream.md)完成TLS/普通WS/gRPC的注入IO、取消回收与关闭差分：12项Debug/Release测试、42项官方Mihomo检查及Apple/Android交叉检查通过。没有新增生产功能或依赖；Windows、真机和完整N0仍未签收。

[N1 h2 补丁升级](acceptance/next-protocols/N1-h2.md)将生产和流实验的 h2 更新至官方稳定版0.4.19，修复已复现的 END_STREAM 后 RST 丢失完整响应问题。关闭回归、旧协议扩展互通和流实验重跑通过；这是 N1 前置子包，不代表完整 N1 或全依赖升级完成。

[N1 依赖基线进度](acceptance/next-protocols/N1-dependencies.md)记录当时的稳定版审计及旧 rustls fork 来源。获准将0.23.45同步结果推送到正式依赖分支后，VCore与四个实验工程曾接入新版fork及官方tokio-rustls0.26.5；当时验证见[N1 TLS接入](acceptance/next-protocols/N1-tls.md)，与较早仅修改地址的证据分开记录。该轮 ring、classic REALITY、API v5/schema14均不变，不描述当前依赖。

[N1 基础与实验依赖更新](acceptance/next-protocols/N1-foundation-dependencies.md)继续升级基础库、smoltcp、WS/HPKE实验和兼容补丁锁，记录已批准的Windows SDK配套例外。全Debug/Release、全目标Clippy、真实对端回归和Apple/Android构建通过；不抵扣完整N1、新协议、真机或Windows原生门禁。

[N1 声明清单校验](acceptance/next-protocols/N1-catalogs.md)提供 `check protocol-coverage --catalog-only`，历史 schema-v1 冻结145字段/69组合ID并检查引用、归属及必要元数据；仅撤回 Restls 后的当前 schema-v2 为139字段/68组合，旧 ID 不重排。有效结果为 `VALID / NOT RUN`，不是字段行为PASS；后续可执行case与运行结果单独签收。

[N1.2 共享安全机制](acceptance/next-protocols/N1-security.md)增加类型化名称/ALPN/mTLS策略与不可变身份缓存隔离，并将标准TLS CloseWrite对齐Mihomo。未新增公开配置字段，独立接口测试不抵扣后续新协议字段互通。

[N1.3 共享流传输](acceptance/next-protocols/N1-stream.md)提供WS/gRPC/HTTP/legacy H2与独立XUDP帧层；15项定向测试、9项官方Mihomo/V2Ray传输用例、旧协议扩展互通及Apple/Android构建通过。该记录是独立历史子包，不代表新协议YAML已开放。

[N1公共基础汇总](acceptance/next-protocols/N1.md)记录定向数据报预算、受控QUIC、runtime/测量resolver、测试作用域RAII观测、独立feature和统一执行/证据门禁。最后的fork密码依赖升级已在单独分支获准发布并接入，[最终N1复验](acceptance/next-protocols/N1-x25519.md)完成21组required/139项断言、Debug/Release、原生传输、旧协议及Apple/Android构建，N1签收。WireGuard预检仍因隔离内核缺设备类型而BLOCKED，只影响依赖它的N8；新协议YAML、物理平台和发布不提前签收。

[N2 Trojan](acceptance/next-protocols/N2.md)于同日完成 TCP/UDP 与 TCP/WS/gRPC 生产接线及阶段签收：41 组 required、18 个适用字段、120 轮生命周期/资源检查、独立 coverage、旧协议回归及 Apple/Android Release 构建通过。Mihomo listener 是默认对端，域名 UDP 缺口由 Xray、扩展 WS ED 由 V2Ray 单独补验并保留原失败。配置修订升至 15，Invoke v5 不变；不抵扣 N3–N10、Windows 原生、真机或发布。

同日 N3 已实现独立 feature 下的 [VMess AEAD wire 层](acceptance/next-protocols/N3-wire.md)，Mihomo TCP/WS/gRPC 的明文/TLS 消费者测试通过。[V2Ray HTTP/H2 半关闭诊断](acceptance/next-protocols/N3-close-blocker.md)在官方 Mihomo 客户端对照中也复现；用户已取消“非 XHTTP 均必须收到半关闭尾包”的统一要求，改为按实际传输对齐 Mihomo 行为、优先与 Mihomo 服务端互通。旧失败不改记 PASS，不再仅因此阻塞；正常数据和关闭对齐分开复验。该记录时 N3 尚未完成，不能将 wire 通过等同公开接线和完整阶段签收。

后续 [N3 UDP 工作记录](acceptance/next-protocols/N3-udp-progress.md)保留了原生端容量差异、Mihomo 首包/响应超时和进行中的修正。[客户端对照诊断](acceptance/next-protocols/N3-udp-client-differential.md)已用官方 Mihomo 客户端复现超时，并通过受控端口实验确认一类本机回环保护误判；另有独立 socket 探针复现双栈同号端口的回包反射。当时未修改生产实现或第三方代码，不将全部历史失败强行归因；这些不是半关闭失败，也不能由新的关闭契约抵扣。该诊断记录本身不是 UDP 完整签收。

隔离规则生效后，[N3 容器 UDP 复测](acceptance/next-protocols/N3-udp-containers.md)将官方服务端、官方对照客户端入口和 UDP 原站全部放入独立容器，并修正测试驱动的来源端口复用。TCP/WS/gRPC 明文/TLS、三编码、13 body 配置、三目标类型及实际大包边界合计 2,808 个关联、1,404,000 次请求/回包通过；正常清理和独立 SIGINT 清理均有证据。历史 FAIL 不改写，不修改第三方或关闭保护；这仍不抵扣 HTTP/H2、UDP 负例/取消/来源隔离、公开接线和 N3 完整阶段门禁。

2026-09-24 [N3 VMess 完整签收](acceptance/next-protocols/N3.md)完成 AEAD、五种传输明文/TLS、raw/XUDP/packetaddr 与公开 YAML/运行时接线：117/117 组 required、30/30 字段、80 轮生命周期/资源检查和独立 coverage 通过。官方协议端及原站全部容器化，57 个容器全部清理；Debug/Release、共享回归、生产 feature、Apple/Android 构建通过。schema 升至 16，Invoke v5 不变。历史失败保留，N4–N10、物理平台、远端 CI 和发布不继承本地通过状态。

同日 [N4 VLESS 阶段签收](acceptance/next-protocols/N4.md)完成基础传输、HTTPUpgrade/fast-open、gRPC 池、TLS/mTLS/经典 REALITY、Vision 和三种 UDP 编码，回归既有 XHTTP。145/145 组 required、39/39 字段、160 轮生命周期/资源检查及独立 coverage 通过；171 个隔离容器均清理，Apple/Android Release 构建通过。WS + REALITY 的三种形态因官方客户端能力缺口采用明确标注的分层关闭参照，数据/认证仍对真实 Mihomo REALITY listener；不是同组合客户端差分通过。schema 17 / Invoke v5，N5/N7、设备和发布保持独立门禁。

2026-09-25 [N5 XHTTP/sing-mux 阶段签收](acceptance/next-protocols/N5.md)完成 H1/H2/H3、请求字段、独立下载安全/复用及 h2mux/smux/yamux。单次完整运行 416/416 组 required、57/57 字段、240 轮生命周期/资源检查与独立 coverage 通过；三个安全组内部 112/112 检查，769/769 个所属容器回收，Apple/Android Release 构建通过。Xray 的直接 packetaddr/sing-mux 和 H3 客户端证书认证缺口分别使用明示的 Mihomo decoder 分层、获准 xcaddy/Caddy H3/mTLS → 单个 Xray handler；不冒称 Xray 直接支持。schema 18 / Invoke v5，N7 高级安全及设备/发布仍未签收。[开发记录](acceptance/next-protocols/N5-progress.md)保留原失败，官方 Mihomo 双腿上传错误的 6 项诊断超时不改记 PASS。

2026-09-26 [N6 Hysteria2 阶段签收](acceptance/next-protocols/N6.md)完成 HTTP/3 认证、TCP/UDP、TLS/mTLS、真实带宽控制、Salamander 和端口跳跃。在同一冻结源码下通过 36/36 组 required、20/20 个字段、10 个带宽样本、八组 60 秒跳跃及 40 轮公共/自有生命周期；两种路径入口的独立 coverage、共享 H3 回归和 Apple/Android Release 构建通过，69/69 个所属容器回收。经 Rust 库复用调研后采用内部薄协议层与官方 Quinn/h3/rustls，不修改第三方。原生 Hysteria 的 UDP 回包缓冲包含头部、实际载荷小于 4096 的限制单列；Mihomo 的 4096 字节业务载荷另验通过。schema21 / Invoke v5；[开发记录](acceptance/next-protocols/N6-progress.md)保留真实失败，不继承为 N7–N10、真机、Windows 原生、远端 CI 或发布通过。

2026-09-26 [N7.2 混合 REALITY 子包](acceptance/next-protocols/N7-reality-hybrid.md)完成 S03/D16 本地验收。获准发布的 boring revision `b7639ab7` 已接入，经典默认不变；显式混合仅接受无命名模板或 Chrome133，实际协商 group 4588，否则失败关闭。完整容器门禁 54/54、四模板定向回归 32/32、160 轮生命周期/资源检查及 Apple 五目标/Android 两 ABI Release 构建通过，88 个所属容器回收。主/下载腿、图/入口/测速、实际 share 和认证负例分别取证；schema22 / Invoke v5。[开发记录](acceptance/next-protocols/N7-progress.md)保留原始接口/夹具失败与 fork 13/13 前置证据；Encryption、ECH、附加封装和 N7.5 尚未完成，不是完整 N7 或完整 VLESS 签收。

同日 [N7.1 Encryption 子包](acceptance/next-protocols/N7-encryption.md)完成 VL06 本地签收。
同一冻结输入通过公开主矩阵 59/59、其他五类组合 35/35、分层传输/复用 36/36，
常规与 ChaCha wire 各 18/18、真实票据过期 9/9、最大 padding 选定项 2/2，
以及 120 轮公开/自有生命周期与资源检查。Apple 五目标/Android 两 ABI Release
构建与本地共享回归通过。schema23 / Invoke v5；认证失败不自动重放业务，Vision
direct 关闭逐外观与真实 Mihomo 对照。N7.3–N7.5、设备、Windows 原生、远端 CI
和完整 N7 仍未签收。[ShadowTLS v3 fork 门禁](acceptance/next-protocols/N7-shadow-tls.md)
25/25 及其单独发布授权不等于 VCore 已支持该封装。

schema26 [仅移除 Restls](acceptance/next-protocols/N7-restls-retirement.md) 及 boring fork 对应扩展，旧 Restls 配置严格拒绝，不再作为 N7 门槛；JLS 继续保留。固定已发布的 boring `5ca9ba3e` 后，10 项隔离 JLS 定向互通、共享本地回归和 iOS/Android ARM64 生产构建通过；13 个所属容器回收，不替代完整 N7 或设备验收。

[N7.4 JLS 接线](acceptance/next-protocols/N7-jls.md)首次固定到获准发布的 boring
`a859a663`，增加主连接/独立下载腿的公开 `jls-opts` 与受控原生 TLS 认证，
schema24 / Invoke v5。S12–S13 / D25–D26 完成本地子包签收：122/122 容器用例、
80 轮生命周期/资源检查、197/197 所属容器清理与 Apple/Android Release 构建；
本地配置、内存 IO、共享检查均通过。原始 Mihomo 无指纹 gRPC ALPN 对照失败
与明示的 Chrome 指纹关闭参照分别记录，不修改第三方或待测节点。
JLS 子包不等于 N7.4、N7.5 或完整 N7 完成，也不是 VCore push、远端 CI 或设备证据。

当前 source/tests 覆盖：

- Invoke API v5、单实例生命周期、Debug/Release 运行时线程重入拒绝、panic 与同步清理；
- schema revision 26、IPv6、严格 YAML、节点 / `select` 组上游混合 DAG 和 node-only 测速；
- 组上游与路由的共享选择、SOCKS5 UDP 建链快照、潜在 DIRECT 首跳准备、独立下载端点和深图回收；
- HTTP 本机 / 认证共享、双栈监听回滚、逐请求认证与分发、Keep-Alive / 正文定界、CONNECT / Upgrade、10 MiB 双向摘要与活动连接 Stop；
- SOCKS5 入站认证、三类目标、半关闭、TCP 授权 UDP、源端口学习/隔离、IPv6 作用域固定端口/学习端口匹配与跨接口隔离、过期/满队列/慢上游取消及纯 SOCKS5 Controller（作用域匹配为合成地址测试，不代表物理 LAN 验证）；
- VLESS TCP/WS/gRPC/HTTP/H2/XHTTP、HTTPUpgrade/fast-open、TLS/mTLS/经典及显式混合 REALITY、Vision、gRPC 池、三种 UDP 编码、响应头/期限/取消与同步 Stop；
- XHTTP H1/H2/H3、请求字段/有界 packet-up 聚合、双腿安全/连接池/受控 QUIC，以及独立 h2mux/smux/yamux、padding/only-tcp 和单流隔离；
- SOCKS5、AnyTLS、代理链、DNS、规则、GeoData 和 HTTP/TLS/QUIC 嗅探；
- AnyTLS 有序 ALPN、WebPKI / 跳过 / 叶与非叶 pin、TLS 1.2/1.3 伪造签名拒绝、节点间策略隔离和精确恢复票据预算；
- Trojan TLS/WS/gRPC、TCP 半关闭、原生 UDP 的有界帧与来源隔离、strict 配置、具体/组上游、独立测速及同步资源回收；
- VMess AEAD、TCP/WS/gRPC/HTTP/H2 明文/TLS、三种 UDP 编码、受控 DNS、认证/篡改/预算/取消负例、组快照、公开入口和同步资源回收；
- Hysteria2 QUIC TCP/UDP、TLS/mTLS/证书 pin、带宽与 pacing、Salamander、固定/随机端口跳跃、认证会话快照和同步资源回收；
- SS 2022 三算法白名单、同库 TCP/UDP 回环、有界 TCP 首写、首次传输前半关闭及 Pending 空握手续写、响应时间/认证/请求盐、UDP Pending/取消、重放/乱序/会话轮换、封装上限与来源检查，socket protect 失败关闭；
- ICMPv4/v6、校验和、分片、MTU、队列与 Apple/Android 帧/fd/protect 所有权；
- Windows 单 Application、token 绑定、Snapshot/profile、控制/数据协议、会合记录、
  物理绑定、on-link prefix 去重、显式排除优先的路由和 MTU 派生的 UDP/DNS 上限；
- Windows Job Object 进程监督，以及 Controller 鉴权、流量、实时组选择和有界请求。

常规命令见 [README Validation](../README.md#validation)，平台构建与脚本检查见
[scripts](../scripts/README.md)。运行时线程重入还需 Release 配置：

```bash
cargo test --locked --release --all-features --all-targets
```

后续外部互操作以 mihomo 官方最新稳定版预编译包为对端，不从单元测试推断。入口从官方 `latest/download/version.txt` 获取资产文件名所需的 release，再下载到本仓库的 `target/interop/`，通过二进制 `-v` 记录实际版本；不调用 GitHub API、不固定版本、不从本地源码编译、不依赖项目外目录。下载或解压失败不能使用旧缓存宣称通过：

```bash
bash tests/run_mihomo_interop.sh
```

该入口当前覆盖 8 个 HTTP 场景、8 个 SOCKS5 TCP/UDP 双向 IPv4/IPv6 场景及 17 个 AnyTLS 检查（12 个 TCP/UoT 数据场景、3 个独立测速、2 个证书拒绝）。版本、二进制 hash、超时及清理见 [scripts](../scripts/README.md#mihomo-协议互通)。既有 Xray / anytls-go 脚本保留为历史专用入口，未迁移的协议场景仍需补充 mihomo 证据，不能自动继承旧对端结果。

2026-09-22 在 macOS ARM64 / Apple Container 1.4.1 执行 `uv run --project scripts --locked --offline vcore-scripts check mihomo-interop --container` 通过基础互通，包括上述 HTTP/SOCKS5/AnyTLS、SS 三算法、代理链、受控 EIH 中继、负例与生命周期清理；这里的 `--offline` 仅限制 uv 依赖解析，mihomo 仍在线下载。通过固定 `latest/download/version.txt` 下载到的官方原生和 Linux ARM64 程序，`-v` 均输出 `v1.19.31` / Go 1.26.8 / `with_gvisor`。程序 SHA-256 分别为 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090` 和 `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`；下载日志另记录压缩包摘要。本次未执行 `--extended`、30 分钟长测或设备/安装包验收，不继承下文旧自编译对端的扩展结果。自建对端和临时配置已清理。

## 协议与数据面

schema 19 的命名 TLS profile、classic REALITY 后端接线及新增原生链接依赖，
单独记录在 [TLS 指纹接线验收](acceptance/tls-client-fingerprint.md)；旧 N4/N5 与设备成绩
不自动继承为新 TLS 路径的验收。

| 能力 | 自动化 | 外部进程互操作 | 物理 TUN / 安装包 |
| --- | --- | --- | --- |
| VLESS 基础传输、TLS/mTLS/REALITY、Vision、三 UDP 编码 | 严格配置、feature、codec/取消、池与公共运行时；[N4 证据](acceptance/next-protocols/N4.md) | Mihomo 为主，V2Ray 补 HTTP/H2/扩展 ED；WS + REALITY 关闭参照的三项范围差异单列 | 新能力未验证；仅 Apple/Android 构建通过 |
| VLESS XHTTP H1/H2/H3 与 sing-mux | 请求/安全/池/严格配置、受控 UDP、公共入口与资源；[N5 证据](acceptance/next-protocols/N5.md) | Mihomo 为主，Xray 补 H3；packetaddr/mux 分层解码及 Caddy mTLS 网关明确标注；HTTPUpgrade/fast-open + 新 sing-mux 未专项验收 | 仅 Apple/Android 构建；Windows ARM64 旧版本包记录不继承为当前版本设备通过 |
| SOCKS5 CONNECT / UDP ASSOCIATE 出站 | 已覆盖 | mihomo TCP/UDP、IPv4/IPv6 | Windows ARM64 历史开发包已覆盖 |
| SOCKS5 CONNECT / TCP 授权 UDP 入站 | 已覆盖 | mihomo 双向 TCP/UDP、IPv4/IPv6 | 真实 LAN / 物理 IPv6 未验证 |
| AnyTLS TCP / UoT v2、ALPN / 证书策略 | 已覆盖 | mihomo 公开 YAML，TCP/UoT IPv4/IPv6、测速及证书拒绝 | 旧能力有 Windows ARM64 历史开发包记录；新 TLS 字段未做设备验证 |
| Trojan TCP/UDP + TLS/WS/gRPC | 严格配置、codec/取消、独立 feature 和公共运行时；[N2 证据](acceptance/next-protocols/N2.md) | Mihomo 基础/组/证书/入口/资源；Xray 域名 UDP；V2Ray 扩展 WS ED | 未验证；仅 Apple/Android 构建通过 |
| Hysteria2 TCP/UDP、带宽、Salamander、端口跳跃 | 严格配置、wire/重组/窗口、feature、公共入口和资源；[N6 证据](acceptance/next-protocols/N6.md) | Mihomo 基础/安全/带宽/关闭；官方 Hysteria 补跳跃和 UDP-disabled，原生回包大小限制明确保留 | 未验证；仅 Apple/Android 构建通过 |
| SS 2022 | 三算法配置与 I/O/安全边界；活动 Stop、绑定失败回滚、独立测速和进程 FD 回收 | mihomo TCP/UDP × IPv4/IPv6/域名及服务器先发；具体/嵌套组/DIRECT 链；AES 1/2 层受控 EIH 中继 → mihomo；错误密钥/算法/身份拒绝 | 未验证 |
| HTTP 本机 / 认证共享、消息定界与隧道 | 已覆盖 | mihomo 双向 harness（8 个场景） | 真实 LAN / 物理 IPv6 未验证 |
| DIRECT 与代理链 | 已覆盖 | 本地 fixture | Windows ARM64 开发包已覆盖 |
| DNS / rules / GeoData / sniffer | 已覆盖 | 本地 DNS 与代理 fixture | Windows ARM64 开发包已覆盖 |
| ICMPv4 / ICMPv6 Echo | 已覆盖 | 不适用 | Windows ARM64 开发包已覆盖 |
| Controller 四字段流量 | 已覆盖 | HTTP fixture | Windows ARM64 开发包已覆盖 |
| Controller `select` 代理组控制 | 已覆盖 | HTTP fixture | 物理设备未验证 |
| `dialer-proxy` 引用 `select` 组 | 配置、建链、切换与回收 fixture | 本地 SOCKS5 fixture | 物理设备未验证 |

Windows 开发包的适用环境与证据入口见下节。本地互操作只证明受控配置，
不代表所有公网服务、所有协议组合或当前发布包。

2026-09-17 的 SS 候选在 macOS arm64 / Rust 1.98.1 上完成 12 项 SS 专项、Debug/Release 各 563 项库测试与 4 项兼容测试、17 项 netstack 测试及 clippy/依赖审计。默认构建、精简 feature 组合、Rust 1.91 检查和无 `interop-test` 的原生 macOS Release `ffi` 构建通过。mihomo 对端为 `ab405bad5beeeac8b003bb01f60f134f6df54471`，二进制 SHA-256 `99462761f951b08df9911cf82f96e2f0cf34cda959b1bc391584b1b1bb2de5b3`；当次三算法 Stop/回滚/测速后测试进程 FD 回到 6 的基线。

SS 原样上游库的 padding 未初始化风险仍存在，未将相关失败证据改记为 PASS；完整说明见 [Shadowsocks](shadowsocks.md)。EIH 中继只处理身份头，最终 SS 业务解密由 mihomo 完成，不是同库自测或 mihomo 原生 EIH 服务端。

跨协议候选增加四类出站的两跳 TCP/UDP、真实嵌套组切换、HTTP-only Controller / 测速快照、合成 utun 和 100 次生命周期检查。首次 1800 秒持续测试约 8 分半后因 UDP 来源异常失败；macOS 双栈 UDP 本地端口串扰已独立复现，但当时未保存完整 socket 映射，不把所有历史超时归为同一根因。随后仅在自有测试中增加双地址族端口保护与跨进程互斥，不修改 VCore 生产 socket 行为或第三方源码。修复后 Debug/Release 各 564 项库测试、4 项兼容测试和 2 项端口保护测试通过，lib/bins 及 mihomo fixture clippy 通过。

修复后的单次 1800 秒长测通过：16 TCP + 16 UDP、1,754 次切组、29 次断连重建、470,248,320 字节校验；FD 为 6 → 195 → 6（含 32 个测试 guard），活动起始/峰值/结束/Stop 后 RSS 分别为 17,616 / 18,688 / 17,264 / 17,120 KiB，32-flow 建立耗时起始 165 ms、末次 166 ms。此结果不等于完整阶段签收：随后新增的 100 次快速重建检查两次失败，一次是收到 origin 请求后的回包超时，另一次在第 11 轮捕获 mihomo 的 `reject loopback connection`，AnyTLS 来源端口与该进程另一 UDP socket 端口同号。后一次有日志与 socket 映射佐证，前一次不强行归因。没有关闭 mihomo 保护或修改第三方；这些失败保留，不因独立网络重跑而改为 PASS。命令及限制见 [mihomo harness](../scripts/README.md#mihomo-协议互通)。

随后配置 Apple Container 1.4.1 的专用 host-only 网络：首跳和末跳使用两个 Linux ARM64 mihomo，仍为相同源码 revision，Linux 程序 SHA-256 `eb35562be501dd6cd9e1f8bdf3ba43162bf6abb6a3946cd1f1ec0511462feab2`。反向 HTTP/SOCKS5 入站仍为原生对端，VCore 不开放 LAN。基础 IPv4/IPv6 互通、全部跨协议与宿主组合、100 次生命周期，以及 100 次快速 32-flow 重建通过；快速重建后 FD 回到 6，在用堆 64,176 B。最初适配中的固定回环断言和 SLAAC 地址未就绪失败分别保留并修正于自有测试。候选 Debug/Release 各 564 lib + 4 compatibility + 2 fixture、netstack 17、Python 18、clippy、feature 组合与依赖审计通过。

该容器候选完成新的 1800 秒长测，完整测试总时长 1840.10 秒：16 TCP + 16 UDP、1,734 次切组、29 次断连重建、420,476,672 字节校验；FD 6 → 195 → 6。RSS 活动初始 / 峰值 / 结束 / Stop 后分别为 19,248 / 21,984 / 19,184 / 18,896 KiB；四次仅统计、不读取内容的堆采样约 4.90–4.91 MB，未出现持续活对象增长，后段 RSS 回落。初次 / 末次 32-flow 建立耗时为 204 / 153 ms；诊断采样扰动使最大 wave 达 441 ms，不能拿本轮的节流速率或最大延迟当无扰动性能基准。本机受控组合与资源门槛签收，全部自建对端与临时配置清理；这不修复或取消旧 macOS 同内核失败，不代表物理 TUN、LAN、IPv6 或平台发布门禁通过。

## Apple 与 Android

主机自动化覆盖 utun/rawIp、nonblocking、借用 fd 复制/关闭、EOF/非法包/部分写入、
Android protect 失败关闭和重复 prepare/start/stop。构建脚本可生成 Apple
XCFramework 与 Android arm64-v8a/x86_64 库。

2026-09-17 在 `926e15b5070316763c82ed8d749580d811e61ddb` 的干净检出、无相邻 rustls 工作目录下，Apple 五目标（iOS arm64、simulator arm64/x86_64、macOS arm64/x86_64）和 Android 两 ABI 的标准 Release 构建通过。环境为 macOS 27 / arm64、Rust 1.98.1、Xcode 27.0（27A266a）及 SDK 27、Android NDK 28.2.13676358 / API 24。所有产物身份为 Invoke API v5 / schema 14，不含 `interop-test`；lockfile SHA-256 为 `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2`。使用完整显式协议 feature 列表重建后，产物哈希与原 `ffi` / `tun` 传递启用方式一致。

macOS ARM64 原生 C 宿主链接该 XCFramework，1,000 次 `version` Invoke / VCoreFree 和身份检查通过；这是 C ABI 冒烟，不是物理 TUN、完整应用或 x64 原生运行验证。新增 CI 构建矩阵仅通过本地静态检查，本轮未触发远端 CI，也未获得 Windows 新能力构建或设备数据面证据。

同一干净检出的 locked fetch、C header、TLS/AWS-LC 来源审计及 Debug/Release 全测试通过（各 564 lib + 4 compatibility + 2 fixture，ignored 不计通过）。本机复用 Cargo cache，不声称验证了空缓存或离线下载。

仍需独立验证：

- Release iOS 无 debugger 的完整 TUN 生命周期与整进程内存轨迹；
- Android 真机的 TUN、protect、DNS、TCP/UDP 和重复启停；
- macOS system extension 的产品安装与生命周期。

## Windows VPN

### 已记录的开发环境

Windows 11 ARM64 开发签名包曾覆盖数据面、生命周期、压力与有界 batching；
单 Application loose-package 和后续 clean-install policy 门禁在 build 26200.9278
执行。不同记录不能拼接成一份完整正式发布结论。

| 记录 | 已观察范围 | 限制 |
| --- | --- | --- |
| 单 Application Gate 0 | AppContainer Provider、无参数激活同包 medium-integrity Session Host、connect/stop、会合清理 | loose-package spike 的基线含未提交目标改动，单独基线 SHA 不能复现；不证明签名包或 Store |
| 全局 policy / IPv4-only clean gate（2026-09-01） | IPv4-only/dual-stack lifecycle、LAN allow/block、IPv4 exclusion/control、Always On、cold profile、失败关闭和 Stop 后清理 | 只验证一个局域网 peer，没有逐个探测全部 on-link prefix |
| PR 修复后同机开发包回归 | TCP、UDP、ICMPv4/v6，DNS 开关两种情况下的清缓存 hostname 请求、link-local route inventory、零残留 | 没有物理 IPv6/default gateway；UDP probe 仅验证正常大小报文，不证明超限传输 |

门禁结束时检查 Session Host、VPN route/interface 和测试进程清理；已停止 Provider
的 AppContainer 外壳可能暂留，原 case 之间显式清理它。Windows 的两条 `/1`、
null IPv6 地址参数、物理 transport 绑定等实现约束见
[Windows VPN](windows-vpn.md)，不在验收文档另维护一份。

### 不可变证据入口

以下记录保留环境、命令、结果和适用范围，替代滚动追加候选包叙述：

- [Session Runtime lifecycle、失败关闭、重连与 pressure](https://github.com/OneVCore/VCore/blob/f41610c/docs/acceptance.md#windows-session-runtime-phase-6-2026-08-24)
- [protocol-v1 有界 batching](https://github.com/OneVCore/VCore/blob/7856bef/docs/acceptance.md#windows-session-runtime-phase-6-2026-08-24)
- [外部 TUN/DNS 地址与安装包边界](https://github.com/OneVCore/VCore/blob/1011955/docs/acceptance.md#6-windows-vpn)
- [external Xray SOCKS tun2socks demo](https://github.com/OneVCore/VCore/blob/6636bd7/docs/acceptance.md#67-external-xray-socks-tun2socks-demo)
- [UWP VPN 最小示例 lifecycle](https://github.com/OneVCore/VCore/blob/26e1095/docs/acceptance.md#windows-vpn)
- [单 Application spike 与 2026-09-01 policy/data-plane gate 完整记录](https://github.com/OneVCore/VCore/blob/9205e2e83dc84905f24a7dda5570582d71d075b5/docs/acceptance.md#windows-vpn)

### 未完成发布门禁

- production-signed MSIX、WACK、Partner Center identity/publisher 与受限能力审批、
  ARM64/x64 Store bundle、提交与安装路径；
- Windows 10 20H2、原生 x64、真实物理 IPv6、新鲜物理网卡禁用场景；
- 多用户和远程会话；
- 带公开可复现命令的 `sessionBackend` package-boundary argv、进程退出和 Job
  清理矩阵，以及 native x64/正式宿主 UI 路径回归。

## TLS / REALITY 发布

REALITY 线上向量、普通 TLS、错误 key/short ID、HRR、并发和取消有自动化覆盖。
正式发布仍需：

- 无相邻 rustls/boring 目录的干净检出执行 locked tests；
- 使用同一 lockfile 完成 Apple、Android、Windows 构建；
- 保存 VCore/boring revision、官方 rustls 版本与 registry 校验值、原生补丁和子模块、toolchain、目标架构、lockfile/产物 SHA-256、
  签名安装与当次物理设备/网络/失败关闭矩阵。

详细要求见 [TLS 发布契约](tls-dependencies.md)。
没有当次证据的项目不得写成发布保证。
