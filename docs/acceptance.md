# VCore 验收

状态：当前 YAML 使用字段名与嵌套均与 Mihomo 一致的严格平铺
VLESS/SOCKS5/AnyTLS 子集，不含 `configVersion` 或 `default-proxy`。Invoke API
v5 的 `version.configVersion` 与 `buildIdentity` 单独报告内部 schema revision
11。宿主必须先调用 `initialize({dataDir})`；VCore 固定管理
`configs`/`geodata`，并经运行配置最终 `MATCH` 指向的实际 proxy 及其完整 graph
后台更新业务实际需要的 GeoData。GeoSite/GeoIP 缺失各自降级，不阻塞首次启动，
更新成功后热激活。公共生命周期始终为单实例；`measureDelay` 单次只接受 1–5
份顶层仅含 `proxies` 的 node-only 配置，由 Core 推导唯一完整链头并固定最多
并发执行五路，不再接受调用方并发参数，也不创建 HTTP listener 或公共实例。
Apple/Android `rust-tun` fd adapter 和既有数据面保持不变。当前 TUN/DNS 资源
策略不设置 TCP session、UDP association、half-open、outbound handshake、DNS
query、DNS upstream 或 active physical TCP 的固定并发上限；只保留局部有界资源。
iOS 35/45 MiB 是 best-effort telemetry 与优化目标，不是生命周期 guard。本轮
物理 iOS/Android TUN 仍为 `NOT RUN`；更早结果只属于对应历史候选。

## Windows UWP Phase 1 当前本机验收（2026-08-23）

环境为 Windows 11 ARM64 build 26200.9168、Rust 1.98.0、VS 18、Windows SDK 26100；基线 HEAD 为 `8a7d6d937e00ac73e184e271d48e885898a025b1`，本节结果来自其后的当前工作树。

- `node-tools/vs-cargo.cmd check --manifest-path VCore/Cargo.toml --all-features` 通过。四组 focused test 分别通过：`Dialer` source bind 2 项、Windows packet adapter 1 项、adapter -> `TunRuntime` ICMP 往返 1 项、provider 内嵌 current-schema config 1 项。
- release `vcore.dll` 与 foreground 均为 ARM64；DLL 同时导出 `DllGetActivationFactory`、`VCoreInvoke`、`VCoreFree`，无 VC runtime 动态依赖。Dev-signed AppX 安装后系统报告 `SignatureKind=Developer`。
- VPN 断开时，TCP DNS probe 从物理 `172.16.29.128` 向中国大陆可达的 `223.5.5.5:53` 查询 `www.baidu.com`，得到 3 个 answer。VPN Connect 后，同一 probe 从虚拟 `192.168.3.1` 经 TUN -> VCore -> DIRECT -> source-bound `Dialer` 得到同样有效响应。
- 对文档地址 `203.0.113.1` 的 fake ICMP reply 为 1 ms；provider 不再包含 Phase 0 fake responder，日志记录首个 40-byte VCore ingress 和首个 60-byte VCore egress packet。
- Disconnect 成功并等待 VCore runtime stop barrier；最终计数为 32 encapsulated / 12 decapsulated。`cargo fmt --all -- --check` 与 `git diff --check` 通过。
- `vcore.dll` SHA-256 为 `9a6b471068abb976084c17bd59758c7a864867ec62cc5fdaea45c5ba47e7115a`；本轮 AppX SHA-256 为 `71b98eae11d2b83b1b40bfe023c135adb4904d3506b8cbcbb98a6524b28eaaeb`。

本轮没有执行 IPv6、UDP 数据面、VCore DNS、VCore 代理协议、Flutter、snapshot、Windows 10、x64、WACK、正式 packaging、压力测试、网络切换或 runtime 意外退出后的自动 Stop；这些项目保持 `NOT RUN`。

## Windows UWP Phase 2A 当前本机验收（2026-08-23）

环境仍为 Windows 11 ARM64 build 26200.9168、Rust 1.98.0、VS 18、Windows SDK 26100；Phase 2 基线提交为 `7d34f9c`，本节额外包含其后的 interface-binding 工作树。

- Windows ARM64 `cargo test --all-features --lib` 为 422 passed / 1 个真实 GeoData 资产测试 ignored。ARM64/x64 `cargo check --all-features`、release build 和针对本轮代码的 Clippy `-D warnings` 通过；Rust 1.98 新增的两项既有 config 风格 lint 在本轮 Clippy 命令中显式 allow，未顺带改动无关 parser。
- `Dialer` 按 family 原子保存 Windows `(source IP, interface index)`；缺少任一字段或 `setsockopt`/source bind 失败必须立即失败，不能无绑定回退。provider 用 UWP-supported `GetAdaptersAddresses` 将 WinRT adapter GUID 映射到 `IfIndex`/`Ipv6IfIndex`，并检查 adapter address、profile/network names 与 connectivity identity。interface-only 在 AppContainer 内仍递归：2 秒空闲分别产生 51,809/74,093 encapsulated packets，UDP 改为 bind 前设置 option 也不变；恢复 source + interface 配对后为 81。
- rapid reconnect 根因是 background task 在 active=false 时对每个尾随 Idle activation 都调用 `CoreApplication::Exit`，与下一次 Connect 竞争。现在只在 Connect 失败或 Disconnect 后设置一次性 dirty-host exit request；承载 session 的 host 在 deferral 完成后退出，新启动的空闲 host 可以保留。1 秒 idle 的 10 次快速完整 lifecycle 全部通过，packet 数为 78–125；每轮 session PID 均退出/更换，未再出现 `VpnManagementErrorStatus(15)`。
- VPN 分配 `192.168.3.1` 与 `fd00::2`，安装 IPv4/IPv6 两组 `/1` routes。`203.0.113.1` ICMPv4 与 `2001:db8::1` ICMPv6 fake reply 均小于 1 ms；本机没有可用物理 IPv6，因此真实 IPv6 outbound 仍为 `NOT RUN`。
- 有效 NRPT `.` namespace 精确列出 `192.168.3.2`、`fd00::1`。清空 Windows DNS cache 后，系统 resolver 经 VCore runtime DNS 解析 `www.taobao.com` 成功；upstream 首选 UDP `223.5.5.5:53#DIRECT`，SERVFAIL 时顺序 failover 到同目标 TCP。既有 TCP DNS probe 在 VPN 内从 `192.168.3.1` 查询成功。普通非 DNS UDP 通过 `NETWORK,UDP,DIRECT`：Aliyun NTP `203.107.6.88:123` 在 VPN 前从 `172.16.29.130`、VPN 内从 `192.168.3.1` 均返回合法 48-byte response。
- 使用外部 Mihomo 配置仅临时生成本地 AppX YAML，未把凭据写入源码/文档。`directXhttpSG` 的 REALITY + XHTTP 与 `cdnXhttpUS` 的标准 TLS + XHTTP 均通过从虚拟 `192.168.3.1` 发起的 Baidu HTTP/TCP 与 Aliyun NTP/XUDP；Disconnect 分别为 121/94 与 145/99。`client -> cdnXhttpUS -> directXhttpSG -> target` 两节点 `dialer-proxy` 链的 TCP/XUDP 同样通过（123/72）。按用户要求未加载不可用的 `anytlsSG`。
- SOCKS5 使用本机临时 Mihomo DIRECT listener；fixture 自身绑定物理 interface，并仅为测试包临时启用 loopback exemption，验收后两者均删除。VCore SOCKS5 CONNECT 的 Baidu HTTP 与 UDP ASSOCIATE 的 Aliyun NTP 均通过，最终 112/88、queue drop 0。
- AnyTLS 使用本机临时 Mihomo inbound 与临时 CA/server leaf；CA 只嵌入 interop AppX 的 rustls root store，未安装系统证书，验收后源码、证书、server 和 exemption 均删除。AnyTLS TCP 与 UoT v2 NTP 均通过（86/58）；`client -> local AnyTLS -> directXhttpSG -> target` 异构链的 XHTTP TCP/XUDP 也通过（157/107）。全程未使用不可用的 `anytlsSG`。
- 实际禁用当前物理网卡 3 秒后，provider 记录 `physical network is no longer available` 并自动 `VpnChannel.Stop`。期间 Windows 重入 Connect；provider 拒绝重复 callback 而不清理活动 runtime，最终 Disconnect 保留 325 encapsulated / 57 decapsulated，网卡恢复后 VPN 保持断开、普通物理 TCP DNS 恢复。后续 pressure 发现 Windows NCSI 会在 VPN active 时持续降级物理 profile 的 connectivity level，旧比较因此误停；现在 callback 只递增 generation，fail-closed worker 等 2 秒静默后按 adapter GUID、绑定地址与 profile/network names 复验，不再比较 NCSI connectivity level。40 轮复现环通过。
- COM activation/callback 均有 panic boundary；后台 task deferral 在 error/panic 边界内完成。以临时 2 秒 shutdown error（验收后删除）注入 runtime 异常：provider 记录 `VCore runtime exited unexpectedly`，独立 worker 完成 `VpnChannel.Stop`，重入 Connect 被拒绝且未清理活动状态，最终 Disconnect 为 70 / 13、queue drop 为 0。显式 Disconnect 仍 join runtime。
- packet adapter 分开统计 ingress queue-full、receiver-closed 与 egress queue-full。20 次连续 `PHASE2 ROUTINE PASS` 均完成 IPv4/IPv6 ICMP、Windows DNS、TCP DNS 与 stop barrier，收发计数非零且两侧 queue-full 全为 0。process-isolated 20-cycle 的第 20 次为 65 encapsulated / 15 decapsulated；source/interface 配对、rapid-reconnect 与 network-monitor 修复后的最终 ARM64 TCP/UDP/DNS/ICMP routine 为 76 / 25；额外 NTP success-rate probe 为 baseline 9/10、VPN 10/10。
- 最初同进程外壳及拆分但长驻的 provider host 两组 20-cycle 后 process handles 分别约增加 123/124；类型为 `Thread`、`Event`、`WaitCompletionPacket`。差分排除了 foreground-only、profile Get/Update、独立 loopback sockets、network monitor、VCore runtime 和两个自建 worker；只有系统 `VpnChannel` association cycle 增长，且 stopped profile 不接受 `StartExistingTransports`/`ReplaceAndAssociateTransport`。最终 shell 使用独立 foreground/provider executable；Connect 失败或 Disconnect 后只退出一次承载过 session 的 dirty provider host，Windows 尾随 activation 创建的 clean idle host 允许保留并承接下一次 Connect。10 次 rapid lifecycle 中每轮 session PID 均退出/更换，因此 association handles/RSS 不能跨 session 累积；同时避免反复退出 Idle activation 与新 Connect 竞争。10 分钟 active-session plateau 结果见下一项。
- x64 AppX 在 Windows 11 ARM64 的 x64 emulation 下完成 build/sign/install 和完整 routine：IPv4/IPv6 ICMP、DNS namespace、TCP DNS、普通 UDP 与 stop barrier 均通过，最终 65/21、queue drop 0；最终 x64 AppX SHA-256 为 `52feb287c1b2fd78b411179aa7c04c04871d1d055c94821511808fdc1e7503b1`。同一 x64 session 的约 10 分钟 pressure 完成 60 轮 TCP DNS + UDP NTP，最终 1395/609、queue drop 0；private 35,815,424→35,381,248 bytes，handles 489→476，threads 16→13，无上升 slope。仍需原生 x64 Windows 机器复测。
- ARM64 `vcore.dll`、x64 `vcore.dll`、ARM64 AppX SHA-256 分别为 `1ebcce474fe32b0a9cf505910a06ad38dc9bf6f25d9dc2a6291e5053e1b25854`、`2c11a1808fee3e06ce230e703629b08c603a4093725ce85fbc35648ed9c9c1e5`、`4c14f09c4cc86664dab2f1a5a0e22ebad203653727dc26248bac98c3dbab47c5`。两份 DLL 均静态 CRT，并导出 `DllGetActivationFactory`、`VCoreInvoke`、`VCoreFree`。

仍为 `NOT RUN`：真实物理 IPv6、Windows 10 22H2、原生 x64 Windows、WACK 与正式 packaging。因此 Phase 2 不能标记完成。

## Windows Phase 3A 首个产品包 tracer（2026-08-23）

- `vcore.dll` 新增独立 revision-1 `VCoreWindowsVpnInvoke`，Dart worker isolate 仍用 `VCoreFree` 释放响应；真实 ARM64 DLL 的 `VCoreInvoke(version)` 返回 API 5 / schema 11。packaged full-trust Rust probe 的 `VpnManagementAgent` Add/Delete 均返回 status 0。
- Rust host bridge 对最终 YAML 再做 strict parse，将内容原子发布到 package LocalState 的固定 snapshot 目录，只把 `onevcore-v1:<sha256>` 写入唯一 `OneVCore` profile。provider 从 `VpnChannel.Configuration().CustomField()` 读取 token，拒绝路径、非 canonical token、reparse point、超限文件与 digest mismatch；硬编码 Phase 2 YAML 已删除。
- VCore 同时构建最小 `vcore-windows-vpn-host.exe`。真实 Flutter ARM64 release、host 与 DLL 已进入同一开发签名 MSIX；manifest 使用独立 full-trust foreground / hidden AppContainer provider application，注册 COM activation、`onevcore:` protocol、StartupTask、`runFullTrust` 和 `networkingVpnProvider`。`OneVCore.Dev_26.8.1.1_arm64` 安装并从 `WindowsApps` 启动成功。
- alternate Flutter acceptance entrypoint 通过生产 Dart FFI adapter 发布 snapshot `da6301a4ccb4207a8088ab6411a706f5ae3ed7da18ad72dd50ccaaf06927fcfe` 并启动正式 provider。IPv4/IPv6 local ICMP、Windows DNS namespace、TCP DNS 与 Aliyun NTP 全部通过；TCP/UDP 客户端 local 均为 `192.168.3.1`。结束 Flutter foreground 后 provider 与 `/1` routes 继续存在，TCP DNS/UDP NTP 再次通过。显式 Stop 的最终统计为 100 encapsulated / 19 decapsulated，queue drop 0。
- provider diagnostics 已移到 package-local `logs/windows-vpn.log`，1 MiB rotate 并只保留一个 previous。日志、profile 和 manifest 不包含 YAML、节点名或凭据。
- VCore Windows lib tests 为 427 passed / 1 ignored；lib Clippy `-D warnings`、ARM64/x64 release DLL 与 provider-host build、Flutter ARM64 release build、MSIX make/sign/install、PowerShell parser、focused Dart/Python contract tests通过。最终 ARM64/x64 `vcore.dll` SHA-256 为 `03aa722f6317db9ee918f9fd4fa3bc7529c49c0daa087a0765f6e0cccf1400f4` / `0e9b633d545e87bc09f580857b78dfd0d81eef6c2eaeaedb37e27d5be1d80946`；对应 host 为 `6c42ef5ebb71ce4ff904f1eabcba745fac3c5507565987b398a0084c8307fc97` / `1ced15314f593e803d440ae94f618b4fa2b4f8199bfacb83ba0cd2af8b119d39`；最终 ARM64 Dev MSIX 为 `2202682ec2255f9ecd44b6578d7e58f40ca6dcf0f0e951e69b8c623de4118e55`。全 target Clippy 仍命中既有 test-only unused imports/dead code；Apple-only C header shell check 在 Windows 无 `xcrun`，两者不记为通过。
- explicit Stop 后的开发 probe uninstall 已通过。一次主动删除仍在运行的 probe package 会先停止 VPN，但本机 package 状态随后停留在 `DeploymentInProgress, Servicing`；Phase 3 不承诺 active upgrade/uninstall，package script 现拒绝在 VPN route active 时 install/replace。该 servicing 状态清理后的最终 clean-uninstall 仍待复测。
- 仍待 Phase 3A：正常 App UI 的 session restore、proxy/measure interop、provider fail-closed 后约一秒 UI 收敛、formal App rapid reconnect。Phase 3B 的正式 Identity、ARM64/x64 bundle、Windows 10、WACK 与 restricted-capability approval 仍为 `NOT RUN`。

## Revision 11 当前配置迁移门禁

- `docs/config.yaml` 必须由当前 runtime parser 直接通过；YAML 顶层写入
  `configVersion`、`default-proxy`、旧 `inbounds/outbounds` 或 Xray 风格嵌套
  proxy 必须失败。`version` 仍返回数值 `configVersion: 11`，但它仅是 ABI 身份。
- `proxies` 至少包含一个平铺 Mihomo VLESS、SOCKS5 或 AnyTLS 节点；三种类型的
  字段名、大小写与嵌套必须和公开子集精确一致。name 唯一，`dialer-proxy` 引用
  必须存在且整图无环。
- 运行配置的 `rules` 必填，必须恰好以一个指向实际 proxy name 的最终 `MATCH`
  收尾。`DIRECT`/`REJECT` 是内置 action；`PROXY`/`#PROXY` 没有默认节点魔法，
  除非配置中确实存在这个 name。
- node-only 测速配置顶层只允许 `proxies`。Core 必须推导恰好一个未被其他
  `dialer-proxy` 引用的链头，且该链覆盖全部节点；多链头、无链头、unused
  proxy、runtime-only 字段都必须失败。
- VLESS/XHTTP `download-settings` 只接受
  `server/port/tls/servername/alpn/reality-opts/host/path`；空 mapping 表示继承，
  两腿共享 session ID。`stream-one` 与 download 互斥，auto 在 TLS 下选择
  packet-up、在 REALITY + download 下选择 stream-up。未知字段、null、
  `tls: false`、非 `[h2]` ALPN，以及 ShadowTLS/Restls/JLS 等 Mihomo 特有层
  必须 fail-closed。
- AnyTLS 验收除 schema 外还必须覆盖：标准 WebPKI TLS 1.3/1.2 且不发送 ALPN；
  v2 announce 与 tracked 3 秒 SYNACK watchdog；未返回 ServerSettings 时的
  v1-compatible 行为；复用 open 写出 `SYN` 与目标后立即返回，非空 SYNACK 或
  watchdog timeout 销毁整条 session 并经已返回 stream 的 I/O/关闭暴露，不承诺
  同步 `ConnectionRefused`，也不为该 stream 静默重拨；TCP stream、sing UoT v2
  datagram 多目标；每 session 单 active stream、idle session 中优先 sequence
  最大者、30 秒 idle；
  `begin_shutdown` 拒绝新工作并取消后台任务，随后 `shutdown().await` 完成回收。
- 本节只定义当前验收条件。紧随其后的 revision 11 记录是当前本机结果；更下方
  所有 revision 10、V9/V8/V7/V6/V5/V4 或旧产物 hash 都是历史快照。

## Revision 11 当前本机验收（2026-08-09）

- `cargo test --all-features --all-targets`：471 passed / 1 ignored；AnyTLS 与
  Xray 两个外部 integration target 默认各自 ignored。`cargo fmt --all -- --check`
  与全 features/targets Clippy `-D warnings` 通过，无默认特性及仅
  `outbound-vless` 的 all-targets check 通过。
- 使用本机 Xray 26.3.27 与 OpenSSL 3.6.3 执行真实进程互操作，
  TLS/REALITY × `packet-up`/`stream-one`/split `download-settings` 六组全部通过；
  split 分别覆盖 TLS auto→packet-up 与 REALITY auto→stream-up。当前实网 split
  使用同 endpoint/security 的空 download mapping；distinct endpoint/path/host、
  TLS→REALITY override 与真实 dialer-proxy parent chain 由 unit/runtime 覆盖，
  尚未加入外部实网矩阵。
- OneVCore `flutter test --no-pub`：253 passed；`flutter analyze --no-pub`、
  layer dependency、Dart format、18 项 Apple/Android build-script contract test、
  Apple bridge smoke 与 Android JNI/ABI/16 KiB alignment 门禁均通过。
- Apple iOS device/simulator 与 macOS、Android arm64-v8a/x86_64 release 制品已按
  Invoke API v4 / internal revision 11 重建并同步。`flutter build apk --debug`、
  `flutter build ios --debug --no-codesign`、`flutter build macos --debug` 均成功。
  VCore `dist` 与 App 内五份目标文件逐项相同：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `3a85985d71dd31991204b2629f7eec514ad86e28c5770f383723ac11f2590f7d` |
| iOS simulator arm64+x86_64 `libvcore.a` | `a2500b07f1e013dc88ccb6ff280b6d6c826a5a08a7dccdb51861314fe9caf09c` |
| macOS arm64+x86_64 `libvcore.a` | `69afecd8e18365d8e30e49a3f5010fe150157ea62a20551e609e9688e9591727` |
| Android arm64-v8a `libvcore.so` | `ddd8850fd13a3dbe435a5072b14986dc282c71aec8446ff852898037d4836a7f` |
| Android x86_64 `libvcore.so` | `62eab0f7cf4c79934444ff9906b5642d929f22d353a750ffbac6bdf2343d6a8c` |

- 本轮未执行物理 iOS/Android TUN、弱网或 footprint 验收；host、真实 Xray、
  交叉构建、native smoke 和模拟/无签名构建不能替代这些项目。

## 历史快照：Revision 10 当前本机验收（2026-07-28）

- VCore `cargo test --all-features --all-targets --no-fail-fast`：
  451 passed / 1 ignored；两个外部 integration harness 默认各自 ignored。
  `cargo fmt --all -- --check`、全 features/targets Clippy `-D warnings`、
  C header 与 TLS dependency 门禁均通过。独立 `vcore-netstack` 的 13 项 unit、
  6 项 integration test 及 Clippy 均通过。
- `tests/run_anytls_interop.sh` 已对本地 anytls-go
  `0c36ca9f0d88bc1af5ddb998e619166913c7445c` 做真实进程互操作并通过：TCP
  首流、TCP 复用、两个 UoT v2 UDP echo、UoT 后 TCP 以及 shutdown；透明转发器
  确认全过程只建立一条物理 AnyTLS session。测试专用连接器只信任该次动态
  自签名证书，生产 WebPKI 配置未放宽。
- OneVCore `flutter test`：107 passed；`flutter analyze`、Dart format、native
  model contract、layer dependency check、Apple bridge smoke、Android
  identity/JNI/ABI/16 KiB LOAD alignment 与 25 项 build-script contract test
  均通过。
- Apple iOS device/simulator 与 macOS、Android arm64-v8a/x86_64 release
  制品均以 Invoke API v4 / internal revision 10 重建并同步到 App。VCore `dist`
  与 App 内五份目标文件逐项相同：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `c9bcbbdbb584d4122eadf0f3bc0eefbbdbff6870a339aead8ee4806b385457c8` |
| iOS simulator arm64+x86_64 `libvcore.a` | `f276057071e9430d7d61bfaf21d0df49e1ce7df58999244830a6cf9f57c0f3db` |
| macOS arm64+x86_64 `libvcore.a` | `8749d9626c661ec75e0aa1bf3edd748821be63ea521bcd4d262136d794f1cd93` |
| Android arm64-v8a `libvcore.so` | `95bd2523940606db74047bbb5ab47b5f4610e47ed97d6ed13d0c385eb1ee5263` |
| Android x86_64 `libvcore.so` | `47fc136a17cc435e78e7fbed518cc96a3c01fce201ac3b3b8535c6f537e33abb` |

- 同步后 `flutter build ios --debug --no-codesign` 与
  `flutter build apk --debug` 均成功；iOS App/Tunnel 与 APK 内
  `libvcore.so` 均可见 revision 10 `buildIdentity`，APK 只携带
  arm64-v8a/x86_64 两个 VCore ABI。
- 当前 macOS 主机没有 Windows SDK，因此未构建 Windows 接入。上述 host、
  交叉编译与真实 AnyTLS server 结果仍不能替代物理 iOS/Android TUN、弱网和
  35/45 MiB footprint 验收。

## 历史快照：Invoke API v4 `measureDelay` 契约收紧（2026-07-26）

- `configVersion: 9` 保持不变；Invoke envelope 升级为严格 `apiVersion: 4`，不兼容
  旧 Invoke payload。
- `measureDelay` payload 只接受必填的 `configPaths`、`timeout` 和 `url`；
  `configPaths` 必须包含 1–5 个路径。Core 固定最多并发执行五个私有 worker，
  实际 worker 数不超过配置项数；同一 runtime 仍只允许一个外部批次。
- Core `cargo test --locked --all-features --all-targets`：420 passed / 2 ignored；
  `cargo fmt --all -- --check`、全 targets/features Clippy `-D warnings`、
  `scripts/check_c_header.sh` 与 iOS arm64 all-features cross-check 均通过。
  `vcore-netstack` 的 13 项 unit、6 项 integration test 及 Clippy 通过。
- OneVCore `flutter test`：106 passed；`flutter analyze`、native model contract、
  layer dependency check 与 25 项 build-script contract test 通过。Android
  `compileDebugKotlin`/`compileDebugAndroidTestKotlin` 通过。
- Apple iOS device/simulator 与 macOS release slices、Android
  arm64-v8a/x86_64 release `.so` 已按 Invoke API v4/configVersion 9 重建并同步
  进 App；Apple bridge smoke 与 Android identity/JNI/ABI/16 KiB LOAD alignment
  门禁通过。源产物与 App 内五份二进制的 SHA-256 逐项一致：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `91d7d3b1cd2078e09e706eb30cb5894e4bb6139a022b33b6978853167420e16f` |
| iOS simulator arm64+x86_64 `libvcore.a` | `2a3c93448150893fdb8f2ec36971b44b69c7ff77d58adc3f223d984d9f0136d7` |
| macOS arm64+x86_64 `libvcore.a` | `990e15154b93f03a895ca3bce7433678b946827b16d457d65e03816ea793dbf6` |
| Android arm64-v8a `libvcore.so` | `ff8ae2a184113be656f662b1f07fb44e9435e0f63fa6cfb0d5db4b0e8a0a3842` |
| Android x86_64 `libvcore.so` | `ed8a05d5c18dd829d5adb6724475dbc36d4294956ef639e147f8f993b595366f` |

- 本轮没有执行物理 iOS/Android TUN 或依赖外部 Xray/OpenSSL 的实际互操作测试；
  host 自动化、交叉构建和 native smoke 不能替代这些验收。下方 V9、V8、V7 与
  Invoke v3 结果只属于对应历史候选，不能外推为当前结果。

## 历史快照：V9 proxy graph 固定上限移除验证（2026-07-26）

- latest-only 配置协议提升为 `configVersion: 9`。运行配置必须至少包含一个 proxy；
  proxy 数量和 `dialer-proxy` 链深没有独立上限，只受整份 YAML 256 KiB、tag
  唯一、引用存在和全图无环约束。node-only 测速配置还要求
  `default-proxy` 路径覆盖全部节点。
- Dart writer/parser 的 graph 校验使用迭代三色状态表，整图校验为线性复杂度，
  不使用递归。自动化覆盖五节点运行图、四节点混合协议测速链、独立节点选路、
  未知引用/重复 tag/环，以及 4096 个 proxy 最终由 256 KiB YAML 总大小拒绝。
- Core `cargo test --locked --all-features --all-targets`：420 passed / 2 ignored；
  ignored 项分别依赖真实 GeoData 与 Xray/OpenSSL 互操作环境。动态 graph 自动化
  覆盖 300 节点配置校验、超过 `u8` 范围的配置与路由索引、六节点 connector chain、
  四节点 TCP/UDP 选路及 UDP transport 惰性创建与接收。
- `cargo fmt --all -- --check`、全 targets/features Clippy `-D warnings`、
  `scripts/check_c_header.sh` 与 iOS arm64 all-features cross-check 均通过；
  `vcore-netstack` 的 13 项 unit、6 项 integration test 及 Clippy 通过。
- OneVCore `flutter test`：103 passed；`flutter analyze`、native model contract
  与 layer dependency check 通过；25 项 build-script contract test 以及 Android
  `compileDebugKotlin`/`compileDebugAndroidTestKotlin` 通过。
- Apple iOS device/simulator 与 macOS release slices、Android
  arm64-v8a/x86_64 release `.so` 已按 configVersion 9 重建并同步进 App；
  Apple bridge smoke 与 Android identity/JNI/ABI/16 KiB LOAD alignment 门禁通过。
  源产物与 App 内五份二进制的 SHA-256 逐项一致：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `9bbc3ea07947b2fae0962045cc2bd7e58d04856d9b0e7a9254c652a2e3229c3a` |
| iOS simulator arm64+x86_64 `libvcore.a` | `553b949c6ead20fbc61674729edaaf9715f1dcdebca2bf04970188d5292b5746` |
| macOS arm64+x86_64 `libvcore.a` | `da5798c15e7db20dd398cd40b870c8cd2a4cd8d6883799354c415e37cc1513d5` |
| Android arm64-v8a `libvcore.so` | `1a91066d4afca12da15ebba977d6a8ba1724cefe5735124de3fc142429d65f3f` |
| Android x86_64 `libvcore.so` | `e7278d201ead5952723c9fd0aaead4f13f747a9efddef3cc17680499427e7611` |

- 本轮 host/synthetic 自动化和交叉构建不等同于物理 iOS/Android TUN 或真实
  长链节点互操作；这些项目仍为 `NOT RUN`。

## 历史快照：V8 TUN 流量 Controller 验证（2026-07-26）

- `cargo test --locked --all-features --all-targets`：416 passed / 2 ignored；
  ignored 项分别依赖真实 GeoData 与 Xray/OpenSSL 互操作环境。
- `cargo fmt --all -- --check`、全 targets/features Clippy `-D warnings`、
  `scripts/check_c_header.sh` 与 iOS arm64 all-features cross-check 均通过；
  `vcore-netstack` 的 13 项 unit 和 6 项 integration test 通过。
- Core 自动化覆盖 Controller 配置组合、secret 脱敏、Bearer 正负例、Mihomo 401
  JSON、单次 `/traffic` snapshot、当前一秒窗口、累计值与 `i64::MAX` 饱和。
  TUN lifecycle 测试通过真实 synthetic fd 验证 ICMP request/reply 的 raw-IP
  上下行 byte，并确认 stop 后监听端口关闭。
- OneVCore `flutter analyze`、101 项 Flutter test、native model contract、
  layer dependency check 与 25 项 build-script contract test 通过；Android
  `:app:compileDebugKotlin` 和 macOS debug build 通过。App 测试覆盖
  `external-controller`/可选 `secret` 的 Dart 往返、严格 loopback 校验，以及
  `/traffic` Bearer header 和累计值解析。
- Apple iOS device/simulator 与 macOS release slices、Android
  arm64-v8a/x86_64 release `.so` 已按 configVersion 8 重建并同步进 App；Apple
  bridge smoke 与 Android identity/JNI/ABI/16 KiB LOAD alignment 门禁通过。
  源产物与 App 内五份二进制的 SHA-256 逐项一致：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `317dd8aed8f825f35de3126a11551790d63bfa9b156dd3aa5c4d0797ee550072` |
| iOS simulator arm64+x86_64 `libvcore.a` | `0f7f1bb3f2869583d4627c3b07eb40fe6d8c9b3f2dbca83ae4ff6f5d51f3a641` |
| macOS arm64+x86_64 `libvcore.a` | `0458ed6de3ed701935dcc2a8c25b16a2fbd98c893bb8817158bcf235a16a8aa6` |
| Android arm64-v8a `libvcore.so` | `9276da953e48a296ac324cd010f3863640e2aef7f4ca31c660bdd2edb4cc2391` |
| Android x86_64 `libvcore.so` | `9790f7a8047da2da74b830bf41c60fac61931cf93ed9fd73e7e2ab21f95c4776` |

- 本轮没有执行物理 iOS/Android TUN。host synthetic fd、cross-check、native
  smoke 和模拟构建都不能证明独立 TUN 进程的 loopback Controller 在真机可达；
  该项保留为实机验收。

## 历史快照：V7 / Invoke v3 单实例与批量测速验证（2026-07-25）

- `cargo test --locked --all-features --all-targets`：409 passed / 2 ignored；
  ignored 项分别依赖真实 GeoData 与 Xray 互操作环境。
- `cargo clippy --locked --all-features --all-targets -- -D warnings` 与
  `cargo fmt --all -- --check` 通过。
- FFI 覆盖公共 singleton、销毁后 generation 递增、12 路并发
  `createInstance` 仅一项成功、12 路并发 `validateConfig` 结果一致，以及
  lifecycle/TUN/protect cleanup。
- `measureDelay` 覆盖 1–256 路 payload 边界、内部 `concurrency: 1..6`、第二个
  batch busy、输入顺序保持、逐项错误、worker panic 收敛、node-only YAML 严格
  字段和两节点完整链约束。`PreparedMeasurement` 不创建 inbound、DNS、rules 或
  GeoData registration。
- `GeoDataManager` 只允许一个活动 registration；第二份配置明确失败，旧 lease
  drop 后才允许下一代。生产调度已删除多 registration 聚合、source cohort 与
  follower；跨 manager 测试仍覆盖 update lock，且同源 winner 提交后 peer 通过
  持久状态二次 due 检查跳过重复下载并热激活 matcher。
- 使用本机 Xray 26.3.27 与 OpenSSL 3.6.3 显式运行 ignored 互操作 harness，
  TLS/REALITY × XHTTP `packet-up`/`stream-one` 四组全部通过。REALITY 两组均在
  单次 Invoke 中以 `concurrency: 6` 同时完成六份 node-only 配置的 HEAD 探测，
  随后验证唯一公共实例的 prepare/start/HTTP CONNECT/stop/destroy，以及旧实例
  存活时第二次 `createInstance` 必须失败。
- OneVCore `flutter analyze` 与完整 `flutter test` 通过，共 98 项；App 使用统一
  FIFO dispatcher，列表测速不再并发发起多个 Invoke，也不再分配 HTTP 端口或凭据。
- Android `:app:compileDebugAndroidTestKotlin` 通过，API v3 version smoke 与 TUN
  lifecycle instrumentation 已完成编译但未在模拟器或真机执行。
- Apple iOS device/simulator 与 macOS release slices、Android
  arm64-v8a/x86_64 release `.so` 已按 Invoke API v3 重建并同步进 App；Apple bridge
  smoke、Android identity/JNI/ABI/16 KiB LOAD alignment 与 25 项 build-script
  contract test 通过。源产物与 App 内五份二进制的 SHA-256 逐项一致：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `115c09638cd7c110105a918055fd6b3b821d93af81baa9ee807dc0e4b943bb11` |
| iOS simulator arm64+x86_64 `libvcore.a` | `c997dd4b2836ce3afaf351f3c5222fbec792f085839fe1861ea96404d13a073b` |
| macOS arm64+x86_64 `libvcore.a` | `ccbba30d4945327c5054509d1b6ab642c1399d13826abec08aca77fcb92f8c6f` |
| Android arm64-v8a `libvcore.so` | `6b59a98e1d3ef23cf7e25953fd748e3c273eea0a01a57f0e3dcaa1b2124214fe` |
| Android x86_64 `libvcore.so` | `9dafa5f26018688e182b3bc846288d0eff523d1c966a76854cf5d7925265a715` |

## V7 GeoData 自管理历史候选验证：2026-07-25

- `cargo test --locked --all-features --all-targets`：Core host target 为
  413 passed / 1 ignored；ignored 项需要真实 Xray GeoData。外部
  `xray_interop` target 另有 1 项因未提供 Xray/OpenSSL 环境而 ignored。
- 自动化覆盖固定 data directory 与 config containment、GeoSite/GeoIP 独立缺失
  降级、不可用 GEOIP 不触发 lazy DNS、跨进程更新锁与状态恢复、损坏状态文件恢复、
  ETag/304、HTTPS redirect、响应/文件边界、取消和超时、原子替换、热加载及
  `getGeoDataState`。双 manager 回归还验证：外部更新不满足本进程正在使用的 code
  时保留旧 matcher，后续兼容 generation 到达后再热切换。测试使用本地 fixture，
  不等同于真实公网下载验收。
- 配置门禁覆盖 `geox-url`、`geo-auto-update`、`geo-update-interval` 全有或全无、
  URL map/HTTPS/domain/credentials/fragment/长度和固定 24 小时间隔。updater
  回归覆盖本 registration demand、auto-update 隔离、source URL 变化立即无 ETag
  检查、同源共享/异源等待的跨进程租约、全局 update lock 内二次 due 检查，以及
  owner 更新成功时其他 live matcher 不降级。App 测试覆盖 Simple Config 固定写出
  MetaCubeX latest URL、true、24，通用 V7 reader/writer 往返，测速配置省略该组，
  以及首次安装和临时配置始终位于初始化后的 `dataDir/configs`。
- `cargo fmt --all -- --check`、全 targets/features Clippy `-D warnings`、
  C header 与 shell syntax 门禁通过。
- OneVCore 的 `flutter analyze`、92 项 Flutter test、native model contract、
  25 项 build-script contract test 和 Android
  `:app:compileDebugAndroidTestKotlin` 通过。
- Apple iOS device/simulator 与 macOS release slices、Android
  arm64-v8a/x86_64 release `.so` 已重建并同步进 App；Apple bridge smoke 与
  Android build identity、JNI symbol、ABI、16 KiB LOAD alignment 门禁通过。
  源产物与 App 内五份二进制的 SHA-256 逐项一致。
- 本轮未执行真实公网 GeoData 更新，也未运行物理 iOS/Android TUN；host、
  release build 与 native smoke 不能替代这些数据面验收。

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `dcf601e662c29046dd044927d5d42f8c7cb96e9edaa4cd1bee01bd7c1f40c440` |
| iOS simulator arm64+x86_64 `libvcore.a` | `26b191390f8d7f6615b580444af99c4a8725508aa0c04b04c407e8bc2871cca6` |
| macOS arm64+x86_64 `libvcore.a` | `8e0cbf7c22f1662246fc677c8a6b8954b5b21ce7ac6017c81227f1da94b7e9e7` |
| Android arm64-v8a `libvcore.so` | `33f08fe356992476f9741b127c58a23e632900effe25a0ba79ec0becbc8b8b3a` |
| Android x86_64 `libvcore.so` | `1d0b29f4066d351c2a39ee2461d882728857c429829eb303e4cd53b6c075ba86` |

## V7 无固定业务并发 gate 历史候选验证：2026-07-25

- `cargo test --locked --all-features --all-targets`：Core host target 为
  373 passed / 1 ignored；外部 `xray_interop` target 另有 1 项因未提供
  Xray/OpenSSL 环境而 ignored。
- `vcore-netstack`：13 个 unit 与 6 个 integration test 全部通过。
- `cargo fmt --all -- --check`、全 targets/features Clippy `-D warnings`、C header、
  TLS dependency、shell syntax 和 iOS arm64 all-features check 全部通过。
- Apple XCFramework 的 iOS device、iOS simulator 和 macOS release slices 构建通过。
- Android arm64-v8a 与 x86_64 release build 通过。
- 该历史候选产物未复制进 App，也未执行物理 iOS/Android TUN；host、cross-check 和
  release build 不能替代真机数据面验收。

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `ac06b3947d778181f460e72dbd1dbfa4470843399cf13918311578839a5a456a` |
| iOS simulator arm64+x86_64 `libvcore.a` | `5519150f87f9d44af0cc9df8c299b9355c91ca95d161713d5a1819b4d7549bd7` |
| macOS arm64+x86_64 `libvcore.a` | `c5b1e26335784c880195f3510b24e6fbd2122ff93925c9b934a613a074330f83` |
| Android arm64-v8a `libvcore.so` | `7fb6016eb75c1e0b2982a284d5400ba134c0e32f1048105116b65f8ede1828c3` |
| Android x86_64 `libvcore.so` | `87365320253a3f49e63962b9f89815a1ed18721cb256a8e6ee03df1559207e0b` |

## V7 资源策略重构前候选验证：2026-07-25

- `cargo fmt --all -- --check` 通过。
- `cargo test --locked --all-features --all-targets` 的主库为 400 passed /
  1 ignored；ignored 项需要真实 Xray GeoData。外部 `xray_interop` harness 另有
  1 项因未提供 Xray/OpenSSL 环境而 ignored。
- `cargo clippy --locked --all-features --all-targets -- -D warnings` 通过。
- `vcore-netstack` 的 13 个 unit + 6 个 integration test 共 19 项通过，其独立
  all-targets Clippy `-D warnings` 通过。
- C header、TLS 单依赖、shell syntax 与
  `cargo check --locked --target aarch64-apple-ios --all-features` 全部通过。
- `./scripts/build_apple.sh` 成功生成 iOS device、iOS simulator 与 macOS release
  slices，并完成固定 build identity 检查。仅更新 VCore 自身 `dist/`，未复制进 App。
- 新增定向覆盖包含 TCP 连接复用、stale EOF 与 ID mismatch 单次 fresh retry、
  malformed/truncated 不复用、最终 egress key 隔离、8 busy/2 per-key idle、4 global
  idle/LRU/30 秒 expiry、idle TCP 与 UDP 共享 aggregate capacity、4 idle + 4 active
  压力下为新 UDP/fresh TCP 淘汰 idle、两个并发 waiter 各自重试 admission、ceiling=1
  不保留 idle、runtime drop 资源归零，以及 netstack
  current/peak/reject/drop/stop 收敛。
- 本轮没有更改 `configVersion`、128/64/32/16/128/8 资源数值，也没有加入 Apple
  `IP_BOUND_IF`/`IPV6_BOUND_IF` 或其他物理接口选择逻辑。

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `6590cf2037a0be01ea50c8ec33bd74fb03dabdc0cc9763fdb9eb1263c0ce55b8` |
| iOS simulator arm64+x86_64 `libvcore.a` | `891c99e7ffaff0d401a36f30e13a6d7173e0db9f522342ab50fab448dbf94515` |
| macOS arm64+x86_64 `libvcore.a` | `bf885aaf6355e095e9b9aa7d87d27bff9be3687720abeca39cec175a3c4470a8` |

真实 Xray/GeoData、App 集成、Android 构建以及物理 iOS/Android TUN 均未在本轮执行；
host、cross-check 和 XCFramework 构建不能替代这些验收。

## V7 QUIC sniffer 上一候选验证：2026-07-24

- `cargo fmt --all -- --check`、全 targets/features Clippy `-D warnings`、C header、
  TLS 单依赖门禁、shell syntax 和 iOS arm64 全特性 cross-check 全部通过。
- `cargo test --locked --all-features --all-targets` 的主库为 387 passed /
  1 ignored；ignored 项需要真实 Xray GeoData。外部 `xray_interop` harness 另有
  1 项因未提供 Xray/OpenSSL 环境而 ignored。`vcore-netstack` 的 13 个 unit +
  6 个 integration test 共 19 项通过。
- QUIC 定向覆盖包含 18 项 parser 与 16 项 TUN runtime test：v1/v2 Initial
  解密、独立 v1 wire fixture、coalesced packet、CRYPTO 乱序/重传、ECH、ACK 与
  CRYPTO range 边界、32 KiB pending byte 边界、DCID 轮换、候选新 Initial AEAD
  认证、completed LRU、超时/fail-open、响应优先的有界 replay 和 UDP/53 fast path。
- OneVCore App 的 Dart format、layer dependency check、`flutter analyze`、
  92 项 Flutter test 与 25 项 build-script contract test 全部通过。
- Apple iOS device/simulator 与 macOS release slices、Android arm64-v8a/x86_64
  release `.so` 已重建并同步到 App。Apple bridge smoke 与 Android identity、
  JNI symbol、ABI 和 16 KiB LOAD alignment 门禁通过，源/App 二进制逐项哈希一致。

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `87f862a30f55f0cc5257ea55c0fd8d73b401710f4ac66f3de02cb984bcd5255a` |
| iOS simulator arm64+x86_64 `libvcore.a` | `52b54dc4b73e8cb76d8fb823dedf334b231a77b22baa0d36c84a791c699ede8d` |
| macOS arm64+x86_64 `libvcore.a` | `992e4344c5ffdab90e34d6032c16aab0ed9f84b573495cfc97f27c8ce5168195` |
| Android arm64-v8a `libvcore.so` | `49d47e30139f0b308e42ead736856698d6b894b57a605bf9ebcf61d6a3f01c3b` |
| Android x86_64 `libvcore.so` | `c65c1cdbc63ca264600348497ecc5574e84b142b20d0c5b8b107c0224bf1d6c3` |

本轮没有运行物理 iOS/Android TUN，也没有执行真实 GeoData 或外部 Xray
互操作项；host、cross-build 与 native smoke 不能替代这些数据面验收。

历史 V6 sniffer 增量门禁结果：

- `cargo test --locked --all-features --all-targets`：351 passed、2 个环境依赖项 ignored；
  `vcore-netstack`：19 passed。
- `cargo fmt --all -- --check` 与全 targets/features Clippy `-D warnings` 通过。
- App `flutter analyze`、layer dependency check、Dart format 与 92 项 Flutter test 通过；
  25 项 build-script contract test 通过。
- Apple iOS device/simulator 与 macOS slices 已重建、同步并通过 bridge smoke；
  源/App XCFramework 规范化树 SHA-256 均为
  `4734c157748d293db68315c02f85dd9b0d7c89804741ade2ecb0c5c06e5ac8af`。
- Android arm64-v8a/x86_64 已重建、同步并通过 identity、JNI symbol 与 16 KiB
  alignment 门禁；SHA-256 分别为
  `9b461b66ed5017d04607bee9183845b14966866bc8ff4c9faeca74c238b95a3b` 与
  `1cd4dcbc1dc8dbc29258135977b38bb00df062682565e87167d31b6f2348ee4f`。
- 当时的 Swift/Kotlin native smoke config 实际包含互不重叠的 HTTP 8080/TLS 8443
  sniffer，并通过 Apple native smoke 与 Android 静态门禁。
- 本轮没有运行物理 iOS/Android TUN；以上结果不能替代真机数据面或 footprint 验收。

V5 历史增量门禁结果：

- `cargo test --locked --all-features --all-targets`：346 passed、2 ignored；ignored 项仍为真实 GeoData 与真实 Xray 环境测试。
- `cargo fmt --all -- --check` 与 `cargo clippy --locked --all-features --all-targets -- -D warnings` 通过。
- App `flutter analyze` 与 90 项 Flutter test 通过；全部 25 项 build-script contract test 通过。
- Apple iOS/macOS slices 和 Android arm64-v8a/x86_64 release 产物已重建并同步；
  Apple bridge smoke 与 Android JNI integration check 通过。

这些历史结果覆盖严格 V5 schema、HTTP Basic 认证、内置 `measureDelay` 自动认证、TUN HTTP
Host/TLS SNI sniff、routing hint 与预读字节回放；它们不替代真实 Xray 服务端、
物理 iOS/Android TUN 或 Release iOS footprint 验收；V6 sniffer schema 只由上方
历史门禁结果证明，不能外推到当前 V7。

## V6 历史业务优先改造：2026-07-24

当时契约为：TUN 128 TCP/64 UDP/32 half-open/16 handshake、256 packet/128 event、
32 KiB TCP direction、64 KiB TLS/XHTTP；DNS 128 client/8 active、bounded
singleflight、64-record scan/16-address retention、256 typed cache、按需启用且最多
256 项的 TUN redir-host hint、64 项/256 KiB opaque cache，以及显式 128
ingress/独立 128 DNS response queue。
普通 UDP association 使用 generation/cancellation、30 秒 idle、10 秒 cleanup 与
10 秒 eviction grace。旧 iOS 20/4 weighted pools、`total × 4` queue 推导、静态 byte
model 和 activity 独占均已退出当时契约；本节全部数值现均为历史。

当时实现把 16 个 handshake permit 和 `runtime_handshake_admission` 固定统计放在
runtime 级，由 DIRECT、所有 proxy graph、runtime DNS 与本地 HTTP listener
共享；TUN 和 internal DNS 可取消等待，本地 listener fail-fast。自动化包含“两 listener
共享一个 permit”的拒绝/回收样例，以及 16 个已占 permit、8 个先排队 DNS、64 个后到
TUN handshake 的公平性样例；后者断言前 8 个获释名额全部属于先排队 DNS，避免被持续
TUN 建连饿死。DNS 另有 upstream wait 次数/毫秒、singleflight join 和 cache hit 固定
计数。这里描述实现与测试覆盖，不替代下表尚未统一执行的最终 host 门禁。

以下 M6 表格和哈希是切换到 V7 前的历史工作树验证；不得用它们填充 V7 验收：

| 门禁 | V6 历史结果 | 说明 |
| --- | --- | --- |
| M0–M5 最终 host 全量 | `PASS` | 320 passed / 1 ignored；netstack 19 passed；fmt、Clippy、header、TLS、shell 均通过 |
| 固定 Xray 26.7.11 互操作 | `PASS` | TLS/REALITY × `packet-up`/`stream-one` 四组全部通过 |
| Apple/Android 当前产物与 App 同步 | `PASS` | 两平台构建、逐文件同步身份和 App 集成检查均通过 |
| iOS Release 物理设备 | `NOT RUN` | 已检测到无线 iPhone，但未执行 TUN、流量、30 分钟与 footprint 真机流程 |
| Android 物理设备 TUN/protect | `NOT RUN` | 当前无 physical Android |

35 MiB cold-start current 与 45 MiB representative-workload peak 只作观测目标；越线
不会把功能结果改为失败。模拟器、host 或 cross-build 均不能把物理设备行改为 PASS。

### V6 历史 M6 host、互操作与产物证据

2026-07-24 V6 历史候选身份：

| 项目 | 值 |
| --- | --- |
| VCore HEAD | `14da2d1a047cc5293d23e48a5a0d52027cdb2038` |
| rustls HEAD | `411fb0278820bbf81ac825b24823f31bed55190e` |
| OneVCore App HEAD | `fadcec98ac1a5aa3e0a2c3235d6d910017f431c7` |
| `Cargo.lock` SHA-256 | `6a0700beb3cf142364a6a052fcbf91b214ec558d488c69e76842782e9155b8f5` |
| VCore 工作树 content manifest SHA-256 | `ca99c50cafb5178c07b9ee265571c64c554e76d8aaef2520a899fbcec9b4167a` |
| OneVCore App 工作树 content manifest SHA-256 | `3b82ab59dbd4ab99ff79616111469831928b0bb4784211316170a91738a8fcf1` |
| Xray-core revision | `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` |
| Xray 26.7.11 binary SHA-256 | `9407c3eeda132ba5326e3c16eff150e7564537079abdd2643cddf5a90a739ebd` |

content manifest 对 `git ls-files --cached --others --exclude-standard` 的普通文件按路径排序，
逐文件计算 SHA-256 后再聚合。VCore 输入排除生成的 `dist/` 和本验收报告
`docs/acceptance.md`；App 输入排除生成的 `build/`、同步的
`swift/All/LibVCore.xcframework/` 与 `android/app/src/main/jniLibs/`。二进制身份由下方
独立 artifact hash 覆盖。当前两个仓库的基线几乎全部是未跟踪文件，因此这里使用
content manifest，而不是会漏掉未跟踪内容的 `git diff` hash。表中 revision、manifest
与产物 SHA-256 都不属于 V7。

V6 历史 host 结果：

- `cargo fmt --all -- --check` 通过。
- `cargo test --locked --all-features --all-targets` 的主测试目标为
  `320 passed / 1 ignored`；`xray_interop` target 另有 1 个默认 ignored harness。
- `cargo clippy --locked --all-features --all-targets -- -D warnings` 通过。
- `vcore-netstack` 的 13 个 unit 与 6 个 integration test，共 19 个通过；对应
  `clippy -D warnings` 通过。
- C header、TLS dependency 与 shell syntax 检查均通过。
- 默认 ignored 的真实 GeoData 兼容测试已显式执行，`1 passed`。当前 8 MiB
  allocation capacity 下的统计为：

| GeoData 样例 | retained bytes | construction ledger peak | capacity |
| --- | ---: | ---: | ---: |
| baseline | 423,252 | 3,385,312 | 8,388,608 |
| documented | 459,844 | 3,421,904 | 8,388,608 |
| real Xray assets | 1,962,020 | 4,935,888 | 8,388,608 |

固定 Xray 26.7.11 在当前候选上完成 TLS/REALITY ×
`packet-up`/`stream-one` 四组互操作，结果 `4/4 PASS`。
最终门禁前的一次 REALITY `packet-up` 运行曾在测试内层 TCP echo 的 3 秒 I/O
deadline 处超时；Xray 日志显示 REALITY 握手在阈值后刚完成，因此将该测试 deadline
调整为 5 秒。调整后连续两轮完整四组合均通过；最终独立门禁为一次执行通过、无重试。
这只放宽测试环境的 echo deadline，不改变 VCore transport 或生产超时语义。

V6 历史平台与 App 结果：

- `./scripts/build_apple.sh` 与 `./scripts/build_android.sh` 通过；Apple/Android
  产物同步到 App 后逐文件 hash 一致，两个 integration check 均通过。
- App `flutter analyze` 通过；Flutter tests 88 个、parser tests 10 个、build-script
  tests 25 个全部通过。
- Android API 37 模拟器执行 `:app:connectedDebugAndroidTest` 为 `10/10 PASS`。
  根级 `connectedDebugAndroidTest` 会额外进入 plugin test task，并因 `file_picker`
  的 `minSdk 21 < 24` 约束失败；该聚合任务结果必须如实保留，不能覆盖已经实际通过的
  App 模块 10 个 instrumentation tests，也不能写成物理 Android TUN/protect 通过。
- `flutter build ios --release` 与 `flutter build appbundle --release` 均通过。

V6 历史产物：

| target / artifact | SHA-256 |
| --- | --- |
| iOS device arm64 `libvcore.a` | `399613e541e317ae03d009fbd23d81e49918a5595acaae1a59ad9255d134b37e` |
| iOS simulator `libvcore.a` | `6b1ee9c5bd884c7e139c17449d8f68f11fd3583488f0366460fcd8a6e4862e6b` |
| macOS `libvcore.a` | `dabe89747a85fe3540a2769c9f9044380a84653f834896493835cd7168a8f3ce` |
| Android arm64-v8a `libvcore.so` | `05eb6a65fd21a2eb9930d6a6e8c042adb67f2fdeaf4c79ad97d0856e8c381ec8` |
| Android x86_64 `libvcore.so` | `cad1a155969cc6e7907e3c537d84e9943106344b3abc743facd482dcc1e9c1cc` |
| Android release AAB | `d17e71f44bbcfef2d0e5533c3a8d9d4bd6c7c60e56d2d447b2feb8498491a5dc` |
| iOS Release `Runner.app` content manifest | `fc8d90cbceefb3101ea3b282bbfa82094961b6da5048c2cd377e90278ff76771` |

物理 iOS TUN/流量/内存与物理 Android TUN/protect 均未执行，继续保持 `NOT RUN`。

## 2026-07-24 `rust-tun` fd adapter 历史快照

本轮把 Apple/Android 的平台 fd 与 packet I/O 从 VCore 自写 `libc` 调用迁移到固定
`tun` 0.8.14。VCore 继续验证 borrowed fd、要求宿主预设 nonblocking 并执行
`F_DUPFD_CLOEXEC`；duplicate 所有权随后转交 rust-tun。adapter 不启用上游 async
feature，而是把同步 device 包装进 Tokio `AsyncFd`，避免 async constructor 对与宿主
共享的 file-status flags 再执行 `F_SETFL`。

2026-07-24 在 macOS arm64 当时工作树已执行：

- `cargo test --offline --locked --all-features --all-targets`：主测试目标
  `308 passed / 1 ignored`；外部 Xray integration target `1 ignored`。
- `cargo clippy --offline --locked --all-features --all-targets -- -D warnings`、fmt、C header、
  shell syntax 与 `git diff --check` 全部通过。
- 新增的 6 个 adapter 单测覆盖 rawIp/utun IPv4+IPv6、固定 1500-byte receive slice、
  非法 IP version、超 MTU write、EOF，以及 rust-tun drop 后宿主原 fd/flags 仍有效。
  既有 TUN runtime 12 个 TCP/UDP/DNS/ICMP 数据面测试继续通过。
- `cargo tree --target x86_64-pc-windows-msvc --features ffi -i tun` 无依赖；
  `aarch64-apple-ios` 与 `aarch64-linux-android` 均精确选择 `tun 0.8.14`。lockfile
  记录的上游 Wintun target package 没有进入 Windows 目标依赖图。
- `./scripts/build_apple.sh` 完成 iOS arm64、simulator arm64/x86_64、macOS
  arm64/x86_64 release 构建；`./scripts/build_android.sh` 完成 arm64-v8a/x86_64。
- OneVCore `check_vcore_apple_integration.sh` 与
  `check_vcore_android_integration.sh` 已同步产物并分别通过 Apple bridge smoke 与
  Android JNI integration check。VCore `dist` 与 App 中五份二进制 hash 逐一一致。

本轮产物：

| target | SHA-256 |
| --- | --- |
| iOS device arm64 | `3bc720624df785014a1e531dae0ff4e7f1d055d63e9ce3dc1ce974bc5ddccc0d` |
| iOS simulator arm64/x86_64 | `7c1f056711a7e5577a6f946e5e88252aa88b663a192d5f85f89967e73d5b5bc4` |
| macOS arm64/x86_64 | `b976072bbe669d8375fa24a8b95e31623892e395e4020e99fce31c4a733f90c6` |
| Android arm64-v8a | `81c964304dcb8db5ba15b635cb26a6b3a43d90283ec2b707fe5a4ff6fa61151b` |
| Android x86_64 | `001d527a0d0fc409c8ad4e720cc9b04af66f80070a969fda490a5cbb1d813034` |

当前 macOS 没有 Windows SDK。本轮只完成 Windows UWP 的 backend/transport/打包边界，
没有编写或声称已验证 `IVpnPlugIn`。Apple/Android release cross build 也不能替代迁移后
的 iOS/Android 真机 TUN、Android protect 时序或 iOS Release 整进程内存验收。

## 0. 2026-07-19 Android REALITY `measureDelay` 502 修复历史快照

根因是 REALITY 的占位 verifier 曾把 ClientHello `signature_algorithms` 收窄为
Ed25519。采用 ECDSA 证书的伪装站会在 ServerHello 前返回
`handshake_failure`，Xray 因而无法接管连接，最终由当时的 HTTP inbound 对
`measureDelay` 返回 502。当前修复让 ClientHello 公布 ring provider 的完整签名算法
列表，并在构建 REALITY 配置时继续硬性要求 Ed25519；REALITY 临时证书、HMAC 和
`CertificateVerify` 的认证规则没有放宽。

本轮当前工作树证据：

- rustls ring + REALITY 的 241 个 unit test、官方 integration/doc test 全部通过；新增测试直接读取 ClientHello 并核对完整 provider signature schemes，缺少 Ed25519 的 provider 仍在 builder 阶段失败。
- VCore `cargo test --locked --all-features --all-targets` 为 304 passed、1 ignored；全特性全 target Clippy 通过 `-D warnings`，iOS arm64 全特性 cross-check、C header、shell 和 TLS 单依赖检查通过。
- 本机 Xray 26.3.27 在本地 ECDSA P-256 TLS 1.3 伪装站上重新通过 REALITY/TLS × `packet-up`/`stream-one` 四组互操作。脚本先证明 Ed25519-only ClientHello 在 ServerHello 前被同一伪装站拒绝，因此该用例能够稳定覆盖本次回归。
- 从 Android 模拟器现有 App 数据读取同一条已失败的 REALITY + XHTTP 节点，在 host `VCoreInvoke/measureDelay` 复测成功；随后重建并同步 arm64-v8a/x86_64 `.so`、构建并安装 debug APK，App UI 中两个 REALITY 节点均返回有效延迟，TLS 节点也保持成功。
- API 37、16 KiB page-size arm64 模拟器的 10 个 instrumentation tests 全部通过。该证据覆盖 JNI 和非 TUN `measureDelay`，不替代 Android 真机 TUN/protect 验收。
- 本轮 Android 源/目标产物 SHA-256 一致：arm64-v8a 为 `1bae4d941a64259a518c8f065ca185e668b7969f4a37231f559b27a1c0a4e7ca`，x86_64 为 `d3546005547ac947d04877dcb4e6aaa9b2c73903dfd1b2f678103219513a69d6`；JNI identity、固定 symbols 和 16 KiB alignment 检查通过。

## 0.1 2026-07-19 自有 rustls REALITY 迁移历史快照

该快照是本轮 DNS 调度改造前的旧截止点。当时环境为 macOS 26.5.2 arm64、
Rust/Cargo 1.97.1、Xcode 26.6、Android NDK 30.0.15729638，开发态使用
相邻 `rustls` 仓库 `vcore/reality-0.23` 的未提交工作树；VCore 尚未固定包含
该实现的不可变 Git revision，因此以下结果不是可复现发布证据。其中
`265 passed / 1 ignored` 的 VCore 结果不包含第 6.1 节的本轮 DNS 变更，不得当作
当前工作树的通过记录。

已通过：

- rustls 0.23.42 ring feature-on/REALITY 当时的 239 个 unit test 及官方 integration/doc test 全部通过；feature-off 官方测试目标也全部通过，两种配置的 clippy 均通过 `-D warnings`。
- 两份不同 public key/short ID 的共享配置完成 100 路并发 ClientHello，全部生成独立 32-byte REALITY session ID；HRR、低阶公钥、错误 HMAC/SPKI/签名、截断 DER、缺失连接状态和真实证书 fallback 均按测试 fail closed。
- REALITY DER fuzz target 使用一份可审查 seed 连续执行 21 秒、3,660,302 次，无 crash；feature-on fuzz build/run smoke 通过，并已修正 rustls CI 对该 opt-in target 的调度。
- VCore 主测试目标为 265 passed、1 ignored；`xray_interop` 集成目标另有一个默认 ignored harness。`vcore-netstack` 13 个单元测试和 6 个集成测试，共 19 个通过；VCore 与 netstack clippy、C header、shell 和 TLS 依赖检查均通过。
- 从 Xray-core revision `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` 构建的 Xray 26.7.11 重新完成 TLS/REALITY × `packet-up`/`stream-one` 四组测试，覆盖 VLESS TCP、XUDP、共享 REALITY connector、取消重连及错误 public key/short ID。
- 依赖树只有一份自有 rustls 0.23.42、官方 crates.io tokio-rustls 0.26.4 和一份 crates.io ring 0.17.14；没有 Watfaq、AWS-LC 或第二份 rustls。
- 最终 Apple XCFramework 包含 iOS arm64、simulator arm64/x86_64、macOS arm64/x86_64；Android arm64-v8a/x86_64 ELF 的 LOAD alignment 均为 16 KiB，固定 C/JNI symbols 和 Rust artifact identity 均通过检查。
- Apple/Android 产物已同步到 OneVCore，五份源/目标 SHA-256 逐一一致；Apple Swift bridge smoke、Android JNI 静态集成检查和 21 个 App build-script contract test 通过。

尚未完成或不能写成通过：

- rustls `cargo test --locked --all-features --all-targets` 在构建 `aws-lc-fips-sys` 前因本机缺少 `cmake` 停止；ring 产品矩阵通过不能替代全 feature 结果。
- Bogo ring 实际为 14,051 passed、3 个 warning-log-output mismatch：`SendWarningAlerts-Pass`、`SendUserCanceledAlerts-TLS13`、`SendSNIWarningAlert`，不能写成零失败。
- rustls 实现尚未提交、通过远端 CI 或打不可变 tag；VCore 仍使用相邻 path patch，未固定精确 `rev`。OneVCore workflow 已切换到 Rust toolchain，但在完成该依赖 pin 前干净 runner 仍不能构建。
- 本轮没有连接 Android 模拟器或真机，未对新同步产物重跑 instrumentation；2026-07-15 的模拟器证据仅作为历史基线。
- 按当时现已废弃的 hard-gate 定义，iOS Release 真机、无调试器、完整 TUN 生命周期的 `scoped peak phys_footprint <= 47,185,920` 字节未执行；Apple XCFramework 交叉构建不能替代真机证据。当前契约改为功能结果与 35/45 MiB 观测目标分离。

## 0.2 2026-07-15 迁移前历史验证快照

本轮环境：macOS 26.5.2 arm64、Rust/Cargo 1.96.1、Xcode 26.6、Android NDK 28.2.13676358。

已通过：

- `cargo test --all-features --all-targets` 的最终结果为 261 passed、2 ignored；真实 GeoData 与真实 Xray 测试按设计分别为 ignored case。
- `vcore-netstack`：13 个单元测试和 6 个集成测试通过；VCore 与 netstack 的 `clippy -D warnings` 均通过。
- 使用 OneVCore 保存的真实 Xray `geosite.dat`/`geoip.dat` 显式运行 ignored 测试通过；`CN`、`GEOLOCATION-!CN` 与 `PRIVATE` 常用组合在当时已退役的 iOS TUN 4 MiB GeoData 预算内 retained memory 为 1,962,020 字节，construction ledger peak 为 4,194,304 字节。
- Invoke 测试覆盖严格 `instanceId` method 矩阵、6 路 admission、6 实例上限、同实例 fail-fast、跨实例生命周期、销毁 tombstone、唯一 TUN lease、内置 `measureDelay` 的不可见临时实例/timeout/失败清理、UTF-8/中文/emoji、1 MiB 输入上限、running/TUN panic 收敛、平台 framing 和 nonblocking borrowed fd。
- Android protector 选择策略已有 host 单元测试：非 TUN 在 controller 缺失时通过，TUN 在缺失时失败，已注册 controller 被 TUN 生命周期捕获。OneVCore 宿主还在 API 37、16 KiB page-size 模拟器通过 9 个 instrumentation tests，覆盖 JNI 加载、version Invoke、UTF-8、controller global reference 注册/注销，以及 TUN 生命周期顺序、失败清理和 fail-closed wrapper；真实 TUN outbound fd 的回调时序仍按下文留待 Android 真机验收。
- 自动化同时覆盖连续 20 次 `prepare/start/stop` 和连续 20 次 `createInstance/prepare/start/stop/destroyInstance`；每轮验证 runtime/prepared state、实例表、activity/TUN lease 的所有权均已清空，宿主原 fd 继续可用。该自动化不声称 task、RSS 或 footprint 不增长。
- 从 Xray-core revision `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` 构建的 `Xray 26.7.11` 完成 TLS/REALITY × `packet-up`/`stream-one` 四组测试；每组并发覆盖两份独立 outbound 的 VLESS TCP、XUDP 和对应安全负例。
- 旧 V4 基线中，REALITY `packet-up` 与 `stream-one` 还通过统一 `VCoreInvoke` 各创建 6 个非 TUN 实例，以当时 6 个独立 mixed listener 并发完成 CONNECT → VLESS → XHTTP → Xray → TCP echo，随后并发 stop/destroy 并回收全部实例；当前 V5 已补齐 HTTP auth 的 host 回归，但尚未重跑这组真实 Xray 六实例矩阵。
- 旧 V4 基线使用本机 `Xray 26.3.27` 重新通过四组互操作；在 REALITY 两种 mode 下，6 个并发内置 `measureDelay` 曾交替使用 HTTP/SOCKS5 probe、共同到达本地 204 HEAD target 后由 VCore 全部 stop/destroy。当前 V5 已删除 SOCKS5 probe，并通过自动 Basic 认证、HTTP-only probe 与清理回收的 host 测试；真实 Xray 两种 mode 和公共 WebPKI target 仍需按 V5 契约重新登记。
- bootstrap DNS worker pool 验证按需复用、最多 4 个并发 worker、全部忙时 fail-fast 和最多 8 个解析地址；第二个 TUN 实例在严格配置解析后、bootstrap DNS 前即被唯一 lease 拒绝。
- C/C++ header 编译、shell 语法、host 全特性 Clippy、Android arm64 cross-Clippy 均通过。
- Apple 产物包含 iOS arm64、iOS simulator arm64/x86_64、macOS arm64/x86_64；Android 产物包含 arm64-v8a 与 x86_64。
- Android ELF 已核对 `VCoreInvoke`、`VCoreFree`、`JNI_OnLoad`、`JNI_OnUnload` 和三个 `com.onevcore.vcore.NativeVCore` JNI 入口。
- OneVCore release APK/AAB 只包含 `arm64-v8a` 与 `x86_64` 的 `libvcore.so`，不包含 libXray/libgojni；APK 的未压缩 native libraries 已通过 16 KiB zip alignment 检查。

仍需平台或真实服务端证据：

- Android 真机验证 TUN controller 注册、每个 TUN outbound fd 的 protect 时序，以及 `false`/Java exception/宿主停止路径；同时验证非 TUN `prepare`/`measureDelay` 无 controller 也能工作。
- 在实际长连接与短连接 churn 下记录 core RSS、fd、task 和 footprint 长期 plateau；当前 20 次自动化只验证 ownership/lease 清理和宿主原 fd 可用性，不把它写成 task/RSS/footprint 数据。
- 当时仍要求按现已废弃的 hard-gate 定义完成 `scoped peak phys_footprint <= 47,185,920` 字节验收；当前仍需 Release iOS 真机数据面与完整 footprint trace，但越过 35/45 MiB 不再判生命周期失败。
- 使用真实外部 VLESS/SOCKS5 endpoint，对 VLESS→VLESS、VLESS→SOCKS5、SOCKS5→VLESS、SOCKS5→SOCKS5 的 TCP/UDP 数据路径逐项完成端到端互操作；当前真实 Xray 证据仍是单 VLESS 基线。

## 1. 文档与 schema

- Invoke API v4 request/response golden tests 必须覆盖 `initialize({dataDir})`、所有
  其他 method、未知 method、未知字段、版本错误（包括拒绝 v1/v2/v3）、无效 UTF-8、
  超限输入、runtime-thread 重入拒绝和 panic 收敛；本轮执行状态以顶部 Invoke API
  v4 小节为准。原 Invoke API v3 覆盖只属于对应历史候选。
- Envelope 矩阵覆盖：实例 method 缺失/空值/`null`/未知 `instanceId` 必须失败；registry 级 method 携带 `instanceId` 必须失败；`instanceId` 放进 payload 或宿主自定义 ID 必须失败。
- `initialize` 必须创建并规范化 `dataDir/configs` 与 `dataDir/geodata`；相同路径重复
  调用幂等，relative/空路径、非目录、子目录逃逸和同 runtime 切换路径必须失败。
  `configPath` 必须是 `configs` 子树内的绝对普通文件，符号链接逃逸必须失败。
- `getGeoDataState` 必须在初始化后按 GeoSite/GeoIP 分别返回
  required/available/updating、时间、错误、ETag 与 hash；携带 `instanceId` 或尚未
  初始化时失败。损坏的调度 state 不得阻止 VCore 初始化。
- YAML 与等价 JSON-compatible tree 产生相同内部配置。
- 重复 key、多 document、anchor/alias/merge、自定义 tag、非字符串 key 和未知字段全部失败。
- YAML 不允许 `configVersion` 或 `default-proxy`；旧 `inbounds/outbounds`、
  `mixed-port`、`socks-port`、`outbounds`、`routing`、Mihomo
  `proxy-groups`/`proxy-providers` 以及 Xray `vnext/users` 必须作为负例失败。
  `port` 与 `authentication` 必须同时省略或同时提供；提供时只允许合法 loopback
  HTTP port 和恰好一条 `user:password`，空/多条/无分隔符/超长凭据都失败。
  `dns`、`rules`、`proxies`、严格子集 `dns.nameserver-policy`、顶层可选
  `sniffer` 以及 TUN-only `external-controller`/`secret` 是当前正式字段。
  `external-controller` 只接受 loopback 地址且可单独出现；没有它时单独出现
  `secret` 必须失败，出现 `secret` 时空值或非法值必须失败。两者都不得用于非
  TUN 运行配置或 node-only 测速配置。
- `dns.enhanced-mode` 与 `dns.respect-rules` 已从当前协议移除，任何值都必须作为未知
  字段拒绝。DNS 启用时 A/AAAA typed cache 始终正常工作；只有 runtime 启用 TUN 且
  业务 `rules` 含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 或 `GEOSITE` 时，
  才创建仅供该 TUN 消费的有界 redir-host hint store。nameserver 没有 fragment 时
  固定解析为 DIRECT，显式 `#DIRECT`/`#RULES`/精确 proxy name 保持既有优先级；
  `#PROXY` 只有存在同名实际节点时才按精确 name 解析。
- `dns.nameserver-policy` 只接受有序 `geosite:` selector；逗号分隔 code 为 OR，code 不区分大小写。按配置顺序首条匹配 query domain，命中后只在该 policy 的 nameserver 组内顺序 failover，组内全部失败必须收敛为当前 query 失败，不能回退主 `dns.nameserver`；只有没有 policy 命中时才使用主组。A、AAAA 与 opaque qtype 必须共享该选择语义。
- policy selector 的 GeoSite code 必须与业务 `GEOSITE` rule 一样进入按需 GeoData 加载、去重、16-code 总上限和 8 MiB allocation capacity；即使业务 rules 没有引用该 code，也不能从需求集合中静默删除。GeoSite 资产不可用时 policy 暂不命中并使用主 nameserver；资产热激活后后续 query 必须使用 matcher。
- `proxies` 必须至少包含一项；name 唯一、大小写敏感。proxy 数量和
  `dialer-proxy` 链深没有独立上限，只受整份 YAML 256 KiB、引用存在和全图无环
  约束。`rules` 必填，必须恰好以指向实际 proxy name 的最终 `MATCH` 收尾。
  rule target 与 DNS fragment 中的精确 name 必须解析到对应 `ProxyId`；
  `PROXY` 没有默认节点魔法。未知引用、自引用和环均失败。
- proxy protocol 只接受平铺 Mihomo VLESS、SOCKS5 与 AnyTLS 严格子集。VLESS
  固定 `type: vless`、`network: xhttp`、`tls: true`，TLS/REALITY 使用
  `servername`、`alpn`、`reality-opts` 与 `xhttp-opts`；其他 transport、Vision、
  普通 VLESS UDP、`packet-encoding`、fingerprint、证书跳过和 ECH 字段必须失败。
  SOCKS5 使用 `username`/`password` 配对；半组、空值或超长凭据必须失败。
  AnyTLS 只接受 `name`、`type`、`server`、`port`、`password`、可选 `sni`、
  `udp` 与可选 `dialer-proxy`；REALITY、fp/insecure/ECH/mTLS、ALPN 和
  session/padding 调参字段必须失败。

## 2. Invoke 单公共生命周期

- `createInstance` 创建唯一的 `stopped` 记录并返回 VCore 生成的 opaque generation
  ID，不提前创建 runtime；从创建到销毁期间第二次调用必须失败。销毁后允许创建
  更高且不复用的新 ID。
- 未知、旧代或已销毁 ID 对全部实例 method 返回 failure。
- `validateConfig` 是 registry 级纯校验，要求已初始化 dataDir；它不创建或改变
  实例，不读取/写入 GeoData，也不发生网络访问。GeoData 缺失时合法配置必须通过；
  并发数量或其他 Invoke 是否正在运行不得把结果改为 busy。
- `measureDelay` 使用独立私有 worker，不进入公共实例表，也不影响
  `createInstance` 的唯一槽位。
- `prepare` 只改变目标实例，并在默认 VPN 路由前完成 bootstrap resolve。缺失
  `geosite.dat` 只禁用 GEOSITE/policy matcher，缺失 `geoip.dat` 只禁用 GEOIP
  matcher；不可用 GEOIP 不触发 lazy DNS，其他规则与数据面继续准备。
- `start` 不等待 GeoData 下载；缺失资产立即、已有资产每 24 小时在后台检查，且
  只能经最终 `MATCH` 指向的实际 proxy 及其完整链下载，业务 rules、DIRECT、
  system proxy 和 DIRECT fallback 均不得参与。候选文件校验成功后原子替换并
  热激活给后续新 flow；
  失败保留上一份有效 matcher。updater 只按唯一公共实例的需求和 source 调度；
  source URL 变化必须立即无旧 ETag 检查。共享 dataDir 仍使用 update lock、
  staging、原子替换和崩溃恢复保护文件一致性。
- `start` 只接受目标实例的 `prepared`，且 TUN 配置与 fd/framing payload 必须匹配。
- TUN fd 由宿主预先设为 nonblocking，并在 `start` 返回前 duplicate；VCore 不修改共享 file-status flags，也不关闭宿主原 fd。
- `stop` 在目标实例为 `stopped` 时幂等；从 `prepared`、`running`、`failed` 均能同步清理。
- `destroyInstance` 对 `prepared`、`running`、`failed` 执行同步清理；一旦取得 instance admission，即使清理返回错误或 panic 也必须 tombstone 并删除目标，目标 ID、fd、task、listener、session 和 callback 全部失效。admission 前的同实例 busy 拒绝是唯一保留目标的路径。
- 单实例连续至少 20 次 `prepare/start/stop`，以及连续至少 20 次 `createInstance/prepare/start/stop/destroyInstance`，自动化已验证目标实例 ownership 与 TUN lease 清空且宿主原 fd 继续可用；fd 数量、task、RSS 与 footprint 是否长期 plateau 仍需独立测量，不能由这些生命周期断言替代。
- 同一 `instanceId` 的生命周期命令并发交错时只有一个取得 command admission，其余立即 busy。
- Invoke 不再设置全局六路 fail-fast admission；单请求 1 MiB 和配置文件 256 KiB
  边界继续生效。
- 异步关键数据面退出后，当前实例的 `getState` 返回 `failed` 和脱敏错误。
- `getState` 是 runtime-local、实例级查询，不提供跨 runtime 状态访问；宿主系统 VPN 状态和 IPC 不属于 VCore 契约。

### 2.1 TUN lease

- 每份配置最多启用一个 `tun`；公共生命周期本身已经是单实例，TUN lease 不承担
  多业务实例仲裁，只保护 core-owned duplicate fd 与 Android protect callback
  在 prepare/start/stop/destroy 间的所有权。
- `measureDelay` 不创建 TUN runtime、不会取得 TUN lease，也不调用 Android
  protect。纯 `validateConfig` 同样不取得 lease。
- TUN `prepare` 失败、`stop` 或 `destroyInstance` 后必须释放 lease；进入
  `failed` 但尚未 stop/destroy 时继续持有，避免同一生命周期内错误重入。
- VCore 只关闭自己的 duplicate fd；任何 stop/destroy/失败清理都不得关闭宿主
  持有的原 fd。

### 2.2 `rust-tun` 平台 adapter

- Unix TUN feature 必须把 `rust-tun` 固定为 `0.8.14`，关闭其默认 feature，并通过 target-specific dependency 保证 Windows/UWP 产物不会编译或链接 Wintun；lockfile 仍可能记录上游的 target-specific Windows 依赖。
- borrowed fd 的有效性、nonblocking 状态和 `F_DUPFD_CLOEXEC` 仍由 VCore 在进入 `rust-tun` 前验证；adapter drop 只关闭 duplicate。
- Apple `utun` 与 Android `rawIp` 必须各覆盖 IPv4/IPv6 收发。迁移不得改变 Invoke 的 `tunFraming` 严格校验。
- 当前配置只接受 MTU 1500；传给 `rust-tun` 的 raw-IP receive buffer 必须固定为 1500 字节，不能恢复为 65,535 字节。Apple PI 路径因此使用上游固定 1504-byte 栈缓冲，不产生约 64 KiB 的逐包临时分配。
- `recv == 0` 必须收敛为 `UnexpectedEof`；非法 IP version 只丢当前包；partial packet write 必须失败，不能把余下字节作为第二个 TUN packet 重试。
- 迁移后仍需重新执行 Apple/Android 平台构建、TUN TCP/UDP/DNS/ICMP 数据面，以及 Release iOS 真机内存验收；host 单测和交叉编译不能替代真机证据。
- `rust-tun` 的 Windows backend 是 Wintun，不属于 VCore 的 Windows 方案。UWP 验收必须另行覆盖 `IVpnPlugIn` activation、`VpnPacketBuffer` ownership、有界 callback bridge、loopback managed transport wake、普通 outbound socket 的物理 source/interface 配对绑定、网络切换 fail-closed、AppX/MSIX 注册和 Windows 实机数据面；完整基线见 [`UWP_TUN_RESEARCH.md`](UWP_TUN_RESEARCH.md)。

### 2.3 TUN 流量 Controller

- 统计只能挂在启用的 TUN session 上；HTTP proxy inbound、GeoData、Controller
  请求、proxy transport framing 和 `measureDelay` 都不能进入计数。
- 上传在去掉 Apple utun packet-information header 后按“宿主 TUN -> VCore”的
  raw-IP packet 长度累计；下载按“VCore -> 宿主 TUN”的 raw-IP packet 长度累计。
- 每秒完成窗口必须原子发布 `up`/`down`，累计值必须原子发布
  `upTotal`/`downTotal`。同一 session 内 total 单调不减且溢出时饱和；首次窗口与
  空闲窗口的当前值为零。每次重新启动 TUN session 四项都从零开始。
- 配置了 `external-controller` 时，Controller 与 TUN runtime 同步 start/stop；
  bind 失败必须使本次 start 失败。未配置时不创建 Controller listener；TUN
  session 的统计计数与一秒窗口仍按 Mihomo 的常开统计语义维护。
- 配置了非空 `secret` 时，只有精确的
  `Authorization: Bearer <secret>` 可访问，缺失、格式错误或不匹配返回 401；
  未配置 secret 时采用 Mihomo 无鉴权语义。secret 原文不得进入日志或错误。
- 授权的 `GET /traffic` 必须立即返回且仅返回一次包含非负整数
  `up/down/upTotal/downTotal` 的 JSON snapshot，随后结束 response；不得等待下个
  tick、保持 chunked stream、升级 WebSocket 或保存调用方查询基线。
- 该 endpoint 不属于 Invoke method，不携带 `instanceId`，不受 Invoke command
  admission 影响。App 从独立进程查询必须通过 loopback HTTP，不能调用 App
  进程内另一份 VCore runtime 的 `getState` 或实例表。
- host 自动化必须覆盖方向、utun/rawIp framing、窗口 rollover、累计、饱和、
  restart 清零、配置组合、bind 失败、Bearer 正负例、单次 response 与停止回收；
  Apple/Android 真机仍需分别验证独立 TUN 进程的 loopback 可达性和代表性流量。

## 3. Android protect

- Android 非 TUN `prepare` 和 `measureDelay` 在未注册 controller 时必须正常工作，且不调用 protect。
- TUN `prepare` 在 controller 缺失时必须失败；注册后，TUN outbound TCP/UDP socket 在 connect 前调用 protect。
- `false`、Java exception、回调失效都必须阻断对应的 TUN outbound 连接。
- controller 为 runtime-local 对象，只被当前持有 TUN lease 的实例捕获。
- TUN 实例 `stop`/`destroyInstance` 返回后没有该实例的线程继续调用 protect。
- 当前 registry 没有 TUN lease 时可以替换/注销 controller，即使非 TUN 实例仍 active；TUN lease 存在时必须拒绝。
- controller 快速返回且不重入 Invoke；从 `vcore-runtime` 线程调用 Invoke 必须立即失败，不能进入自 join。
- Android binding 正确处理包含中文和 emoji 的 JSON，不依赖 Modified UTF-8。

## 4. 配置与协议矩阵

| 安全层 | XHTTP mode | VLESS TCP | XUDP | 安全负例 |
| --- | --- | --- | --- | --- |
| TLS | `packet-up` | 必须通过 | 必须通过 | 证书、SNI、ALPN 错误必须失败 |
| TLS | `stream-one` | 必须通过 | 必须通过 | 同上 |
| REALITY | `packet-up` | 必须通过 | 必须通过 | 错误 public key/short ID 必须 fail-closed |
| REALITY | `stream-one` | 必须通过 | 必须通过 | 同上 |

- `auto` 单独验证 TLS→`packet-up`、REALITY→`stream-one`。
- 服务端使用固定 revision 的真实 Xray-core，报告记录版本和 commit。
- REALITY 还必须将 Xray `dest` 指向本地 ECDSA P-256 TLS 伪装站完成数据面回归。ClientHello `signature_algorithms` 必须公布 provider 的完整支持列表（至少 ECDSA、RSA、Ed25519），但 REALITY 临时证书 SPKI、证书 HMAC 和服务端 `CertificateVerify` 仍只接受 Ed25519；收到真实伪装站证书或其他 scheme 必须 fail closed。
- XUDP 覆盖 IPv4、IPv6、domain、正常 END、带 error 关闭、超限 datagram 和取消；TUN 路径在 payload 分配前拒绝超过 1,452 字节的远端长度。HTTP inbound 不提供 UDP。
- 未实现 cone/reconnect 复用时验证 Global ID 不产生随机非零复用语义。

AnyTLS 当前验收矩阵：

- 平铺配置字段必须严格使用 Mihomo name：必填 `name`、`type: anytls`、
  `server`、`port`、`password`，可选 `sni`、`udp` 与 `dialer-proxy`。未列出的
  TLS/session/padding 字段全部失败。
- TLS 只允许标准 WebPKI TLS 1.3/1.2，不发送 ALPN；证书、SNI 或信任链错误
  fail-closed，不回退明文、DIRECT 或证书跳过。
- 新 session 先宣布 v2。收到 ServerSettings v2 后，stream reuse 写出 `SYN` 与
  目标即返回可用 stream，并启动 tracked 3 秒 SYNACK watchdog；服务端未返回
  ServerSettings 时，该 session 保持 v1-compatible，不启动 watchdog。
- reused stream 收到非空 SYNACK 或 watchdog timeout 时销毁整个 session；由于
  open 已返回，错误经 stream I/O 或 session 关闭暴露，不承诺同步
  `ConnectionRefused`，也不得为该 stream 静默重拨。只有 open 返回前的 stale
  idle write/setup failure 可以在当前 open 丢弃旧 session 后建立一次 fresh
  session；open 返回后的失败只能由后续独立 open 建立 fresh。
- TCP 覆盖单 stream 与 session reuse；`udp: true` 覆盖
  `sp.v2.udp-over-tcp.arpa:0` sing UoT v2 datagram mode，以及同一 stream 的
  per-packet 不同 destination。`udp: false` 时 UDP dispatch 必须失败。
- pool 每个 session 同时只允许一个 active stream，并在 idle session 中选择
  sequence 最大者；idle check
  和 timeout 均为 30 秒，`min-idle-session` 固定为 0，不设置 active-session
  hard limit。内置 padding 更新只影响未来创建的 session，既有 session 保持创建时
  snapshot。
- runtime start 共享 client pool；`begin_shutdown` 后拒绝新工作并取消相关后台
  task，`shutdown().await` 是释放 session、stream、timer 与 task 的最终同步屏障。
  重复启动停止与中途失败必须覆盖资源回收。
- 2026-07-28 已运行
  `bash tests/run_anytls_interop.sh` 对本地 anytls-go
  `0c36ca9f0d88bc1af5ddb998e619166913c7445c` 做真实进程互操作：TCP 首流、
  TCP reuse、sing UoT v2 两份 UDP echo、UoT 后再次 TCP、单物理 session 计数及
  显式 shutdown 全部通过。参考服务端使用动态自签名证书，因此仅
  `interop-test` integration binary 内的 test connector 跳过证书链信任、仍校验
  TLS handshake signature；生产 AnyTLS 继续固定 WebPKI，release 不包含该
  connector。Mihomo 与公网 AnyTLS 服务端互操作仍为 `NOT RUN`。

V5 proxy graph 的历史自动化矩阵为：

| 被选择节点 | `dialer-proxy` 节点 | 物理路径 | TCP | UDP |
| --- | --- | --- | --- | --- |
| VLESS | 无 | client → VLESS → target | VLESS TCP | XUDP |
| SOCKS5 | 无 | client → SOCKS5 → target | CONNECT | UDP ASSOCIATE |
| VLESS | VLESS | client → 上游 VLESS → 被选 VLESS → target | 上游 VLESS TCP tunnel + 被选 VLESS TCP | 上游 VLESS TCP tunnel + 被选 VLESS XUDP |
| VLESS | SOCKS5 | client → SOCKS5 → VLESS → target | SOCKS5 CONNECT tunnel + VLESS TCP | SOCKS5 CONNECT tunnel + VLESS XUDP |
| SOCKS5 | VLESS | client → VLESS → SOCKS5 → target | VLESS TCP tunnel + SOCKS5 CONNECT | VLESS TCP control tunnel + VLESS XUDP 承载 SOCKS5 UDP |
| SOCKS5 | SOCKS5 | client → 上游 SOCKS5 → 被选 SOCKS5 → target | 两层 CONNECT | 上游 CONNECT 承载被选节点 control + 两层 UDP ASSOCIATE 数据路径 |

- 节点 A 设置 `dialer-proxy: B` 时，A 是被规则/DNS 选择的逻辑出口，物理网络先到 B；数组顺序不参与链或默认出口选择。删除 `dialer-proxy` 后两个节点必须能由规则和 DNS 独立选择。
- SOCKS5 历史自动化覆盖 no-auth、RFC 1929 username/password、IPv4/IPv6/domain、
  UDP relay、FRAG/控制连接 EOF、payload ceiling 和真实双 SOCKS5 control/relay
  wire。四种两跳协议组合当时覆盖配置归一化与 connector graph 构建；涉及 VLESS
  的三种组合尚未形成真实 wire 传输证据，不能把结构覆盖写成端到端互操作。任一
  下游失败都不得回退 DIRECT 或另一节点。

## 5. Inbound

- TUN 覆盖 IPv4/IPv6 TCP/UDP、raw IP/utun framing、背压和停止。
- HTTP 只绑定 loopback，覆盖 CONNECT early/late data、absolute-form 改写、hop-by-hop header 移除和 Basic auth。缺失、错误、畸形或重复 `Proxy-Authorization` 必须在 dispatch 前返回 407；认证与内部诊断 header 都不得转发。
- 不存在 SOCKS5 inbound；`mixed-port`、`socks-port`、非 loopback bind、LAN 暴露、
  DIRECT fallback 和配置/协议大小超限必须失败；业务并发越过旧阈值不属于这里的
  “超限”。
- V7 sniffer schema 必须覆盖：顶层省略与 `enable: false` 默认关闭；sniffer 出现但缺失 `enable` 失败；关闭时可省略或保留合法 `sniff`；`enable: true` 但 `sniff` 为空失败；HTTP、TLS、QUIC 的单独和组合配置成功。协议值可使用 Mihomo 形式的空值（`HTTP:`/`TLS:`/`QUIC:`）并分别采用 80/443/443，mapping 省略 `ports` 同义；显式 `ports: []` 失败。单端口和升序闭区间、每协议最多 64 项、1..65535 边界必须通过，反向/越界/非法表达式、第 65 项失败。HTTP/TLS 重叠必须拒绝；QUIC 与 HTTP/TLS 使用相同数字端口必须接受。未知协议、`override-destination`、force/skip 系列以及旧 `sniffing`/`port-whitelist` 必须作为未知字段失败。
- TUN TCP 的已配置 HTTP 端口覆盖分片 header 与规范化 `Host`，已配置 TLS 端口覆盖跨 TLS record/分片的 ClientHello SNI。TUN UDP 的已配置 QUIC 端口覆盖标准 v1/v2 Initial、分片/乱序 CRYPTO、多 packet Initial 和同 association 多 destination；Draft-29 与其他版本不得生成 sniffed domain。UDP/53 runtime-DNS fast path 必须在 ordinary association 与 QUIC sniff state 创建前生效。
- QUIC route selection 前缓存必须覆盖每 association 最多 4 个 destination state、全部 pending 合计 8 个 datagram/32 KiB、500 ms，单 state CRYPTO 16 KiB/64 ranges 和 ACK 总计 64 ranges。满 4 个 state 时必须 LRU 淘汰最老 completed state；只有全部为 pending 时，第 5 个 destination 才直接 fail-open。不同 version/DCID 的 v1/v2 Initial 只有候选 Initial keys 完成 AEAD 认证后才能替换 completed state；pending 必须先尝试原 Initial keys，以容纳同一连接的 header DCID 轮换。0-RTT/Handshake 的 DCID 变化不得重置，未认证候选不得引入 500 ms 等待。达到任一上限、超时或解析失败时只结束相应 pending flow；未知非零版本还必须清除该 destination 的旧 completed hint。所有失败路径都回退 DNS hint/IP，并将已缓存 datagram 按该 flow 原顺序、原字节且只回放一次。
- TLS/QUIC sniffer 必须扫描完整 ClientHello extension 列表，不能在读到 SNI 后提前返回。`encrypted_client_hello` (`0xfe0d`) 位于 SNI 前、SNI 后或输入分片边界时，都必须丢弃 outer SNI；无法区分的 GREASE ECH 采用相同保守语义，回退到有效 DNS hint，否则使用原 IP。命中的 domain 参与 `DOMAIN`/`DOMAIN-SUFFIX`/`DOMAIN-KEYWORD`/`GEOSITE` routing，优先级为 `sniffed domain > DNS redir-host hint > IP`，但 actual outbound destination 始终保持原 IP。
- HTTP/TLS 的 200 ms/32 KiB prefix 与 QUIC 的 500 ms/8-datagram/32 KiB pending 路径都必须 fail-open；逐字节验证预读内容只回放一次且顺序不变。未配置端口不引入 sniff 等待。
- 必须分别覆盖非 TUN runtime、sniffer 关闭、TUN 但不含 domain rule，以及 TUN + sniffer 启用 + 四类 domain rule 的初始化：只有最后一种实际启用 sniffer。redir-host store 独立按 TUN + domain-rule scope 创建，从空容量按需增长、最多 256 项且只被所属 TUN 消费；关闭 sniffer 不得关闭该 store。A/AAAA typed cache 在所有场景中都保持正常。
- TUN 没有上述 domain rule 或 sniffer 关闭时，即使目标端口已配置也必须证明没有 TCP prefix/QUIC pending state 分配，没有 200 ms/500 ms sniff deadline 等待。

## 6. TUN 资源与 iOS footprint 验收要求

本节定义必须满足的验收要求，不等于本轮已执行结果；本轮已执行结果见文件顶部，
第 6.1 节仅为 2026-07-19 历史快照。

- 所有 channel、queue、packet、每流 buffer、cache、parser/wire size 必须有明确上限及
  压力测试；timeout 与 idle cleanup 必须有停止/取消回归。TCP session、UDP
  association、half-open、outbound handshake、DNS query、DNS upstream 和 active
  physical TCP 不得恢复固定并发 admission。
- 局部 queue/full、wire/parser oversize、timeout 和真实 transport failure 继续使用
  对应诊断；不得把超过旧 128/64/32/16 或 DNS 128/8 阈值映射成
  `ResourceLimit`/HTTP 502。每个 runtime 使用固定字段 atomic 统计 TCP、UDP、
  half-open、handshake 与 DNS current/peak，以及 queue drop、singleflight join、
  cache hit 和 TCP pool 状态；首次事件立即记录，之后最多每 30 秒聚合一次，stop
  输出最终摘要。不得使用动态 label map 或记录目标、DNS question、payload/密钥。
- 当前资源观测至少保留 `runtime_dns_singleflight_join`、
  `runtime_dns_cache_hit`、`runtime_dns_response_drop`、`resource_stats_periodic`、
  `resource_stats_final`、`tun_netstack_stats_periodic`、`tun_netstack_stats_final`、
  `runtime_dns_tcp_pool_final`、`ios_memory_snapshot`、
  `ios_memory_observation_target_crossed` 与 `ios_memory_measurement_failed`。旧的
  session/association/handshake/DNS admission reject/wait 事件不再属于当前契约；
  重命名其余事件必须同步更新日志消费者、本文和优化计划。
- Invoke envelope 和配置文件分别验证 1 MiB 与 256 KiB 大小上限，失败时不留下
  大对象或部分状态。当前不设置全局 Invoke 并发 gate，也不承诺固定的跨请求输入
  聚合上限。
- 压力测试必须覆盖唯一公共实例的 queue、buffer、cache 与 parser/wire 边界，
  以及单次 `measureDelay` 最多五个私有 worker；stop、destroy 和批次返回后资源
  必须可回收。VCore 不做跨 runtime 总额验收。
- TUN workload profile 在 Apple/Android 间一致：256 packet queue、128 event/ordinary
  UDP response queue、1,500-byte TUN raw packet、32 KiB/TCP direction 及 64 KiB
  TLS/XHTTP。TUN final proxy UDP payload ceiling 为 1,452。
- TUN runtime DNS 不设置 client request 或 aggregate live upstream transport 上限；
  typed cache 最多 256 项，按需 redir-host store 启用时同样最多 256 项并从空容量增长，
  opaque cache 为 64 项/256 KiB。TUN DNS ingress 与独立 DNS response queue 各 128；ordinary UDP
  response 另有 128 项 queue。两类 datagram 共享 netstack ingress receiver，因此必须
  把验收写成 response capacity 隔离，而不是完整 ingress 隔离。
- 显式 `tcp://` nameserver pool 的 key 必须包含 endpoint 与 `#RULES` 求值后的最终
  egress；active 物理连接不设固定上限，默认最多保留 4 个 idle、同 key 2 个 idle，
  30 秒过期，一条连接同一时刻只服务一个 query。任意数量的 busy query 收敛后仍只能
  留下上述 idle 数量；expired 回收计入 `idle_expirations`，LRU 回收计入
  `idle_evictions`。
- 只有完成 framing 和 typed/opaque response 校验的 TCP 连接可以归还池。复用连接
  的 EOF/I/O/reset/response mismatch 最多 fresh retry 一次；malformed、truncated、
  oversize 不重试。测试必须覆盖 key 隔离、stale retry、ID mismatch、global/per-key
  idle/LRU/expiry、active 超过旧 8 阈值、runtime drop 后 physical/busy/connecting/idle
  current 全部归零且 idle reaper 收到取消。
- 同 key singleflight 的 key 必须包含 canonical question 和排除 transaction ID 后
  `message[2..]` 的 semantics digest。leader 在发起方 task 内运行；leader cancel/drop
  通过 RAII 广播 Retry，followers 重新选举。caller ID 必须逐一恢复；cache hit 不创建
  flight。response 最多扫描 64 条 record，typed cache 以及启用时的 hint 最多保留
  16 个唯一 IP。
- runtime DNS query 固定使用 5 秒总 deadline、每 nameserver 最多 3 秒 attempt；UDP 在 1 秒无合法 response 后最多在同一 transport 上重发一次，前 2 个 peer/QR/opcode/ID/question mismatch 只丢当前 response，累计到第 3 个即判当前 attempt 失败。UDP nameserver 返回 TC 时只判当前 attempt 失败并继续下一 nameserver，不隐式创建 TCP transport；显式 `tcp://` nameserver 不受影响。DNS disabled 回普通业务路径，malformed TUN UDP query 在 task 创建前 request-local drop。bounded netstack UDP ingress 在 fast path 前已满时只丢当前 request；response queue full/closed 时仍可 request-local drop，只有成功入队并发出的 response 才能到达客户端，不承诺 UDP 必达。TUN UDP DNS response 超过 1,452 字节时只丢当前 response，不合成本地替代包。未被 timeout/cancel 中断的 UDP attempt 正常收敛路径显式调用 `close()`；runtime stop/cancel 必须终止所有 tracked request，drop 并释放 transport，停止后不得回包，但取消路径不承诺 XUDP END 等协议级 graceful close。
- outbound handshake 不设全局 semaphore；DIRECT、全部 proxy graph、runtime DNS 和
  本地 listener 按需建链。回归测试必须让并发越过旧 16 阈值，并证明取消、timeout、
  transport failure 和 runtime stop 能收敛 current 统计且不遗留 task。旧 iOS 20/4
  weighted pools 与 cost admission 不得恢复。
- bootstrap resolver 最多创建 4 个 worker thread；第 5 个及后续请求在调用方既有
  timeout 内等待可用 worker，不得因 worker 全忙立即返回资源上限错误。worker 完成、
  发送失败和调用取消后都必须唤醒后续 waiter。
- 普通 UDP association 使用 generation-aware completion 和 child cancellation，
  不设置固定 map 项数。idle timeout 30 秒、cleanup 10 秒；cleanup 先 remove
  expired/closed 再 cancel。completion 只能删除同 generation；parent stop 删除/cancel
  全部 child 并 drain completion。drop/full 不刷新 activity。
- XHTTP 静态 host/path 和 packet-up session ID 使用 `Arc<str>` 复用；测试只证明
  allocation 去重，未取得真机 trace 前不得宣称 footprint 收益。UDP DNS 保持
  request-scoped；TCP 仅实现上方 active 不限量、idle 有界的单连接串行 pool，不包含
  pipeline/ID demux。
- TUN runtime resource stats 与 netstack stats 共同保留 active TCP、half-open TCP、
  UDP、handshake 和 DNS 的 current/peak，并在停止后将 current 收敛为 0、peak 保留。
  `tun_netstack_stats_periodic/final` 还必须输出 TCP
  reject、UDP drop、invalid packet、ICMP replied/dropped；周期固定 30 秒，不使用
  destination、domain、DNS question 或其他动态 label。
- iOS memory snapshot 和 allocator pressure relief 都是 best-effort。current
  首次跨过 35/40/45 MiB 时每档只记录一次，running 最多每 30 秒采样一次；测量失败
  只记一次 warning。它们不得写 `lastError`、拒绝启动、停止 runtime、覆盖原始错误或
  让成功 stop 失败。
- 旧的 iOS static byte model、历史 lifetime-peak reuse rejection、100 ms watchdog 和
  registry activity exclusivity 均不得恢复；只保留 runtime-local 唯一 TUN lease。
- VCore 自动化验证资源边界、生命周期 ownership/lease 和宿主 fd；task/RSS/footprint
  plateau 仍必须独立测量。最终对 Release iOS 真机记录：

```text
cold-start current phys_footprint（35 MiB observation target）
representative-workload peak phys_footprint（45 MiB observation target）
30-minute running plateau 与 stop 后 plateau
```

- 最终矩阵覆盖空闲、混合 TCP/UDP、超过旧业务并发阈值的持续压力、局部 queue/buffer
  背压、远端重连和至少 20 次完整生命周期。
  越过 35/45 MiB 必须记录分析但不判功能失败；极端压力下允许 iOS 终止 Extension。
  外部连续 trace 才能描述单次 lifecycle peak，进程 lifetime ledger 不能替代它。

### 6.1 2026-07-19 旧 DNS 调度历史快照

2026-07-19 在 macOS host 执行：

```bash
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
sh -n scripts/*.sh tests/run_xray_interop.sh
./scripts/check_tls_dependencies.sh
cargo check --locked --target aarch64-apple-ios --all-features
XRAY_BIN=/opt/homebrew/bin/xray tests/run_xray_interop.sh
```

当时工作树的主 crate 结果为 296 passed、1 ignored；ignored 项是真实 GeoData 资产测试。默认
`xray_interop` harness 按设计 ignored。本轮资源重构未重新显式运行该 harness；同日较早记录曾使用
本机 Xray 26.3.27 通过 TLS/REALITY × `packet-up`/`stream-one` 四组。netstack 结果为
13 个 unit 与 6 个 integration tests 全部通过；fmt、两组 clippy、C header、shell syntax、
TLS dependency 检查和 `aarch64-apple-ios` 全 feature 交叉检查全部通过。既有 Xray 记录只验证
VLESS/XHTTP 数据面，不把它写成真实上游 DNS、固定 Xray 26.7.11 或物理 iOS 验收。

#### 6.1.1 当时已通过的 host 自动化

- 多 source-port TUN UDP/53 pre-association burst 不创建普通 association，8-slot total
  overflow 生成 SERVFAIL，且 stalled DNS 不阻塞普通 UDP。
- iOS/通用 8/32 total 和 2/8 active/logical 档位、pre-admitted exchange 只消耗
  一个 total slot、lazy resolve 在 total 满时返回有界错误，以及 TCP/UDP 合并
  logical admission；8 个 total query 同时最多只有 2 个 active logical transport。
- DNS-only session/handshake/weighted-pool wait 等待容量释放与 deadline；TUN outbound
  handshake 在既有 15 秒 open timeout 与 cancellation 域内等待，本地 HTTP
  handshake 仍保持 fail-fast。weighted-pool waiter 不提前占用共享 handshake permit。
- iOS TUN 的 16 个 half-open SYN 与 2 个 outbound handshake 已拆为独立上限，前者仍被
  16 个 TCP session 总上限约束；等待中的 TUN TCP/UDP handshake 可被取消并正确归还 permit。
- A/AAAA cache 与 redir-host hint 从空容量按需几何增长，并分别采用 iOS TUN 128 项、
  通用档 256 项的运行时上限；opaque cache 同样不再在构造时预留 64 项。
- iOS TUN scope 入口会拒绝 lifetime peak 已超过 45 MiB 的进程；低于、等于和高于边界
  的 host 单元测试均已覆盖。
- 1 秒后同 transport/同 transaction ID 的单次 UDP 重发，mismatch 累计到
  第 3 个即 failover、UDP TC 只进入下一 nameserver 且不打开 TCP、malformed
  pre-admission drop、超长 TUN UDP DNS response drop 和 blocked upstream 下的 stop barrier。
- total permit 随 wire response、TCP framing 或 TUN UDP queue item 持有到实际发送或
  request-local drop；response queue full 会立即释放 permit。IPv4/IPv6 回包都保持
  客户端请求中的 server/client endpoint 方向。
- DNS-enabled iOS TUN UDP ingress burst 固定为 32 个 datagram；fast-path request、
  active transport、ingress/response queue 和 control state 的精确模型为 260,992 字节，
  小于等于 256 KiB 子预算。
- 资源档位断言保持 7,640,960-byte modeled growth、747,648-byte modeled
  remainder 和最后 2 MiB unmodeled safety。

#### 6.1.2 仍待补写或加强

- 先填满普通 UDP association 再验证 DNS fast path 仍可进入；在一个集成测试中
  同时混合 TUN UDP、TUN TCP 与 lazy resolve，验证它们共享唯一
  total/active admission。
- cache/local result 在 active 容量满时仍不取得 active permit；5 秒 total、3 秒
  attempt 和 1 秒 resend 的真实时序边界。
- cancel 分别命中 permit wait、open、send、receive、retry 与 response
  send 时的 task/permit/transport 最终回收计数；现有测试已经覆盖 blocked upstream
  stop barrier、queue-full permit 回收与 stop 后不保留 detached task，但尚不是上述
  阶段的穷举矩阵。

#### 6.1.3 仍待真实服务端或平台证据

这些旧 host 自动化只证明当时的 core 契约；它不能写成当前无 admission 的 DNS
scheduler、固定 Xray 服务端 DNS、物理 iOS/Android TUN 或 Release iOS footprint
已通过。当前实现的最终结果只允许写入本文件顶部新建的本轮验证区。

## 7. 内置并发节点测速

- `measureDelay` 是 Invoke API v4 的 registry 级批量 method，必须省略
  `instanceId`。payload 只接受必填的 `configPaths`、`timeout` 与 `url`，
  未知字段失败。
- `configPaths` 必须包含 1–5 个非空路径；每个路径都必须是已初始化
  `dataDir/configs` 子树内的普通文件。`timeout` 为 1–30 秒整数。
- 同一 runtime 同时只允许一个外部 `measureDelay` 调用；重叠调用立即返回
  `measureDelay is busy`。Core 固定最多并发执行五个私有 worker，实际 worker
  数不超过配置项数，并且不进入公共实例表、不占用唯一公共生命周期实例。
- 每份 YAML 顶层只允许 `proxies`，且至少包含一个平铺 VLESS、SOCKS5 或 AnyTLS
  proxy。Core 从未被其他节点的 `dialer-proxy` 引用的节点中推导唯一链头，该链
  必须覆盖全部节点；多个链头、没有链头、未使用的独立节点、未知引用、自引用、
  环，以及 `port`/`authentication`、`tun`、`sniffer`、
  `external-controller`/`secret`、`dns`、`rules`、GeoData 下载字段等 runtime-only
  内容都必须失败。
- worker 直接准备 outbound graph；不创建 loopback HTTP listener、公共/内部实例
  ID、TUN lease，不调用 Android protect，也不注册、读取或下载 GeoData。
- `url` 必须是无 userinfo/fragment 的绝对 HTTP/HTTPS URL。目标 domain 原样交给
  outbound graph，不能在宿主侧预解析；HTTPS 使用内置 WebPKI，随后只发送一次
  HTTP/1.1 `HEAD`，不跟随 redirect、不读取 body。任何语法合法的 HTTP status 都
  表示目标已经响应。
- 单项计时覆盖 outbound connect、可选目标 TLS、`HEAD` 发送与 response head；
  配置解析、bootstrap、graph build 和资源释放不计入 delay。单项失败不得取消批次
  中的其他项。
- 返回的 `results` 与 `configPaths` 严格等长同序。成功项为
  `{"success":true,"delay":<毫秒>,"error":""}`；失败项省略 `delay` 并返回
  有界、脱敏的 `error`。只有 payload 无效、runtime 未初始化或批次 admission
  失败才作为顶层 failure。
- method 只有在全部 worker、connector 和临时资源释放后才返回。VCore 不返回
  10000/11000 delay 哨兵，不提供内部重试、多次采样、聚合或调用中的取消 handle；
  这些能力如需增加必须另行更新契约与验收矩阵。

历史记录（非当前契约）：V4 曾允许六个外部单项调用，各自创建临时实例、带认证
loopback HTTP listener，并通过该 listener 探测 REALITY `packet-up`/`stream-one`。
这些旧的实例容量、listener 回收和 HTTP Basic 认证证据不能替代当前 API v4
node-only 批量 runner 的配置、排序、并发隔离与资源释放验收。

## 8. 独立交付

- Apple XCFramework 和 Android `.so` 输出到 VCore 自身 `dist/`。
- VCore 的构建和测试不要求相邻 OneVCore App 仓库存在。
- OneVCore Apple 薄适配层已接入并在 App 仓库单独验收；VCore 的独立构建与交付边界不因此改变。

历史记录：2026-07-19 使用当时 DNS M1–M5 且已删除 TC 专项路径的工作树重新执行
`./scripts/build_apple.sh`，生成并核对：

| slice | architectures | `libvcore.a` SHA-256 |
| --- | --- | --- |
| iOS device | arm64 | `2f95d4ad51b5dd474ec5fd28c6dd7fc3b9eb7191191a4050e8818c41b0c0ef1d` |
| iOS simulator | arm64, x86_64 | `a7331c4771880325dda2846d078a4334487c28007bd7ceaa4df94966620b7a52` |
| macOS | arm64, x86_64 | `67db78a642d3ddd89848881b00f8b0d2134a3033c55706e74b93b4e0a054c1d1` |

共享 DNS runtime 的 Android 产物也使用 `./scripts/build_android.sh` 重建：

| ABI | `libvcore.so` SHA-256 |
| --- | --- |
| arm64-v8a | `61deab026175c9c5f988ec7db56c3a9add7bbbfe847b7dcf4536f88ef0733a11` |
| x86_64 | `eebeb1b925e5bc7fe773664f178bb3a569a6cbb3c4879e21f83bc3219978c5d5` |

随后通过 OneVCore 的 `sync_vcore_apple.sh` 与 `sync_vcore_android.sh` 同步到 App；
Apple/Android 源目标目录 `diff -qr` 均无差异，Apple bridge smoke、Android JNI/16 KiB
LOAD alignment、10 个 Apple integration tests 与全部 25 个 App build-script tests 通过。
该构建与 host 集成证据不替代 Release iOS 真机 Network Extension 数据面和 35/45 MiB
验收。

相邻 OneVCore App 随后执行 `flutter build ios --release` 成功，生成 80.2 MB 的签名
arm64 `Runner.app`。Runner 与 `tunnel.appex` 的 identifier 分别为
`net.yuandev.onevcore` / `net.yuandev.onevcore.tun`，TeamIdentifier 均为
`2CKAULFA9J`；Tunnel entitlement 包含 `packet-tunnel-provider` 与
`group.net.yuandev.onevcore`，release entitlement 的 `get-task-allow` 为 false，最终
Tunnel executable 可见 `VCoreInvoke`/`VCoreFree`。本次只完成编译、链接和签名检查，
未自动安装或启动设备 VPN，因此不能据此填写真机流量/footprint 结果。

同一批产物执行 `flutter build apk --release` 也成功，生成 81.0 MB 的
`app-release.apk`，SHA-256 为
`e515731a31b5dc521238657e12196980e1ad8c5bacbdfd8bce75f6a2144a9991`。APK 只包含
`arm64-v8a` 与 `x86_64` 的 `libvcore.so`，不含 libXray/libgojni，并通过 16 KiB
zip alignment 检查；本轮没有安装 Android 模拟器或真机。
