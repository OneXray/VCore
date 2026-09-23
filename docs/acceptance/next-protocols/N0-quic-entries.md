# N0-D：官方单状态跳端口与 Xray H3 入口

日期：2026-09-23。**N0-D 的最小可行性门禁 PASS；N0 整体未签收。** 本轮在既有受控 QUIC 实验中补齐官方 Hysteria 单状态 hop、Xray XHTTP/H3 两个入口，并重跑原有 HY2 用例。只证明公开接口可行，不开放生产字段，不签收 N5/N6。附加原生半关闭用例仍有 FAIL，见下文。

后续追加的 [XHTTP 关闭对齐](XHTTP-close.md)以 Mihomo 客户端为基准，已修正生产 H2 和独立 H3 实验。以下输入身份、正常8项和半关闭失败均保留原始历史；当前脚本默认增加整连接关闭第9项，另可选官方 Mihomo 客户端对照。XHTTP 的客户端契约不再要求上传 EOF 后继续接收尾包，不把这一决定改写成原半关闭测试通过。

## 输入与对端身份

- 分支 `feat/next-protocols`；实际父提交 `101f20fee30ec1275226b6db811701fba7996d43` 加本次自有实验变更。提交在测试之后；报告保存被测源文件、脚本、独立锁和二进制摘要，不冒称测试时已有随后提交的 SHA。
- 生产 `src/`、Cargo.toml / Cargo.lock 与 `bbe5100abcf07b1158f86cff39cd835e1f32ccf9` 相同。主锁 SHA-256 `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2`；Invoke v5 / schema 14 不变。
- [独立实验](../../../tests/protocols/spikes/hysteria2/README.md)继续使用 Quinn 0.11.12、quinn-proto 0.11.18、h3 0.0.8、h3-quinn 0.0.10；本轮未增加依赖。独立锁 SHA-256 `26114362039efecee8d9253a0aab6f2074e82b4e1f177d85d4ca3f6326aaba58`。
- rustls 0.23.43 仍锁定原 `df261c84cbac4f708e63ac8644ce70daa90d771c`，TLS ring / 官方 tokio-rustls；没有使用混合 REALITY 实验 fork、修改第三方或扩大 SS 的 AWS-LC 例外。
- macOS 27 ARM64、Rust/Cargo 1.98.1、uv 0.12.17、Apple Container 1.4.1。Linux peer 内核 6.18.35、nftables 1.1.5；镜像 `alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40`。Linux 仅为对端，不改变 VCore 平台范围。

每次脚本执行重新下载官方 latest，运行二进制查询版本；不调用 GitHub API、不编译对端、不回退旧缓存。hash 仅标识内容，不冒称上游签名校验。

| 官方资产 | 实际版本 | 程序 SHA-256 |
| --- | --- | --- |
| [Hysteria Linux ARM64](https://github.com/HyNetworks/hysteria/releases/latest/download/hysteria-linux-arm64) | v2.12.3，`e1366b173ccf5706e1e4630fe8aa654a4b574085` | `c8dc653c3ba0a28d29a26b8fa52d2086f27c0927afddce95c09965e7174e78b0` |
| [Xray macOS ARM64](https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-arm64-v8a.zip) | 26.3.27，d2758a0，Go 1.26.1 | `5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404` |
| [Mihomo latest](https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt) | v1.19.31，darwin arm64，Go 1.26.8 | `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090` |

Xray ZIP 摘要为 `2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf`，只解出唯一 `xray` 成员，不运行附带脚本。HY2 回归还重新下载原生 Darwin Hysteria v2.12.3，程序摘要 `9065dc5dc9cd75f7ba881f481e8cb77e7eae17139460ca09d399682ca6fad443`。这不是固定未来运行版本。

## 官方 Hysteria：两个入口、一个连接、一条流

本轮使用官方 `listen: <owned-vm-ip>:18444-18445`、测试证书、合成密码、`ignoreClientBandwidth: true`、`disableUDP: true`。只有一个进程、一个首端口 UDP socket、一个原生 nft NAT 表；第二端口没有独立 listener。选择原生端是因为此门禁要求共享一个 QUIC 状态，不能用两个互不共享状态的 Mihomo listener 代替。[原生端口范围实现](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/server.go#L337-L375)、[原生规则](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/internal/firewall/firewall_linux.go)。

复用 VCore `OutboundConnector::open_datagram`，先完成 auth 与服务器先发、前 32 KiB 逐字节回显；再创建新的受保护 transport，通过 [Quinn 公共 rebind](https://docs.rs/quinn/0.11.12/quinn/struct.Endpoint.html#method.rebind_abstract)切换。新 adapter 只在一个固定逻辑 peer 与第二个物理入口之间映射目的/来源端口；不新建 QUIC connection、不重新认证、不重放前缀、不重新打开业务 stream。

| Case | 本轮观测 |
| --- | --- |
| `native-hysteria-one-state-hop` | PASS：connect/auth 各 1 次；同一 connection stable ID / stream ID；目标 accept=1、65,536 bytes 完整；protect=2；公开 BBR factory=1 |
| 物理路径证据 | 独立 pre-DNAT 观察表记录第一/第二入口 46 / 36 包；两者源端口集合各一个且不同；新 adapter 实际发/收 36 / 29 包；服务端认证连接日志=1 |
| `native-hysteria-reject-hop` | PASS：第二次 protect 返回拒绝；第二入口和新 adapter 收/发均为 0，目标只收到已完成的前 32 KiB；connect/auth 仍各 1 次，没有退回未保护路径 |
| Stop / 清理 | 两个 owner 在同一 5 秒停止期限内 join，停后发送拒绝；正例约 106.026 ms，拒绝例约 0.046 ms；原生进程 TERM 后自己的 nft 表消失；观察表和本次两个 VM 清理完成 |

单向队列仍为 32 × 1400 bytes、QUIC MTU 1200，无锁内 await。过渡期间最多两个 adapter，旧 owner 保留到 endpoint idle；Quinn 收到新 socket 的 connection packet 后可能不再消费旧 socket，**不据此宣称正式重叠窗口、多次轮换或资源策略已完成**。HY07/HY08 的解析、默认值、定时/随机/双栈、Salamander、业务 UDP 和60秒组合验收仍属 N6。

### 保留的环境失败与修正

首轮 APK fetch 未更新索引，得到空安装包集合。Apple Container 1.4.1 的 `exec` 本轮还出现 guest 非零而 CLI 返回0；新 harness 除检查 CLI 外，读取自己的 guest 状态标记，避免误把安装失败当成功。准备 VM 现在显式更新官方 APK 索引并 fetch 依赖；隔离运行 VM 使用枚举的 APK 离线安装，仍做官方签名校验，不使用 `--allow-untrusted`。

随后官方服务启动但握手超时。单端口与关闭 GSO 对照仍失败，接收上限不是原因。容器内包头/系统调用诊断显示：Hysteria 试图发送1280-byte UDP Initial，`sendmsg` 返回 **EMSGSIZE**；peer 的 `eth0` MTU 为1280，连 IP/UDP 头后的报文超过它。宿主到专用网桥的路径 MTU 为1500。仅在本次拥有的 VM 将 `eth0` 调成1500后，单连接数据例子通过，再完成真实 hop。没有放宽 VCore 接收预算、关闭证书验证、修改宿主网络或第三方。临时 tracing 依赖、包长度日志、tcpdump/strace 进程和包已从最终脚本移除；本地诊断证据保留。

对应 RED→GREEN：端口映射接口测试先因缺 `attach_mapped` 失败；原生 harness 在未实现 rebind 时能完成普通回显，但因 `rebinds` 缺失失败；真正切换后才通过。环境失败不改称上述功能 RED，也不被最后 PASS 覆盖。

## Xray：VLESS / XHTTP stream-one / H3

Mihomo 的 XHTTP listener 仅在 TCP 上接 H1/H2，没有接 H3 UDP listener，因此此入口使用 Xray；SOCKS5 上游仍用官方 Mihomo。[Mihomo listener](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/listener/sing_vless/server.go#L207-L283)。Clash-RS 可参考 VLESS framing 与 HY2 的 h3 用法，但其 transport 枚举不含 XHTTP，本例以 [Xray stream-one handler](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/splithttp/hub.go#L335-L377)为 wire 依据。

原生配置为 VLESS 无 flow / decryption=none，`network=xhttp`、TLS ALPN仅 `[h3]`、`mode=stream-one`。客户端通过同一个受控 Quinn adapter 发一条 POST，使用默认范围内的 Referer padding 和原始 VLESS body，不加 gRPC 消息帧。请求/响应同时驱动；VLESS response 与 greeting 在首段业务上传前检查；响应头最多257 bytes、完整响应有界，HTTP header section 上限8192 bytes。H3 sender 和 driver 均持有至业务完成，然后显式清理。

| Case | 结果 / 独立断言 |
| --- | --- |
| `xray-h3-direct` | PASS：HTTP200 + 有效 VLESS response；服务器先发；64 KiB byte-exact echo、尾部和服务器 EOF；目标 accept=1；protect=1 |
| `xray-h3-socks5-udp` | PASS：同上，经已有 SOCKS5 UDP ASSOCIATE；TCP control / UDP 共 protect=2 |
| `xray-h3-wrong-name` | PASS：`tls_rejected`，目标连接/字节=0 |
| `xray-h3-wrong-path` | PASS：HTTP404，目标连接/字节=0 |
| `xray-h3-wrong-uuid` | PASS：**HTTP200 但无有效 VLESS response**，`vless_rejected`，目标连接/字节=0；不是把200当认证成功 |
| `xray-h3-reject-direct` | PASS：第1次 protect 拒绝，数据报发送/目标连接=0 |
| `xray-h3-reject-socks-control` | PASS：control protect 拒绝，未创建 Quinn driver，目标连接=0 |
| `xray-h3-reject-socks-udp` | PASS：第2次 protect 拒绝，UDP 发送/目标连接=0 |

正常8项均检查队列上界、H3 task 完成、endpoint idle、owner join、停止后不能发送；最大停止耗时约119.886 ms。仅主机合成 protect 回调，不代表 Android VPN 或 Windows 真机。

### 附加半关闭诊断 FAIL，不签收完整 N5

`native_h3.py --half-close` 在正常8项后追加第9项：上传完立即表达 HTTP request body EOF，继续等目标在 TCP EOF 后发送的尾包。实测 HTTP200/VLESS response 正常、目标收到65,536 bytes；客户端收到 **65,552 / 65,566 bytes**（含16-byte greeting），payload 前缀完整，**缺14-byte尾部**。停止清理仍通过。首次失败只有 mismatch分类，增加字节计数后复现，原结果分别保留。

此处只证明该 native stream-one/EOF 组合未通过，不泛化为所有 Xray transport 不支持半关闭。原生 handler 将上下行交给 `splitConn`，其 Close 同时关闭 reader/writer；完整关闭传播仍需 N5 继续定位/验证。[Xray splitConn](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/splithttp/connection.go#L24-L38)。未修改第三方、没有延迟/吞掉 FIN 或删掉正式目标；诊断命令仍以非零退出。普通正例在收到完整响应后才关闭发送方向，**不是半关闭证据**。先前官方 Hysteria 半关闭 FAIL 仍见[历史记录](N0-hysteria2.md)。

N0-D 要求的是 H3 入口可用；X03 完整 mode、TLS/REALITY、下载腿、池、UDP codec 和 N5 的 EOF/Stop 全集仍未签收。

## 回归、编译和基线数字

本轮实际执行：

| 检查 | 结果 |
| --- | --- |
| 独立 spike `cargo test --locked` | 6/6 PASS：新增真实 UDP 端口映射/来源归一，加原5项 |
| 独立 spike fmt / all-targets clippy `-D warnings` | PASS；作为路径依赖的精简 VCore 保留既有97条 unused/dead-code warnings |
| iOS arm64 `cargo check --locked --all-targets` | PASS，非真机运行 |
| Android arm64 同一 check | PASS，NDK28.2.13676358 / API24；非真机 protect |
| 原 datagram workspace 回归 | 4/4 PASS |
| 主 TLS 来源审计 | PASS：唯一既有 rustls、ring、官方 tokio-rustls；SS 局部例外不变 |
| 既有脚本离线单元测试 | 42/42 PASS；不冒称新原生 runner 的故障注入矩阵已完成 |
| 三个 Python harness lint/format、diff空白检查 | PASS |
| 原 HY2 `run.py --native-hysteria` | 8/8 PASS：Mihomo DIRECT/SOCKS5 UDP、认证/名称/三处 protect，原生 UDP=false/TCP |

本轮 HY2 无显式速率限制基线：Mihomo DIRECT / SOCKS5 / 原生 UDP-disabled 的64KiB回显分别约2.513 / 4.010 / 3.560 ms，官方 hop 约3.927 ms。Xray DIRECT / SOCKS5 响应完整结束约1004 / 1007 ms，包含 EOF 等待；其 setup 计时从 QUIC handshake 后开始，不能与 HY2 handshake+auth计时横比。以上均 Debug、本机/VM、单次观察；只证明控制器公开 factory被安装，不证明限速、Brutal或N6吞吐门槛。N1仍需冻结正式负载/窗口/容差。

没有重跑生产完整 Debug/Release、Windows/其他架构、长测、物理设备、远端CI、发布或安装包。完整复现入口见[实验 README](../../../tests/protocols/spikes/hysteria2/README.md)；编译命令沿用[既有 Hysteria报告](N0-hysteria2.md#验证命令与证据)，本轮输出前缀为 `target/interop/n0-quic-entry-*`。

## 持久摘要与清理边界

以下日志含本机路径、合成目的地址等，只在忽略的 target 中保留；此文为可提交摘要。报告中的 `inputs` 将源码/锁/脚本与实际结果绑定，最终提交后再次核对。

| 原始证据（相对 `target/interop/`） | SHA-256 |
| --- | --- |
| `n0-hysteria-hop/20260923T031319Z-12109e7e/result.json`，hop PASS | `56f0a7dfb98d82e463882655961c45f4aec25b0fb8161daaa97b3274bd91bec0` |
| `n0-hysteria-hop/20260923T031218Z-07f51fa5/result.json`，新socket拒绝 PASS | `f46e229c7eafbd397637581f6b5c61c7eb0ddf7395f90e7f25bad91da41cf8eb` |
| `n0-xray-h3/20260923T031339Z-011ea514/result.json`，正常8项 PASS | `b1c382fcd49a2495272f5c05a75c20aad98493e339ebc6fc5ea4e8563ffcc84f` |
| `n0-xray-h3/20260923T031022Z-4b694d8e/result.json`，半关闭诊断 FAIL | `145c1b798dea01961591c3c374629f0236c4fee8ed5b7642ecabd5f060d95afe` |
| `n0-hysteria2/result.json`，既有8项回归 PASS | `06fec9d46360069530af43b88c10cfd7479ec7b482023b4c82cbb229e501c711` |
| `n0-hysteria-hop/20260923T025913Z-2cb45273/send.log`，MTU诊断 EMSGSIZE | `51a454c460424e5350a2178e07b765675058b1e3f95709711d5026abee565420` |

准备 VM只下载官方依赖，运行 VM只在既有专用 host-only 网络内；不发布宿主端口。所有清理使用本次唯一命名/带标签的所属实例，不全局 stop/prune。原生规则随正常进程退出删除，观察表显式删除，两个 VM验证已移除；证书/配置由私有临时目录回收。保留已拥有的网络、固定镜像、官方二进制和脱敏证据。**没有修改宿主路由、DNS、防火墙、VPN、第三方源码或其他仓库；没有 push。**
