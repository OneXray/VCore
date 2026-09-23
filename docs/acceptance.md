# VCore 验收矩阵

本文记录验证范围与发布门禁，不把历史开发包结果当作当前 release 保证。
源码 revision、lockfile/产物 hash、签名、环境、命令和结果保存在当次 PR 或发布记录中。

## 证据规则

- 主机测试、交叉编译、模拟器和虚拟网络不能替代对应物理 TUN 或安装包证据。
- x64 模拟不能替代原生 x64；VPN 双栈接口不能替代真实物理 IPv6。
- 外网吞吐与进程间通信基准各自独立，不能相互替代。
- 未执行或缺少可复现记录的项目保持未验证；不从旧产物继承通过结论。
- 记录不得包含 secret、UUID、密钥、完整用户配置或私有目标信息。

## 自动化覆盖

下一版协议从独立 N0 基线开始，进度见 [N0 基线与可行性门禁](acceptance/next-protocols/N0.md)。2026-09-22/23 的新基线与接口实验不继承本页历史通过状态，也不代表新五协议或平台交付已经完成。混合 REALITY 的自有 fork 局部实验已通过；fork 依赖已升级，但 VCore 生产仍未启用混合组；[N0-D QUIC 原生入口](acceptance/next-protocols/N0-quic-entries.md)已验证，原生半关闭失败和 N0 其余门禁仍保留。

2026-09-23 追加的 [XHTTP 关闭对齐](acceptance/next-protocols/XHTTP-close.md)修正了既有生产 H2 的三种模式：应用上传 EOF 结束整条逻辑连接，不再保留下行半关闭。独立 H3 实验与官方 Mihomo 客户端完成同一 Xray 对端的行为对照；H3 仍未接入生产，历史 request-EOF/尾包失败不改记为成功，也不再作为 XHTTP 的客户端契约。

同日 [N0-B 公共流接口实验](acceptance/next-protocols/N0-stream.md)完成TLS/普通WS/gRPC的注入IO、取消回收与关闭差分：12项Debug/Release测试、42项官方Mihomo检查及Apple/Android交叉检查通过。没有新增生产功能或依赖；Windows、真机和完整N0仍未签收。

[N1 h2 补丁升级](acceptance/next-protocols/N1-h2.md)将生产和流实验的 h2 更新至官方稳定版0.4.19，修复已复现的 END_STREAM 后 RST 丢失完整响应问题。关闭回归、旧协议扩展互通和流实验重跑通过；这是 N1 前置子包，不代表完整 N1 或全依赖升级完成。

[N1 依赖基线进度](acceptance/next-protocols/N1-dependencies.md)记录最新稳定版审计及依赖来源OneXray/rustls。获准将0.23.45同步结果推送到正式依赖分支后，VCore与四个实验工程已接入新版fork及官方tokio-rustls0.26.5；新版验证见[N1 TLS接入](acceptance/next-protocols/N1-tls.md)，与较早仅修改地址的证据分开记录。ring、classic REALITY、API v5/schema14均不变。

[N1 基础与实验依赖更新](acceptance/next-protocols/N1-foundation-dependencies.md)继续升级基础库、smoltcp、WS/HPKE实验和兼容补丁锁，记录已批准的Windows SDK配套例外。全Debug/Release、全目标Clippy、真实对端回归和Apple/Android构建通过；不抵扣完整N1、新协议、真机或Windows原生门禁。

当前 source/tests 覆盖：

- Invoke API v5、单实例生命周期、Debug/Release 运行时线程重入拒绝、panic 与同步清理；
- schema revision 14、IPv6、严格 YAML、节点 / `select` 组上游混合 DAG 和 node-only 测速；
- 组上游与路由的共享选择、SOCKS5 UDP 建链快照、潜在 DIRECT 首跳准备、独立下载端点和深图回收；
- HTTP 本机 / 认证共享、双栈监听回滚、逐请求认证与分发、Keep-Alive / 正文定界、CONNECT / Upgrade、10 MiB 双向摘要与活动连接 Stop；
- SOCKS5 入站认证、三类目标、半关闭、TCP 授权 UDP、源端口学习/隔离、IPv6 作用域固定端口/学习端口匹配与跨接口隔离、过期/满队列/慢上游取消及纯 SOCKS5 Controller（作用域匹配为合成地址测试，不代表物理 LAN 验证）；
- VLESS/XHTTP/TLS/REALITY、SOCKS5、AnyTLS、代理链、DNS、规则、GeoData 和 HTTP/TLS/QUIC 嗅探；
- AnyTLS 有序 ALPN、WebPKI / 跳过 / 叶与非叶 pin、TLS 1.2/1.3 伪造签名拒绝、节点间策略隔离和精确恢复票据预算；
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

| 能力 | 自动化 | 外部进程互操作 | 物理 TUN / 安装包 |
| --- | --- | --- | --- |
| VLESS + XHTTP + TLS/REALITY | 已覆盖 | mihomo stream-one/REALITY 有受控组合证据；其他模式仍待迁移；历史 Xray harness 保留 | Windows ARM64 开发包已覆盖 |
| SOCKS5 CONNECT / UDP ASSOCIATE 出站 | 已覆盖 | mihomo TCP/UDP、IPv4/IPv6 | Windows ARM64 历史开发包已覆盖 |
| SOCKS5 CONNECT / TCP 授权 UDP 入站 | 已覆盖 | mihomo 双向 TCP/UDP、IPv4/IPv6 | 真实 LAN / 物理 IPv6 未验证 |
| AnyTLS TCP / UoT v2、ALPN / 证书策略 | 已覆盖 | mihomo 公开 YAML，TCP/UoT IPv4/IPv6、测速及证书拒绝 | 旧能力有 Windows ARM64 历史开发包记录；新 TLS 字段未做设备验证 |
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

## rustls REALITY 发布

REALITY 线上向量、普通 TLS、错误 key/short ID、HRR、并发和取消有自动化覆盖。
正式发布仍需：

- 无相邻 rustls 目录的干净检出执行 locked tests；
- 使用同一 lockfile 完成 Apple、Android、Windows 构建；
- 保存 VCore/rustls revision、toolchain、目标架构、lockfile/产物 SHA-256、
  签名安装与当次物理设备/网络/失败关闭矩阵。

详细要求见 [rustls 发布契约](rustls-reality-release.md)。
没有当次证据的项目不得写成发布保证。
