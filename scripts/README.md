# VCore Scripts

本目录是由 `uv` 管理的 Python 工程，统一提供 VCore 平台构建、静态检查和可选互操作 demo。所有命令都从 VCore 仓库根目录执行：

```bash
uv sync --project scripts --locked
uv run --project scripts --locked vcore-scripts --help
```

运行时只使用 Python 标准库；`ruff` 是由 `uv.lock` 固定的开发依赖。

Mihomo 下载产物统一放在 VCore 仓库内、被 Git 忽略的 `target/interop/`。测试脚本不推断项目外目录布局；历史专用入口需要外部源码目录或配置文件时，必须显式传入。旧 Xray 二进制仍通过 `XRAY_BIN` 或标准 `PATH` 定位。

## 平台构建

```bash
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows
```

- Apple 命令只能在 macOS 运行，输出 `dist/apple/LibVCore.xcframework`。
- Android 命令在 macOS/Linux 运行，默认输出 `dist/android/{arm64-v8a,x86_64}/libvcore.so`。
- Windows 命令只能在已安装 Visual Studio C++ 工具的 Windows 运行；命令从系统注册表读取原生 ARM64/x64 处理器架构，通过 `vswhere` 加载对应的 MSVC 环境，验证三项 PE 的 machine type 后输出 `dist/windows/<architecture>` 下的 DLL、Provider Host、Session Host 和记录 package integration revision、架构及三项 SHA-256 的 `vcore-windows-artifacts.json`。
- 所有构建都使用 `Cargo.lock`，并检查产物内的 Invoke API v5/config revision 14 身份。
- 标准 Apple、Android、Windows 构建显式包含两种客户端入站和四种出站，不依赖 `ffi` / `tun` 的传递 feature 来隐式补齐；不包含 `interop-test`。Apple/Android 的自定义 `VCORE_FEATURES` 不得将测试信任注入用于交付。

Apple/Android 继续接受现有环境变量：

| 变量 | 默认值 |
| --- | --- |
| `VCORE_BUILD_PROFILE` | `release`，也可为 `debug` |
| `VCORE_FEATURES` | `ffi,tun,inbound-http,inbound-socks5,outbound-anytls,outbound-socks5,outbound-shadowsocks,outbound-vless` |
| `VCORE_APPLE_DIST_DIR` | `dist/apple` |
| `VCORE_IOS_DEPLOYMENT_TARGET` | `13.0` |
| `VCORE_MACOS_DEPLOYMENT_TARGET` | `10.15` |
| `VCORE_ANDROID_NDK_VERSION` | `28.2.13676358` |
| `VCORE_ANDROID_API` | `24` |
| `VCORE_ANDROID_TARGETS` | `aarch64-linux-android x86_64-linux-android` |
| `VCORE_ANDROID_OUTPUT_DIR` | `dist/android` |

Android NDK 优先读取 `ANDROID_NDK_HOME`，否则使用 `$ANDROID_HOME/ndk/<version>`。

`.github/workflows/test.yml` 配置 macOS 的完整/精简协议 feature 检查，以及 Apple 五目标、Android 两 ABI、原生 Windows ARM64/x64 的 Release 构建和短期未签名产物归档。Android job 显式使用 NDK `28.2.13676358`，避免继承 runner 的另一默认版本；Linux runner 只作 Android 交叉构建，不意味着 VCore 支持 Linux 运行。runner 标签依据 [GitHub 官方清单](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。工作流配置不等于已执行的 CI 或设备验收，通过记录仍见 [验收矩阵](../docs/acceptance.md)。

## 检查

```bash
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

`c-header` 在 macOS 使用 `xcrun clang/clang++`，其他平台使用 `PATH` 中的 `clang/clang++`。`tls-dependencies` 直接读取 `cargo metadata`，验证唯一的 OneXray/rustls 0.23.45 来自 GitHub `vcore/reality-0.23` 分支、官方 tokio-rustls 0.26.5、registry ring，并禁止 Watfaq 来源和 TLS 的 AWS-LC/FIPS provider。AWS-LC 仅允许出现在锁定官方 Shadowsocks 1.25.0 → registry shadowsocks-crypto 0.8.0 → aws-lc-rs → aws-lc-sys 链；额外使用方、非官方来源、重复版本和 FIPS 包均失败。该局部例外不更换 TLS/REALITY 的 ring provider。

## Windows tun2socks demo

后续协议互通统一使用下节的 mihomo harness。已有 Xray / anytls-go 脚本及本节的 Windows demo 保留为历史、显式专用入口，不作为新一轮协议互通的默认对端。

```powershell
uv run --project scripts --locked vcore-scripts demo windows-tun2socks C:\path\to\xray-config.json --xray-source C:\path\to\Xray-core
```

该命令仍是显式互操作验收：它临时构建 `--xray-source` 指定的 checkout，使用已安装的 `VCore.UwpDemo.Dev` 示例 package，并在结束时停止测试 VPN 和删除临时文件。不再读取约定的兄弟目录或用户主目录配置；源配置不会被修改。历史 anytls-go 入口同样要求显式设置 `ANYTLS_GO_DIR`。真实配置、凭据和临时访问日志不得提交。

## mihomo 协议互通

使用独立 mihomo 进程验证公开 YAML → Invoke prepare/start → 实际数据路径。HTTP forward、分块上传、CONNECT 预读和 WebSocket Upgrade 各自验证以下两条路径，共 8 个场景：

1. VCore HTTP 入站 → VCore SOCKS5 出站 → mihomo → 本机 origin。
2. mihomo HTTP 入站 → mihomo HTTP 出站 → VCore CONNECT → 本机 origin。

SOCKS5 另覆盖 CONNECT / UDP ASSOCIATE × IPv4 / IPv6 × 两个方向，共 8 个场景：VCore SOCKS5 入站 → VCore SOCKS5 出站 → mihomo，以及 mihomo SOCKS5 入站 → mihomo SOCKS5 出站 → VCore SOCKS5 入站。UDP 控制连接、端口学习与真实远端回包一并验证。

AnyTLS 使用同一 mihomo 的独立 TLS listener：跳过常规验证、叶 pin、叶 pin + skip + 有序 ALPN 三种公开配置各覆盖 TCP/UoT × IPv4/IPv6 和独立 `measureDelay`，另检查默认不可信证书与错误 pin 的拒绝，共 17 项。证书由 PATH 中的 OpenSSL/LibreSSL 临时生成（RSA 2048，仅测试），因此需要可用的 `openssl` 命令；密钥和证书放在临时 mihomo dataDir，结束即清理。VCore 不开启测试信任注入或 `listeners` 配置。

SS 使用三个独立 2022 listener 和合成 PSK，检查 TCP/UDP × IPv4/IPv6/域名及服务器先发，随后检查具体 SOCKS5 上游和嵌套组 / DIRECT 路径。域名仅使用 mihomo 测试 hosts 映射，不访问外网。SS 对端与首跳在不同进程，保留 mihomo 回环保护。

该 mihomo 服务端不暴露 EIH 用户配置；`tests/mihomo/eih.rs` 的受控中继独立校验并剥离 AES 的 1/2 层身份头，业务密文仍交给 mihomo，明确区别于原生 EIH 服务端。错误身份/密钥/算法有 TCP/UDP 负例。另通过公开 Invoke 验证各算法的活动 TCP/UDP Stop、绑定失败回滚和独立测速，macOS 记录清理前后的 `/dev/fd` 数量；这些不替代完整压力与物理设备验收。

```bash
# 可先单独下载当前宿主平台的官方最新稳定版：
uv run --project scripts --locked vcore-scripts download mihomo
# 互通入口也会自动下载官方最新稳定版：
uv run --project scripts --locked vcore-scripts check mihomo-interop
# 等价的 shell 入口：
bash tests/run_mihomo_interop.sh
# 跨协议组合、Controller 切组、合成 utun 和重复生命周期：
uv run --project scripts --locked vcore-scripts check mihomo-interop --extended
# 30 分钟持续测试（单次通过不等于完整阶段签收，见下方限制）：
uv run --project scripts --locked vcore-scripts check mihomo-interop --extended --soak-seconds 1800
# macOS 推荐：上游和末端对端使用 Apple Container 独立 Linux VM：
uv run --project scripts --locked vcore-scripts check mihomo-interop \
  --container --extended --soak-seconds 1800
```

对端只使用 [MetaCubeX/mihomo 官方 Releases](https://github.com/MetaCubeX/mihomo/releases/latest) 的预编译包，不调用 Go 编译或读取研究 checkout。每次下载命令或互通运行都从固定的 [latest/download/version.txt](https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt) 下载小型版本文件，仅用于拼接官方带版本号的资产文件名；不调用 GitHub API、不固定版本。单次互通的原生与容器对端使用同一次解析的下载地址，避免下载期间发布新版本导致混用。实际运行版本由各自二进制的 `-v` 输出确认。

每次通过 HTTPS 重新下载并解压到仓库内的 `target/interop/mihomo/<release>/<平台>/`，不以已有文件跳过下载。限制下载大小、解压大小和等待时间，完成后原子替换程序；下载或解压失败直接终止，不使用旧缓存或源码编译兜底。输出压缩包和程序的 SHA-256 供验收留证，但不将本地计算的摘要称为官方摘要校验。宿主支持 macOS / Windows / Linux 的 ARM64 与 x86_64 产物选择，Linux 下载支持仅用于测试对端，不改变 VCore 的平台支持范围。

`download mihomo --target linux-arm64` 可单独准备容器程序；省略 `--target` 自动识别宿主。旧 `--binary`、`--container-binary` 和 `VCORE_MIHOMO_BIN` 不再用于选择对端，容器模式改用 `--container`。下载需要网络；普通 Python 单元测试使用离线夹具，不下载程序或启动对端。

验收时记录实际 release tag、官方 asset URL、压缩包 SHA-256 和 harness 输出的程序版本 / SHA-256，不能只依赖版本字符串。最新版会变化，每次验收单独留证；旧的本地编译版本、hash 和历史通过结果仍保留为当时证据，不转记为官方最新版的验证。下载包不加入 VCore 的生产依赖。

默认模式四个对端仅开放本机回环，使用临时测试凭据、配置和 dataDir；origin 使用 IPv4/IPv6 回环，不启用系统 TUN，不改变系统代理或现有 mihomo 服务。容器模式的边界见下节。就绪期限 10 秒、socket I/O 与 Invoke 清理看门狗 5 秒、测试进程总期限 `300 + soak-seconds` 秒；退出或测试失败时停止并等待全部对端，必要时在 5 秒后强制结束，再移除本次临时目录。Invoke Stop 返回后检查 VCore TCP/UDP 端口可重绑。

`--extended` 增加 VLESS/XHTTP stream-one/REALITY 对端，需要 OpenSSL 3 的 TLS 1.3/X25519 服务端能力；可用 `OPENSSL_BIN` 指定路径，或从常见 Homebrew 路径及 PATH 查找。伪装站点绑定回环（容器模式绑定专用 host-only bridge），证书和密钥由夹具生成，不启用测试信任注入。SOCKS5、AnyTLS、SS（AES-128 代表算法）、VLESS 的两跳 TCP/UDP 组合重复 8 轮，另检查真实 Controller 切组、HTTP-only 宿主生命周期、具体链 / DIRECT 测速快照与批量结果顺序，以及 100 次活动 Stop/失败回滚/独立测速。Apple 主机使用 UnixDatagram 对模拟 utun 帧入口，不创建系统接口，不能计为物理 TUN 验收。自建 mihomo 的带认证 Controller 只负责用例间清理自身连接，不接触已有服务。

macOS 扩展入口另在同一 Running Session 中执行 100 次 32-flow 断连重建（120 秒看门狗），读取系统公开 `malloc_zone_statistics` 的在用堆字节数，并记录 RSS / FD 与 Stop 后状态。此采样不读取或输出分配内容、不改分配器；用于区分活对象增长和驻留内存现象，仍需人工审查趋势，不能仅凭进程退出成功判定没有泄漏。

`--soak-seconds` 必须与 `--extended` 一起使用，范围 0–7200；非零时持续保持 16 TCP + 16 UDP flow，每秒切组、每分钟断开自建对端的连接并显式建立新客户端，逐包校验来源与负载，记录 RSS/FD/延迟。短于 1800 秒的运行只验证夹具，不能替代长测。当前资源采样仅在 macOS 主机执行；测试内含节流，输出的负载速率不是最大吞吐基准。

测试隔离：入口使用跨进程非阻塞锁，另一套 harness 在启动服务前失败；Python 同时预留回环 TCP/UDP 的 IPv4、IPv6 端口，IPv4-only 对端启动后保留 IPv6 guard。Rust 测试客户端、origin 和 EIH 中继也持有另一地址族的 UDP guard，直到对应 socket 释放。所有 IPv6 guard 为 v6-only，不启用地址复用，不关闭 IPv6 测试；仅在流量启动前有界重选占用端口，不重试业务包。32 个活动 flow 的进程 FD 比原夹具增加 32，来自 UDP 客户端/origin 的测试 guard，结束后仍必须回到空闲基线。第三方源码及 VCore 生产 socket 创建策略不因该隔离改动而改变。

历史失败与当前门槛：2026-09-17 的首次 1800 秒长测约 8 分半后出现 UDP 来源异常。该 macOS 环境独立复现了 IPv6 双栈 UDP 自动端口与 IPv4 socket 同号、回包进入无关 IPv4 socket 的现象；并行短测也出现 UDP 超时，但未保留完整 socket 映射，不能把两次失败都断言为已逐跳证明的同一原因。端口隔离后一次完整 30 分钟通过，FD 回到 6；随后加入的 100 次快速重建检查两次 FAIL，第二次在第 11 轮同时捕获 mihomo 的回环拒绝日志和自建进程 UDP 映射：AnyTLS 的来源端口与同一 mihomo 的另一个 UDP 出口端口同号，触发按来源端口匹配的保护。保护测试端点不能约束所有内部自动端口，清理用例间连接也不能排除同轮活动流之间的同号端口。首次快速重建的回包超时未获得同等根因证据，单独保留。

UDP 失败时，macOS 夹具在退出前用有界 `lsof` 采样，仅检查本测试进程和 Python 入口提供的自建本机对端 PID，不读取负载、不检查无关进程；容器进程不伪装成 macOS PID，失败时另读取本次容器日志。来源校验、mihomo 回环保护及所有原始失败记录保留，不重试业务包来规避失败。

默认 Cargo 测试会将外部互通标记 ignored，必须显式执行 harness 才算有外部对端证据。2026-09-17 的 Apple Container 组合/资源验收结果见下节及 [验收矩阵](../docs/acceptance.md)；VLESS 的其他模式、设备和安装包结果不能从当前夹具推导，也不把旧对端或同库回环结果改写为 mihomo 结果。

### Apple Container 对端

需要已安装并运行的 Apple `container`（历史实际使用 1.4.1，macOS 27 / arm64）。先准备一次专用 host-only 网络和固定摘要的基础镜像；mihomo Linux ARM64 程序由脚本从官方最新稳定版下载。若同名网络已存在，先检查其 `mode=hostOnly` 和 `purpose=vcore-mihomo-interop` 标签，不覆盖其他网络：

```bash
container network inspect vcore-mihomo-interop
# 仅在该网络不存在时创建：
container network create --internal --label purpose=vcore-mihomo-interop vcore-mihomo-interop
container image pull --arch arm64 docker.io/library/alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
uv run --project scripts --locked vcore-scripts download mihomo --target linux-arm64
uv run --project scripts --locked vcore-scripts check mihomo-interop --container --extended
```

下述历史验收使用的本地编译源码 revision 为 `ab405bad5beeeac8b003bb01f60f134f6df54471`，Go 1.27.1、未添加 build tags，Linux 程序 SHA-256 为 `eb35562be501dd6cd9e1f8bdf3ba43162bf6abb6a3946cd1f1ec0511462feab2`，不是当前官方下载产物的 hash。当前 `--container` 自动获取同一官方 release 的原生与 Linux ARM64 程序；缺少基础镜像、网络或下载/解压失败时终止，不降级到本机、不回退旧版本。

- 首跳与末跳分别在两个 Linux VM 中，每个 1 CPU / 256 MiB；只读根和夹具挂载，临时可写 dataDir。直接访问隔离网络 IP，不发布宿主端口，不配置系统 DNS/PF、代理或 TUN，不关闭 mihomo 回环保护。
- origin 和 REALITY 伪装站点只绑定该 host-only bridge 的地址，保留 IPv4 / IPv6 数据校验；启动时发现实际地址，不硬编码 DHCP 或 SLAAC 地址。排除尚处于 DAD、重复或失效状态的 IPv6 地址，再验证可绑定及两个容器可达，全部发生在业务测试前。域名 origin 和末端节点分别映射，避免把容器回环当成宿主。
- 反向 HTTP/SOCKS5 入站测试仍使用两个原生 mihomo 进程，VCore 保持仅回环监听和原有认证。这不是四个对端全容器化，也不是 LAN 共享或物理 IPv6 验收。
- 每次分配唯一容器名；成功、断言失败、超时或启动失败均只清理本次已创建且带标签的容器及临时目录。保留专用网络、缓存镜像和仓库内下载产物，不执行全局 stop/prune。

网络行为依据 [Apple Container 1.4.1 networking](https://github.com/apple/container/blob/1.4.1/docs/networking.md)。虚拟网络通过只证明该受控环境，不等于已经修复 macOS 同内核碰撞或第三方实现。

本次完整入口通过全部基础/扩展检查、100 次快速 32-flow 重建和 1800 秒长测：1,734 次切组、29 次断连重建、420,476,672 字节校验，FD 为 6 → 195 → 6。RSS 活动起始 / 峰值 / 结束 / Stop 后为 19,248 / 21,984 / 19,184 / 18,896 KiB；多次 `heap --noContent` 采样的存活分配约 2,109–2,127 个、4.90–4.91 MB，未随 RSS 同步累积。堆诊断会扰动延迟（最大 wave 441 ms），节流负载速率不是吞吐基准；32-flow 初次 / 末次建连为 204 / 153 ms。容器、原生对端与临时配置清理完成，专用网络及镜像缓存保留。最初适配中的固定回环断言、IPv6 地址未就绪，以及此前所有本机失败均保留，不用最终通过覆盖历史。
