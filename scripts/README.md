# VCore Scripts

本目录是由 `uv` 管理的 Python 工程，统一提供 VCore 平台构建、静态检查和可选互操作 demo。所有命令都从 VCore 仓库根目录执行：

```bash
uv sync --project scripts --locked
uv run --project scripts --locked vcore-scripts --help
```

运行时只使用 Python 标准库；`ruff` 是由 `uv.lock` 固定的开发依赖。

所有后续服务端测试遵守[服务端测试隔离规则](../docs/testing-isolation.md)：协议对端、测试原站和对照客户端的服务入口均在隔离容器中运行。以下历史入口未完成全链路容器化时只能作为历史说明，不能直接运行或回退到宿主服务端；旧 `--container` 不自动代表原站也已隔离。

Mihomo 下载产物统一放在 VCore 仓库内、被 Git 忽略的 `target/interop/`。测试脚本不推断项目外目录布局；历史专用入口需要外部源码目录或配置文件时，必须显式传入。旧 Xray 二进制仍通过 `XRAY_BIN` 或标准 `PATH` 定位。

## 平台构建

```bash
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows
```

- Apple 命令只能在 macOS 运行，输出 `dist/apple/LibVCore.xcframework`。
- Android 命令在 macOS/Linux 运行，默认输出 `dist/android/{arm64-v8a,x86_64}/libvcore.so` 及同 ABI 的 `libc++_shared.so`；宿主必须一起打包，不能假定 Android 系统提供该 C++ runtime。
- Windows 命令只能在已安装 Visual Studio C++ 工具的 Windows 运行；命令从系统注册表读取原生 ARM64/x64 处理器架构，通过 `vswhere` 加载对应的 MSVC 环境，验证三项 PE 的 machine type 后输出 `dist/windows/<architecture>` 下的 DLL、Provider Host、Session Host 和记录 package integration revision、架构及三项 SHA-256 的 `vcore-windows-artifacts.json`。
- 所有构建都使用 `Cargo.lock`，并检查产物内的 Invoke API v5/config revision 20 身份。
- 标准 Apple、Android、Windows 构建显式包含两种客户端入站和六种代理出站（含 VMess），不依赖 `ffi` / `tun` 的传递 feature 来隐式补齐；不包含 `interop-test`。Apple/Android 的自定义 `VCORE_FEATURES` 不得将测试信任注入用于交付。

Apple/Android 继续接受现有环境变量：

| 变量 | 默认值 |
| --- | --- |
| `VCORE_BUILD_PROFILE` | `release`，也可为 `debug` |
| `VCORE_FEATURES` | `ffi,tun,inbound-http,inbound-socks5,outbound-anytls,outbound-socks5,outbound-shadowsocks,outbound-trojan,outbound-vmess,outbound-vless` |
| `VCORE_APPLE_DIST_DIR` | `dist/apple` |
| `VCORE_IOS_DEPLOYMENT_TARGET` | `13.0` |
| `VCORE_MACOS_DEPLOYMENT_TARGET` | `10.15` |
| `VCORE_ANDROID_NDK_VERSION` | `28.2.13676358` |
| `VCORE_ANDROID_API` | `24` |
| `VCORE_ANDROID_TARGETS` | `aarch64-linux-android x86_64-linux-android` |
| `VCORE_ANDROID_OUTPUT_DIR` | `dist/android` |

Android NDK 优先读取 `ANDROID_NDK_HOME`，否则使用 `$ANDROID_HOME/ndk/<version>`。
本仓库的 `scripts/cmake/android.toolchain.cmake` 将 ABI/API 交给该 NDK 管理，避免
boring-sys 两次 CMake configure 时显式 clang 包装器被 NDK 替换而触发缓存重置。
Apple 的 module map 声明 `c++` 链接依赖；不使用模块的 C 宿主还需显式链接 `-lc++`。

`.github/workflows/test.yml` 配置 macOS 的完整/精简协议 feature 检查，以及 Apple 五目标、Android 两 ABI、原生 Windows ARM64/x64 的 Release 构建和短期未签名产物归档。Android job 显式使用 NDK `28.2.13676358`，避免继承 runner 的另一默认版本；Linux runner 只作 Android 交叉构建，不意味着 VCore 支持 Linux 运行。runner 标签依据 [GitHub 官方清单](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。工作流配置不等于已执行的 CI 或设备验收，通过记录仍见 [验收矩阵](../docs/acceptance.md)。

## 检查

```bash
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

`c-header` 在 macOS 使用 `xcrun clang/clang++`，其他平台使用 `PATH` 中的 `clang/clang++`。`tls-dependencies` 直接读取 `cargo metadata`，验证唯一的官方 crates.io rustls 0.23.45、tokio-rustls 0.26.5 和 registry ring；拒绝 rustls Git/path 覆盖，REALITY/AWS-LC/FIPS 必须关闭。boring/boring-sys/tokio-boring 5.2.0 必须来自同一个已批准的 Git revision，检查实际依赖边、REALITY/profile feature，并禁止 FIPS/RPK/PQ 实验模式和 Watfaq 来源。AWS-LC 仅允许出现在锁定官方 Shadowsocks 1.25.0 → registry shadowsocks-crypto 0.8.0 → aws-lc-rs → aws-lc-sys 链；这个例外不作为 TLS provider 使用。完整边界见 [TLS 依赖](../docs/tls-dependencies.md)。

### TLS 指纹接线验证

```sh
cargo test --locked --all-features --lib security::
cargo test --locked --all-features --lib config::
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint target/interop/runs/<fresh-run>
```

`protocol_fingerprint` 复用容器化 VLESS 公共配置/数据面消费者，默认设置 `chrome120`，可用 `--client-fingerprint` 选择七个公开值。覆盖 AnyTLS、Trojan、VMess、VLESS TLS/REALITY、Vision、XHTTP、mTLS 和负例。不给 case ID 时执行 CF5 默认矩阵：`transports/` 46 项，再执行 `xhttp/` 11 项，汇总到 `fingerprint-results.json`。可在输出目录后给出 case ID 定向运行，定向结果保留 `vless-results.json` 布局。各子报告保留官方 latest 二进制、版本/hash、实际流量、来源身份和容器清理结果；不使用仓库外源码或宿主原站。关闭对照使用同名 Mihomo profile；只有 REALITY 的 `none` 对照因 Mihomo 依赖 uTLS 而用 `chrome`，该项仅比较关闭行为、不声称模板相同。平台发布仍有独立门禁。

默认矩阵包含 gRPC TLS 和 Vision REALITY 各 20 轮公共启停、20 轮资源归零检查，
每轮 Stop 当时检查，再静默 5 秒；阶段源码在一轮运行中不得修改。
XHTTP 补充项覆盖 H1/H2 × 三模式、下载腿继承/异模板/关闭/错误 pin，以及 H2 命名指纹上传 +
H3 关闭指纹下载。最后一项使用获准的官方 latest xcaddy/Caddy 构建，导入隔离容器，
H2/H3 TLS/mTLS 经同一个原生 Xray h2c handler，再由 Mihomo 解码 VLESS；不自制协议服务端。
原冻结清单 900 秒漏计上述扩大后的整套覆盖，CF5 单模板总预算修订为 3600 秒并记录实际耗时；
各单项超时、数据断言、20 轮及静默时间不变，不将超出旧预算的运行追记为旧门禁通过。

实际 VCore ClientHello 与独立参考比较、TLS1.2/1.3 的真实恢复/过期，以及真实节点工厂的
下载腿票据/mTLS 隔离另有纯内存门禁（不打开宿主监听器）：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_shape target/interop/runs/<fresh-run>
cargo test --locked --all-features --lib fingerprint_leg_tests
```

精选指纹的 `selected-v1` 增量基线使用独立入口：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --list
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --run-dir target/interop/runs/<fresh-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --check-run target/interop/runs/<reference-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint --help
```

基线入口每轮下载官方 latest Mihomo，在隔离容器中记录 116 组参考 ClientHello（包含
16 组 OpenSSL TLS-only 握手）。原始记录、来源、清理和结构检查均通过才返回
`BASELINE VERIFIED`；这不是 VCore 业务互通结果。`--case` 可重复用于定向采样，
部分选择不能签收 CF0。比较规则与后续冻结门禁见 [selected-v1](../tests/fingerprints/README.md)。
业务驱动的 `--client-fingerprint` 接受 `none/chrome/chrome120/firefox/firefox120/safari/safari16`。
七值映射四模板；未支持名称不会借用旧模板。单次运行仅签收选中的 profile 和 case，
不从别名或其他模板的 PASS 推导当前模板通过。

### 协议声明清单

N5 前置原生能力诊断（不是阶段签收）另有以下入口，输出目录必须是本仓库 `target/interop/runs/` 下尚不存在的直接子目录：

```sh
uv run --project scripts --locked vcore-scripts check xhttp-peers --run-dir target/interop/runs/<fresh-run>
uv run --project scripts --locked vcore-scripts check xhttp-peers --identities-only --run-dir target/interop/runs/<fresh-identity-run>
uv run --project scripts --locked vcore-scripts check xhttp-gateway --run-dir target/interop/runs/<fresh-gateway-run>
uv run --project scripts --locked vcore-scripts check xhttp-gateway --identities-only --run-dir target/interop/runs/<fresh-gateway-identities>
```

官方 Mihomo 客户端、Mihomo/Xray 服务端与原站均隔离容器化，guest MTU 显式 1500、不修改宿主或共享网络。普通探针区分 Xray 直接解码与 Xray XHTTP → 原生 Mihomo VLESS 分层解码；身份探针独立检查下载腿缺失/过期/错误 CA 证书。已确认的原生能力缺口保留 FAIL 并非零退出，详见 [N5 前置记录](../docs/acceptance/next-protocols/N5-progress.md)。69 字节探针不替代完整字段、负例、资源或 VCore 消费者验收。

`xhttp-gateway` 使用[明确批准的 xcaddy 构建例外](../docs/testing-isolation.md)：PATH 需有 Go 和官方最新稳定 xcaddy（可用 `go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest` 安装），每次通过官方 latest 重定向确认稳定版本，再 `xcaddy build latest` 编译 linux/arm64。生成源码/锁、构建日志/hash 和容器内版本留在该次目录；不查 API、不加插件、不改第三方、不改宿主 HOME。Mihomo/Xray 仍下载官方 latest 资产。网关仅终结 H3/mTLS 并以 h2c 转发到同一个原生 Xray XHTTP handler，不是两个 listener 模拟共享会话。

普通网关探针包含双向 10 MiB、server-first、整连接关闭、TCP/XUDP echo 和两腿身份负例。`--identities-only` 只运行小流量对照并读回原生 QUIC 证书错误码，另核对原站零连接；详细 trace 留在临时容器，不在大流量用例启用。认证生效与客户端及时返回错误是两个维度，超时仍 FAIL / 非零退出，不能把网关诊断当成 N5 验收入口。

`protocol-coverage --catalog-only`只检查本仓库`tests/protocols/fields.json`和`combinations.json`声明，也可用`--catalog-dir <directory>`指定副本。不读取清单所引用的源码、研究目录或URL，不下载或启动对端。必须显式选择`--catalog-only`或下面的`--run-dir`结果模式。

检查 schema-v1 的完整145字段/69组合家族ID、重复JSON键、字段/来源/对端/override引用、协议适用范围、阶段与子包归属、必要观察项/模式维度、负例拒绝阶段、原生未知项说明及64个有序上游组合声明。稳定ID的增删必须同时审查版本化清单及验证器契约，不能靠改自报数量绕过漏项。来源只接受无凭据/查询参数的HTTPS链接或无 `..` 的相对路径，不检查其内容或网络可用性。

有效清单退出0，stdout为JSON，`status: VALID`、`behavior_status: NOT RUN`；无效清单退出1、stderr只报告诊断，不输出JSON原文；缺少模式参数退出2。声明中不能写入PASS等运行结果。这个结果**不是145项字段或69项互通通过**，不解析条件说明或自动生成笛卡尔积。当前生产能力仍以`docs/config.yaml`为准。历史声明校验记录见[N1清单校验](../docs/acceptance/next-protocols/N1-catalogs.md)。

### 阶段执行与原始证据检查

```sh
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N1 --list
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N1 --case N1-QUIC
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N1 --protocol foundation --list
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N1 --preflight
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N1
uv run --project scripts --locked vcore-scripts check protocol-coverage --stage N1 --run-dir target/interop/runs/<run-id>
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N2
uv run --project scripts --locked vcore-scripts check protocol-coverage --stage N2 --run-dir target/interop/runs/<run-id>
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N3 --list
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N3 --preflight
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N3
uv run --project scripts --locked vcore-scripts check protocol-coverage --stage N3 --run-dir target/interop/runs/<run-id>
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N4 --list
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N4 --preflight
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N4
uv run --project scripts --locked vcore-scripts check protocol-coverage --stage N4 --run-dir target/interop/runs/<run-id>
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N5 --list
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N5 --preflight
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N5
uv run --project scripts --locked vcore-scripts check protocol-coverage --stage N5 --run-dir target/interop/runs/<run-id>
```

统一入口具有 N1 公共基础（21 组 required）、N2 Trojan（41 组 / 18 字段）、N3 VMess（117 组 / 30 字段）、N4 VLESS（145 组 / 39 字段）和 N5 XHTTP / sing-mux（416 组 / 57 字段）的独立清单。`cases.json` 逐组列出断言、字段关联、对端、期限和证据类型；`limits.json` 引用可执行边界 case，Rust 测试核对真实常量。未来阶段没有可执行 required 集合时非零返回 NOT RUN。N1/N2 的历史宿主服务入口未全部迁移，不得用于新的服务端验收；全容器阶段入口是 N3/N4/N5。阶段之间不继承 PASS。

N2三种传输分别执行真实Mihomo TCP/UDP、上游/组、HTTP/模拟TUN/DNS、外层IPv6、证书/路径负例和UDP隔离；公共Invoke生命周期、协议自有资源各20轮，每轮Stop返回即检查，再静默5秒。域名UDP因Mihomo listener缺口由Xray单独补验，自定义头/路径ED由V2Ray补验；失败与对端缓冲限制保留在[N2.2记录](../docs/acceptance/next-protocols/N2-tcp.md)。`fields.json`按row ID汇总，只有完整执行、原始事件和所有必需项通过才可签收；单独运行原生子工具用于开发定位，不替代统一门禁。

N3 公开 VMess 配置见 [VMess](../docs/vmess.md)。统一入口执行 AEAD/身份/重放、五种传输明文/TLS、三种 UDP 编码、HTTP/SOCKS/模拟 TUN、受控 DNS、外层 IPv6、上游/嵌套组、证书/ALPN/路径负例和来源隔离；TCP 与 gRPC 各执行 20 轮公共生命周期及 20 轮协议自有资源检查。Stop 返回即检查，再静默 5 秒。另包含 Debug/Release、独立/default feature、共享 XUDP/TLS/Trojan 回归、Apple 五目标和 Android 两 ABI 的生产构建。服务器、原站、上游入口均在独占 host-only 容器中；Mihomo 验 TCP/WS/gRPC，V2Ray 仅补 HTTP/H2/扩展 WS ED 缺口。

开发定位可单独调用原生子工具，并在目录参数后指定一个或多个 case ID；未指定时执行全部 wire/public case，但不包含统一入口的其他门禁，不能据此签收 N3：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess target/interop/runs/<new-native-run>
```

正常完整性与关闭行为分开验证，不再把所有非 XHTTP 传输的 EOF 后尾包作为统一门槛。旧 `protocol_vmess_close`、`protocol_vmess_udp_diagnostic` 宿主诊断入口已关闭并返回 BLOCKED；历史观察仍见 [N3 关闭行为记录](../docs/acceptance/next-protocols/N3-close-blocker.md)，不追改失败结果。

N4 配置见 [VLESS](../docs/vless.md)。136 组原生/公开消费者与 9 组本地门禁分别覆盖普通 TCP、WS/HTTPUpgrade、gRPC 调度/PING/节点池、HTTP/H2、标准 TLS/mTLS、经典 REALITY、Vision 及既有 XHTTP 双腿回归。Mihomo listener 优先，V2Ray 只补 HTTP/H2/扩展 WS ED；关闭对照客户端也运行在容器内。TCP、gRPC、Vision TLS/REALITY 各执行 20 轮公共生命周期及 20 轮自有资源检查，共 160 轮。Vision 有真实内层 TLS 1.3 direct 双向字节证据，TLS 1.2/非 TLS 为独立控制；不能用普通 HTTP 成功代替 direct。

关闭验证中 18 组使用相同组合的 Mihomo 客户端对照。WS + REALITY 的普通 WS、HTTPUpgrade 与 fast-open 三组单独标记为分层参照：VCore 仍连接真实 REALITY listener，Mihomo 客户端使用标准 TLS 的同种传输 listener 来提供关闭基线，因为其 WS 客户端分支尚未接入 REALITY。这不代表同组合差分通过；REALITY 认证及这些组合的正常数据由独立用例验证，原始对照失败保留。离线门禁另外对照原始组合清单，防止可执行清单遗漏已纳入的传输/安全类别。

N4 包含 Debug/Release、独立/default/生产 feature、共享 VMess/Trojan/TLS 回归及 Apple/Android 生产构建。开发定位可使用下列入口，只执行选中的原生/公开用例，不代替完整阶段：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vless_container \
  target/interop/runs/<new-native-run> N4-TCP-TLS-BASE
```

`protocol_vless` 提供按传输模式筛选的便捷入口，复用同一容器夹具。N4 不签收 N5 的 XHTTP 新功能，也不签收 N7 的高级安全；完整 VLESS 仍需后续阶段。

N5 的冻结清单为 416 组 required / 57 个字段（X01–X29、D01–D15/D27–D32、M01–M07）。七个本地门禁、406 个原生/公开路径及三个安全组分别记录；安全组内部为 112 项身份与双腿行为检查，不把组数与内部断言相加计算覆盖率。有限枚举逐项、耦合 HTTP 版本/安全/mode/下载分支显式覆盖；独立调节项按 pairwise 组合，不宣称无约束笛卡尔积。

H1/H2 以官方 Mihomo 为主；H3 用 Xray，V2Ray 补 HTTP/H2/自定义 ED 外层。非 Mihomo 传输需要 packetaddr/sing-mux 时明确接入独立 Mihomo decoder；H3 客户端身份由获准的最新 xcaddy/Caddy 网关验证，仍只有一个后端 XHTTP 会话 handler。SOCKS 首跳与最终 listener 分开容器，保留 Mihomo 回环保护。六个代表拓扑各执行 20 轮公共启停及 20 轮自有资源检查，共 240 轮，Stop 当时归零再静默 5 秒。关闭用官方 Mihomo 同模式客户端差分，不要求 EOF 后尾包。

N5 包含 Debug/Release、默认/独立/生产 feature、既有协议回归、资源常量登记、Apple 五目标及 Android 两 ABI 构建。`--preflight` 只下载并在自有隔离容器内读取 M/XR/V2/Caddy 版本与哈希，不做业务，不签收 required case。阶段主入口每次重新取得官方 latest；二进制身份固定用于同轮全部 case，配置/密钥随临时容器夹具清理。N5 单独开发入口仍可用于定位，但部分选择、缺失结构化事件或原始报告均不能通过完整 coverage。

N3 UDP 同参数客户端对照现已全链路容器化，仍是独立诊断，不是阶段门禁：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_vmess_udp_ab \
  target/interop/runs/<new-udp-ab-run> --rounds 2 --packets 100 --sizes 1 64 512 1200
```

需要已运行的 Apple Container 及带 `purpose=vcore-mihomo-interop` 标签的同名 host-only 网络。每轮重新下载官方最新 Linux ARM64 Mihomo，刷新官方 `python:3-alpine` 镜像并记录 digest；每个传输使用独立的服务端、官方对照客户端和 UDP 原站三个容器，不发布宿主端口。所有 IPv4/IPv6/域名原站均来自容器，虚拟 IPv6 不代表物理链路。默认三编码 × 13 body 配置 × 三地址类型 × TCP/WS/gRPC 明文/TLS，2轮、每大小100包；省略 `--sizes` 或使用 `--include-boundary` 时追加实际负载边界：raw/XUDP 15000字节，packetaddr 从15000中扣除7/19字节地址头（域名按可解析为IPv6的预算保守计算）。服务端回环保护和默认 socket 行为不变，send/原站观测/reply 各1秒、不重试业务包。

原站在容器内自主 echo，经单独的只读 TCP 观察流传回实际收到的字节供测试比对；宿主不负责 UDP 回包。旧的宿主 `--collision-probe` / `--socket-probe` 入口明确返回 BLOCKED（非零），不能用于启动宿主原站。wire/public 已迁移到同一容器工具，旧 close/UDP 差分不再可执行。历史结论与未归因失败见 [UDP 客户端差分](../docs/acceptance/next-protocols/N3-udp-client-differential.md)。

官方对照客户端的 SOCKS UDP 入口按来源 tuple 缓存关联；测试驱动为每个独立用例保留独立 UDP 来源 socket，直到该传输组结束才释放，避免快速复用端口继承其他用例的目标/编码。`--nat-reuse-probe` 在全容器服务拓扑中专门复现该机制：旧原站收到新用例报文、新原站未收到、独立来源对照通过；预期复现记为 REPRODUCED 并返回非零，不计入正常互通 PASS。历史未记录入口来源端口的失败不据此全部追认原因。

`--case` 可重复，`--protocol` 与其取交集；未知、重复、矛盾或空选择拒绝。`--list` 只列清单，不下载/启动。N3/N4 `--preflight` 只检查所选清单的 M/V2：新下载、实际容器版本/hash、隔离网络、原站/服务端就绪和清理，不执行业务，不算 required PASS。历史 N1/N2 预检 M/W/H/XR/V2 的方式不用于新的服务端验收；未来协议的环境缺口不阻塞 N3/N4。版本命令就绪不能证明具体协议模式已通过。

每次创建`target/interop/runs/`下的新目录；`--run-dir`只能指定其下尚不存在的目录。记录`run.json`、`peers.json`、`cases.json`、`resources.jsonl`、脱敏日志和`summary.md`，并为原始事件/报告记录SHA-256。输入身份包括父提交、源码树（含未提交新文件）/diff/lock摘要、工具链、SDK、API/schema、features。执行期间源码变化不得签收；部分选择和预检不能通过完整阶段coverage。

coverage重新校验必需case、结构化Rust断言、原生探针/目标回包、原始peer身份、离线脚本结果、命令退出/清理、资源基线/峰值/Stop/静默窗口和artifact内容摘要。不从stdout的PASS文字猜测通过；缺失/重复/未知case、CFG-only、FAIL/BLOCKED/NOT RUN、超时、清理失败均非零。原生Mihomo还执行注入调用方异常后的真实进程join和端口重绑，离线测试用真实SIGINT检查子进程回收且不停止无关进程。

对端均重新下载官方latest，不查GitHub API、不从源码编译、不退回缓存；同轮M宿主/容器固定同一release。V2/XR下载官方zip，H下载官方可执行文件。版本/hash只是产物身份，不是官方签名验证。合成密钥/配置/私有日志留在本轮临时目录并清理，不进入保留报告。下载、解压、子进程输出、单case和整套执行均有界；失败报告保留，重新运行另建目录，不自动重试业务包。

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
