# 构建与验证

所有命令从 VCore 根目录运行，或为 `--project` 显式指定本仓库 scripts。
Python 工程由 uv/uv.lock 管理，运行时只用标准库；不推断相邻研究仓库。

## 日常检查

```sh
uv run --project scripts --locked vcore-scripts check core --profile debug
uv run --project scripts --locked vcore-scripts check core --profile release
uv run --project scripts --locked vcore-scripts check core --profile features
uv run --project scripts --locked python -m unittest discover -s scripts/tests
cargo fmt --all -- --check
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
uv run --project scripts --locked vcore-scripts check c-header
# PR/发布来源门禁；本地 boring path 开发态不执行。
uv run --project scripts --locked vcore-scripts check tls-dependencies
```

`check core --list` 只显示命令。Debug/Release 只执行明确的纯内存/配置/安全回归；
features 检查精简构建、准入和完整生产构建，全目标只编译 `--no-run`。
每条真正执行的 Cargo 测试须有非空成功结果，失败、超时或未 join 均非零退出。
**不要执行无过滤的 cargo test --all-features --all-targets**：部分历史 fixture 含宿主监听器。

额外生产/测试代码静态检查与 netstack：

```sh
cargo clippy --locked --features ffi --lib --bins -- -D warnings
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
```

C header 检查只编译 C/C++；TLS 检查审查 resolved graph、provider、来源及批准 revision，
不是网络互通。边界见 [TLS 依赖](../docs/tls-dependencies.md)。

## 容器互通

```sh
uv run --project scripts --locked vcore-scripts check protocol-interop --suite integration --list
uv run --project scripts --locked vcore-scripts check protocol-interop --suite integration --preflight
uv run --project scripts --locked vcore-scripts check protocol-interop --suite integration
uv run --project scripts --locked vcore-scripts check protocol-coverage --suite integration --run-dir target/interop/runs/<run-id>
uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only
```

可执行容器 suite：vmess、vless、xhttp、hysteria2、security、integration、shadowtls、uot、tuic、httpupgrade。
`--case` 可重复、`--protocol` 可筛选；子集只证明实际执行的项目，不能签收整套。
foundations/trojan 保留基础用例和断言，其旧服务端编排尚未全容器化，不能执行；
需要 Trojan 互通时用 integration 中的真实容器路径。

文件、用例、事件与报告按协议或验证用途命名，例如 INTEGRATION-PAIR-SS-SS、
SECURITY-ECH-CHROME；不再提供阶段编号或 --stage 别名。旧报告保持原样，使用
其记录的 Git revision 复核，不重写旧证据，也不将旧名称解释为新运行结果。

执行清单从 Python 的协议定义生成；不再提交重复 cases.json 或规划字段/组合表。
`--catalog-only` 只检查可执行清单与上限引用，输出 VALID / NOT RUN，不冒充通过。
`limits.json` 仍与 Rust 常量和边界断言校验。原始事件、命令/退出码、源/锁文件、
对端身份、artifact hash、资源与清理证据独立复核；缺失/重复/部分结果不能 PASS。

每轮新建 target/interop/runs 子目录；不得运行中修改源码。合成凭据/私有日志放临时
目录并清理，不进入报告。Stop 时和后续静默窗口分别采样；短 tracer 不代替完整长测。
容器不可用即 BLOCKED，不能退回宿主。完整规则见[测试隔离](../docs/testing-isolation.md)。

shadowtls 包含配置/feature、真实 TLS 内存负例、三算法与五种握手模式、ALPN/HRR、
记录故障、Stop/测速期限和原生 UDP 分流；主对端为 Mihomo，官方 ShadowTLS +
原样 ssserver 另作 TCP 对照。裸 SS、共享 TLS/REALITY/JLS、独立指纹 golden 与
Apple/Android 编译是同轮必需组；不签收 UoT、实机或旧 SS 空首包风险。

uot 验证 SS v2 三算法 × 裸流/v3 的六组合，分别经直连、TCP-only SOCKS5 和
嵌套 select；覆盖零包、三地址族、交替原站、16 KiB Mihomo 边界/超限和零原生 UDP
旁路。错误密钥/v3 身份及原样 ssserver 不支持是独立负例。内存检查另验 u16 上限、
预算、首包门控、DNS、取消与 Stop；AnyTLS、裸 SS、精简 feature 和 Apple/Android
是同轮必需回归。使用 protocol-interop / check protocol-coverage 的 `--suite uot`。

tuic 覆盖 v5 的双向 TCP、native/quic UDP、三种官方拥塞算法、认证/TLS 负例和
SOCKS5/SS UoT/AnyTLS 六种上游组合。服务端与上游分容器，避免触发 Mihomo 的
同进程回环检测；不关闭对端检测或修改其源码。会话重用/重建、嵌套组、node-only 测速、
回滚与 Stop 独立取证；本轮包含 HY2/H3 共享回归及 Apple/Android 构建。
内存 u16 上限不当成对端端到端容量，旧七协议压力结果不替代 TUIC 混合压力。

httpupgrade 覆盖 VMess 明文/TLS、Trojan TLS × 普通/fast-open 六种模式；
包含双向数据、既有 UDP 编码、ED、身份负例、四个命名 TLS 模板及 Mihomo 关闭对照。
域名 Trojan UDP 用原生 Xray 补验；VMess 与 Xray 的空包限制分别记录，不把超限
回复截断计为成功。共享配置/内存握手、VLESS Upgrade/WS、其他 VMess/Trojan
传输、精简 feature 和 Apple/Android 构建均为同轮必需组。
使用 `protocol-interop` / `protocol-coverage` 的 `--suite httpupgrade`。

integration 保留 64 个八协议有序配对，另加 TUIC 双模式 → SS v3 三算法六条链，
复跑 UoT 的 TCP-only 上游/嵌套组及 TUIC 上游消费者。公开入站/TUN、DNS/测速、
回滚和 100 次生命周期与 100 轮 40-flow 重建、1800 秒混合长测属于同一完整门禁。
TCP 为 SOCKS5/SS v3/TUIC/HTTPUpgrade 各五条，UDP 为 SS UoT/SS UoT+v3/
TUIC/HTTPUpgrade 各五条，轮换算法与模式；独立核对逐轮实际配置、资源和静默证据。
Debug/Release、精简 feature、脚本、netstack、HY2 跳端口和共享安全/传输回归同源重跑。
integration 可在获准的本地 boring 开发态执行，不替代 release 来源审计；PR/交付候选
仍须切回 release 分支，在干净 checkout 单独通过 `check tls-dependencies` 并重跑集成。
SS TCP 数据用客户端预先提交的非空首段验证；SS 叶节点的配对记录明确包含
`server_first:false` 和上游空首包限制，其他叶节点仍须 server-first。此范围调整不
减小双向数据量、不移除确定性空首包拒绝回归，也不通过重试取得成功。

### 新协议对端能力预检

```sh
uv run --project scripts --locked vcore-scripts check protocol-peers --run-dir target/interop/runs/<fresh-run>
```

独立的原站/cover、Mihomo 服务端与 Mihomo 对照客户端都在容器中。当前检查 SS2022
三算法的 v3/原生 UDP、裸流及 v3 上的 UoT v2、TUIC v5 双 UDP 模式、六种
VMess/Trojan HTTPUpgrade 承载和 SOCKS5 上游；UoT 对照显式选择 v2，关闭服务端原生 UDP。
`--case` 可选单项，语义 ID 由 `protocol_completion_peers.py` 生成。
每项必须实际完成 TCP 回传与原站观测的 UDP 请求/回复；记录来源、官方版本/hash、
原始观测及清理。该工具只证明对端能力，**VCore 新协议行为始终记 NOT RUN**，
不更新生产配置、不代替协议 suite、负例/边界、压力或发布验收。

### 对端下载

```sh
uv run --project scripts --locked vcore-scripts download mihomo
uv run --project scripts --locked vcore-scripts download mihomo --target linux-arm64
```

使用官方 latest 下载链接；Mihomo 从 latest/download/version.txt 取得资产名所需版本，
再通过二进制 -v 确认实际版本。不查 API、不固定旧版、不本地编译或静默复用旧缓存。
同轮对端使用同一 release；下载/解压大小与超时有界，失败终止。产物在 target/interop，
版本、URL、压缩包/二进制 SHA-256 和容器镜像 digest 随结果记录；本地摘要不是官方签名。

所有协议端、原站、DNS、提供入口的对照客户端在本轮独占容器中；仅清理本轮所有者，
不全局 stop/prune。默认 Mihomo，明确缺口由官方 Xray/V2Ray/Hysteria/ssserver 补验。
唯一源码构建例外是获准的 xcaddy/Caddy H3/mTLS 网关，仍导入容器、不修改第三方。

### 定向安全验证

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_shape target/interop/runs/<fresh-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint target/interop/runs/<fresh-run> --client-fingerprint chrome
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --list
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --run-dir target/interop/runs/<fresh-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --check-run target/interop/runs/<reference-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_jls target/interop/runs/<fresh-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_encryption target/interop/runs/<fresh-run>
uv run --project scripts --locked vcore-scripts check reality-hybrid --run-dir target/interop/runs/<fresh-run>
```

指纹验证的 reference、wire、interop 三层证据及 golden 比对规则见
[指纹验证](../tests/fingerprints/README.md)。模板、主/下载身份、恢复/过期与容器数据面
各有独立断言；不从别名、另一个模板或 fork 接口探针推导通过。更多参数读对应 --help。

## 平台构建与产物

```sh
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows
# 正式候选要求干净、已提交的 checkout：
uv run --project scripts --locked vcore-scripts build apple --delivery
uv run --project scripts --locked vcore-scripts check platform-artifacts --manifest dist/apple/vcore-delivery.json
uv run --project scripts --locked vcore-scripts check platform-abi --manifest dist/apple/vcore-delivery.json
```

- Apple 在 macOS 构建，输出 dist/apple/LibVCore.xcframework，包含 iOS 真机/模拟器、
  macOS、tvOS 真机/模拟器五切片。tvOS 仅 ARM64、最低 17.0；先用 rustup 安装
  aarch64-apple-tvos 与 aarch64-apple-tvos-sim（稳定版 std，无需 nightly/build-std）。
  iOS 仍为 13.0、macOS 仍为 10.15；ARM64 模拟器/桌面各自下限为 14.0/11.0。
  构建和验产物均检查每个 Rust/原生库对象的 Mach-O 平台、架构与最低版本，
  不接受用 iOS ARM64 冒充 tvOS。最终链接 libc++；module map 已声明，直接 C 链接需 -lc++。
- Android 在 macOS/Linux 构建，输出 dist/android 下两 ABI 的 libvcore.so 及配套
  libc++_shared.so，宿主一起打包。NDK 优先 ANDROID_NDK_HOME，否则 ANDROID_HOME/ndk。
- Windows 在原生 ARM64/x64、Visual Studio C++ 环境构建，输出配套 DLL/Provider Host/
  Session Host 及架构/摘要。ARM64 需要 clang-cl/clang、Ninja；保持 BoringSSL 汇编启用。
  契约见 [Windows VPN](../docs/windows-vpn.md)。

Apple/Android 可设置 VCORE_BUILD_PROFILE、VCORE_FEATURES、VCORE_APPLE_DIST_DIR、
VCORE_IOS_DEPLOYMENT_TARGET、VCORE_TVOS_DEPLOYMENT_TARGET（至少 17.0）、
VCORE_MACOS_DEPLOYMENT_TARGET、VCORE_ANDROID_NDK_VERSION、
VCORE_ANDROID_API、VCORE_ANDROID_TARGETS、VCORE_ANDROID_OUTPUT_DIR。默认值查看 builds.py；
交付禁用隐藏覆盖、测试 feature、非 Release profile，标准 feature 集合显式包含所有支持协议。

--delivery 绑定 commit/tree、lockfile、API/schema、features、toolchain/SDK/NDK、架构及
全部文件大小/hash；本地 boring 开发态还要求 fork 干净并记录其 commit/tree，仍不能
替代 PR/发布前切回 Git release 的依赖审计。所有平台在清旧记录或构建前拒绝输出路径及其仓库内祖先目录的
符号链接和 Windows reparse point（包括 junction），不沿链接删除或写入外部产物。
开始前清旧记录，失败不签收。Android 交付还会清空标准 dist/android
构建输出，避免纳入开发构建遗留的额外 ABI。platform-artifacts 拒绝缺失/额外文件、
错架构/身份及缺 C++ runtime；可重复 --manifest，--complete 要求 Apple、Android、
原生 Windows ARM64/x64，仍只证明构建。--source-dir 须显式指定同一候选 checkout。
platform-abi 在原生 macOS/Windows 链接/加载并执行 C ABI；Apple 额外链接 iOS/tvOS
真机与模拟器 C 消费者（不在该命令中运行），Windows 另验 snapshot/未打包失败关闭。
它不创建业务运行时，不证明设备 VPN 或正式安装。

Apple Silicon 上安装对应 Simulator runtime、启动 Apple Container，并准备既有
vcore-mihomo-interop host-only 网络后，显式运行原生消费者：

```sh
uv run --project scripts --locked vcore-scripts check apple-runtime --platform tvos
uv run --project scripts --locked vcore-scripts check apple-runtime --platform ios
# 干净候选额外绑定 --delivery 的产物与源码身份：
uv run --project scripts --locked vcore-scripts check apple-runtime --platform tvos --manifest dist/apple/vcore-delivery.json
```

该命令链接生产库，通过公共 ABI 检查三轮 local/TUN 生命周期、SOCKS5 TCP/UDP、
合成 utun TCP/UDP、错误 framing/fd、Stop/Destroy、借用 fd 和日志/内存 API。IPv4
原站在专用容器中；仅启动临时专用模拟器，退出或失败时清理自有资源，不修改宿主 VPN。
结果保存在 target/platform-delivery/runtime；未传 manifest 的运行仅为开发烟测。
它不是物理 Packet Tunnel、IPv6 完整协议矩阵、CN 内存峰值或 1 Gbps 带宽验收。

## 独立进程内存设施

内存专项各开发阶段只做相关编译、必要回归、短烟测与定位；完整内存/吞吐矩阵和长测
统一留到最终候选验收，不是每个开发阶段的提交门禁。以下命令保持正式用例的时长、
重复次数和阈值，选例不自动变成短烟测；开发完成、子集结果与最终通过分开记录。

```sh
uv run --project scripts --locked vcore-scripts check memory --list
uv run --project scripts --locked vcore-scripts check memory --preflight
uv run --project scripts --locked vcore-scripts check memory
uv run --project scripts --locked vcore-scripts check memory --suite cold-start
uv run --project scripts --locked vcore-scripts check memory --suite peer-capacity --list
# 所选联合子集，不代表完整负载或移动平台通过：
uv run --project scripts --locked vcore-scripts check memory --suite socks-tcp-split
uv run --project scripts --locked vcore-scripts check memory --suite socks-tcp-v4 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-tcp-v6 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-udp-v6 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-correctness-v6 --list
uv run --project scripts --locked vcore-scripts check memory --suite socks-overlap-v6 --list
# 独立短烟测，结果只作 DIAGNOSTIC；另有相同范围的 v6 集合：
uv run --project scripts --locked vcore-scripts check memory --suite socks-smoke-v4
uv run --project scripts --locked vcore-scripts check memory --resume target/memory/<run-id>
```

原生 macOS Release/生产 feature ABI 宿主，外部约 20 ms 采样与内核 lifetime footprint
峰值、最终退出屏障、冻结官方 latest CN/Mihomo、专属容器和可恢复用例。
1 Gbps 对照驱动使用有界原生生成/校验；对端丢包为设施 INVALID，不冒充核心内存通过。
输入、结果和恢复记录位于 target/memory；详见[测量范围与负例](../tests/memory/README.md)。
`--case full-cn-loader` 先跑独立全量 CN 参考，再由生产宿主验证双资源可用、实际
DIRECT/代理/REJECT 路由与生命周期峰值。它不证明正式移动 Provider 或 VCore 的 1 Gbps 承载能力。
`--suite cold-start` 是四种规则配置各五个未插桩冷进程和独立分配诊断，详见上述测量文档。
环境中不得继承 `Malloc*` / `DYLD_*` 覆盖项；例如用 `env -u MallocNanoZone` 显式移除。

## CI 与证据

Tests 工作流只跑 core Debug/Release、quality/features 和 memory-only netstack；
通用 Python、格式检查只在 quality 执行一次。Release builds 复用 Apple、Android、
Windows ARM64/x64 构建，每个平台保留产物路径/架构/ABI 检查和未签名 artifacts。
CI 配置存在不等于已运行或通过；原始 run URL、commit、artifact 有效期随当次记录。

真实设备、正式宿主、签名安装和商店发布单独签收，见[验收边界](../docs/acceptance.md)。
旧 Windows tun2socks demo 是显式平台人工验收工具，不是允许在宿主运行协议服务端的例外。
