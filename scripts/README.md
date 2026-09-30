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

所有平台构建尊重 Cargo 的 `CARGO_TARGET_DIR`，默认仍为本 checkout 的 `target`；
相对路径按 Cargo 执行的 VCore 根目录解析。库查找和 Apple 中间归档使用同一个目标目录。
它只改变构建缓存/中间产物位置，Apple/Android 的交付输出仍由各自的 output/dist 参数控制。

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

## 独立容器 benchmark

容器协议互通、官方对端下载、Apple 模拟器网络消费者及内存/吞吐实验，
统一由独立的 container-benchmark 工程负责。该工程通过 `--vcore` 显式指定
被测 checkout；VCore 构建、core 检查和 CI 不查找相邻目录，也不要求该工程存在。

```sh
uv run --project /path/to/container-benchmark --locked container-benchmark --vcore /path/to/VCore check protocol-interop --suite integration --list
uv run --project /path/to/container-benchmark --locked container-benchmark --vcore /path/to/VCore check memory --list
uv run --project /path/to/container-benchmark --locked container-benchmark --vcore /path/to/VCore check apple-runtime --platform tvos
```

benchmark 的用例、输入和运行约束由其 README 维护。所有协议端、原站、DNS 和
提供入口的对照客户端遵守[测试隔离](../docs/testing-isolation.md)，不能退回宿主服务端。
内存专项仅使用 fd-TUN 入站，SOCKS5 出站与独立对端容量校准保留。
每次测试结束后清理生成的构建、下载、规则、镜像、日志及原始流量证据，仅保留
脱敏文字结论；需要复验时重新准备输入并执行。生产构建交付产物独立管理。

## CI 与证据

Tests 工作流只跑 core Debug/Release、quality/features 和 memory-only netstack；
通用 Python、格式检查只在 quality 执行一次。Release builds 复用 Apple、Android、
Windows ARM64/x64 构建，每个平台保留产物路径/架构/ABI 检查和未签名 artifacts。
CI 配置存在不等于已运行或通过；原始 run URL、commit、artifact 有效期随当次记录。

真实设备、正式宿主、签名安装和商店发布单独签收，见[验收边界](../docs/acceptance.md)。
旧 Windows tun2socks demo 是显式平台人工验收工具，不是允许在宿主运行协议服务端的例外。
