# 平台与 CLI 编译

`vcore-scripts` 负责编译 Apple、Android、Windows 库产物及记录交付身份；
独立 `vcore_scripts.cli_release` 模块维护六目标 CLI tag 归档与内部构建记录。
命令从 VCore 根目录运行，或通过 `--project` 显式指定本仓库 scripts；Python 工程由
uv / uv.lock 管理，不推断外部工程。Rust 的定向离线回归见 [tests](../tests/README.md)。

## 入口

```sh
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows

# 交付记录要求干净、已提交的 checkout；在对应构建宿主执行。
uv run --project scripts --locked vcore-scripts build apple --delivery
uv run --project scripts --locked vcore-scripts build android --delivery
uv run --project scripts --locked vcore-scripts build windows --delivery
```

原生依赖需要 C/C++、CMake、Perl 和 libclang；Rust 目标须预先安装。
平台构建拒绝 `interop-test` / `benchmark-geodata-http` 等测试 feature。

## 平台产物

| 平台 | 构建环境与产物 |
| --- | --- |
| Apple | macOS / Xcode；`dist/apple/LibVCore.xcframework`，含 iOS 真机/模拟器、macOS、tvOS 真机/模拟器五切片 |
| Android | macOS 或 Linux / Android NDK；`dist/android` 的 ARM64、x86_64 库及同 ABI / NDK 的 `libc++_shared.so` |
| Windows | 原生 ARM64 或 x64 Windows / Visual Studio C++；`dist/windows/<architecture>` 的 DLL、Provider Host、Session Host 及身份摘要 |

Apple 的 iOS/tvOS 真机和模拟器仅 ARM64，macOS 为 ARM64/x86_64 universal。
iOS 最低 13.0、macOS 10.15、tvOS 17.0；ARM64 iOS 模拟器/macOS 切片分别至少
14.0/11.0。构建检查每个 Rust/原生库对象的 Mach-O 平台、架构和最低版本。
最终链接 libc++；module map 已声明，直接 C 链接需 `-lc++`。

Android NDK 优先使用 `ANDROID_NDK_HOME`；否则从 `ANDROID_HOME/ndk` 选择
`VCORE_ANDROID_NDK_VERSION` 指定的完整版本或主版本内最新已安装正式版，默认主版本
为 30，排除预览版。Windows ARM64 还需要 clang-cl / clang 和 Ninja，并保留
BoringSSL 汇编；Windows 构建固定使用 Release 和完整生产 feature 集合。

Android 的 C/C++、CMake 与 bindgen 使用同一 API level（默认 24）；绑定生成显式
传入带 API 版本的 clang target，兼容 NDK 30 的版本要求，并保留生效的额外 clang 参数。

普通 Apple/Android 构建可通过 `VCORE_BUILD_PROFILE`、`VCORE_FEATURES` 和各平台
输出/部署目标/NDK/API/ABI 环境变量定制，具体默认值以 `builds.py` 为准。
`CARGO_TARGET_DIR` 改变普通构建的中间产物位置，相对路径从本 VCore checkout 解析；
交付模式禁用这些隐藏输出、编译选项和 feature 覆盖。

Linux 使用原生 GNU/glibc 工具链，不属于上述打包交付入口：

```sh
cargo build --locked --release --lib --features ffi
```

## 交付边界

`--delivery` 在标准输出目录生成 `vcore-delivery.json`，绑定 VCore commit/tree、
lockfile、核心软件版本与构建身份、完整 features、工具链/SDK/NDK 和全部产物的大小/hash。
本地 boring path 开发态要求 fork 同样干净并记录 commit/tree；PR/发布仍须切回
Git release 依赖，按 [TLS 来源契约](../docs/tls-dependencies.md) 审查。

交付前拒绝输出路径中的符号链接/reparse point，清除旧记录；Android 同时清空标准
输出以隔离旧 ABI。构建后的内部完整性检查核对文件集合、源码身份、架构与平台元数据，
包括 Android C++ runtime、Apple 全部切片和 Windows 配套进程。Windows 包构建显式
启用 `ffi,windows-uwp` 与完整生产协议；`windows-uwp` 和 `windows-wintun` 在 Windows
编译时互斥，UWP 依赖图不包含 tun-rs 的 Windows Wintun 后端。原生 Windows x64 /
ARM64 交付矩阵随后对 `cli,windows-wintun` 执行 locked release `cargo check`，检查
另一后端的真实 Windows Rust/API 编译；此步骤不运行驱动、不打包或增加交付资产。
检查失败不保留交付 manifest。它不执行原生 C/Swift 消费者，不证明设备 VPN、
签名安装、许可证审核或正式发布；这些按 [验收边界](../docs/acceptance.md) 独立取证。

## CLI tag 发布

本地前台程序可直接构建：

```sh
# Linux / macOS
cargo build --locked --release --no-default-features --features cli --bin vcore
# Windows
cargo build --locked --release --no-default-features --features cli,windows-wintun --bin vcore
```

[CLI release 工作流](../.github/workflows/cli-release.yml) 在正式 `vX.Y.Z` tag 上
调用下列独立入口；要求版本匹配且 checkout 干净、已提交并位于该 tag。
每个目标在对应 OS/架构的原生宿主构建，完整生产协议通过 `cli` / `invoke` feature 启用。
Windows CLI 显式选择 `cli,windows-wintun`，不启用 FFI、UWP 或 WinRT 宿主程序。
Wintun interruptible I/O 的间接 Windows Win32 bindings 允许存在，门禁拒绝直接
包 SDK 依赖和 `Networking_Vpn` 等 WinRT features。

```sh
uv run --project scripts --locked python -m vcore_scripts.cli_release build \
  --target aarch64-apple-darwin --tag v0.1.0 --repository YuanDevTeam/VCore
uv run --project scripts --locked python -m vcore_scripts.cli_release assemble \
  --tag v0.1.0 --repository YuanDevTeam/VCore \
  --input dist/cli-incoming --notes /path/to/release.md
```

`build` 输出 `dist/cli/<target>` 中的固定名称归档及内部 `manifest.json`，校验实际
依赖图、二进制格式/架构/构建身份，并运行 `-h/-v/-t` 离线检查。完整已链接依赖许可证
与原生通知嵌入可执行文件，打包前验证文本保留。`assemble` 要求六项源代码和锁文件
身份一致，解压检查二进制及通知 hash，生成 Release 描述；模块本身不发布。
工作流只上传六个可执行文件归档，不发布 manifest、checksums、Wintun DLL 或 WinRT hosts。
矩阵、配置路径和参数语义见 [CLI](../docs/cli.md)。

## 独立容器验证

互通与压力编排位于公开的 [container-benchmark](https://github.com/YuanDevTeam/container-benchmark)，
始终显式提供 VCore checkout；VCore 编译入口不导入该工程或猜测相邻路径。

```sh
uv run --project /path/to/container-benchmark --locked container-benchmark interop --list
uv run --project /path/to/container-benchmark --locked container-benchmark interop --source vcore=/path/to/VCore
uv run --project /path/to/container-benchmark --locked container-benchmark stress --source vcore=/path/to/VCore --geodata-records 1280000
```

`interop` 保留 Mihomo listener 和 Xray-core / Hysteria2 / V2Ray / Caddy 补充对端；
`stress` 使用原生 Linux TUN、GeoData 与混合吞吐/DNS 负载，二者独立执行。
所有服务端在隔离容器运行，规则见 [测试隔离](../docs/testing-isolation.md)。
依赖身份、用例、指标与清理方式由 benchmark 维护；迁移代码或离线测试通过不等于
当次网络互通或压力测试已经通过。
