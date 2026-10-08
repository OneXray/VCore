# 平台与 CLI 编译

`vole-scripts` 负责编译 CLI 与 Apple、Android、Linux、Windows FFI 库产物；
`vole_scripts.release` 调用平台编译入口、打包并汇总同一次 Release。
命令从 Vole 根目录运行，或通过 `--project` 显式指定本仓库 scripts；Python 工程由
uv / uv.lock 管理，不推断外部工程。Rust 的定向离线回归见 [tests](../tests/README.md)。

## 入口

```sh
uv run --project scripts --locked vole-scripts build apple
uv run --project scripts --locked vole-scripts build android
uv run --project scripts --locked vole-scripts build linux
uv run --project scripts --locked vole-scripts build windows --backend uwp
uv run --project scripts --locked vole-scripts build windows --backend wintun

# CLI 默认当前宿主和 Release；Windows 固定使用 Wintun。
uv run --project scripts --locked vole-scripts build cli
uv run --project scripts --locked vole-scripts build cli --profile debug
uv run --project scripts --locked vole-scripts build cli --target aarch64-apple-darwin
```

原生依赖需要 C/C++、CMake、Perl 和 libclang；Rust 目标须预先安装。
平台构建拒绝 `interop-test` / `benchmark-geodata-http` 等测试 feature。

## 平台产物

| 平台 | 构建环境与产物 |
| --- | --- |
| Apple | macOS / Xcode；`dist/apple/LibVole.xcframework`，含 iOS 真机/模拟器、macOS、tvOS 真机/模拟器五切片 |
| Android | macOS 或 Linux / Android NDK；`dist/android` 的 ARM64、x86_64 库及同 ABI / NDK 的 `libc++_shared.so` |
| Linux | 原生 ARM64 或 x64 Linux / GNU 工具链；`dist/linux/<architecture>` 的 `libvole.so`、`libvole.a` 和 C 头文件 |
| Windows | 原生 ARM64 或 x64 Windows / Visual Studio C++；`dist/windows/<architecture>/<backend>`，Wintun 为 DLL，UWP 另含 Provider Host、Session Host |
| CLI | Linux、macOS、Windows；Cargo target 目录中的 `vole` / `vole.exe`，脚本输出实际路径 |

Apple 的 iOS/tvOS 真机和模拟器仅 ARM64，macOS 为 ARM64/x86_64 universal。
iOS 最低 13.0、macOS 10.15、tvOS 17.0；ARM64 iOS 模拟器/macOS 切片分别至少
14.0/11.0。构建检查每个 Rust/原生库对象的 Mach-O 平台、架构和最低版本。
最终链接 libc++；module map 已声明，直接 C 链接需 `-lc++`。

Android NDK 优先使用 `ANDROID_NDK_HOME`；否则从 `ANDROID_HOME/ndk` 选择
`VOLE_ANDROID_NDK_VERSION` 指定的完整版本或主版本内最新已安装正式版，默认主版本
为 30，排除预览版。Windows ARM64 还需要 clang-cl / clang 和 Ninja，并保留
BoringSSL 汇编；Windows 构建固定使用 Release 和完整生产 feature 集合。

Android 的 C/C++、CMake 与 bindgen 使用同一 API level（默认 24）；绑定生成显式
传入带 API 版本的 clang target，兼容 NDK 30 的版本要求，并保留生效的额外 clang 参数。

普通 Apple/Android 构建可通过 `VOLE_BUILD_PROFILE`、`VOLE_FEATURES` 和各平台
输出/部署目标/NDK/API/ABI 环境变量定制，具体默认值以 `builds.py` 为准。
`CARGO_TARGET_DIR` 改变普通构建的中间产物位置，相对路径从本 Vole checkout 解析；
发布入口固定生产 profile、features 和输出布局。

Linux FFI 使用原生 GNU/glibc 工具链；交付矩阵分别在 x64、ARM64 宿主构建。
本地 CLI 的 `--target` 允许同一 OS 的受支持目标，所需 Rust target 和原生工具链须已安装。
Windows CLI 固定使用 Wintun，不提供后端选择参数。Windows FFI 的 `--backend` 选择
Cargo features，不增加 CLI 运行参数或修改 TUN 配置。
Wintun 与 UWP 的输出分目录保存，切换后端不会覆盖另一后端产物。

## CLI 与 FFI 统一发布

[Release 工作流](../.github/workflows/release.yml) 在正式 `vX.Y.Z` tag 上
统一构建、汇总并发布；要求 tag 与 Cargo 版本匹配，且指向当前 checkout 的提交。
每个目标在对应 OS/架构的原生宿主构建，完整生产协议通过 `cli` / `invoke` feature 启用。
Windows CLI 显式选择 `cli,windows-wintun`，不启用 FFI、UWP 或 WinRT 宿主程序。
Wintun interruptible I/O 的间接 Windows Win32 bindings 允许存在，门禁拒绝直接
包 SDK 依赖和 `Networking_Vpn` 等 WinRT features。

```sh
uv run --project scripts --locked python -m vole_scripts.release build-cli \
  --target aarch64-apple-darwin --tag v0.1.0 --repository YuanDevTeam/Vole
uv run --project scripts --locked python -m vole_scripts.release build-ffi \
  --platform windows --target aarch64-pc-windows-msvc --backend wintun \
  --tag v0.1.0 --repository YuanDevTeam/Vole
uv run --project scripts --locked python -m vole_scripts.release assemble \
  --tag v0.1.0 --repository YuanDevTeam/Vole \
  --inputs dist/release-incoming --output dist/release --notes /path/to/release.md
```

构建入口可省略 `--tag`，供本地、PR、可复用工作流或手工触发进行 Release 构建；
只有正式 tag push 才发布 GitHub Release。
`build-cli` 复用 CLI 编译入口，并运行 `-h/-v/-t` 离线检查；`build-ffi` 复用对应平台
编译入口。两者从实际目标依赖图收集许可证和原生通知，嵌入 CLI、FFI 核心库与 UWP
配套进程，再按固定文件清单直接打包。同时收集 Rust 标准库通知，Android 另收集所带
NDK C++ runtime 的通知。CI 安装 `rust-docs` 以读取原始标准库版权报告。

每个构建任务只上传归档。`assemble` 收齐六项 CLI 和八项 FFI 归档，检查名称与数量，
生成 Release 描述；全部构建和汇总成功后，工作流一次性发布十四个归档。
编译与打包不执行原生 C/Swift 消费者，设备与安装验收见 [验收边界](../docs/acceptance.md)。

| FFI 归档 | 内容 |
| --- | --- |
| `vole-ffi-apple.tar.gz` | 完整 `LibVole.xcframework`，含五切片与 headers/module maps |
| `vole-ffi-android.tar.gz` | ARM64、x86_64 的 `libvole.so` 和同 ABI / NDK 的 `libc++_shared.so`，及 C 头文件 |
| `vole-ffi-linux-amd64.tar.gz` | `libvole.so`、`libvole.a` 与 C 头文件 |
| `vole-ffi-linux-arm64.tar.gz` | 同上，ARM64 |
| `vole-ffi-windows-wintun-amd64.zip` | Wintun `vole.dll`、`vole.dll.lib` 与 C 头文件 |
| `vole-ffi-windows-wintun-arm64.zip` | 同上，ARM64 |
| `vole-ffi-windows-uwp-amd64.zip` | UWP `vole.dll`、`vole.dll.lib`、Provider Host、Session Host 与 C 头文件 |
| `vole-ffi-windows-uwp-arm64.zip` | 同上，ARM64 |

另有六个 CLI 归档，名称、配置路径和参数语义见 [CLI](../docs/cli.md)。
所有文件名不带版本号；不附带 checksums、独立 license 文件或 `wintun.dll`。
只有 FFI UWP 包包含 WinRT hosts。

## 独立容器验证

互通与压力编排位于公开的 [container-benchmark](https://github.com/YuanDevTeam/container-benchmark)，
始终显式提供 Vole checkout；Vole 编译入口不导入该工程或猜测相邻路径。

```sh
uv run --project /path/to/container-benchmark --locked container-benchmark interop --list
uv run --project /path/to/container-benchmark --locked container-benchmark interop --source vole=/path/to/Vole
uv run --project /path/to/container-benchmark --locked container-benchmark stress --source vole=/path/to/Vole --geodata-records 1280000
```

`interop` 保留 Mihomo listener 和 Xray-core / Hysteria2 / V2Ray / Caddy 补充对端；
`stress` 使用原生 Linux TUN、GeoData 与混合吞吐/DNS 负载，二者独立执行。
所有服务端在隔离容器运行，规则见 [测试隔离](../docs/testing-isolation.md)。
依赖身份、用例、指标与清理方式由 benchmark 维护；迁移代码或离线测试通过不等于
当次网络互通或压力测试已经通过。
