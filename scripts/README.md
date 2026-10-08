# 编译与发布

在 Vole 根目录执行。需要 Rust、uv、C/C++、CMake、Perl 和 libclang，以及对应平台工具链。

```sh
uv run --project scripts --locked vole-scripts build cli
uv run --project scripts --locked vole-scripts build cli --profile debug
uv run --project scripts --locked vole-scripts build cli --target aarch64-apple-darwin
uv run --project scripts --locked vole-scripts build apple
uv run --project scripts --locked vole-scripts build android
uv run --project scripts --locked vole-scripts build linux
uv run --project scripts --locked vole-scripts build windows --backend wintun
uv run --project scripts --locked vole-scripts build windows --backend uwp
```

CLI 默认构建当前宿主的 Release，Windows 固定 Wintun；Windows FFI 默认 UWP。
脚本输出产物路径，编译失败直接返回失败。

| 目标 | 工具链与输出 |
| --- | --- |
| CLI | Linux/macOS/Windows amd64、arm64；`target/<triple>/<profile>/vole[.exe]` |
| Apple FFI | macOS/Xcode；`dist/apple/LibVole.xcframework`，iOS/tvOS ARM64 真机及模拟器、macOS universal 共五切片 |
| Android FFI | macOS/Linux + NDK 30；`dist/android/<abi>`，ARM64、x86_64 的 `libvole.so` 与匹配的 `libc++_shared.so` |
| Linux FFI | 原生 GNU 工具链；`dist/linux/<architecture>` 的静态库、动态库和头文件 |
| Windows FFI | 原生 Visual Studio C++；`dist/windows/<architecture>/<backend>` 的 DLL/import library 和头文件；UWP 另含两个 host 程序 |

Apple 最低版本为 iOS 13、macOS 10.15、tvOS 17；ARM64 iOS 模拟器/macOS 分别至少
14/11。原生消费者需链接 libc++，module map 已声明。Windows ARM64 还需要 LLVM 与 Ninja。
Android 优先使用 `ANDROID_NDK_HOME`，否则在 `ANDROID_HOME/ndk` 中选择 NDK 30 的最新已安装正式版。
`VOLE_ANDROID_NDK_VERSION` 可指定版本，`VOLE_ANDROID_API` 默认 24。
`CARGO_TARGET_DIR` 按 Cargo 约定覆盖中间产物目录；其余本地覆盖见 `builds.py`。

## 发布

[Release workflow](../.github/workflows/release.yml) 在 `vX.Y.Z` tag push 时构建并发布，
tag 必须匹配 Cargo 版本。PR 使用同一构建矩阵，全部构建成功后汇总十四个归档。
CLI 构建后执行 `-h/-v/-t` 检查。
Apple FFI 的六个 Rust 目标分别在独立 job 并行编译并缓存；`FFI Apple` 等待全部目标
成功后合并 macOS 双架构、生成五切片 XCFramework 并打包。
CI 的依赖来源检查见 [TLS 依赖](../docs/tls-dependencies.md)。

| 归档 | 内容 |
| --- | --- |
| `vole-{linux,darwin}-{amd64,arm64}.gz` | 单个 CLI 可执行文件 |
| `vole-windows-{amd64,arm64}.zip` | `vole.exe`，Wintun 后端 |
| `vole-ffi-apple.tar.gz` | XCFramework，含 headers/module maps |
| `vole-ffi-android.tar.gz` | 两种 ABI 的核心库、C++ runtime 和 C 头文件 |
| `vole-ffi-linux-{amd64,arm64}.tar.gz` | `libvole.so`、`libvole.a` 和 C 头文件 |
| `vole-ffi-windows-{wintun,uwp}-{amd64,arm64}.zip` | `vole.dll`、`vole.dll.lib` 和 C 头文件；UWP 另含 Provider Host、Session Host |

公共 C 接口由 `vole.h` 提供；UWP 另附 `vole_windows_uwp.h`，声明 Windows 安装包桥接接口。
文件名不带版本号，不附带 checksums 或 `wintun.dll`。
发布脚本不收集许可证；CLI、FFI、XCFramework 与归档不额外内嵌或打包许可证内容。

Linux/macOS 的 CLI 使用 gzip 单文件归档，解压后需设置执行权限。下载匹配系统与架构的
归档后执行（以 Linux amd64 为例）：

```sh
gzip -dc vole-linux-amd64.gz > vole
chmod +x vole
./vole -v
```

发布入口为 `python -m vole_scripts.release`，参数见 `--help`；
`build-apple-target` 构建单个 Apple 静态库，`assemble-apple --inputs <目录> --output <目录>`
从 `<inputs>/<Rust target>/libvole.a` 汇总六个目标并打包，不重复编译。
省略 `--tag` 可在本地验证打包。`builds.py` 负责平台编译，`release.py` 负责打包与汇总。

CLI 参数见 [CLI](../docs/cli.md)，测试命令见 [tests](../tests/README.md)。
