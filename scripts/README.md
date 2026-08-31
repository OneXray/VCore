# VCore Scripts

本目录是由 `uv` 管理的 Python 工程，统一提供 VCore 平台构建、静态检查和可选互操作 demo。所有命令都从 VCore 仓库根目录执行：

```bash
uv sync --project scripts --locked
uv run --project scripts --locked vcore-scripts --help
```

运行时只使用 Python 标准库；`ruff` 是由 `uv.lock` 固定的开发依赖。

## 平台构建

```bash
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows
```

- Apple 命令只能在 macOS 运行，输出 `dist/apple/LibVCore.xcframework`。
- Android 命令在 macOS/Linux 运行，默认输出 `dist/android/{arm64-v8a,x86_64}/libvcore.so`。
- Windows 命令只能在已安装 Visual Studio C++ 工具的 Windows 运行；命令从系统注册表读取原生 ARM64/x64 处理器架构，通过 `vswhere` 加载对应的 MSVC 环境，验证三项 PE 的 machine type 后输出 `dist/windows/<architecture>` 下的 DLL、Provider Host、Session Host 和记录 package integration revision、架构及三项 SHA-256 的 `vcore-windows-artifacts.json`。
- 所有构建都使用 `Cargo.lock`，并检查产物内的 Invoke API v5/config revision 13 身份。

Apple/Android 继续接受现有环境变量：

| 变量 | 默认值 |
| --- | --- |
| `VCORE_BUILD_PROFILE` | `release`，也可为 `debug` |
| `VCORE_FEATURES` | `ffi,tun,inbound-http,outbound-vless` |
| `VCORE_APPLE_DIST_DIR` | `dist/apple` |
| `VCORE_IOS_DEPLOYMENT_TARGET` | `13.0` |
| `VCORE_MACOS_DEPLOYMENT_TARGET` | `10.15` |
| `VCORE_ANDROID_NDK_VERSION` | `28.2.13676358` |
| `VCORE_ANDROID_API` | `24` |
| `VCORE_ANDROID_TARGETS` | `aarch64-linux-android x86_64-linux-android` |
| `VCORE_ANDROID_OUTPUT_DIR` | `dist/android` |

Android NDK 优先读取 `ANDROID_NDK_HOME`，否则使用 `$ANDROID_HOME/ndk/<version>`。

## 检查

```bash
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

`c-header` 在 macOS 使用 `xcrun clang/clang++`，其他平台使用 `PATH` 中的 `clang/clang++`。`tls-dependencies` 直接读取 `cargo metadata`，验证唯一的 OneXray rustls 0.23.43 来自 GitHub `vcore/reality-0.23` 分支、官方 tokio-rustls 0.26.4、registry ring，以及禁止的 Watfaq/AWS-LC 依赖。

## Windows tun2socks demo

```powershell
uv run --project scripts --locked vcore-scripts demo windows-tun2socks
uv run --project scripts --locked vcore-scripts demo windows-tun2socks C:\path\to\xray-config.json
```

该命令仍是显式互操作验收：它临时构建 `references/Xray-core`，使用已安装的 `VCore.UwpDemo.Dev` 示例 package，并在结束时停止测试 VPN 和删除临时文件。源配置不会被修改。真实配置、凭据和临时访问日志不得提交。
