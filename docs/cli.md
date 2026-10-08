# CLI 与 tag 发布

`vole` 是前台命令行入口，所有内核功能通过与库相同的 Invoke 请求处理器调用。
tag 发布工作流见 [CLI release](../.github/workflows/cli-release.yml)。工作流存在不代表
六个平台的发布已在当前环境执行；真实驱动和设备数据面仍须独立验证。
库接口见 [Invoke API](invoke-api.md)，平台边界见 [TUN 平台层](tun-platform.md)
与 [Windows VPN](windows-vpn.md)。

```sh
cargo build --locked --release --no-default-features --features cli --bin vole
./target/release/vole -f /path/to/config.yaml
./target/release/vole -d /path/to/data -f ./config.yaml
./target/release/vole -t -f ./config.yaml
# Windows 桌面 TUN 构建选择 Wintun 后端：
cargo build --locked --release --no-default-features --features cli,windows-wintun --bin vole
```

## 薄入口与参数

CLI 使用独立 `cli` feature，依赖共享 `invoke`，不要求链接 C ABI 或 WinRT 包入口。
`src/cli.rs` 只解析参数、组装 Invoke 请求、渲染响应和设置退出码；路径解析、环境默认、
配置读取、校验、初始化、退出信号和清理由 `src/invoke/foreground.rs` 管理。
配置解析、图校验、GeoData、DNS、监听器、TUN 与代理协议继续复用现有内核。
CLI 不复制配置规则，不为 `tun.enable` 增加额外的配置错误或平台特判。

支持以下五个参数；解析语法参考仓库中的 Mihomo Go `flag` 入口，不增加其余业务参数、
服务或后台运行模式：

| 参数 | 语义 |
| --- | --- |
| `-d <data-dir>` | 配置及数据目录；默认用户目录下的 `.config/vole`，默认配置文件为 `<data-dir>/config.yaml`。 |
| `-f <config-file>` | 显式配置文件；相对路径从进程启动时的工作目录解析，可位于数据目录之外；`-f -` 从标准输入读取。Invoke 前台操作读取配置并交给同一内核。 |
| `-t` | 仅调用内核配置校验；不创建数据目录、不启动监听器、不解析远端、不联网，不对 TUN 配置另加拒绝分支。 |
| `-v` | 输出内核软件版本和构建身份，不读取配置。 |
| `-h` | 输出帮助，不读取配置。 |

支持 `-f config.yaml`、`-f=config.yaml`、`--f=config.yaml` 等 Go flag 写法，
布尔参数可用 `-t=true`、`-v=false`。遇到第一个位置参数或 `--` 停止参数解析。
`-h`（也接受 `--help`）立即向 stderr 输出帮助并成功退出；`-v` 优先于 `-t`。
参数错误向 stderr 输出静态帮助并返回 2，内核或配置错误返回 1。
文件输入必须是普通文件，文件和标准输入均按既有内核的 256 KiB 上限读取；路径可包含空格和平台原生字符，
例如 `vole -f "/path with spaces/config.yaml"`。配置内容不写回磁盘。

`VOLE_HOME_DIR`、`VOLE_CONFIG_FILE` 分别提供 `-d`、`-f` 的环境默认值，显式参数覆盖环境值；
空值使用默认行为。Unix 用户目录来自 `HOME`，Windows 来自 `USERPROFILE`；缺失时回落到
启动工作目录。默认 `.config/vole` 不存在或无法读取元数据时，若定义了 `XDG_CONFIG_HOME`，
则使用其中的 `vole` 目录。这沿用 Mihomo 的目录选择规则，以 Vole 的名称和环境变量命名。

`-d` 与 `-f` 原样进入 Invoke 路径元数据，路径归属互相独立。Invoke 从启动工作目录
分别解析相对路径，初始化时收到绝对数据目录；只有正常运行模式执行初始化。
非 Unicode 的 Unix 字节路径或 Windows 原生宽字符路径通过 `unixBytes` / `windowsWide`
元数据无损传递。`-t` 通过 `foreground.action=validate` 读取配置并纯校验，不执行初始化、
内部准备或启动。TUN 的平台资源检查留给正常启动。

请求映射固定为：正常运行使用 `foreground.action=run`，`-t` 使用 `validate`，
`-h` 使用 `help`；`-v` 调用 `version`。正常前台操作复用同一个公共实例表，执行
`initialize → createInstance → start(configYaml)`，等待退出后 `stop → destroyInstance`。
配置准备是 `start` 的内部阶段，公共 `prepare` 方法已删除。前台操作的文件、环境和信号行为
只在显式调用 `foreground` 时生效，普通原生宿主的 `start` 不接管进程退出机制。

退出信号、启动失败和关键数据面失败都等待既有停止屏障。CLI 不绕过物理出口、认证或未知
字段拒绝规则。参数错误由入口报告，配置与启动错误由 Invoke 返回。前台诊断仅写入有界
stderr，不输出配置正文、凭据或流量目标；运行期还等待引擎完成通知，并通过 join 保留退出错误。

Unix 通过 SIGINT 或 SIGTERM 请求退出；Windows 通过控制台 Ctrl+C 或 Ctrl+Break
请求退出。信号在准备和启动前注册；标准输入在注册前读取，等待输入时仍可由系统默认 Ctrl+C 终止。
内部准备和启动期间等待当前启动工作器完成后清理，沿用内核已有的 bootstrap DNS 超时。
运行中的会话等待全部组件停止和实例销毁。
参数或配置错误、启动失败、数据面失败与清理失败返回非零状态。

## 平台接入

TUN 完全由配置驱动。`tun.file-descriptor > 0` 时，内核借用宿主 fd 并持有自己的副本；
省略或为 0 时，Linux 与 macOS 的内核根据 `tun.device` 创建或打开原生 TUN。
CLI 不增添 fd 参数或 TUN 专用错误，也不忽略、改写 TUN 配置。移动平台所需的宿主 fd
和 Android protect 仍遵守平台契约，系统接口地址、DNS、路由与物理出口隔离由宿主管理。

Windows 编译时选择互斥的 `windows-wintun` / `windows-uwp`，桌面 CLI 发布选择前者。
已启用 TUN 的业务 Invoke 自动启动该 Wintun 后端；UWP Provider、Session Host
和库交付独立维护，不放入 CLI 归档，也不作为桌面 CLI 的后备启动路径。

Wintun DLL 由宿主提供，与可执行程序目标架构一致。Windows CLI 包不携带 `wintun.dll`。
首版的接口地址、DNS、路由和防递归物理出口配置由宿主承担，Vole 不自动配置系统网络，
也不增加 TUN 专用 CLI 参数。
Wintun 的设备名与 MTU 来自 `tun.device` / `tun.mtu`；默认 MTU 为 9000。设备所有权由
[TUN 平台层](tun-platform.md) 维护，统一启动与前台 payload 见 [Invoke API](invoke-api.md)。

## 发布矩阵与文件

正式版本 tag 自动编译并发布 Linux、Windows、macOS 的 amd64 与 arm64，共六项。
Linux 使用 GNU/glibc 目标，Windows 使用 MSVC，macOS 分别构建两个架构。
归档名称固定如下；文件名不带版本号：

| 平台 | 架构 | Rust 目标 | 归档名称 |
| --- | --- | --- | --- |
| Linux | amd64 | `x86_64-unknown-linux-gnu` | `vole-linux-amd64.gz` |
| Linux | arm64 | `aarch64-unknown-linux-gnu` | `vole-linux-arm64.gz` |
| Windows | amd64 | `x86_64-pc-windows-msvc` | `vole-windows-amd64.zip` |
| Windows | arm64 | `aarch64-pc-windows-msvc` | `vole-windows-arm64.zip` |
| macOS | amd64 | `x86_64-apple-darwin` | `vole-darwin-amd64.gz` |
| macOS | arm64 | `aarch64-apple-darwin` | `vole-darwin-arm64.gz` |

Linux/macOS 仅 gzip 压缩 `vole` 可执行文件，Windows zip 包含 `vole.exe`。
CI 从实际锁定的目标依赖图收集许可证及原生第三方通知，并将完整文本嵌入可执行文件；
打包前逐字节验证保留，Release 描述保留来源说明。不增加通知归档、CLI 参数或额外发布资产。
不生成或发布独立 checksums 文件。版本由 release tag 与核心 `coreVersion` 标识，
构建仍在 CI 内记录 commit、Cargo.lock、目标架构、feature 集、工具链和 artifact hash。
构建身份保持 `Vole;engine=rust;coreVersion=<Cargo package version>`，不增加 API
或配置 revision 字段，也不把版本号写进可执行文件名或归档文件名。

CLI 发布采用独立工作流；现有 [平台库编译](../scripts/README.md) 的 Apple、Android、
Windows 交付约束继续生效。六项 CLI 均使用 locked 依赖和正式 Release 配置，
完整保留生产代理协议；Windows 的 TUN 平台选择为 Wintun。

## tag 触发与验证

以 `v<major>.<minor>.<patch>` 正式版本 tag 的 push 触发，先检查 tag 与 Cargo
package version 一致，再并行完成六项构建。全部构建和检查成功后才创建对应 GitHub
Release 并上传六个归档；某项失败则不发布残缺的 release。
发布身份来自同一 tag 的 commit 与 lockfile，不从工作目录或旧产物推断。

五个参数、请求转换和输出由 `cli::tests::` 覆盖；路径、读取、纯校验与启动中退出由
`invoke::foreground::tests::` 覆盖，配置语义复用现有测试。
`-t` 对有效 TUN 配置只做内核校验，`-v`/`-h` 在没有配置文件时仍可工作。
每个发布目标检查程序格式、架构与构建身份；可执行的本机目标再运行帮助、版本和纯配置校验。
这些检查与真实 TUN、Windows 驱动安装、权限、路由和设备数据面验收分别记录。
macOS 编译或内存测试不能证明 Windows Wintun 设备成功。

本地构建可运行帮助、版本和配置校验。正常运行的监听器及真实网络验收遵守
[测试隔离规则](testing-isolation.md)，不在宿主启动测试服务。
