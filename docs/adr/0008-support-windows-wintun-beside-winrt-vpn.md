---
status: accepted
---

# ADR 0008：Windows Wintun 与 WinRT VPN 共用内核

Windows 保留两种用途明确的平台适配。已有 MSIX VPN 继续使用
`Windows.Networking.Vpn`、AppContainer Provider、packet channel 和每会话
Session Host；普通桌面宿主通过 Wintun 接入原始 IP 包。两者共用 `TunIo` 边界后的
TunRuntime、netstack、DNS、规则、代理图、资源策略与 Dialer，不新增第二个代理内核、
按协议 socket 工厂或文件描述符模拟层。

桌面 Wintun 不借助 Windows VPN profile、包身份、Provider 激活或 Session Host
会合协议。WinRT 路径也不在失败时切换到 Wintun。适配器选择发生在正常平台启动边界，
配置校验继续由既有内核执行；CLI 只组装参数请求、调用共用 Invoke 并渲染响应。
`windows-wintun` 与 `windows-uwp` 在 Windows 编译时互斥；Wintun 选择不引入
WinRT VPN 功能或包宿主，UWP 选择也不引入 tun-rs 的 Windows Wintun 依赖。
Wintun 依赖的 Win32 bindings 可以间接存在于图中；按实际 Windows features
区分它们与 `Networking_Vpn` / `ApplicationModel` 等 WinRT 包功能。

Wintun 的动态库由宿主提供，Windows CLI 归档不携带 `wintun.dll`。首版地址、DNS、
路由和防递归物理出口配置由宿主负责，Vole 不自动配置系统网络。
平台启动失败和资源取消都受同步停止屏障约束，不能回退到未经保护的普通 socket。

ADR 0001、0002、0004 与 0007 的安装包参与者和所有权约束继续适用于 WinRT VPN；
它们不定义桌面 Wintun 的进程边界。ADR 0003 中不引入 Wintun 的拆分理由也仅适用于
该 WinRT 包路径，不再构成整个 Vole 禁止 Wintun 的约束。
已有 Windows 11 包环境验收不转移到 Wintun；驱动、权限、原始包、物理出口和停止释放
必须独立取证。当前非 Windows 主机不能完成这组设备验收。

当前平台契约见 [TUN 平台层](../tun-platform.md)；后续 CLI 与发布见
[CLI 与 tag 发布](../cli.md)。
