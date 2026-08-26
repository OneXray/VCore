---
status: accepted
---

# ADR 0002：由 VCore 构建 Windows Provider Host

VCore 与 `vcore.dll` 一同构建最小的 Rust AppContainer 可执行文件 `vcore-windows-vpn-host.exe`，供 Windows 激活 VPN Provider。该进程不拥有前台界面、配置快照或产品业务。

OneVCore 按目标架构把 DLL 和 Host 作为一组不可变输入打包，不在 Flutter 侧复制 Provider 进程契约，也不维护第二套实现。
