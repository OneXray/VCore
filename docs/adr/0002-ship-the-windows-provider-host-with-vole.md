---
status: accepted
---

# ADR 0002：由 Vole 构建 Windows Provider Host

Vole 与 `vole.dll` 一同构建最小的 Rust AppContainer 可执行文件 `vole-windows-vpn-host.exe`，供 Windows 激活 VPN Provider。该进程不拥有前台界面、配置快照或产品业务。

宿主按目标架构把 DLL 和 Host 作为一组不可变输入打包，不复制 Provider 进程契约，也不维护第二套实现。
