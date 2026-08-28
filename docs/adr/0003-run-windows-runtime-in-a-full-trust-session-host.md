---
status: accepted
---

# ADR 0003：在完全信任的 Session Host 中运行 Windows 会话

AppContainer Provider 只拥有 `VpnChannel`、包缓冲区、路由、物理网络监控、失败关闭和两条命名管道服务端。每次 VPN 会话由一个隐藏的同包完全信任进程 `vcore-windows-session-host.exe` 独占完整 VCore 运行时。

Session Host 通过 `IApplicationActivationManager` 激活，并使用 Provider 发布的 AppContainer 限定对象路径连接控制管道和数据管道。会合记录只包含协议版本、快照令牌、相对对象路径和固定管道名称。

该拆分使 Controller 和本机 SOCKS5 服务可由完全信任进程正常访问，同时不引入 Wintun、`CheckNetIsolation` 豁免、宽泛 DACL 或按协议转发层。完整契约见 [Windows 会话运行时](../windows-session-runtime.md)。
