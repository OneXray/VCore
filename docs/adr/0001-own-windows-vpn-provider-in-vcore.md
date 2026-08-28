---
status: accepted
---

# ADR 0001：Windows VPN Provider 归属 VCore

Windows VPN Provider 是 `vcore.dll` 中仅限 Windows 的模块，与现有 FFI 一同由 VCore 构建，不拆成独立 crate。

该边界把 Windows 包适配器和运行时生命周期保留在 VCore 内部，避免为连接另一个 DLL 而公开 `PreparedCore`、`RunningCore` 等内部类型。宿主只负责打包和调用公开桥接接口。
