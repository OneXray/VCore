# Own the Windows VPN provider in VCore

The Windows VPN provider will be a Windows-only VCore module exported from `vcore.dll`, alongside the existing FFI, rather than a separate crate. This keeps the Windows packet adapter and runtime lifecycle private instead of exposing `PreparedCore`, `RunningCore`, or a temporary spike interface solely to connect another DLL.
