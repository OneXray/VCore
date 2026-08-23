---
status: proposed
---

# Run the Windows runtime in a full-trust session host

The AppContainer Windows VPN provider will own `VpnChannel`, packet buffers, routes, physical-network monitoring, and fail-closed Stop, while a dedicated packaged full-trust Session Host owns the complete VCore runtime for one VPN session. The two processes will exchange bounded raw-IP packets and lifecycle messages over same-package named pipes. This preserves VCore's existing proxy protocols while making its authenticated traffic Controller and ordinary loopback SOCKS5 outbounds reachable without Wintun, `CheckNetIsolation`, `LoopbackAccessRules`, or protocol-specific relays. This decision becomes accepted only after the process-identity, ACL, lifecycle, and packet-channel spike in the [Windows Session Runtime refactor plan](../windows-session-runtime-refactor-plan.md) passes.
