---
status: accepted
---

# Run the Windows runtime in a full-trust session host

The AppContainer Windows VPN provider owns `VpnChannel`, packet buffers, routes, physical-network monitoring, fail-closed Stop, and the two AppContainer-local named-pipe servers. A dedicated hidden packaged full-trust Session Host, activated through `IApplicationActivationManager`, owns the complete VCore runtime for one VPN session and connects through the Provider's qualified AppContainer named-object path. A strict package-local rendezvous carries only the protocol version, snapshot token, relative object path, and fixed pipe leaf names. This preserves VCore's existing proxy protocols while making its authenticated traffic Controller and ordinary loopback SOCKS5 outbounds reachable without Wintun, `CheckNetIsolation`, `LoopbackAccessRules`, custom broad DACLs, or protocol-specific relays. The process identity, parent-exit lifecycle, namespace isolation, 100,002-frame packet channel, EOF, and initial throughput gates passed in Phase 0 of the [Windows Session Runtime refactor plan](../windows-session-runtime-refactor-plan.md).
