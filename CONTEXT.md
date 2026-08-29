# VCore

VCore turns host-captured IP traffic into routed proxy or direct sessions while keeping platform tunnel integration separate from its protocol graph.

## Language

**Windows VPN provider**:
The packaged AppContainer participant that owns one active Windows tunnel session and exchanges its raw-IP packets with the Windows session runtime.
_Avoid_: Plugin, background task when referring to the whole participant, proxy core

**Windows session runtime**:
The VCore runtime serving one active Windows tunnel session inside the Windows session host.
_Avoid_: Foreground runtime, provider runtime, external core

**Windows session host**:
The hidden packaged full-trust Application that owns one Windows session runtime and its optional Windows session backend independently of the foreground host.
_Avoid_: Foreground process, provider host, external-core host

**Windows session backend**:
The optional ordered set of package-local processes whose lifetime is owned by one Windows session host. VCore supervises process liveness but does not interpret their arguments, files, ports, or protocols.
_Avoid_: External core, process service, plugin

**Windows managed session process**:
One ordinary-user child in a Windows session backend. Every managed process is critical to its VPN session and runs inside the Session Host-owned Job Object.
_Avoid_: Daemon, Windows service, helper PID

**Windows provider host**:
The minimal AppContainer executable that supplies a process for Windows to activate the Windows VPN provider.
_Avoid_: Foreground host, plugin executable, background core

**Windows packet adapter**:
The raw-IP exchange point between Windows VPN callbacks and a VCore tunnel runtime.
_Avoid_: UWP TUN, fake fd, channel transport

**Windows packet channel**:
The Provider-owned AppContainer named-pipe connection carrying raw-IP packets and lifecycle control to the Windows session host.
_Avoid_: Controller, VPN transport, socket exemption

**Windows rendezvous record**:
The small package-local record that lets one Windows session host locate the active Provider's AppContainer packet channel.
_Avoid_: Session record, tunnel snapshot, configuration file

**Physical network binding**:
The immutable adapter identity and source-IP/interface-index pairs selected for one Windows tunnel session.
_Avoid_: Default interface, automatic fallback, interface-only binding

**TUN traffic snapshot**:
The current rate and session totals for raw-IP bytes crossing a VCore TUN boundary.
_Avoid_: Proxy traffic, transport traffic, per-node traffic

**Local SOCKS5 outbound**:
A normal VCore SOCKS5 outbound to a loopback server. The server may be managed outside VCore or happen to run in a Windows session backend; SOCKS5 readiness and protocol health remain outside the backend contract.
_Avoid_: Managed core, child core, URI configuration

**Proxy node**:
A named, concrete outbound protocol path that can be selected as a route target or referenced by another proxy node through `dialer-proxy`.
_Avoid_: Proxy when a proxy group or route target is intended, server profile

**Proxy group**:
A named route target whose current group selection identifies one direct member route target.
_Avoid_: Folder, provider, subscription

**Route target**:
A proxy node, proxy group, or reserved built-in target that routing rules, the final `MATCH`, and DNS routes can select.
_Avoid_: Proxy when the distinction between a node and group matters, dialer

**Group selection**:
The running-session state identifying the direct member route target currently chosen by a proxy group.
_Avoid_: Variant, configuration switch, active profile
