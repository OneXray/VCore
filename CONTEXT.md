# VCore

VCore turns host-captured IP traffic into routed proxy or direct sessions while keeping platform tunnel integration separate from its protocol graph.

## Language

**Windows VPN provider**:
The packaged AppContainer participant that owns one active Windows tunnel session and exchanges its raw-IP packets with the Windows session runtime.
_Avoid_: Plugin, background task when referring to the whole participant, proxy core

**Windows session runtime**:
The VCore runtime serving one active Windows tunnel session inside the Windows session host.
_Avoid_: Flutter runtime, provider runtime, external core

**Windows session host**:
The hidden packaged full-trust Application that owns the Windows session runtime independently of the Flutter foreground.
_Avoid_: Flutter process, provider host, external-core host

**Windows provider host**:
The minimal AppContainer executable that supplies a process for Windows to activate the Windows VPN provider.
_Avoid_: Flutter host, plugin executable, background core

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
A normal VCore SOCKS5 outbound whose loopback server is owned and managed outside VCore. A `socks5://` URI describes the endpoint but is not a second configuration format.
_Avoid_: Managed core, child core, URI configuration
