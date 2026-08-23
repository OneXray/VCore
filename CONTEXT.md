# VCore

VCore turns host-captured IP traffic into routed proxy or direct sessions while keeping platform tunnel integration separate from its protocol graph.

## Language

**Windows VPN provider**:
The packaged Windows background participant that owns one active Windows tunnel session and the VCore runtime serving it.
_Avoid_: Plugin, background task when referring to the whole participant

**Windows provider host**:
The minimal AppContainer executable that supplies a process for Windows to activate the Windows VPN provider.
_Avoid_: Flutter host, plugin executable, background core

**Windows packet adapter**:
The raw-IP exchange point between Windows VPN callbacks and a VCore tunnel runtime.
_Avoid_: UWP TUN, fake fd, channel transport
