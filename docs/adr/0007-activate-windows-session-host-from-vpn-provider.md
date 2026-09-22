---
status: accepted
---

# Activate the Windows Session Host from the VPN Provider

A package has one Application but keeps separate full-trust foreground, AppContainer Provider, and full-trust Session Host processes. The Provider launches the Session Host through parameterless `FullTrustProcessLauncher`; the rendezvous token remains untrusted until the Provider binds it to the profile token during the existing handshake, preserving Windows 10 support without another protocol or compatibility path.
