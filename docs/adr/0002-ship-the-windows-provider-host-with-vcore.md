# Ship the Windows provider host with VCore

VCore builds the minimal Rust AppContainer executable that hosts activation of its Windows VPN provider, alongside `vcore.dll`; the host contains no foreground profile, snapshot, or product behavior. OneVCore packages the matching host and DLL as immutable architecture-specific inputs instead of promoting the research shell, making Flutter executable code, or maintaining a second implementation of the provider process contract.
