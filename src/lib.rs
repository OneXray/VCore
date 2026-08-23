//! VCore's platform-neutral Rust core.
//!
//! Public native bindings are intentionally kept behind the `ffi` feature. Its
//! only business entry point is the JSON `VCoreInvoke` API; that single ABI
//! dispatches to one public runtime lifecycle plus private batch-measurement workers.

pub mod config;
pub mod data_dir;
pub mod dialer;
pub mod dispatch;
pub mod dns;
pub mod error;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod geodata;
pub mod inbound;
pub mod lifecycle;
pub mod limits;
pub mod outbound;
pub mod packet;
pub mod platform;
#[cfg(any(feature = "tun", test))]
mod quic_sniffer;
pub mod resources;
pub mod routing;
#[cfg(all(
    any(
        feature = "outbound-anytls",
        feature = "outbound-socks5",
        feature = "outbound-vless"
    ),
    any(feature = "ffi", test)
))]
mod runtime;
#[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
pub mod security;
pub mod session;
#[cfg(any(feature = "outbound-anytls", feature = "outbound-socks5"))]
mod socks5;
#[cfg(any(feature = "tun", test))]
mod tcp_sniffer;
#[cfg(any(feature = "tun", test))]
pub(crate) mod traffic;
#[cfg(feature = "outbound-vless")]
pub mod transport;
#[cfg(all(feature = "tun", any(unix, windows)))]
mod tun_runtime;
#[cfg(all(windows, feature = "ffi"))]
mod windows_host;
#[cfg(all(windows, feature = "ffi"))]
mod windows_packet_channel;
#[cfg(all(windows, feature = "ffi"))]
mod windows_snapshot;
#[cfg(all(windows, feature = "ffi"))]
mod windows_vpn;
#[cfg(feature = "outbound-vless")]
pub mod xudp;

pub use error::{Result, VCoreError};
pub use lifecycle::{Lifecycle, LifecycleState};
pub use limits::ResourceLimits;
pub use packet::{IpVersion, TunFraming};

/// Strict version carried by every current Invoke request and version response.
pub const INVOKE_API_VERSION: u32 = 5;

/// Internal configuration schema revision reported through Invoke.
///
/// The strict Mihomo YAML subset deliberately carries no version field.
pub const CONFIG_VERSION: u8 = 11;

/// Stable implementation identifier returned by the version Invoke method.
pub const ENGINE: &str = "rust";

/// Stable compatibility identity embedded in every native artifact.
///
/// This is deliberately independent from a source revision. Release tooling
/// records the immutable Git revision and artifact hash separately.
pub const BUILD_IDENTITY: &str = concat!(
    "OneVCore/VCore;engine=rust;coreVersion=",
    env!("CARGO_PKG_VERSION"),
    ";invokeApiVersion=5;configVersion=11"
);
