#[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
pub mod http;

#[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
pub(crate) mod listen;

#[cfg(feature = "inbound-socks5")]
pub mod socks5;

pub const DEFAULT_HEADER_LIMIT: usize = 32 * 1024;
pub const DEFAULT_HEADER_COUNT_LIMIT: usize = 100;
