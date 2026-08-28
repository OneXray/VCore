#[cfg(feature = "inbound-http")]
pub mod http;

pub const DEFAULT_HEADER_LIMIT: usize = 32 * 1024;
pub const DEFAULT_HEADER_COUNT_LIMIT: usize = 100;
