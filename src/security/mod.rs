//! TLS and REALITY security layers used by outbound transports.

#[cfg(feature = "outbound-vless")]
mod client;
mod context;
mod tls;

#[cfg(feature = "outbound-vless")]
pub use client::{REALITY_CLIENT_VERSION, SecurityClient};
pub use context::SecurityContext;
pub use tls::TLS_RESUMPTION_SESSION_BUDGET;
pub(crate) use tls::{StandardTlsClient, StandardTlsProfile};
