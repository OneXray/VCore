//! TLS and REALITY security layers used by outbound transports.

#[cfg(feature = "outbound-anytls")]
mod anytls_verifier;
#[cfg(feature = "outbound-vless")]
mod client;
mod context;
mod resumption;
mod tls;

#[cfg(feature = "outbound-vless")]
pub use client::{REALITY_CLIENT_VERSION, SecurityClient};
pub use context::SecurityContext;
pub(crate) use tls::StandardTlsClient;
pub use tls::TLS_RESUMPTION_SESSION_BUDGET;
