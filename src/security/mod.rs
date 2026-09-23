//! TLS and REALITY security layers used by outbound transports.

#[cfg(feature = "outbound-vless")]
mod client;
mod context;
mod resumption;
mod stream;
mod tls;
mod verifier;

#[cfg(feature = "outbound-vless")]
pub use client::{REALITY_CLIENT_VERSION, SecurityClient};
pub use context::SecurityContext;
pub use tls::{
    StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsCertificatePolicy, TlsClientIdentity,
    TlsClientOptions, TlsVersions,
};
