//! TLS and REALITY security layers used by outbound transports.

#[cfg(feature = "tls-fingerprint")]
mod boring;
#[cfg(feature = "tls-fingerprint")]
mod boring_resumption;
#[cfg(feature = "tls-fingerprint")]
mod boring_stream;
#[cfg(feature = "outbound-vless")]
mod client;
mod context;
mod resumption;
mod stream;
mod tls;
mod verifier;
#[cfg(feature = "outbound-vless")]
pub(crate) mod vision;

#[cfg(feature = "outbound-vless")]
pub use client::{REALITY_CLIENT_VERSION, SecurityClient};
pub use context::SecurityContext;
pub use stream::CLOSE_NOTIFY_TIMEOUT;
pub use tls::{
    StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsCertificatePolicy, TlsClientIdentity,
    TlsClientOptions, TlsVersions,
};

#[cfg(test)]
fn test_profiles() -> &'static [Option<crate::config::ClientFingerprint>] {
    #[cfg(feature = "tls-fingerprint")]
    {
        &[None, Some(crate::config::ClientFingerprint::Chrome120)]
    }
    #[cfg(not(feature = "tls-fingerprint"))]
    {
        &[None]
    }
}
