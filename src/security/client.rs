use std::{io, sync::Arc};

#[cfg(feature = "interop-test")]
use rustls::RootCertStore;
use rustls::{
    ClientConfig,
    client::{RealityClientConfig, Resumption},
    pki_types::ServerName,
    version::TLS13,
};
use tokio_rustls::TlsConnector;

use crate::{
    config::{SecurityConfig, VlessOutboundConfig},
    dispatch::BoxStream,
};

use super::{
    SecurityContext,
    tls::{
        DEFAULT_TLS_BUFFER_LIMIT, StandardTlsClient, StandardTlsProfile,
        TLS_RESUMPTION_SESSION_BUDGET,
    },
};

/// Current Xray compatibility version carried in the encrypted REALITY session ID.
///
/// Xray-core 26.7.11 defaults `minClientVer` to 26.3.27. VCore pins the wire
/// version here rather than exposing another profile field.
pub const REALITY_CLIENT_VERSION: [u8; 3] = [26, 7, 11];

#[derive(Clone)]
enum SecurityBackend {
    Standard(StandardTlsClient),
    Reality {
        connector: TlsConnector,
        server_name: String,
        buffer_limit: usize,
    },
}

#[derive(Clone)]
pub struct SecurityClient {
    backend: SecurityBackend,
}

impl std::fmt::Debug for SecurityClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.backend {
            SecurityBackend::Standard(client) => formatter
                .debug_tuple("SecurityClient::Standard")
                .field(client)
                .finish(),
            SecurityBackend::Reality {
                server_name,
                buffer_limit,
                ..
            } => formatter
                .debug_struct("SecurityClient::Reality")
                .field("server_name", server_name)
                .field("buffer_limit", buffer_limit)
                .finish_non_exhaustive(),
        }
    }
}

impl SecurityClient {
    /// Builds one TLS or REALITY transport leg from its normalized security
    /// configuration. A VLESS XHTTP download leg may use security settings
    /// distinct from the enclosing proxy's primary leg.
    pub fn from_security(config: &SecurityConfig) -> io::Result<Self> {
        Self::from_security_with_context(
            config,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
    }

    /// Backwards-compatible primary-leg constructor.
    pub fn from_proxy(config: &VlessOutboundConfig) -> io::Result<Self> {
        Self::from_security(&config.security)
    }

    /// Builds one node from instance-shared cryptographic material. The
    /// caller allocates the aggregate TLS resumption budget across standard-TLS
    /// nodes; zero disables resumption when the fixed four-session runtime
    /// budget cannot provide a slot for every node. REALITY always ignores the
    /// budget because its resumption policy is disabled.
    pub(crate) fn from_proxy_with_context(
        config: &VlessOutboundConfig,
        context: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Self::from_security_with_context(
            &config.security,
            context,
            resumption_sessions,
            buffer_limit,
        )
    }

    pub(crate) fn from_security_with_context(
        config: &SecurityConfig,
        context: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Self::from_security_with_security_context(
            config,
            context,
            resumption_sessions,
            buffer_limit,
        )
    }

    /// Builds a standard-TLS client with explicit local-test trust anchors.
    ///
    /// This entry point does not exist unless the `interop-test` feature is
    /// enabled. Production builds always use the bundled WebPKI roots.
    #[cfg(feature = "interop-test")]
    pub(crate) fn from_proxy_with_test_tls_roots(
        config: &VlessOutboundConfig,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        Self::from_security_with_test_tls_roots(&config.security, roots_der)
    }

    #[cfg(feature = "interop-test")]
    pub(crate) fn from_security_with_test_tls_roots(
        config: &SecurityConfig,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        if !matches!(config, SecurityConfig::Tls(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "test TLS roots can only be used with standard TLS",
            ));
        }
        let mut roots = RootCertStore::empty();
        for root in roots_der {
            roots
                .add(rustls::pki_types::CertificateDer::from(root))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        }
        if roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one test TLS root is required",
            ));
        }
        Self::from_security_with_security_context(
            config,
            &SecurityContext::with_tls_roots(roots),
            TLS_RESUMPTION_SESSION_BUDGET,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
    }

    fn from_security_with_security_context(
        config: &SecurityConfig,
        context: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        if buffer_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS buffer limit must be greater than zero",
            ));
        }
        let backend = match config {
            SecurityConfig::Tls(tls) => SecurityBackend::Standard(StandardTlsClient::new(
                context,
                &tls.server_name,
                StandardTlsProfile::VlessXhttp,
                resumption_sessions,
                buffer_limit,
            )?),
            SecurityConfig::Reality(reality) => {
                let reality = RealityClientConfig::new(
                    reality.public_key,
                    &reality.short_id,
                    REALITY_CLIENT_VERSION,
                )
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let mut tls_config = ClientConfig::builder_with_provider(context.provider.clone())
                    .with_protocol_versions(&[&TLS13])
                    .map_err(io_other)?
                    .with_reality(reality)
                    .map_err(io_other)?
                    .with_no_client_auth();
                tls_config.resumption = Resumption::disabled();
                tls_config.enable_early_data = false;
                // Xray REALITY does not echo ALPN, so XHTTP deliberately starts
                // h2 even when negotiated ALPN is nil.
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
                SecurityBackend::Reality {
                    connector: TlsConnector::from(Arc::new(tls_config)),
                    server_name: config.server_name().to_owned(),
                    buffer_limit,
                }
            }
        };

        Ok(Self { backend })
    }

    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        match &self.backend {
            SecurityBackend::Standard(client) => client.connect(stream).await,
            SecurityBackend::Reality {
                connector,
                server_name,
                buffer_limit,
            } => {
                let server_name = ServerName::try_from(server_name.clone())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let tls = connector
                    .connect_with(server_name, stream, |connection| {
                        connection.set_buffer_limit(Some(*buffer_limit));
                    })
                    .await
                    .map_err(io_other)?;
                Ok(Box::new(tls))
            }
        }
    }

    #[cfg(test)]
    const fn buffer_limit(&self) -> usize {
        match &self.backend {
            SecurityBackend::Standard(client) => client.buffer_limit(),
            SecurityBackend::Reality { buffer_limit, .. } => *buffer_limit,
        }
    }
}

fn io_other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SecurityConfig, TlsConfig, VlessEncryption, XHttpConfig, XHttpMode};

    fn tls_proxy() -> VlessOutboundConfig {
        VlessOutboundConfig {
            address: "example.com".to_owned(),
            port: 443,
            id: uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
            encryption: VlessEncryption::None,
            flow: String::new(),
            security: SecurityConfig::Tls(TlsConfig {
                server_name: "example.com".to_owned(),
            }),
            xhttp: XHttpConfig {
                path: "/xhttp".to_owned(),
                host: "example.com".to_owned(),
                mode: XHttpMode::StreamOne,
                download: None,
            },
        }
    }

    #[test]
    fn default_and_shared_clients_keep_distinct_tls_buffer_limits() {
        let config = tls_proxy();
        let default = SecurityClient::from_proxy(&config).unwrap();
        assert_eq!(default.buffer_limit(), 64 * 1024);

        let context = SecurityContext::new();
        let limited =
            SecurityClient::from_proxy_with_context(&config, &context, 4, 16 * 1024).unwrap();
        assert_eq!(limited.buffer_limit(), 16 * 1024);
        let without_resumption =
            SecurityClient::from_proxy_with_context(&config, &context, 0, 16 * 1024).unwrap();
        assert_eq!(without_resumption.buffer_limit(), 16 * 1024);
        assert!(SecurityClient::from_proxy_with_context(&config, &context, 4, 0).is_err());
    }

    #[test]
    fn security_level_constructor_matches_the_proxy_wrapper() {
        let config = tls_proxy();
        let direct = SecurityClient::from_security(&config.security).unwrap();
        let wrapped = SecurityClient::from_proxy(&config).unwrap();
        assert_eq!(direct.buffer_limit(), wrapped.buffer_limit());

        let context = SecurityContext::new();
        let direct =
            SecurityClient::from_security_with_context(&config.security, &context, 1, 8 * 1024)
                .unwrap();
        assert_eq!(direct.buffer_limit(), 8 * 1024);
    }

    #[test]
    fn security_level_constructor_keeps_an_independent_reality_identity() {
        let security = SecurityConfig::Reality(crate::config::RealityConfig {
            server_name: "download.example.com".to_owned(),
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
        });
        let client = SecurityClient::from_security_with_context(
            &security,
            &SecurityContext::new(),
            4,
            12 * 1024,
        )
        .unwrap();
        let SecurityBackend::Reality {
            server_name,
            buffer_limit,
            ..
        } = &client.backend
        else {
            panic!("REALITY security must build the REALITY backend")
        };
        assert_eq!(server_name, "download.example.com");
        assert_eq!(*buffer_limit, 12 * 1024);
    }
}
