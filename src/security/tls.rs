use std::{io, sync::Arc};

use rustls::{
    ClientConfig,
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    version::{TLS12, TLS13},
};
use tokio_rustls::TlsConnector;

use crate::dispatch::BoxStream;

use super::SecurityContext;

pub(crate) const DEFAULT_TLS_BUFFER_LIMIT: usize = 64 * 1024;

/// Aggregate per-runtime cache budget shared across standard TLS nodes.
/// REALITY disables resumption and does not consume this budget.
pub const TLS_RESUMPTION_SESSION_BUDGET: usize = 4;

/// Certificate policy shared by TLS transports. A matching leaf pin is the
/// trust decision; a non-leaf pin still verifies the chain and name. Explicit
/// pin/name checks take precedence over `skip_cert_verify`, as in Mihomo.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TlsCertificatePolicy {
    pub verification_name: Option<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<[u8; 32]>,
}

impl std::fmt::Debug for TlsCertificatePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCertificatePolicy")
            .field("explicit_name", &self.verification_name.is_some())
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("pinned", &self.fingerprint.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsVersions {
    #[default]
    Tls12And13,
    Tls13,
}

/// Immutable per-node, per-transport TLS options. Constructing another client
/// always creates an independent resumption store, even for the same SNI.
#[derive(Default)]
pub struct TlsClientOptions {
    pub versions: TlsVersions,
    pub alpn: Vec<Vec<u8>>,
    pub required_alpn: Option<Vec<u8>>,
    pub certificate: TlsCertificatePolicy,
    pub identity: Option<TlsClientIdentity>,
}

impl std::fmt::Debug for TlsClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientOptions")
            .field("versions", &self.versions)
            .field("alpn_count", &self.alpn.len())
            .field("requires_alpn", &self.required_alpn.is_some())
            .field("certificate", &self.certificate)
            .field("client_identity", &self.identity.is_some())
            .finish()
    }
}

/// A node-owned certificate chain and matching key. The provider validates the
/// key pair while constructing the client, before any supplied stream is used.
/// No file loading, environment key logging or dynamic identity reload occurs.
pub struct TlsClientIdentity {
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl TlsClientIdentity {
    pub fn from_der(
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self { certificates, key }
    }
}

impl std::fmt::Debug for TlsClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientIdentity").finish_non_exhaustive()
    }
}

/// TLS protocol policy for a standard WebPKI client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(feature = "outbound-vless", test))]
pub(crate) enum StandardTlsProfile {
    /// VLESS XHTTP is TLS 1.3 and HTTP/2 only.
    VlessXhttp,
}

/// Reusable standard TLS client shared by protocol-specific outbound code.
///
/// REALITY remains in [`super::SecurityClient`] because it uses the local
/// rustls fork's distinct verifier and session policy.
#[derive(Clone)]
pub struct StandardTlsClient {
    connector: TlsConnector,
    server_name: String,
    required_alpn: Option<Vec<u8>>,
    buffer_limit: usize,
}

impl std::fmt::Debug for StandardTlsClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandardTlsClient")
            .field("requires_alpn", &self.required_alpn.is_some())
            .field("buffer_limit", &self.buffer_limit)
            .finish_non_exhaustive()
    }
}

impl StandardTlsClient {
    #[cfg(any(feature = "outbound-vless", test))]
    pub(crate) fn new(
        context: &SecurityContext,
        server_name: impl Into<String>,
        profile: StandardTlsProfile,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let options = match profile {
            StandardTlsProfile::VlessXhttp => TlsClientOptions {
                versions: TlsVersions::Tls13,
                alpn: vec![b"h2".to_vec()],
                required_alpn: Some(b"h2".to_vec()),
                ..Default::default()
            },
        };
        Self::with_options(
            context,
            server_name,
            options,
            resumption_sessions,
            buffer_limit,
        )
    }

    #[cfg(feature = "outbound-anytls")]
    pub(crate) fn for_anytls(
        context: &SecurityContext,
        server_name: impl Into<String>,
        policy: &crate::config::AnyTlsCertificatePolicy,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Self::with_options(
            context,
            server_name,
            TlsClientOptions {
                alpn: policy.alpn.clone(),
                certificate: TlsCertificatePolicy {
                    verification_name: None,
                    skip_cert_verify: policy.skip_cert_verify,
                    fingerprint: policy.fingerprint,
                },
                ..Default::default()
            },
            resumption_sessions,
            buffer_limit,
        )
    }

    /// Wraps caller-supplied streams only: no socket, resolver, background task
    /// or unbounded shared cache is created here. The graph allocates ticket
    /// capacity from its existing aggregate budget; zero disables resumption.
    pub fn with_options(
        context: &SecurityContext,
        server_name: impl Into<String>,
        options: TlsClientOptions,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let server_name = server_name.into();
        let name = ServerName::try_from(server_name.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        if buffer_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS buffer limit must be greater than zero",
            ));
        }
        if resumption_sessions > TLS_RESUMPTION_SESSION_BUDGET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS ticket capacity exceeds the runtime budget",
            ));
        }
        let alpn_size = options.alpn.iter().try_fold(0_usize, |size, protocol| {
            if !(1..=255).contains(&protocol.len()) {
                return None;
            }
            size.checked_add(1 + protocol.len())
                .filter(|total| *total <= 65_533)
        });
        if alpn_size.is_none()
            || options
                .required_alpn
                .as_ref()
                .is_some_and(|required| !options.alpn.contains(required))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TLS ALPN policy",
            ));
        }

        let protocol_versions: &[&'static rustls::SupportedProtocolVersion] = match options.versions
        {
            TlsVersions::Tls13 => &[&TLS13],
            TlsVersions::Tls12And13 => &[&TLS13, &TLS12],
        };
        let builder = ClientConfig::builder_with_provider(context.provider.clone())
            .with_protocol_versions(protocol_versions)
            .map_err(io_other)?
            .with_root_certificates(context.tls_roots.clone());
        let mut config = if let Some(identity) = options.identity {
            let identity_size = identity
                .certificates
                .iter()
                .try_fold(identity.key.secret_der().len(), |size, cert| {
                    size.checked_add(cert.len())
                });
            if identity_size.is_none_or(|size| size > crate::config::MAX_CONFIG_BYTES) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS client identity exceeds the configuration bound",
                ));
            }
            builder
                .with_client_auth_cert(identity.certificates, identity.key)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS client identity")
                })?
        } else {
            builder.with_no_client_auth()
        };
        config.resumption = if resumption_sessions == 0 {
            Resumption::disabled()
        } else {
            Resumption::store(Arc::new(super::resumption::NodeSessionStore::new(
                name,
                resumption_sessions,
            )))
        };

        config.alpn_protocols = options.alpn;
        config.dangerous().set_certificate_verifier(Arc::new(
            super::verifier::CertificateVerifier::new(context, options.certificate)?,
        ));

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            required_alpn: options.required_alpn,
            buffer_limit,
        })
    }

    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let tls = self
            .connector
            .connect_with(server_name, stream, |connection| {
                connection.set_buffer_limit(Some(self.buffer_limit));
            })
            .await
            .map_err(|error| io::Error::new(error.kind(), "TLS handshake failed"))?;

        if let Some(required_alpn) = self.required_alpn.as_deref()
            && tls.get_ref().1.alpn_protocol() != Some(required_alpn)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS server did not negotiate the required ALPN",
            ));
        }

        Ok(Box::new(super::stream::TlsStream::new(tls)))
    }

    #[cfg(test)]
    pub(super) const fn buffer_limit(&self) -> usize {
        self.buffer_limit
    }
}

fn io_other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
