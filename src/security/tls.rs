use std::{io, sync::Arc};

use rustls::{
    ClientConfig,
    client::Resumption,
    pki_types::ServerName,
    version::{TLS12, TLS13},
};
use tokio_rustls::TlsConnector;

use crate::dispatch::BoxStream;

use super::SecurityContext;

pub(crate) const DEFAULT_TLS_BUFFER_LIMIT: usize = 64 * 1024;

/// Aggregate per-runtime cache budget shared across standard TLS nodes.
/// REALITY disables resumption and does not consume this budget.
pub const TLS_RESUMPTION_SESSION_BUDGET: usize = 4;

/// TLS protocol policy for a standard WebPKI client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandardTlsProfile {
    /// VLESS XHTTP is TLS 1.3 and HTTP/2 only.
    VlessXhttp,
    /// AnyTLS uses TLS 1.2 or 1.3 and intentionally sends no ALPN.
    AnyTls,
}

/// Reusable standard TLS client shared by protocol-specific outbound code.
///
/// REALITY remains in [`super::SecurityClient`] because it uses the local
/// rustls fork's distinct verifier and session policy.
#[derive(Clone)]
pub(crate) struct StandardTlsClient {
    connector: TlsConnector,
    server_name: String,
    required_alpn: Option<&'static [u8]>,
    buffer_limit: usize,
}

impl std::fmt::Debug for StandardTlsClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandardTlsClient")
            .field("server_name", &self.server_name)
            .field("required_alpn", &self.required_alpn)
            .field("buffer_limit", &self.buffer_limit)
            .finish_non_exhaustive()
    }
}

impl StandardTlsClient {
    pub(crate) fn new(
        context: &SecurityContext,
        server_name: impl Into<String>,
        profile: StandardTlsProfile,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        if buffer_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS buffer limit must be greater than zero",
            ));
        }

        let protocol_versions: &[&'static rustls::SupportedProtocolVersion] = match profile {
            StandardTlsProfile::VlessXhttp => &[&TLS13],
            StandardTlsProfile::AnyTls => &[&TLS13, &TLS12],
        };
        let mut config = ClientConfig::builder_with_provider(context.provider.clone())
            .with_protocol_versions(protocol_versions)
            .map_err(io_other)?
            .with_root_certificates(context.tls_roots.clone())
            .with_no_client_auth();
        config.resumption = if resumption_sessions == 0 {
            Resumption::disabled()
        } else {
            Resumption::in_memory_sessions(resumption_sessions)
        };

        let required_alpn = match profile {
            StandardTlsProfile::VlessXhttp => {
                config.alpn_protocols = vec![b"h2".to_vec()];
                Some(b"h2".as_slice())
            }
            StandardTlsProfile::AnyTls => None,
        };

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name: server_name.into(),
            required_alpn,
            buffer_limit,
        })
    }

    pub(crate) async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let tls = self
            .connector
            .connect_with(server_name, stream, |connection| {
                connection.set_buffer_limit(Some(self.buffer_limit));
            })
            .await
            .map_err(io_other)?;

        if let Some(required_alpn) = self.required_alpn
            && tls.get_ref().1.alpn_protocol() != Some(required_alpn)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS server did not negotiate the required ALPN",
            ));
        }

        Ok(Box::new(tls))
    }

    #[cfg(test)]
    pub(super) const fn buffer_limit(&self) -> usize {
        self.buffer_limit
    }
}

fn io_other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}
