//! Named TLS profiles over caller-supplied IO. Certificate policy is shared with
//! rustls, not a second OpenSSL trust policy. This module never resolves or dials.
use super::boring_stream::{BoringStream, KeepOpen};
use super::{SecurityContext, TlsClientOptions, TlsVersions};
use crate::dispatch::BoxStream;
use boring::{
    pkey::PKey,
    ssl::{
        ClientFingerprint, ConnectConfiguration, FingerprintConnector, SslAlert, SslConnector,
        SslMethod, SslVerifyError, SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
pub(super) struct BoringTlsClient {
    connector: Connector,
    server_name: String,
    alpn: Vec<u8>,
    required_alpn: Option<Vec<u8>>,
    sessions: super::boring_resumption::Sessions,
    #[cfg(feature = "outbound-vless")]
    reality: Option<boring::ssl::RealityClientConfig>,
}

#[derive(Clone)]
enum Connector {
    #[cfg(feature = "outbound-vless")]
    Default(SslConnector),
    Named(FingerprintConnector),
}
impl Connector {
    fn configure(&self, alpn: &[u8]) -> Result<ConnectConfiguration, boring::error::ErrorStack> {
        match self {
            #[cfg(feature = "outbound-vless")]
            Self::Default(connector) => {
                let mut config = connector.configure()?;
                config.set_alpn_protos(alpn)?;
                Ok(config)
            }
            Self::Named(connector) => connector.configure(alpn),
        }
    }
}

impl BoringTlsClient {
    pub(super) fn standard(
        context: &SecurityContext,
        server_name: &str,
        options: &TlsClientOptions,
        capacity: usize,
    ) -> io::Result<Self> {
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| invalid())?;
        let verifier = Arc::new(super::verifier::CertificateVerifier::new(
            context,
            options.certificate.clone(),
        )?);
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| invalid())?;
        builder
            .set_min_proto_version(Some(match options.versions {
                TlsVersions::Tls13 => SslVersion::TLS1_3,
                TlsVersions::Tls12And13 => SslVersion::TLS1_2,
            }))
            .map_err(|_| invalid())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        let sessions = super::boring_resumption::Sessions::new(&mut builder, capacity)?;
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let reject = || SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE);
            let chain = ssl.peer_cert_chain().ok_or_else(reject)?;
            let certificates = chain
                .iter()
                .map(|cert| cert.to_der().map(CertificateDer::from))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| reject())?;
            let (leaf, rest) = certificates.split_first().ok_or_else(reject)?;
            verifier
                .verify_server_cert(
                    leaf,
                    rest,
                    &name,
                    ssl.ocsp_status().unwrap_or_default(),
                    UnixTime::now(),
                )
                .map(|_| ())
                .map_err(|_| reject())
        });
        if let Some(identity) = &options.identity {
            let size = identity
                .certificates
                .iter()
                .try_fold(identity.key.secret_der().len(), |size, cert| {
                    size.checked_add(cert.len())
                });
            if size.is_none_or(|n| n > crate::config::MAX_CONFIG_BYTES) {
                return Err(invalid());
            }
            let (leaf, rest) = identity.certificates.split_first().ok_or_else(invalid)?;
            let leaf = X509::from_der(leaf).map_err(|_| invalid())?;
            builder.set_certificate(&leaf).map_err(|_| invalid())?;
            for cert in rest {
                builder
                    .add_extra_chain_cert(X509::from_der(cert).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
            }
            let key =
                PKey::private_key_from_der(identity.key.secret_der()).map_err(|_| invalid())?;
            builder.set_private_key(&key).map_err(|_| invalid())?;
            builder.check_private_key().map_err(|_| invalid())?;
        }
        let profile = profile(options.client_fingerprint.ok_or_else(invalid)?);
        let connector = FingerprintConnector::new(builder, profile).map_err(|_| invalid())?;
        let alpn = wire_alpn(&options.alpn)?;
        Ok(Self {
            connector: Connector::Named(connector),
            server_name: server_name.to_owned(),
            alpn,
            required_alpn: options.required_alpn.clone(),
            sessions,
            #[cfg(feature = "outbound-vless")]
            reality: None,
        })
    }

    #[cfg(feature = "outbound-vless")]
    pub(super) fn reality(config: &crate::config::RealityConfig) -> io::Result<Self> {
        config.validate_fingerprint().map_err(|_| invalid())?;
        ServerName::try_from(config.server_name.to_owned()).map_err(|_| invalid())?;
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| invalid())?;
        builder
            // A named REALITY hello preserves the template's TLS1.2 fields,
            // as Mihomo does. Native REALITY independently rejects every
            // pre-TLS1.3 ServerHello before certificate/application processing.
            .set_min_proto_version(Some(if config.client_fingerprint.is_some() {
                SslVersion::TLS1_2
            } else {
                SslVersion::TLS1_3
            }))
            .map_err(|_| invalid())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        builder
            .set_curves_list(if config.support_x25519mlkem768 {
                "X25519MLKEM768"
            } else {
                "X25519"
            })
            .map_err(|_| invalid())?;
        let sessions = super::boring_resumption::Sessions::new(&mut builder, 0)?;
        let connector = match config.client_fingerprint {
            Some(value) => Connector::Named(
                FingerprintConnector::new(builder, profile(value)).map_err(|_| invalid())?,
            ),
            None => Connector::Default(builder.build()),
        };
        let reality = boring::ssl::RealityClientConfig::new(
            config.public_key,
            &config.short_id,
            super::REALITY_CLIENT_VERSION,
        )
        .map_err(|_| invalid())?;
        let reality = if config.support_x25519mlkem768 {
            reality.require_x25519mlkem768()
        } else {
            reality
        };
        Ok(Self {
            connector,
            server_name: config.server_name.clone(),
            alpn: wire_alpn(&config.alpn)?,
            // REALITY peers can omit negotiated ALPN. XHTTP retains the
            // configured HTTP version; no ordinary PKI fallback is permitted.
            required_alpn: None,
            sessions,
            reality: Some(reality),
        })
    }

    pub(super) async fn connect(
        &self,
        stream: BoxStream,
        buffer_limit: usize,
    ) -> io::Result<BoxStream> {
        Ok(Box::new(BoringStream::new(
            self.handshake(stream).await?,
            buffer_limit,
        )))
    }

    #[cfg(feature = "outbound-vless")]
    pub(super) async fn connect_vision(
        &self,
        stream: BoxStream,
        stats: Arc<super::vision::SpliceStats>,
        buffer_limit: usize,
    ) -> io::Result<(BoxStream, super::vision::SpliceControl)> {
        let tls = self.handshake(super::vision::RecordIo::new(stream)).await?;
        super::vision::BoringSplice::wrap(tls, stats, buffer_limit)
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> io::Result<tokio_boring::SslStream<KeepOpen<S>>> {
        let mut config = self
            .connector
            .configure(&self.alpn)
            .map_err(|_| invalid())?;
        // The shared WebPKI verifier owns name checking, including independent
        // verification names and pin precedence; wire SNI still uses server_name.
        config.set_verify_hostname(false);
        let sink = self.sessions.configure(&mut config)?;
        #[cfg(feature = "outbound-vless")]
        if let Some(reality) = &self.reality {
            config.set_reality_client(reality).map_err(|_| invalid())?;
        }
        let tls = tokio_boring::connect(config, &self.server_name, KeepOpen(stream))
            .await
            .map_err(|_| io::Error::other("TLS handshake failed"))?;
        if self
            .required_alpn
            .as_deref()
            .is_some_and(|required| tls.ssl().selected_alpn_protocol() != Some(required))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS server did not negotiate the required ALPN",
            ));
        }
        // The HTTP drivers use on-wire SETTINGS and do not import ALPS into
        // their initial state. Never silently accept nonempty peer settings.
        if tls
            .ssl()
            .peer_application_settings()
            .is_some_and(|settings| !settings.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "nonempty TLS ALPS settings are not supported",
            ));
        }
        sink.accept()?;
        Ok(tls)
    }
}

fn profile(value: crate::config::ClientFingerprint) -> ClientFingerprint {
    match value {
        crate::config::ClientFingerprint::Chrome120 => ClientFingerprint::Chrome120,
        crate::config::ClientFingerprint::Chrome133 => ClientFingerprint::Chrome133,
        crate::config::ClientFingerprint::Firefox120 => ClientFingerprint::Firefox120,
        crate::config::ClientFingerprint::Safari16 => ClientFingerprint::Safari16,
    }
}

fn wire_alpn(protocols: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 || wire.len() + 1 + protocol.len() > 65_533 {
            return Err(invalid());
        }
        wire.push(protocol.len() as u8);
        wire.extend_from_slice(protocol);
    }
    Ok(wire)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid fingerprinted TLS policy",
    )
}
