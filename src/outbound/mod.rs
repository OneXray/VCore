//! Composable proxy connectors and the built-in DIRECT dispatcher.

#[cfg(feature = "outbound-anytls")]
mod anytls;
mod connector;
mod direct;
#[cfg(feature = "outbound-socks5")]
mod socks5;
#[cfg(feature = "outbound-vless")]
mod vless;

#[cfg(feature = "outbound-vless")]
use std::{io, sync::Arc};

#[cfg(feature = "outbound-vless")]
use async_trait::async_trait;
#[cfg(feature = "outbound-vless")]
use tokio::io::AsyncWriteExt as _;

#[cfg(feature = "outbound-vless")]
use crate::{
    config::{VlessOutboundConfig, XHttpMode as ConfigXHttpMode},
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    security::{SecurityClient, SecurityContext, TLS_RESUMPTION_SESSION_BUDGET},
    session::{DatagramSession, StreamSession},
    transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode},
    xudp::XudpTransport,
};

#[cfg(feature = "outbound-vless")]
const DEFAULT_VLESS_TLS_BUFFER_LIMIT: usize = 64 * 1024;

#[cfg(feature = "outbound-vless")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct VlessResourceLimits {
    tls_buffer_limit: usize,
    xhttp_send_buffer_size: usize,
    xhttp_upload_chunk_size: usize,
}

#[cfg(feature = "outbound-vless")]
impl VlessResourceLimits {
    pub(crate) const fn new(
        tls_buffer_limit: usize,
        xhttp_send_buffer_size: usize,
        xhttp_upload_chunk_size: usize,
    ) -> Self {
        Self {
            tls_buffer_limit,
            xhttp_send_buffer_size,
            xhttp_upload_chunk_size,
        }
    }
}

#[cfg(feature = "outbound-anytls")]
pub use anytls::{AnyTlsLifecycle, AnyTlsOutbound, AnyTlsStream, AnyTlsTlsConnector};
pub use connector::{
    ConnectedStream, ConnectorDispatcher, DatagramRequest, DispatcherConnector, EstablishContext,
    OutboundConnector, UpstreamPath, server_destination,
};
pub(crate) use connector::{
    MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES, OutboundDiagnostic, capture_outbound_diagnostic,
};
pub use direct::DirectOutbound;
#[cfg(feature = "outbound-socks5")]
pub use socks5::{Socks5Auth, Socks5Outbound};
#[cfg(feature = "outbound-vless")]
pub use vless::{VlessCommand, VlessStream, encode_request_header, read_response_header};

#[cfg(feature = "outbound-vless")]
#[derive(Clone)]
struct VlessTransportLeg {
    server: crate::session::Destination,
    upstream: UpstreamPath,
    security: SecurityClient,
}

#[cfg(feature = "outbound-vless")]
impl std::fmt::Debug for VlessTransportLeg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessTransportLeg")
            .field("server", &self.server)
            .field("upstream", &self.upstream)
            .field("security", &self.security)
            .finish()
    }
}

#[cfg(feature = "outbound-vless")]
#[derive(Clone)]
struct VlessDownloadLeg {
    transport: VlessTransportLeg,
    xhttp: XHttpClient,
}

#[cfg(feature = "outbound-vless")]
impl std::fmt::Debug for VlessDownloadLeg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessDownloadLeg")
            .field("transport", &self.transport)
            .field("xhttp", &self.xhttp)
            .finish()
    }
}

#[cfg(feature = "outbound-vless")]
#[derive(Clone)]
pub struct VlessOutbound {
    uuid: uuid::Uuid,
    upload: VlessTransportLeg,
    xhttp: XHttpClient,
    download: Option<VlessDownloadLeg>,
}

#[cfg(feature = "outbound-vless")]
impl std::fmt::Debug for VlessOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessOutbound")
            .field("uuid", &self.uuid)
            .field("upload", &self.upload)
            .field("xhttp", &self.xhttp)
            .field("download", &self.download)
            .finish()
    }
}

#[cfg(feature = "outbound-vless")]
impl VlessOutbound {
    /// Builds an outbound from configuration and an endpoint resolved during
    /// the host's prepare phase, before the VPN becomes active.
    pub fn new(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
    ) -> io::Result<Self> {
        Self::new_with_endpoints(config, endpoint, None, dialer)
    }

    /// Builds a directly connected node from endpoints resolved during the
    /// prepare phase. A distinct download server requires its own prepared
    /// endpoint; an identical server reuses the primary resolution.
    pub fn new_with_endpoints(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        download_endpoint: Option<ResolvedEndpoint>,
        dialer: Dialer,
    ) -> io::Result<Self> {
        let (upload_path, download_path) =
            Self::direct_paths(config, endpoint, download_endpoint, dialer)?;
        Self::new_with_paths(config, upload_path, download_path)
    }

    /// Builds a VLESS node on top of another configured outbound connector.
    /// Its server name remains a logical destination and is resolved by the
    /// upstream proxy.
    pub fn new_with_upstream(
        config: &VlessOutboundConfig,
        upstream: Arc<dyn OutboundConnector>,
    ) -> io::Result<Self> {
        let upload_path = UpstreamPath::proxy(upstream.clone());
        let download_path = config
            .xhttp
            .download
            .as_ref()
            .map(|_| UpstreamPath::proxy(upstream));
        Self::new_with_paths(config, upload_path, download_path)
    }

    pub fn new_with_path(config: &VlessOutboundConfig, upstream: UpstreamPath) -> io::Result<Self> {
        let download_path = Self::download_path_from_primary(config, &upstream)?;
        Self::new_with_paths(config, upstream, download_path)
    }

    pub fn new_with_paths(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
    ) -> io::Result<Self> {
        let security_context = SecurityContext::new();
        let standard_tls_count = usize::from(matches!(
            &config.security,
            crate::config::SecurityConfig::Tls(_)
        )) + config.xhttp.download.as_ref().map_or(0, |download| {
            usize::from(matches!(
                &download.security,
                crate::config::SecurityConfig::Tls(_)
            ))
        });
        let resumption_sessions =
            if standard_tls_count == 0 || standard_tls_count > TLS_RESUMPTION_SESSION_BUDGET {
                0
            } else {
                TLS_RESUMPTION_SESSION_BUDGET / standard_tls_count
            };
        let upload_security = SecurityClient::from_proxy_with_context(
            config,
            &security_context,
            resumption_sessions,
            DEFAULT_VLESS_TLS_BUFFER_LIMIT,
        )?;
        let download_security = config
            .xhttp
            .download
            .as_ref()
            .map(|download| {
                SecurityClient::from_security_with_context(
                    &download.security,
                    &security_context,
                    resumption_sessions,
                    DEFAULT_VLESS_TLS_BUFFER_LIMIT,
                )
            })
            .transpose()?;
        Self::assemble(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
        )
    }

    /// Runtime graph constructor using instance-shared TLS material and an
    /// explicitly partitioned resumption-cache budget.
    pub(crate) fn new_with_shared_security(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        security_context: &SecurityContext,
        resumption_sessions: usize,
        limits: VlessResourceLimits,
    ) -> io::Result<Self> {
        let upload_security = SecurityClient::from_security_with_context(
            &config.security,
            security_context,
            resumption_sessions,
            limits.tls_buffer_limit,
        )?;
        let download_security = config
            .xhttp
            .download
            .as_ref()
            .map(|download| {
                SecurityClient::from_security_with_context(
                    &download.security,
                    security_context,
                    resumption_sessions,
                    limits.tls_buffer_limit,
                )
            })
            .transpose()?;
        Self::assemble_with_xhttp_limits(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
            limits.xhttp_send_buffer_size,
            limits.xhttp_upload_chunk_size,
        )
    }

    /// Builds a standard-TLS outbound with local interoperability-test roots.
    ///
    /// This constructor is absent from normal and release builds. It must only
    /// be enabled by the opt-in local Xray interoperability harness.
    #[cfg(feature = "interop-test")]
    #[doc(hidden)]
    pub fn new_with_test_tls_roots(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        let (upload_path, download_path) = Self::direct_paths(config, endpoint, None, dialer)?;
        let roots = roots_der.into_iter().collect::<Vec<_>>();
        let upload_security =
            SecurityClient::from_proxy_with_test_tls_roots(config, roots.clone())?;
        let download_security = config
            .xhttp
            .download
            .as_ref()
            .map(|download| match &download.security {
                crate::config::SecurityConfig::Tls(_) => {
                    SecurityClient::from_security_with_test_tls_roots(
                        &download.security,
                        roots.clone(),
                    )
                }
                crate::config::SecurityConfig::Reality(_) => {
                    SecurityClient::from_security(&download.security)
                }
            })
            .transpose()?;
        Self::assemble(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
        )
    }

    fn validate_endpoint(
        address: &str,
        port: u16,
        endpoint: &ResolvedEndpoint,
        leg: &str,
    ) -> io::Result<()> {
        if endpoint.logical_host != address || endpoint.port != port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("resolved endpoint does not match the configured VLESS {leg} server"),
            ));
        }
        if endpoint.addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("resolved VLESS {leg} endpoint has no addresses"),
            ));
        }
        Ok(())
    }

    fn direct_paths(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        download_endpoint: Option<ResolvedEndpoint>,
        dialer: Dialer,
    ) -> io::Result<(UpstreamPath, Option<UpstreamPath>)> {
        Self::validate_endpoint(&config.address, config.port, &endpoint, "upload")?;
        let download_path = match (&config.xhttp.download, download_endpoint) {
            (None, None) => None,
            (None, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a download endpoint was provided without VLESS download-settings",
                ));
            }
            (Some(download), supplied) => {
                let resolved = match supplied {
                    Some(resolved) => resolved,
                    None if download.address == config.address && download.port == config.port => {
                        endpoint.clone()
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "distinct VLESS download server requires a prepared download endpoint",
                        ));
                    }
                };
                Self::validate_endpoint(&download.address, download.port, &resolved, "download")?;
                Some(UpstreamPath::direct(resolved, dialer.clone()))
            }
        };
        Ok((UpstreamPath::direct(endpoint, dialer), download_path))
    }

    fn download_path_from_primary(
        config: &VlessOutboundConfig,
        primary: &UpstreamPath,
    ) -> io::Result<Option<UpstreamPath>> {
        let Some(download) = config.xhttp.download.as_ref() else {
            return Ok(None);
        };
        match primary {
            UpstreamPath::Proxy(_) => Ok(Some(primary.clone())),
            UpstreamPath::Direct { endpoint, .. }
                if endpoint.logical_host == download.address && endpoint.port == download.port =>
            {
                Ok(Some(primary.clone()))
            }
            UpstreamPath::Direct { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "distinct VLESS download server requires an explicit download upstream path",
            )),
        }
    }

    fn assemble(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        upload_security: SecurityClient,
        download_security: Option<SecurityClient>,
    ) -> io::Result<Self> {
        Self::assemble_with_xhttp(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
            |config| Ok(XHttpClient::new(config)),
        )
    }

    fn assemble_with_xhttp_limits(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        upload_security: SecurityClient,
        download_security: Option<SecurityClient>,
        send_buffer_size: usize,
        upload_chunk_size: usize,
    ) -> io::Result<Self> {
        Self::assemble_with_xhttp(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
            |config| XHttpClient::new_with_limits(config, send_buffer_size, upload_chunk_size),
        )
    }

    fn assemble_with_xhttp(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        upload_security: SecurityClient,
        download_security: Option<SecurityClient>,
        mut build_xhttp: impl FnMut(XHttpConfig) -> io::Result<XHttpClient>,
    ) -> io::Result<Self> {
        let mode = match config.xhttp.mode {
            ConfigXHttpMode::PacketUp => XHttpMode::PacketUp,
            ConfigXHttpMode::StreamOne => XHttpMode::StreamOne,
            ConfigXHttpMode::StreamUp => XHttpMode::StreamUp,
        };
        if mode == XHttpMode::StreamOne && config.xhttp.download.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP stream-one cannot use download settings",
            ));
        }
        let xhttp = build_xhttp(XHttpConfig::new(
            config.xhttp.host.clone(),
            config.xhttp.path.clone(),
            mode,
        )?)?;
        let download = match (
            config.xhttp.download.as_ref(),
            download_path,
            download_security,
        ) {
            (None, None, None) => None,
            (Some(config), Some(upstream), Some(security)) => Some(VlessDownloadLeg {
                transport: VlessTransportLeg {
                    server: server_destination(&config.address, config.port)?,
                    upstream,
                    security,
                },
                xhttp: build_xhttp(XHttpConfig::new(
                    config.host.clone(),
                    config.path.clone(),
                    mode,
                )?)?,
            }),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS download configuration, path, and security must be provided together",
                ));
            }
        };
        Ok(Self {
            uuid: config.id,
            upload: VlessTransportLeg {
                server: server_destination(&config.address, config.port)?,
                upstream: upload_path,
                security: upload_security,
            },
            xhttp,
            download,
        })
    }

    /// Overrides the transport mode for focused interoperability tests.
    #[must_use]
    pub fn with_xhttp_mode(mut self, config: XHttpConfig) -> Self {
        self.xhttp = XHttpClient::new(config);
        self
    }

    async fn connect_transport(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let upload = Self::connect_transport_leg(&self.upload, session.clone(), context);
        let Some(download) = &self.download else {
            let secured = upload.await?;
            let connected = context
                .run_io("VLESS XHTTP handshake", self.xhttp.connect(secured))
                .await?;
            tracing::debug!(stage = "xhttp", "VLESS transport stage completed");
            return Ok(connected);
        };

        let download_stream = Self::connect_transport_leg(&download.transport, session, context);
        let (upload_stream, download_stream) = tokio::try_join!(upload, download_stream)?;
        let connected = context
            .run_io(
                "VLESS XHTTP handshake",
                self.xhttp
                    .connect_with_download(upload_stream, &download.xhttp, download_stream),
            )
            .await?;
        tracing::debug!(stage = "xhttp-split", "VLESS transport stage completed");
        Ok(connected)
    }

    async fn connect_transport_leg(
        leg: &VlessTransportLeg,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let raw = leg
            .upstream
            .connect_server(session, &leg.server, context)
            .await?;
        tracing::debug!(stage = "upstream", "VLESS transport stage completed");
        let secured = context
            .run_io("VLESS TLS/REALITY handshake", leg.security.connect(raw.io))
            .await?;
        tracing::debug!(stage = "security", "VLESS transport stage completed");
        Ok(secured)
    }

    async fn connect_vless_tcp(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let stream = self.connect_transport(session.clone(), context).await?;
        let header =
            encode_request_header(self.uuid, VlessCommand::Tcp, Some(&session.destination))
                .map_err(DispatchError::from)?;
        Ok(ConnectedStream {
            io: Box::new(VlessStream::new(stream, header)),
            effective_peer,
        })
    }

    async fn connect_vless_xudp(
        &self,
        request: &DatagramRequest,
        context: &EstablishContext,
    ) -> Result<XudpTransport, DispatchError> {
        let mut stream = self
            .connect_transport(
                StreamSession {
                    inbound: request.session.inbound,
                    source: request.session.source,
                    destination: self.upload.server.clone(),
                    sniffed_domain: None,
                },
                context,
            )
            .await?;
        let header = encode_request_header(self.uuid, VlessCommand::Mux, None)
            .map_err(DispatchError::from)?;
        context
            .run_io("VLESS XUDP request header", async {
                stream.write_all(&header).await?;
                stream.flush().await
            })
            .await?;
        // VCore does not implement Xray's cone/reconnect association
        // reuse. Xray uses the all-zero Global ID to explicitly disable that
        // behavior; a per-association random value would claim reuse semantics
        // that this runtime cannot honor.
        Ok(XudpTransport::new(
            stream,
            [0_u8; 8],
            request.max_response_payload_size(),
        ))
    }
}

#[cfg(feature = "outbound-vless")]
#[async_trait]
impl OutboundConnector for VlessOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.connect_vless_tcp(session, context).await
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.connect_vless_xudp(&request, context)
            .await
            .map(|transport| Box::new(transport) as Box<dyn DatagramTransport>)
    }
}

#[cfg(feature = "outbound-vless")]
#[async_trait]
impl Dispatcher for VlessOutbound {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        OutboundConnector::connect_stream(self, session, &EstablishContext::default())
            .await
            .map(|connected| connected.io)
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        OutboundConnector::open_datagram(
            self,
            DatagramRequest::new(session),
            &EstablishContext::default(),
        )
        .await
    }
}

#[cfg(feature = "outbound-vless")]
#[must_use]
pub fn shared(outbound: VlessOutbound) -> Arc<dyn Dispatcher> {
    Arc::new(outbound)
}

#[cfg(feature = "outbound-vless")]
#[must_use]
pub fn shared_connector(outbound: VlessOutbound) -> Arc<dyn OutboundConnector> {
    Arc::new(outbound)
}

#[cfg(all(test, feature = "outbound-socks5", feature = "outbound-vless"))]
mod connector_composition_tests {
    use super::*;
    use crate::{
        config::{
            SecurityConfig, Socks5OutboundConfig, TlsConfig, VlessEncryption, VlessOutboundConfig,
            XHttpConfig as ConfigXHttpConfig, XHttpDownloadConfig, XHttpMode as ConfigXHttpMode,
        },
        dispatch::{DatagramTransport, DispatchError},
        session::StreamSession,
    };

    struct NeverConnector;

    #[async_trait]
    impl OutboundConnector for NeverConnector {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            Err(DispatchError::NetworkUnreachable)
        }

        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NetworkUnreachable)
        }
    }

    fn vless_config(address: &str) -> VlessOutboundConfig {
        VlessOutboundConfig {
            address: address.to_owned(),
            port: 443,
            id: uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
            encryption: VlessEncryption::None,
            flow: String::new(),
            security: SecurityConfig::Tls(TlsConfig {
                server_name: address.to_owned(),
            }),
            xhttp: ConfigXHttpConfig {
                path: "/xhttp".to_owned(),
                host: address.to_owned(),
                mode: ConfigXHttpMode::PacketUp,
                download: None,
            },
        }
    }

    fn socks_config(address: &str) -> Socks5OutboundConfig {
        Socks5OutboundConfig {
            address: address.to_owned(),
            port: 1080,
            username: None,
            password: None,
        }
    }

    fn split_vless_config(upload: &str, download: &str, download_port: u16) -> VlessOutboundConfig {
        let mut config = vless_config(upload);
        config.xhttp.download = Some(Box::new(XHttpDownloadConfig {
            address: download.to_owned(),
            port: download_port,
            security: SecurityConfig::Tls(TlsConfig {
                server_name: download.to_owned(),
            }),
            path: "/download".to_owned(),
            host: download.to_owned(),
        }));
        config
    }

    fn endpoint(address: &str, port: u16) -> ResolvedEndpoint {
        ResolvedEndpoint {
            logical_host: address.to_owned(),
            port,
            addresses: vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))],
        }
    }

    #[test]
    fn all_two_hop_protocol_combinations_build_as_connector_graphs() {
        let physical: Arc<dyn OutboundConnector> = Arc::new(NeverConnector);
        let vless_leaf: Arc<dyn OutboundConnector> = Arc::new(
            VlessOutbound::new_with_upstream(&vless_config("vless-leaf.example"), physical.clone())
                .unwrap(),
        );
        let socks_leaf: Arc<dyn OutboundConnector> = Arc::new(
            Socks5Outbound::new_with_upstream(&socks_config("socks-leaf.example"), physical)
                .unwrap(),
        );

        let combinations: [Arc<dyn OutboundConnector>; 4] = [
            Arc::new(
                VlessOutbound::new_with_upstream(
                    &vless_config("vless-over-vless.example"),
                    vless_leaf.clone(),
                )
                .unwrap(),
            ),
            Arc::new(
                VlessOutbound::new_with_upstream(
                    &vless_config("vless-over-socks.example"),
                    socks_leaf.clone(),
                )
                .unwrap(),
            ),
            Arc::new(
                Socks5Outbound::new_with_upstream(
                    &socks_config("socks-over-vless.example"),
                    vless_leaf,
                )
                .unwrap(),
            ),
            Arc::new(
                Socks5Outbound::new_with_upstream(
                    &socks_config("socks-over-socks.example"),
                    socks_leaf,
                )
                .unwrap(),
            ),
        ];
        assert_eq!(combinations.len(), 4);
    }

    #[test]
    fn direct_download_constructor_reuses_or_requires_the_precise_prepared_endpoint() {
        let same = split_vless_config("same.example", "same.example", 443);
        let outbound =
            VlessOutbound::new(&same, endpoint("same.example", 443), Dialer::default()).unwrap();
        assert!(outbound.download.is_some());

        let mut invalid_mode = same.clone();
        invalid_mode.xhttp.mode = ConfigXHttpMode::StreamOne;
        let error = VlessOutbound::new(
            &invalid_mode,
            endpoint("same.example", 443),
            Dialer::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("stream-one"));

        let distinct = split_vless_config("upload.example", "download.example", 8443);
        let error = VlessOutbound::new(
            &distinct,
            endpoint("upload.example", 443),
            Dialer::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("prepared download endpoint"));

        let outbound = VlessOutbound::new_with_endpoints(
            &distinct,
            endpoint("upload.example", 443),
            Some(endpoint("download.example", 8443)),
            Dialer::default(),
        )
        .unwrap();
        let download = outbound.download.as_ref().unwrap();
        assert_eq!(outbound.upload.server.port(), 443);
        assert_eq!(download.transport.server.port(), 8443);
    }

    #[test]
    fn split_node_over_a_proxy_automatically_reuses_its_parent_for_both_legs() {
        let parent: Arc<dyn OutboundConnector> = Arc::new(NeverConnector);
        let config = split_vless_config("upload.example", "download.example", 8443);
        let outbound = VlessOutbound::new_with_upstream(&config, parent).unwrap();
        let UpstreamPath::Proxy(upload_parent) = &outbound.upload.upstream else {
            panic!("upload leg must use the configured parent")
        };
        let UpstreamPath::Proxy(download_parent) =
            &outbound.download.as_ref().unwrap().transport.upstream
        else {
            panic!("download leg must use the configured parent")
        };
        assert!(Arc::ptr_eq(upload_parent, download_parent));
    }
}
