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
    security::{SecurityClient, SecurityContext},
    session::{DatagramSession, StreamSession},
    transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode},
    xudp::XudpTransport,
};

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
pub struct VlessOutbound {
    uuid: uuid::Uuid,
    server: crate::session::Destination,
    upstream: UpstreamPath,
    security: SecurityClient,
    xhttp: XHttpClient,
}

#[cfg(feature = "outbound-vless")]
impl std::fmt::Debug for VlessOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessOutbound")
            .field("uuid", &self.uuid)
            .field("server", &self.server)
            .field("upstream", &self.upstream)
            .field("security", &self.security)
            .field("xhttp", &self.xhttp)
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
        Self::validate_endpoint(config, &endpoint)?;
        let security = SecurityClient::from_proxy(config)?;
        Self::assemble(config, UpstreamPath::direct(endpoint, dialer), security)
    }

    /// Builds a VLESS node on top of another configured outbound connector.
    /// Its server name remains a logical destination and is resolved by the
    /// upstream proxy.
    pub fn new_with_upstream(
        config: &VlessOutboundConfig,
        upstream: Arc<dyn OutboundConnector>,
    ) -> io::Result<Self> {
        Self::new_with_path(config, UpstreamPath::proxy(upstream))
    }

    pub fn new_with_path(config: &VlessOutboundConfig, upstream: UpstreamPath) -> io::Result<Self> {
        let security = SecurityClient::from_proxy(config)?;
        Self::assemble(config, upstream, security)
    }

    /// Runtime graph constructor using instance-shared TLS material and an
    /// explicitly partitioned resumption-cache budget.
    pub(crate) fn new_with_shared_security(
        config: &VlessOutboundConfig,
        upstream: UpstreamPath,
        security_context: &SecurityContext,
        resumption_sessions: usize,
        tls_buffer_limit: usize,
        xhttp_send_buffer_size: usize,
        xhttp_upload_chunk_size: usize,
    ) -> io::Result<Self> {
        let security = SecurityClient::from_proxy_with_context(
            config,
            security_context,
            resumption_sessions,
            tls_buffer_limit,
        )?;
        Self::assemble_with_xhttp_limits(
            config,
            upstream,
            security,
            xhttp_send_buffer_size,
            xhttp_upload_chunk_size,
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
        Self::validate_endpoint(config, &endpoint)?;
        let security = SecurityClient::from_proxy_with_test_tls_roots(config, roots_der)?;
        Self::assemble(config, UpstreamPath::direct(endpoint, dialer), security)
    }

    fn validate_endpoint(
        config: &VlessOutboundConfig,
        endpoint: &ResolvedEndpoint,
    ) -> io::Result<()> {
        if endpoint.logical_host != config.address || endpoint.port != config.port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resolved endpoint does not match the configured proxy server",
            ));
        }
        if endpoint.addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resolved proxy endpoint has no addresses",
            ));
        }
        Ok(())
    }

    fn assemble(
        config: &VlessOutboundConfig,
        upstream: UpstreamPath,
        security: SecurityClient,
    ) -> io::Result<Self> {
        Self::assemble_with_xhttp(config, upstream, security, |config| {
            Ok(XHttpClient::new(config))
        })
    }

    fn assemble_with_xhttp_limits(
        config: &VlessOutboundConfig,
        upstream: UpstreamPath,
        security: SecurityClient,
        send_buffer_size: usize,
        upload_chunk_size: usize,
    ) -> io::Result<Self> {
        Self::assemble_with_xhttp(config, upstream, security, |config| {
            XHttpClient::new_with_limits(config, send_buffer_size, upload_chunk_size)
        })
    }

    fn assemble_with_xhttp(
        config: &VlessOutboundConfig,
        upstream: UpstreamPath,
        security: SecurityClient,
        build_xhttp: impl FnOnce(XHttpConfig) -> io::Result<XHttpClient>,
    ) -> io::Result<Self> {
        let mode = match config.xhttp.mode {
            ConfigXHttpMode::PacketUp => XHttpMode::PacketUp,
            #[allow(unreachable_patterns)]
            _ => XHttpMode::StreamOne,
        };
        let xhttp = XHttpConfig::new(config.xhttp.host.clone(), config.xhttp.path.clone(), mode)?;
        Ok(Self {
            uuid: config.id,
            server: server_destination(&config.address, config.port)?,
            upstream,
            security,
            xhttp: build_xhttp(xhttp)?,
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
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?;
        tracing::debug!(stage = "upstream", "VLESS transport stage completed");
        let secured = context
            .run_io("VLESS TLS/REALITY handshake", self.security.connect(raw.io))
            .await?;
        tracing::debug!(stage = "security", "VLESS transport stage completed");
        let connected = context
            .run_io("VLESS XHTTP handshake", self.xhttp.connect(secured))
            .await?;
        tracing::debug!(stage = "xhttp", "VLESS transport stage completed");
        Ok(connected)
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
                    destination: self.server.clone(),
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
            XHttpConfig as ConfigXHttpConfig, XHttpMode as ConfigXHttpMode,
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
}
