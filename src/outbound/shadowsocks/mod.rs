//! Official SS 2022 codec over VCore-owned TCP and UDP transports.
use super::{
    ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    server_destination,
};
use crate::{
    config::ShadowsocksOutboundConfig,
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{DatagramSession, Destination, StreamSession},
};
use async_trait::async_trait;
use shadowsocks::{ServerConfig, config::ServerType, context::Context};
use std::{io, sync::Arc};

mod datagram;
mod packet_io;
mod packet_window;
mod stream;

#[derive(Clone)]
pub struct ShadowsocksOutbound {
    server: Destination,
    config: Arc<ServerConfig>,
    context: shadowsocks::context::SharedContext,
    upstream: UpstreamPath,
}

impl std::fmt::Debug for ShadowsocksOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksOutbound")
            .finish_non_exhaustive()
    }
}

impl ShadowsocksOutbound {
    pub fn new_with_path(
        config: &ShadowsocksOutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        config.validate().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks configuration",
            )
        })?;
        let server = server_destination(&config.address, config.port)?;
        let method = config.cipher.as_str().parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported Shadowsocks cipher",
            )
        })?;
        let config = ServerConfig::new(
            (config.address.clone(), config.port),
            config.password.clone(),
            method,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks credentials",
            )
        })?;
        Ok(Self {
            server,
            config: Arc::new(config),
            context: Context::new_shared(ServerType::Local),
            upstream,
        })
    }
}

#[async_trait]
impl OutboundConnector for ShadowsocksOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let target = session.destination.clone();
        let connected = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?;
        let stream = shadowsocks::ProxyClientStream::from_stream(
            self.context.clone(),
            connected.io,
            &self.config,
            address(&target),
        );
        Ok(ConnectedStream {
            io: Box::new(stream::SsStream::new(stream)),
            effective_peer: target,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let server = self.upstream.datagram_server(&self.server, context)?;
        let maximum = request.max_response_payload_size();
        let wire_maximum = maximum.saturating_add(datagram::MAX_RESPONSE_HEADER);
        let inner = self
            .upstream
            .open_datagram(
                request.with_max_response_payload_size(wire_maximum),
                context,
            )
            .await?;
        Ok(Box::new(datagram::SsDatagram::new(
            inner,
            server,
            self.context.clone(),
            &self.config,
            maximum,
            wire_maximum,
        )))
    }
}

#[async_trait]
impl Dispatcher for ShadowsocksOutbound {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        OutboundConnector::connect_stream(self, session, &EstablishContext::default())
            .await
            .map(|stream| stream.io)
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

fn address(target: &Destination) -> shadowsocks::relay::socks5::Address {
    match target {
        Destination::Ip(value) => (*value).into(),
        Destination::Domain { host, port } => (host.clone(), *port).into(),
    }
}

fn destination(target: shadowsocks::relay::socks5::Address) -> io::Result<Destination> {
    match target {
        shadowsocks::relay::socks5::Address::SocketAddress(value) if value.port() != 0 => {
            Ok(Destination::Ip(value))
        }
        shadowsocks::relay::socks5::Address::DomainNameAddress(host, port) => {
            Destination::domain(host, port)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Shadowsocks response address",
        )),
    }
}

fn safe_io(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "Shadowsocks stream operation failed")
}

#[cfg(test)]
mod tests;
