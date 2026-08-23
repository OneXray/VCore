use std::{future::Future, io, net::SocketAddr, pin::Pin};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::future::select_all;
use tokio::net::UdpSocket;

use crate::{
    dialer::Dialer,
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{Datagram, DatagramSession, Destination, StreamSession},
};

use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};

/// Built-in DIRECT action. Domain destinations must be resolved and pinned by
/// the routing layer before they reach this dispatcher.
#[derive(Debug, Clone)]
pub struct DirectOutbound {
    dialer: Dialer,
}

impl DirectOutbound {
    #[must_use]
    pub const fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

#[async_trait]
impl Dispatcher for DirectOutbound {
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

#[async_trait]
impl OutboundConnector for DirectOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let Destination::Ip(address) = session.destination else {
            return Err(DispatchError::HostUnreachable);
        };
        let stream = context
            .run_io("direct TCP connect", self.dialer.connect_address(address))
            .await?;
        let effective_peer = Destination::Ip(stream.peer_addr().map_err(DispatchError::from)?);
        Ok(ConnectedStream {
            io: Box::new(stream),
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        _context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(DirectDatagramTransport::new(
            self.dialer.clone(),
            usize::from(request.max_response_payload_size()),
        )))
    }
}

struct DirectDatagramTransport {
    dialer: Dialer,
    sockets: Vec<(UdpSocketClass, UdpSocket)>,
    max_response_payload_size: usize,
    receive_buffer: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpSocketClass {
    ipv6: bool,
    loopback: bool,
}

impl DirectDatagramTransport {
    fn new(dialer: Dialer, max_response_payload_size: usize) -> Self {
        // `recv_from` is allowed to truncate a datagram to the supplied
        // buffer without reporting the original length. One sentinel byte is
        // enough to distinguish an allowed maximum-size payload from every
        // oversized payload while preserving a hard allocation ceiling.
        let receive_buffer_size = max_response_payload_size
            .checked_add(1)
            .expect("direct UDP response ceiling fits usize");
        Self {
            dialer,
            sockets: Vec::with_capacity(4),
            max_response_payload_size,
            receive_buffer: vec![0; receive_buffer_size],
        }
    }

    async fn socket_for(&mut self, address: SocketAddr) -> Result<&UdpSocket, DispatchError> {
        let class = UdpSocketClass {
            ipv6: address.is_ipv6(),
            loopback: address.ip().is_loopback(),
        };
        if let Some(index) = self.sockets.iter().position(|(key, _)| *key == class) {
            return Ok(&self.sockets[index].1);
        }
        let socket = self
            .dialer
            .bind_udp_for(address)
            .await
            .map_err(DispatchError::from)?;
        self.sockets.push((class, socket));
        Ok(&self
            .sockets
            .last()
            .expect("direct UDP socket was inserted")
            .1)
    }

    async fn receive_from_ready_socket(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            if self.sockets.is_empty() {
                return Err(DispatchError::Other(
                    "direct UDP receive requested before the first datagram".to_owned(),
                ));
            }
            let readiness: Vec<Pin<Box<dyn Future<Output = io::Result<usize>> + Send + '_>>> = self
                .sockets
                .iter()
                .enumerate()
                .map(|(index, (_, socket))| {
                    Box::pin(async move { socket.readable().await.map(|()| index) })
                        as Pin<Box<dyn Future<Output = io::Result<usize>> + Send + '_>>
                })
                .collect();
            let (selected, _, _) = select_all(readiness).await;
            let selected = selected.map_err(DispatchError::from)?;
            let socket = &self.sockets[selected].1;
            match socket.try_recv_from(&mut self.receive_buffer) {
                // A UDP datagram is indivisible. Never turn an oversized
                // response into a shorter, apparently valid datagram for the
                // SOCKS5 client or TUN netstack.
                Ok((length, _)) if length > self.max_response_payload_size => continue,
                Ok((length, remote)) => {
                    return Ok(Datagram {
                        remote: Destination::Ip(remote),
                        payload: Bytes::copy_from_slice(&self.receive_buffer[..length]),
                        sniffed_domain: None,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(DispatchError::from(error)),
            }
        }
    }
}

#[async_trait]
impl DatagramTransport for DirectDatagramTransport {
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        let Destination::Ip(address) = datagram.remote else {
            return Err(DispatchError::HostUnreachable);
        };
        let socket = self.socket_for(address).await?;
        let written = socket
            .send_to(&datagram.payload, address)
            .await
            .map_err(DispatchError::from)?;
        if written != datagram.payload.len() {
            return Err(DispatchError::Other(
                "direct UDP socket truncated a datagram".to_owned(),
            ));
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.receive_from_ready_socket().await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.sockets.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::net::{TcpListener, UdpSocket};

    use super::*;
    #[cfg(unix)]
    use crate::dialer::SocketProtector;
    use crate::session::InboundKind;

    #[cfg(unix)]
    struct CountingProtector(AtomicUsize);

    #[cfg(unix)]
    impl SocketProtector for CountingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn direct_tcp_connects_to_a_pinned_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let outbound = DirectOutbound::new(Dialer::default());
        let session = StreamSession {
            inbound: InboundKind::Http,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::Ip(destination),
            sniffed_domain: None,
        };
        let (_stream, accepted) = tokio::join!(outbound.connect_tcp(session), listener.accept());
        assert!(accepted.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn direct_udp_round_trips_and_protects_the_socket() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = echo.local_addr().unwrap();
        let protector = Arc::new(CountingProtector(AtomicUsize::new(0)));
        let outbound = DirectOutbound::new(Dialer::default().with_protector(protector.clone()));
        let session = DatagramSession::new(InboundKind::Http, "127.0.0.1:10000".parse().unwrap());
        let mut transport = Dispatcher::open_datagram(&outbound, session).await.unwrap();
        transport
            .send(Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"ping"),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        let mut received = [0_u8; 16];
        let (length, peer) = echo.recv_from(&mut received).await.unwrap();
        echo.send_to(&received[..length], peer).await.unwrap();
        let reply = transport.receive().await.unwrap();
        assert_eq!(reply.remote, Destination::Ip(destination));
        assert_eq!(&reply.payload[..], b"ping");
        assert_eq!(protector.0.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn direct_udp_drops_an_oversized_response_without_truncating_it() {
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = remote.local_addr().unwrap();
        let mut transport = DirectDatagramTransport::new(Dialer::default(), 4);
        transport
            .send(Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"open"),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        let mut request = [0_u8; 16];
        let (_, peer) = remote.recv_from(&mut request).await.unwrap();
        remote.send_to(b"large", peer).await.unwrap();
        remote.send_to(b"good", peer).await.unwrap();

        let response = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive())
            .await
            .expect("valid response behind oversized datagram timed out")
            .unwrap();
        assert_eq!(response.remote, Destination::Ip(destination));
        assert_eq!(&response.payload[..], b"good");
        assert_eq!(transport.receive_buffer.len(), 5);
    }
}
