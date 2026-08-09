use std::{io, net::SocketAddr};

use async_trait::async_trait;
use bytes::Bytes;
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
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
    max_response_payload_size: usize,
    receive_buffer: Vec<u8>,
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
            ipv4: None,
            ipv6: None,
            max_response_payload_size,
            receive_buffer: vec![0; receive_buffer_size],
        }
    }

    async fn socket_for(&mut self, address: SocketAddr) -> Result<&UdpSocket, DispatchError> {
        let slot = if address.is_ipv4() {
            &mut self.ipv4
        } else {
            &mut self.ipv6
        };
        if slot.is_none() {
            *slot = Some(
                self.dialer
                    .bind_udp(address.is_ipv6())
                    .await
                    .map_err(DispatchError::from)?,
            );
        }
        Ok(slot.as_ref().expect("direct UDP socket was initialized"))
    }

    async fn receive_from_ready_socket(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            let selected = match (&self.ipv4, &self.ipv6) {
                (Some(ipv4), Some(ipv6)) => tokio::select! {
                    result = ipv4.readable() => {
                        result.map_err(DispatchError::from)?;
                        4_u8
                    }
                    result = ipv6.readable() => {
                        result.map_err(DispatchError::from)?;
                        6_u8
                    }
                },
                (Some(ipv4), None) => {
                    ipv4.readable().await.map_err(DispatchError::from)?;
                    4
                }
                (None, Some(ipv6)) => {
                    ipv6.readable().await.map_err(DispatchError::from)?;
                    6
                }
                (None, None) => {
                    return Err(DispatchError::Other(
                        "direct UDP receive requested before the first datagram".to_owned(),
                    ));
                }
            };
            let socket = if selected == 4 {
                self.ipv4.as_ref().expect("selected IPv4 socket")
            } else {
                self.ipv6.as_ref().expect("selected IPv6 socket")
            };
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
        self.ipv4 = None;
        self.ipv6 = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::net::{TcpListener, UdpSocket};

    use super::*;
    use crate::{dialer::SocketProtector, session::InboundKind};

    struct CountingProtector(AtomicUsize);

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
