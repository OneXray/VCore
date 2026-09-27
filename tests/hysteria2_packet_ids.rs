#![cfg(feature = "outbound-hysteria2")]
//! Public connector over memory-only QUIC IO; no host sockets or native-peer claim.
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::sync::mpsc;
use vcore::{
    config::{Config, ProxyProtocol},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        hysteria2::Hysteria2Outbound,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

struct MemoryPackets {
    send: mpsc::Sender<Bytes>,
    receive: mpsc::Receiver<Bytes>,
    remote: SocketAddr,
}
#[async_trait]
impl DatagramTransport for MemoryPackets {
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1400, 1400)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        assert_eq!(packet.remote, self.remote.into());
        self.send
            .send(packet.payload)
            .await
            .map_err(|_| DispatchError::NotAllowed)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        Ok(Datagram {
            remote: self.remote.into(),
            payload: self.receive.recv().await.ok_or(DispatchError::NotAllowed)?,
            sniffed_domain: None,
        })
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.receive.close();
        Ok(())
    }
}
struct MemoryUpstream(Mutex<Option<MemoryPackets>>);
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(self.0.lock().unwrap().take().unwrap()))
    }
}

// The passive fixture uses Quinn's socket seam, not VCore's client-only
// adapter (which intentionally waits for its first authorized outbound send).
#[derive(Debug)]
struct PeerSocket {
    send: mpsc::Sender<Bytes>,
    receive: Mutex<mpsc::Receiver<Bytes>>,
    local: SocketAddr,
    remote: SocketAddr,
}
#[derive(Debug)]
struct Writable(Mutex<tokio_util::sync::PollSender<Bytes>>);
impl quinn::UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock().unwrap();
        ready!(sender.poll_reserve(cx)).map_err(|_| io::ErrorKind::BrokenPipe)?;
        sender.abort_send();
        Poll::Ready(Ok(()))
    }
}
impl quinn::AsyncUdpSocket for PeerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(Writable(Mutex::new(tokio_util::sync::PollSender::new(
            self.send.clone(),
        ))))
    }
    fn try_send(&self, packet: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        assert_eq!(packet.destination, self.remote);
        self.send
            .try_send(Bytes::copy_from_slice(packet.contents))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let packet =
            ready!(self.receive.lock().unwrap().poll_recv(cx)).ok_or(io::ErrorKind::BrokenPipe)?;
        bufs[0][..packet.len()].copy_from_slice(&packet);
        meta[0] = quinn::udp::RecvMeta {
            addr: self.remote,
            len: packet.len(),
            stride: packet.len(),
            ecn: None,
            dst_ip: Some(self.local.ip()),
        };
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[tokio::test]
async fn completed_fragment_id_can_be_reused_without_losing_the_next_datagram() {
    #[cfg(feature = "interop-test")]
    let _case =
        vcore::resources::case_events::Case::new("N9-ADAPTER", "hysteria2_fragment_id_reuse");
    let server_address: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let client_address: SocketAddr = "192.0.2.2:1234".parse().unwrap();
    let (to_server, from_client) = mpsc::channel(32);
    let (to_client, from_server) = mpsc::channel(32);
    let client_io = MemoryPackets {
        send: to_server,
        receive: from_server,
        remote: server_address,
    };
    let socket = Arc::new(PeerSocket {
        send: to_client,
        receive: Mutex::new(from_client),
        local: server_address,
        remote: client_address,
    });
    let certificate = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .datagram_receive_buffer_size(Some(64 * 1024))
        .mtu_discovery_config(None);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let peer = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let (request, mut response) = h3
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert_eq!(request.uri().path(), "/auth");
        response
            .send_response(
                http::Response::builder()
                    .status(233)
                    .header("Hysteria-UDP", "true")
                    .header("Hysteria-CC-RX", "0")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        response.finish().await.unwrap();
        // Native Hysteria randomizes its 16-bit Packet ID. A completed ID can
        // recur, including immediately; Mihomo releases the completed pieces.
        for (sequence, id) in [17_u16, 18, 17, 17].into_iter().enumerate() {
            let Ok(request) = connection.read_datagram().await else {
                break;
            };
            assert_eq!(&request[6..], &[0, 1, 3, b'x', b':', b'1', sequence as u8]);
            // Literal protocol fixtures, independent of VCore's wire encoder.
            // Out of order plus a duplicate within the unfinished assembly.
            for index in [1, 1, 0] {
                let mut frame = request[..4].to_vec();
                frame.extend_from_slice(&id.to_be_bytes());
                frame.extend_from_slice(&[index, 2, 3, b'x', b':', b'1']);
                frame.extend_from_slice(&[sequence as u8; 50]);
                connection.send_datagram_wait(frame.into()).await.unwrap();
            }
        }
        connection.closed().await;
        drop(h3);
        endpoint.close(0_u32.into(), b"");
        endpoint.wait_idle().await;
    });
    let config = Config::parse_yaml(br#"{"socks-port":1080,"proxies":[{"name":"peer","type":"hysteria2","server":"192.0.2.1","port":443,"udp":true,"skip-cert-verify":true,"sni":"fixture.invalid"}],"rules":["MATCH,peer"]}"#).unwrap();
    let ProxyProtocol::Hysteria2(config) = &config.proxies[0].protocol else {
        panic!("protocol")
    };
    let outbound = Hysteria2Outbound::new_with_path(
        config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(client_io))))),
    )
    .unwrap();
    let mut udp = tokio::time::timeout(
        Duration::from_secs(2),
        outbound.open_datagram(
            DatagramRequest::new(DatagramSession::new(
                InboundKind::InternalMeasure,
                client_address,
            )),
            &EstablishContext::default(),
        ),
    )
    .await
    .expect("memory peer must authenticate")
    .unwrap();
    let mut delivered = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(2), async {
        let target = Destination::domain("x", 1).unwrap();
        for sequence in 0..4 {
            udp.send(Datagram {
                remote: target.clone(),
                payload: vec![sequence].into(),
                sniffed_domain: None,
            })
            .await
            .unwrap();
            let reply = udp.receive().await.unwrap();
            assert_eq!(reply.remote, target);
            assert_eq!(reply.payload, vec![sequence; 100]);
            delivered.push(sequence);
        }
        udp.close().await.unwrap();
    })
    .await;
    outbound.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        delivered,
        [0, 1, 2, 3],
        "completed Packet IDs are not replay nonces"
    );
    outcome.expect("all legal replies, including completed ID reuse, must be delivered");
}
