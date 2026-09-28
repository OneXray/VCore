#![cfg(feature = "outbound-hysteria2")]
//! Public connector over memory-only QUIC IO; no host sockets or native-peer claim.
use bytes::Bytes;
use std::{
    io::IoSliceMut,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use vcore::{
    config::{Config, ProxyProtocol},
    outbound::{
        DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        hysteria2::Hysteria2Outbound,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind},
};

#[path = "support/memory_quic.rs"]
mod memory_quic;
use memory_quic::{MemoryPackets, MemoryUpstream, PeerSocket};

#[test]
fn memory_udp_peer_shutdown_is_not_a_local_socket_failure() {
    let (send, remote_receive) = mpsc::channel(1);
    let (remote_send, receive) = mpsc::channel(1);
    remote_send
        .try_send(Bytes::from_static(b"last packet"))
        .unwrap();
    drop(remote_send);
    drop(remote_receive);
    let socket = Arc::new(PeerSocket {
        send,
        receive: Mutex::new(receive),
        local: "192.0.2.1:443".parse().unwrap(),
        remote: "192.0.2.2:1234".parse().unwrap(),
    });
    use quinn::AsyncUdpSocket;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut bytes = [0; 64];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut meta = [quinn::udp::RecvMeta::default()];
    assert!(matches!(
        socket.poll_recv(&mut cx, &mut bufs, &mut meta),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(&bufs[0][..meta[0].len], b"last packet");
    assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
    socket
        .try_send(&quinn::udp::Transmit {
            destination: socket.remote,
            ecn: None,
            contents: b"late close",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let mut poller = socket.create_io_poller();
    assert!(matches!(
        poller.as_mut().poll_writable(&mut cx),
        Poll::Ready(Ok(()))
    ));
}

#[tokio::test]
async fn completed_fragment_id_can_be_reused_without_losing_the_next_datagram() {
    #[cfg(feature = "interop-test")]
    let _case = vcore::resources::case_events::Case::new(
        "INTEGRATION-ADAPTER",
        "hysteria2_fragment_id_reuse",
    );
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
