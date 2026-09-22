//! Independent N0 compile and packet-interface probes; no production protocol.
//! In-memory peers establish API feasibility, not official-server interoperability.

#[cfg(test)]
mod tests {
    use quinn::{AsyncUdpSocket, UdpPoller};
    use quinn_proto::congestion::{BbrConfig, Controller, ControllerFactory};
    use std::{
        collections::VecDeque,
        io::{self, IoSliceMut},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    #[test]
    fn boringtun_packet_timer_handshake_and_inner_packet() {
        use boringtun::{
            noise::{Tunn, TunnResult},
            x25519::{PublicKey, StaticSecret},
        };
        let a_secret = StaticSecret::from([1; 32]);
        let b_secret = StaticSecret::from([2; 32]);
        let a_public = PublicKey::from(&a_secret);
        let b_public = PublicKey::from(&b_secret);
        let psk = Some([3; 32]);
        let mut a = Tunn::new(a_secret, b_public, psk, Some(25), 1, None);
        let mut b = Tunn::new(b_secret, a_public, psk, None, 2, None);
        let mut output = [0; 2048];
        assert!(matches!(a.update_timers(&mut output), TunnResult::Done));
        let initiation = match a.format_handshake_initiation(&mut output, false) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            result => panic!("expected handshake initiation: {result:?}"),
        };
        assert_eq!(initiation.len(), 148);
        let response = match b.decapsulate(None, &initiation, &mut output) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            result => panic!("expected handshake response: {result:?}"),
        };
        assert_eq!(response.len(), 92);
        let keepalive = match a.decapsulate(None, &response, &mut output) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            result => panic!("expected keepalive: {result:?}"),
        };
        assert!(matches!(
            b.decapsulate(None, &keepalive, &mut output),
            TunnResult::Done
        ));
        // A minimal IPv4/UDP packet with a synthetic payload, no operating-system network.
        let mut packet = vec![0; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&32_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[28..].copy_from_slice(b"N0WG");
        let encrypted = match a.encapsulate(&packet, &mut output) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            result => panic!("expected transport packet: {result:?}"),
        };
        match b.decapsulate(None, &encrypted, &mut output) {
            TunnResult::WriteToTunnelV4(bytes, _) => assert_eq!(bytes, packet),
            result => panic!("expected inner IPv4 packet: {result:?}"),
        }
        assert!(a.time_since_last_handshake().is_some());
        assert!(b.time_since_last_handshake().is_some());
    }

    #[test]
    fn gotatun_ring_public_packet_and_timer_interfaces() {
        use gotatun::{
            noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
            x25519::{PublicKey, StaticSecret},
        };
        let private = StaticSecret::from([4; 32]);
        let public = PublicKey::from(&private);
        let peer = PublicKey::from(&StaticSecret::from([5; 32]));
        let mut tunnel = Tunn::new(
            private,
            peer,
            Some([6; 32]),
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&public, 100)),
        );
        assert!(tunnel.update_timers().expect("timer").is_none());
        let initiation = tunnel
            .format_handshake_initiation(false)
            .expect("initiation");
        let raw: gotatun::packet::Packet = initiation.into();
        assert_eq!(raw.as_ref().len(), 148);
        tunnel.set_persistent_keepalive(Some(25));
        assert_eq!(tunnel.persistent_keepalive(), Some(25));
        tunnel.set_persistent_keepalive(None);
        assert_eq!(tunnel.persistent_keepalive(), None);
        tunnel.reset();
        assert!(tunnel.time_since_last_handshake().is_none());
    }

    #[derive(Debug, Default)]
    struct Queue {
        packets: VecDeque<(SocketAddr, Vec<u8>)>,
        reader: Option<Waker>,
        writers: Vec<Waker>,
    }

    #[derive(Debug)]
    struct PacketSocket {
        local: SocketAddr,
        remote: SocketAddr,
        input: Arc<Mutex<Queue>>,
        output: Arc<Mutex<Queue>>,
        sent: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct PacketPoller(Arc<Mutex<Queue>>);

    impl UdpPoller for PacketPoller {
        fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut queue = self.0.lock().unwrap();
            if queue.packets.len() < 32 {
                return Poll::Ready(Ok(()));
            }
            if !queue
                .writers
                .iter()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                queue.writers.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }

    impl AsyncUdpSocket for PacketSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(PacketPoller(self.output.clone()))
        }

        fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            if transmit.destination != self.remote
                || transmit.contents.len() > 1400
                || transmit.segment_size.is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet contract",
                ));
            }
            let mut queue = self.output.lock().unwrap();
            if queue.packets.len() == 32 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            queue
                .packets
                .push_back((self.local, transmit.contents.to_vec()));
            self.sent.fetch_add(1, Ordering::Relaxed);
            if let Some(waker) = queue.reader.take() {
                waker.wake();
            }
            Ok(())
        }

        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let mut queue = self.input.lock().unwrap();
            let Some((source, data)) = queue.packets.pop_front() else {
                queue.reader = Some(cx.waker().clone());
                return Poll::Pending;
            };
            if bufs.is_empty() || meta.is_empty() || bufs[0].len() < data.len() {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            bufs[0][..data.len()].copy_from_slice(&data);
            meta[0] = quinn::udp::RecvMeta {
                addr: source,
                len: data.len(),
                stride: data.len(),
                ecn: None,
                dst_ip: Some(self.local.ip()),
            };
            for waker in queue.writers.drain(..) {
                waker.wake();
            }
            Poll::Ready(Ok(1))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local)
        }
        fn may_fragment(&self) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct ObservedController(Arc<AtomicUsize>);

    #[derive(Debug)]
    struct RejectProtector(Arc<AtomicUsize>);

    impl vcore::dialer::SocketProtector for RejectProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn existing_dialer_rejects_udp_before_adapter_can_send() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let dialer = vcore::dialer::Dialer::default()
            .with_protector(Arc::new(RejectProtector(calls.clone())));
        let result = dialer.bind_udp_for(receiver.local_addr().unwrap()).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let mut bytes = [0; 1500];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.recv_from(&mut bytes))
                .await
                .is_err()
        );
    }

    impl ControllerFactory for ObservedController {
        fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Arc::new(BbrConfig::default()).build(now, current_mtu)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quinn_custom_packet_io_and_congestion_with_existing_rustls() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate = certified.cert.der().clone();
            let key =
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
            let mut server_config =
                quinn::ServerConfig::with_single_cert(vec![certificate.clone()], key.into())
                    .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate).unwrap();
            let mut client_config =
                quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
            let controller_builds = Arc::new(AtomicUsize::new(0));
            let mut transport = quinn::TransportConfig::default();
            transport
                .initial_mtu(1200)
                .min_mtu(1200)
                .mtu_discovery_config(None);
            transport.congestion_controller_factory(Arc::new(ObservedController(
                controller_builds.clone(),
            )));
            let transport = Arc::new(transport);
            client_config.transport_config(transport.clone());
            server_config.transport_config(transport);
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39001);
            let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39002);
            let input_a = Arc::new(Mutex::new(Queue::default()));
            let input_b = Arc::new(Mutex::new(Queue::default()));
            let sent = Arc::new(AtomicUsize::new(0));
            let socket_a = Arc::new(PacketSocket {
                local: a,
                remote: b,
                input: input_a.clone(),
                output: input_b.clone(),
                sent: sent.clone(),
            });
            let socket_b = Arc::new(PacketSocket {
                local: b,
                remote: a,
                input: input_b,
                output: input_a,
                sent: sent.clone(),
            });
            let runtime = Arc::new(quinn::TokioRuntime);
            let mut client = quinn::Endpoint::new_with_abstract_socket(
                Default::default(),
                None,
                socket_a,
                runtime.clone(),
            )
            .unwrap();
            let server = quinn::Endpoint::new_with_abstract_socket(
                Default::default(),
                Some(server_config),
                socket_b,
                runtime,
            )
            .unwrap();
            client.set_default_client_config(client_config);
            let (client_connection, server_connection) =
                tokio::join!(client.connect(b, "localhost").unwrap(), async {
                    server.accept().await.unwrap().await
                },);
            let client_connection = client_connection.unwrap();
            let server_connection = server_connection.unwrap();
            let mut stream = client_connection.open_uni().await.unwrap();
            stream
                .write_all(b"N0-QUIC-public-packet-seam")
                .await
                .unwrap();
            stream.finish().unwrap();
            let mut received = server_connection.accept_uni().await.unwrap();
            assert_eq!(
                received.read_to_end(64).await.unwrap(),
                b"N0-QUIC-public-packet-seam"
            );
            let _h3 = h3_quinn::Connection::new(client_connection.clone());
            assert!(sent.load(Ordering::Relaxed) > 0);
            assert!(controller_builds.load(Ordering::Relaxed) >= 2);
            client.close(0_u32.into(), b"done");
            server.close(0_u32.into(), b"done");
            tokio::join!(client.wait_idle(), server.wait_idle());
        })
        .await
        .expect("10 second smoke deadline");
    }
}
