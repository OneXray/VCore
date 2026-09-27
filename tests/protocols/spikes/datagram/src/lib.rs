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
