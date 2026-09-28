#![cfg(all(feature = "outbound-vless", feature = "interop-test"))]

use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::{Instant, timeout, timeout_at},
};
use vcore::{
    dialer::Dialer,
    dispatch::BoxStream,
    outbound::{VlessCommand, VlessEncryptionClient as Client, VlessStream, encode_request_header},
    session::Destination,
};

struct CountWrites(BoxStream, Arc<AtomicUsize>, Arc<Mutex<Vec<u8>>>);
fn encryption_client(fixture: &serde_json::Value, settings: &str) -> Client {
    let client = Client::parse(settings).unwrap();
    if fixture["force_chacha"] == true {
        client.with_chacha20_poly1305_for_interop()
    } else {
        client
    }
}
impl AsyncRead for CountWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, b)
    }
}

#[tokio::test]
#[ignore = "requires the owned SECURITY Encryption container harness"]
async fn public_tcp_roundtrip() {
    use vcore::{
        config::{Config, ProxyProtocol},
        dialer::ResolvedEndpoint,
        outbound::{EstablishContext, OutboundConnector, VlessOutbound},
        session::{InboundKind, StreamSession},
    };
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_ENCRYPTION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    let config=Config::parse_yaml(&serde_json::to_vec(&serde_json::json!({"socks-port":1080,"proxies":[fixture["node"]],"rules":["MATCH,edge"]})).unwrap()).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        panic!()
    };
    let outbound = VlessOutbound::new(
        node,
        ResolvedEndpoint {
            logical_host: node.address.clone(),
            port: node.port,
            addresses: vec![SocketAddr::new(node.address.parse().unwrap(), node.port)],
        },
        Dialer::default(),
    )
    .unwrap();
    for round in 0..4 {
        timeout(Duration::from_secs(25), async {
            let family = if round % 2 == 0 { "ipv4" } else { "ipv6" };
            let mut control =
                tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                    .await
                    .unwrap();
            control
                .write_u8(if round % 2 == 0 { 10 } else { 138 })
                .await
                .unwrap();
            let port = control.read_u16().await.unwrap();
            let destination = Destination::Ip(SocketAddr::new(
                fixture[format!("origin_{family}")]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                port,
            ));
            let mut stream = outbound
                .connect_stream(
                    StreamSession {
                        inbound: InboundKind::InternalMeasure,
                        source: "127.0.0.1:1".parse().unwrap(),
                        destination,
                        sniffed_domain: None,
                    },
                    &EstablishContext::default(),
                )
                .await
                .unwrap()
                .io;
            let mut hello = [0; 5];
            stream.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, *b"hello");
            assert_eq!(control.read_u8().await.unwrap(), b'A');
            let payload = vec![0x5a; 10 * 1024 * 1024];
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut received = vec![0; payload.len() + 7];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received[..payload.len()], &payload);
            assert_eq!(&received[payload.len()..], b"trailer");
            stream.shutdown().await.unwrap();
            drop(stream);
            assert_eq!(control.read_u8().await.unwrap(), b'D');
        })
        .await
        .unwrap();
    }
    outbound.shutdown().await;
    println!("SECURITY-ENCRYPTION-CONSUMER-PASS rounds=4 bytes_per_direction=10485760");
}
impl AsyncWrite for CountWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.0).poll_write(cx, b);
        if let Poll::Ready(Ok(n)) = result {
            self.1.fetch_add(n, Ordering::SeqCst);
            let mut prefix = self.2.lock().unwrap();
            let count = n.min(4096 - prefix.len());
            prefix.extend_from_slice(&b[..count]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Fault injection at caller-owned IO, not a custom peer or decoder.
struct CorruptRead(BoxStream, usize, usize);
impl AsyncRead for CorruptRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = b.filled().len();
        let result = Pin::new(&mut self.0).poll_read(cx, b);
        if let Poll::Ready(Ok(())) = result {
            let count = b.filled().len() - start;
            if self.1 >= self.2 && self.1 < self.2 + count {
                b.filled_mut()[start + self.1 - self.2] ^= 1;
            }
            self.2 += count;
        }
        result
    }
}
impl AsyncWrite for CorruptRead {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::test]
#[ignore = "requires the owned SECURITY Encryption container harness"]
async fn native_encryption_roundtrip() {
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_ENCRYPTION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    let client = encryption_client(&fixture, fixture["encryption"].as_str().unwrap());
    let mut full_flight = 0;
    for round in 0..4 {
        let family = if round % 2 == 0 { "ipv4" } else { "ipv6" };
        let deadline = Instant::now() + Duration::from_secs(25);
        timeout_at(deadline, async {
            let mut control =
                tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                    .await
                    .unwrap();
            control
                .write_u8(if family == "ipv4" { 10 } else { 10 | 0x80 })
                .await
                .unwrap();
            let port = control.read_u16().await.unwrap();
            let origin: IpAddr = fixture[format!("origin_{family}")]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let peer: IpAddr = fixture[format!("server_{family}")]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let raw = Dialer::default()
                .connect_address(SocketAddr::new(
                    peer,
                    fixture["port"].as_u64().unwrap() as u16,
                ))
                .await
                .unwrap();
            let sent = Arc::new(AtomicUsize::new(0));
            let capture = Arc::new(Mutex::new(Vec::new()));
            let encrypted = client
                .connect(
                    Box::new(CountWrites(Box::new(raw), sent.clone(), capture.clone())),
                    deadline,
                )
                .await
                .unwrap();
            let handshake_bytes = sent.load(Ordering::SeqCst);
            let resumed = round != 0 && fixture["encryption"].as_str().unwrap().contains(".0rtt.");
            if resumed {
                assert_eq!(
                    handshake_bytes, 0,
                    "0-RTT must return without waiting for or sending a full handshake"
                );
            } else {
                assert!(
                    handshake_bytes >= 1333,
                    "a fresh client must perform the complete authenticated handshake"
                );
                full_flight = handshake_bytes;
            }
            let destination = Destination::Ip(SocketAddr::new(origin, port));
            let header = encode_request_header(
                uuid::Uuid::from_bytes([7; 16]),
                VlessCommand::Tcp,
                Some(&destination),
            )
            .unwrap();
            let mut stream = VlessStream::with_deadline(encrypted, header, deadline);
            let mut hello = [0; 5];
            stream.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, *b"hello");
            if resumed {
                assert!(
                    sent.load(Ordering::SeqCst) + 1000 < full_flight,
                    "resumed wire prefix must not contain a full PFS exchange"
                );
            }
            assert_eq!(control.read_u8().await.unwrap(), b'A');
            let replay = if resumed && round == 1 {
                Some(capture.lock().unwrap().clone())
            } else {
                None
            };
            let payload = vec![0x5a; 10 * 1024 * 1024];
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut received = vec![0; payload.len() + 7];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received[..payload.len()], &payload);
            assert_eq!(&received[payload.len()..], b"trailer");
            stream.shutdown().await.unwrap();
            drop(stream);
            assert_eq!(control.read_u8().await.unwrap(), b'D');
            if let Some(replay) = replay {
                let mut raw = Dialer::default()
                    .connect_address(SocketAddr::new(
                        peer,
                        fixture["port"].as_u64().unwrap() as u16,
                    ))
                    .await
                    .unwrap();
                raw.write_all(&replay).await.unwrap();
                raw.flush().await.unwrap();
                let mut byte = [0; 1];
                let result = timeout(Duration::from_secs(3), raw.read(&mut byte))
                    .await
                    .expect("replayed NFS flight must be rejected promptly");
                assert!(
                    matches!(result, Ok(0))
                        || result.as_ref().is_err_and(|e| matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                        ))
                );
                assert!(
                    timeout(Duration::from_millis(150), control.read_u8())
                        .await
                        .is_err(),
                    "replay must not reach the original live origin listener"
                );
            }
        })
        .await
        .unwrap();
    }
    let encryption = fixture["encryption"].as_str().unwrap();
    // A separately constructed node must never inherit this node's ticket.
    identity_probe(
        &encryption_client(&fixture, encryption),
        &fixture,
        false,
        true,
        false,
        None,
    )
    .await;
    if encryption.contains(".0rtt.") {
        identity_probe(&client, &fixture, true, false, true, None).await;
        identity_probe(&client, &fixture, false, true, false, None).await;
        identity_probe(&client, &fixture, false, true, true, None).await;
    }
    use base64::Engine as _;
    let mut parts: Vec<String> = encryption.split('.').map(str::to_owned).collect();
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&parts[3])
        .unwrap();
    parts[3] = if key.len() == 32 {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32])
    } else {
        let (public, _) =
            boring::mlkem::MlKemPrivateKey::generate(boring::mlkem::Algorithm::MlKem768).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes())
    };
    identity_probe(
        &encryption_client(&fixture, &parts.join(".")),
        &fixture,
        false,
        false,
        false,
        None,
    )
    .await;
    for offset in [0, 1136, 1168] {
        identity_probe(
            &encryption_client(&fixture, encryption),
            &fixture,
            false,
            false,
            false,
            Some(offset),
        )
        .await;
    }
    client.close();
    println!("SECURITY-ENCRYPTION-WIRE-PASS rounds=4 bytes_per_direction=10485760");
}

#[tokio::test]
#[ignore = "requires the owned SECURITY Encryption container harness with short-lived tickets"]
async fn native_ticket_expiry() {
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_ENCRYPTION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    assert_eq!(fixture["ticket_expiry"], true);
    let encryption = fixture["encryption"].as_str().unwrap();
    assert!(encryption.contains(".0rtt."));
    let client = encryption_client(&fixture, encryption);
    identity_probe(&client, &fixture, false, true, false, None).await;
    identity_probe(&client, &fixture, false, true, true, None).await;
    // The independent peer advertises two seconds. Real monotonic time, no
    // mutation of the cache or server clock, and no automatic business retry.
    tokio::time::sleep(Duration::from_secs(3)).await;
    identity_probe(&client, &fixture, false, true, false, None).await;
    identity_probe(&client, &fixture, false, true, true, None).await;
    client.close();
    println!("SECURITY-ENCRYPTION-EXPIRY-PASS full-resumed-expired-full-resumed");
}

async fn identity_probe(
    client: &Client,
    fixture: &serde_json::Value,
    other_handler: bool,
    should_succeed: bool,
    resumed: bool,
    corrupt: Option<usize>,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut control = tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
        .await
        .unwrap();
    control.write_u8(12).await.unwrap();
    let port = control.read_u16().await.unwrap();
    let origin: IpAddr = fixture["origin_ipv4"].as_str().unwrap().parse().unwrap();
    let server: IpAddr = fixture["server_ipv4"].as_str().unwrap().parse().unwrap();
    let peer_port = fixture[if other_handler { "reject_port" } else { "port" }]
        .as_u64()
        .unwrap() as u16;
    let bytes = Arc::new(AtomicUsize::new(0));
    let result = timeout_at(deadline, async {
        let raw = Dialer::default()
            .connect_address(SocketAddr::new(server, peer_port))
            .await?;
        let raw: BoxStream = if let Some(offset) = corrupt {
            Box::new(CorruptRead(Box::new(raw), offset, 0))
        } else {
            Box::new(raw)
        };
        let raw = client
            .connect(
                Box::new(CountWrites(raw, bytes.clone(), Arc::default())),
                deadline,
            )
            .await?;
        assert_eq!(
            bytes.load(Ordering::SeqCst) == 0,
            resumed,
            "cache must be node-local and rejected tickets must be replaced by a full handshake"
        );
        let header = encode_request_header(
            uuid::Uuid::from_bytes([7; 16]),
            VlessCommand::Tcp,
            Some(&Destination::Ip(SocketAddr::new(origin, port))),
        )?;
        let mut stream = VlessStream::with_deadline(raw, header, deadline);
        stream.write_all(b"synthetic-probe").await?;
        stream.flush().await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        assert_eq!(response, *b"ok");
        stream.shutdown().await?;
        Ok::<_, io::Error>(())
    })
    .await
    .expect("authentication outcome must be explicit, not timeout");
    if should_succeed {
        result.unwrap();
        assert_eq!(control.read_u8().await.unwrap(), b'A');
        assert_eq!(control.read_u8().await.unwrap(), b'D');
    } else {
        assert!(result.is_err(), "invalid authentication must not succeed");
        if corrupt.is_some() {
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "modified handshake must fail authentication"
            );
        }
        assert!(
            timeout(Duration::from_millis(150), control.read_u8())
                .await
                .is_err(),
            "failed authentication must produce zero origin accepts"
        );
    }
}
