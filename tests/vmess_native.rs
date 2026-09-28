#![cfg(all(feature = "outbound-vmess", feature = "interop-test"))]
use std::{io, net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vcore::{
    dialer::{Dialer, ResolvedEndpoint},
    outbound::vmess::{
        BodyCipher, BodyOptions, ClientHandshake, Command, VmessIdentity, VmessStream,
    },
    security::{SecurityContext, StandardTlsClient, TlsCertificatePolicy, TlsClientOptions},
    session::Destination,
    transport::{
        HttpObfsOptions, StreamDriver, WebSocketOptions, connect_websocket, grpc, http_obfs,
        legacy_h2,
    },
};

const UUID: uuid::Uuid = uuid::Uuid::from_bytes([7; 16]);
const PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

#[path = "vmess_native/origin.rs"]
mod origin;
#[path = "vmess_native/udp_ab.rs"]
mod udp_ab;

fn native_udp_budget(
    fixture: &serde_json::Value,
    codec: &str,
    cipher: BodyCipher,
    padding: bool,
    length: bool,
    family: &str,
) -> usize {
    let address = if codec == "packetaddr" {
        if family == "ipv4" { 7 } else { 19 }
    } else {
        0
    };
    let host = (fixture["udp_path_limit"].as_u64().unwrap() as usize).min(15000 - address);
    if fixture["peer_kind"] != "V2" {
        return host;
    }
    // Official V2Ray 5.53's packet writer is bounded by its 2048-byte
    // buffer. Mux data is framed outside the body packet boundary; raw and
    // packetaddr must leave room for VMess length, tag and maximum padding.
    // This is a native-fixture budget, never a production protocol limit.
    if codec == "xudp" {
        return host.min(2048);
    }
    let overhead = if cipher == BodyCipher::None {
        2
    } else {
        16 + if length { 18 } else { 2 } + if padding { 63 } else { 0 }
    };
    host.min(2048 - overhead - address)
}

fn event_for(assertion: &str, status: &str) {
    use std::io::Write;
    let path = std::env::var("VCORE_CASE_EVENTS").expect("owned harness events");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{}", serde_json::json!({"schema_version":1,"suite":"VMESS-WIRE","assertion":assertion,"status":status})).unwrap();
}

async fn stream(
    peer: SocketAddr,
    target: Destination,
    cipher: BodyCipher,
    padding: bool,
    length: bool,
) -> io::Result<(VmessStream, Option<StreamDriver>)> {
    wire_stream(peer, target, cipher, padding, length, Command::Tcp).await
}

async fn wire_stream(
    peer: SocketAddr,
    target: Destination,
    cipher: BodyCipher,
    padding: bool,
    length: bool,
    command: Command,
) -> io::Result<(VmessStream, Option<StreamDriver>)> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let endpoint = ResolvedEndpoint {
        logical_host: peer.ip().to_string(),
        port: peer.port(),
        addresses: vec![peer],
    };
    let raw = tokio::time::timeout_at(deadline, Dialer::default().connect(&endpoint)).await??;
    let handshake = ClientHandshake::new(
        &VmessIdentity::new(UUID),
        command,
        &target,
        BodyOptions::new(cipher, padding, length)?,
    )?;
    let mut raw = Box::new(raw) as vcore::dispatch::BoxStream;
    let fixture: serde_json::Value = serde_json::from_str(
        &std::env::var("VCORE_VMESS_TRANSPORT").unwrap_or_else(|_| "{}".into()),
    )
    .unwrap();
    let mode = fixture["mode"].as_str().unwrap_or("tcp");
    let encrypted = fixture["tls"].as_bool().unwrap_or(false);
    let scheme = if encrypted { "https" } else { "http" };
    if encrypted {
        let pin = fixture["pin"].as_str().unwrap();
        let mut fingerprint = [0; 32];
        for (index, byte) in fingerprint.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&pin[2 * index..2 * index + 2], 16).unwrap();
        }
        let alpn = match mode {
            "grpc" | "h2" => vec![b"h2".to_vec()],
            "ws" => vec![b"http/1.1".to_vec()],
            _ => vec![],
        };
        let tls = StandardTlsClient::with_options(
            &SecurityContext::new(),
            "localhost",
            TlsClientOptions {
                required_alpn: alpn.first().cloned(),
                alpn,
                certificate: TlsCertificatePolicy {
                    fingerprint: Some(fingerprint),
                    ..Default::default()
                },
                ..Default::default()
            },
            0,
            65536,
        )?;
        raw = tokio::time::timeout_at(deadline, tls.connect(raw)).await??;
    }
    let mut driver = None;
    match mode {
        "tcp" => {}
        "ws" => {
            let scheme = if encrypted { "wss" } else { "ws" };
            let options = WebSocketOptions::new(
                &format!("{scheme}://localhost:{}/vmess-ws", peer.port()),
                http::HeaderMap::new(),
                None,
            )?;
            raw = connect_websocket(raw, &options, handshake.request(), deadline).await?;
        }
        "grpc" | "h2" => {
            let uri = format!(
                "{scheme}://localhost/{}",
                if mode == "grpc" {
                    "vmess-grpc/Tun"
                } else {
                    "vmess-h2"
                }
            );
            let connected = if mode == "grpc" {
                grpc(raw, &uri, deadline).await?
            } else {
                legacy_h2(raw, &uri, deadline).await?
            };
            raw = connected.0;
            driver = Some(connected.1);
        }
        "http" => {
            let options = HttpObfsOptions::new(
                http::Method::GET,
                &format!("{scheme}://localhost:{}/vmess-http", peer.port()),
                http::HeaderMap::new(),
            )?;
            raw = http_obfs(raw, &options, handshake.request(), deadline).await?;
        }
        _ => panic!("unknown owned transport"),
    }
    if !matches!(mode, "ws" | "http") {
        raw.write_all(handshake.request()).await?;
        raw.flush().await?;
    }
    let stream = VmessStream::new(raw, handshake, deadline);
    Ok((
        if matches!(mode, "grpc" | "http" | "h2") {
            stream.with_whole_close()
        } else {
            stream
        },
        driver,
    ))
}

#[tokio::test]
#[ignore = "requires owned official native peer"]
async fn native_cipher_matrix() {
    event_for("native_cipher_matrix", "BEGIN");
    let peer: SocketAddr = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
    for cipher in [
        BodyCipher::None,
        BodyCipher::Auto,
        BodyCipher::Aes128Gcm,
        BodyCipher::Chacha20Poly1305,
    ] {
        for padding in [false, true] {
            for length in [false, true] {
                if cipher == BodyCipher::None && (padding || length) {
                    continue;
                }
                println!("VMess fixture: {cipher:?} padding={padding} length={length}");
                tokio::time::timeout(Duration::from_secs(30), async {
                    let mut origin = origin::TcpOrigin::new(10).await;
                    let target = origin.target.clone();
                    let (mut client, driver) =
                        stream(peer, target, cipher, padding, length).await.unwrap();
                    let mut greeting = [0; 5];
                    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut greeting))
                        .await
                        .expect("server-first greeting deadline")
                        .unwrap();
                    assert_eq!(&greeting, b"hello");
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        client.write_all(&vec![0x5a; PAYLOAD_BYTES]),
                    )
                    .await
                    .expect("upload deadline")
                    .unwrap();
                    client.flush().await.unwrap();
                    let mut echo = vec![0; PAYLOAD_BYTES];
                    let echoed =
                        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echo))
                            .await;
                    assert!(
                        echoed.is_ok(),
                        "native echo deadline: echo_bytes={}",
                        echo.iter().filter(|byte| **byte == 0x5a).count()
                    );
                    echoed.unwrap().unwrap();
                    assert!(echo.iter().all(|byte| *byte == 0x5a));
                    let mut tail = [0; 7];
                    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut tail))
                        .await
                        .expect("normal response tail deadline")
                        .unwrap();
                    assert_eq!(&tail, b"trailer");
                    client.shutdown().await.unwrap();
                    let mut remaining = Vec::new();
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        client.read_to_end(&mut remaining),
                    )
                    .await
                    .expect("close deadline")
                    .unwrap();
                    assert!(remaining.is_empty());
                    origin.accepted().await;
                    origin.completed().await;
                    drop(client);
                    if let Some(driver) = driver {
                        driver.stop().await.unwrap();
                    }
                })
                .await
                .expect("native exchange deadline");
            }
        }
    }
    event_for("native_cipher_matrix", "PASS");
}

#[tokio::test]
#[ignore = "requires owned official native peer"]
async fn native_raw_udp_boundaries() {
    use vcore::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::vmess::VmessDatagram,
        session::Datagram,
    };
    event_for("native_raw_udp_boundaries", "BEGIN");
    let peer: SocketAddr = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(&std::env::var("VCORE_VMESS_TRANSPORT").unwrap()).unwrap();
    for cipher in [
        BodyCipher::None,
        BodyCipher::Auto,
        BodyCipher::Aes128Gcm,
        BodyCipher::Chacha20Poly1305,
    ] {
        for padding in [false, true] {
            for length in [false, true] {
                if cipher == BodyCipher::None && (padding || length) {
                    continue;
                }
                for family in ["ipv4", "ipv6", "domain"] {
                    let path_limit =
                        native_udp_budget(&fixture, "raw", cipher, padding, length, family);
                    println!(
                        "raw UDP: {cipher:?} padding={padding} length={length} target={family}"
                    );
                    tokio::time::timeout(Duration::from_secs(15), async {
                        let mut origin = udp_ab::ContainerOrigin::connect(&origin::fixture(), family).await.unwrap();
                        let address = origin.address;
                        let target = if family == "domain" {
                            Destination::domain("vcore-fixture.test", address.port()).unwrap()
                        } else {
                            address.into()
                        };
                        let (client, driver) =
                            wire_stream(peer, target.clone(), cipher, padding, length, Command::Udp)
                                .await
                                .unwrap();
                        let mut client = VmessDatagram::raw(client, target.clone(), DatagramBudget::new(path_limit as u16, path_limit as u16));
                        for size in [1, 64, 512, 1200, path_limit] {
                            println!("raw UDP size={size}");
                            for sequence in 0..100 {
                                let packet = vec![sequence as u8; size];
                                client.send(Datagram { remote: target.clone(), payload: packet.clone().into(), sniffed_domain: None }).await.unwrap();
                                let (received, _) = tokio::time::timeout(
                                    Duration::from_secs(1),
                                    origin.receive(),
                                )
                                .await
                                .unwrap_or_else(|_| panic!("native UDP origin deadline: size={size} sequence={sequence}"))
                                .unwrap();
                                assert_eq!(received.len(), size, "raw UDP origin length, sequence={sequence}");
                                assert!(received == packet, "raw UDP origin content, size={size} sequence={sequence}");
                                let echo = tokio::time::timeout(
                                    Duration::from_secs(1),
                                    client.receive(),
                                )
                                .await
                                .expect("native UDP response deadline")
                                .unwrap();
                                assert_eq!(echo.remote, target);
                                assert_eq!(echo.payload.len(), size, "raw UDP response length, sequence={sequence}");
                                assert!(echo.payload == packet, "raw UDP response content, size={size} sequence={sequence}");
                            }
                        }
                        assert!(client.send(Datagram { remote: target, payload: vec![0; path_limit + 1].into(), sniffed_domain: None }).await.is_err());
                        assert!(
                            tokio::time::timeout(
                                Duration::from_millis(30),
                                origin.receive()
                            )
                            .await
                            .is_err()
                        );
                        drop(client);
                        if let Some(driver) = driver {
                            driver.stop().await.unwrap();
                        }
                    })
                    .await
                    .expect("native UDP matrix deadline");
                }
            }
        }
    }
    event_for("native_raw_udp_boundaries", "PASS");
}

#[tokio::test]
#[ignore = "requires owned official native peer"]
async fn native_encoded_udp_boundaries() {
    use bytes::Bytes;
    use vcore::{
        dispatch::{DatagramBudget, DatagramTransport},
        dns::resolution::ResolutionContext,
        outbound::vmess::VmessDatagram,
        session::Datagram,
    };
    event_for("native_encoded_udp_boundaries", "BEGIN");
    let peer: SocketAddr = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(&std::env::var("VCORE_VMESS_TRANSPORT").unwrap()).unwrap();
    for codec in ["xudp", "packetaddr"] {
        for cipher in [
            BodyCipher::None,
            BodyCipher::Auto,
            BodyCipher::Aes128Gcm,
            BodyCipher::Chacha20Poly1305,
        ] {
            for padding in [false, true] {
                for length in [false, true] {
                    if cipher == BodyCipher::None && (padding || length) {
                        continue;
                    }
                    for family in ["ipv4", "ipv6", "domain"] {
                        let maximum =
                            native_udp_budget(&fixture, codec, cipher, padding, length, family);
                        println!(
                            "encoded UDP: {codec} {cipher:?} padding={padding} length={length} target={family}"
                        );
                        tokio::time::timeout(Duration::from_secs(15), async {
                            let mut origin = udp_ab::ContainerOrigin::connect(&origin::fixture(), family).await.unwrap();
                            let address = origin.address;
                            let target = if family == "domain" {
                                Destination::domain("vcore-fixture.test", address.port()).unwrap()
                            } else {
                                address.into()
                            };
                            let (command, magic) = if codec == "xudp" {
                                (Command::Mux, "v1.mux.cool")
                            } else {
                                (Command::Udp, "sp.packet-addr.v2fly.arpa")
                            };
                            let (client, driver) = wire_stream(
                                peer,
                                Destination::domain(magic, 443).unwrap(),
                                cipher,
                                padding,
                                length,
                                command,
                            )
                            .await
                            .unwrap();
                            let resolver = std::sync::Arc::new(FixtureResolver(
                                std::sync::atomic::AtomicUsize::new(0),
                            ));
                            let mut transport: Box<dyn DatagramTransport> = if codec == "xudp" {
                                Box::new(vcore::xudp::XudpTransport::with_budget(
                                    Box::new(client),
                                    [0; 8],
                                    DatagramBudget::new(maximum as u16, maximum as u16),
                                ))
                            } else {
                                Box::new(VmessDatagram::packet_addr(
                                    client,
                                    DatagramBudget::new(maximum as u16, maximum as u16),
                                    ResolutionContext::measurement(resolver.clone(), true),
                                ))
                            };
                            for size in [1, 64, 512, 1200, maximum] {
                                println!("encoded UDP size={size}");
                                for sequence in 0..100 {
                                    let packet = vec![sequence as u8; size];
                                    transport
                                        .send(Datagram {
                                            remote: target.clone(),
                                            payload: Bytes::from(packet.clone()),
                                            sniffed_domain: None,
                                        })
                                        .await
                                        .unwrap();
                                    let (incoming, _) = tokio::time::timeout(
                                        Duration::from_secs(1),
                                        origin.receive(),
                                    )
                                    .await
                                    .unwrap_or_else(|_| panic!("encoded UDP origin deadline: size={size} sequence={sequence}"))
                                    .unwrap();
                                    assert_eq!(incoming.len(), size, "encoded UDP origin length, sequence={sequence}");
                                    assert!(incoming == packet, "encoded UDP origin content, size={size} sequence={sequence}");
                                    let response = tokio::time::timeout(
                                        Duration::from_secs(1),
                                        transport.receive(),
                                    )
                                    .await
                                    .unwrap_or_else(|_| panic!("encoded UDP response deadline: size={size} sequence={sequence}"))
                                    .unwrap();
                                    assert_eq!(response.payload.len(), size, "encoded UDP response length, sequence={sequence}");
                                    assert!(response.payload == packet, "encoded UDP response content, size={size} sequence={sequence}");
                                    assert_eq!(response.remote.port(), address.port());
                                    if family != "domain" || codec == "packetaddr" {
                                        assert_eq!(response.remote, address.into());
                                    }
                                }
                            }
                            assert_eq!(
                                resolver.0.load(std::sync::atomic::Ordering::SeqCst),
                                if family == "domain" && codec == "packetaddr" {
                                    500
                                } else {
                                    0
                                }
                            );
                            let oversized = transport.send(Datagram {
                                remote: target.clone(), payload: vec![0; maximum + 1].into(), sniffed_domain: None,
                            }).await;
                            assert!(oversized.is_err());
                            assert!(tokio::time::timeout(Duration::from_millis(30), origin.receive()).await.is_err());
                            transport.close().await.unwrap();
                            drop(transport);
                            if let Some(driver) = driver {
                                driver.stop().await.unwrap();
                            }
                        })
                        .await
                        .expect("encoded UDP matrix deadline");
                    }
                }
            }
        }
    }
    event_for("native_encoded_udp_boundaries", "PASS");
}

struct FixtureResolver(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl vcore::dialer::Resolver for FixtureResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        assert_eq!(
            host, "vcore-fixture.test",
            "internal magic names must not be resolved"
        );
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let address = std::env::var("VCORE_VMESS_ORIGIN_V4")
            .unwrap_or_else(|_| "127.0.0.1".into())
            .parse::<std::net::IpAddr>()
            .map_err(|_| io::Error::other("invalid fixture resolver address"))?;
        Ok(ResolvedEndpoint {
            logical_host: host.into(),
            port,
            addresses: vec![SocketAddr::new(address, port)],
        })
    }
}

#[tokio::test]
#[ignore = "requires owned official native peer"]
async fn native_mihomo_close_alignment() {
    event_for("native_mihomo_close_alignment", "BEGIN");
    tokio::time::timeout(Duration::from_secs(10), async {
        let peer: SocketAddr = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(&std::env::var("VCORE_VMESS_TRANSPORT").unwrap()).unwrap();
        let mode = fixture["mode"].as_str().unwrap();
        let expected_tail = matches!(mode, "tcp" | "ws");
        let mut origin = origin::TcpOrigin::new(11).await;
        let target = origin.target.clone();
        let (mut client, driver) = stream(peer, target, BodyCipher::Auto, false, false)
            .await
            .unwrap();
        let mut greeting = [0; 5];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"hello");
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut echo = [0; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        client.shutdown().await.unwrap();
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        assert_eq!(
            tail.as_slice(),
            if expected_tail {
                b"native-after-upload-eof".as_slice()
            } else {
                b""
            },
            "close behavior differs from the official Mihomo client"
        );
        origin.accepted().await;
        origin.completed().await;
        drop(client);
        if let Some(driver) = driver {
            driver.stop().await.unwrap();
        }
    })
    .await
    .expect("native close differential deadline");
    event_for("native_mihomo_close_alignment", "PASS");
}

#[tokio::test]
#[ignore = "requires owned official native peer"]
async fn native_identity_time_replay_rejection() {
    event_for("native_identity_time_replay_rejection", "BEGIN");
    let peer: SocketAddr = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
    let mut origin = origin::TcpOrigin::new(12).await;
    let destination = origin.target.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let options = BodyOptions::new(BodyCipher::None, false, false).unwrap();
    let mut replay: Option<Vec<u8>> = None;
    for (id, time, accepted) in [
        (UUID, now, true),
        (uuid::Uuid::from_bytes([8; 16]), now, false),
        (UUID, now - 600, false),
        (UUID, now + 600, false),
        (UUID, now, false),
    ] {
        let handshake = ClientHandshake::with_test_timestamp(
            &VmessIdentity::new(id),
            Command::Tcp,
            &destination,
            options,
            time,
        )
        .unwrap();
        let request = if id == UUID && time == now && !accepted {
            replay.as_ref().unwrap()
        } else {
            handshake.request()
        };
        let mut raw = Dialer::default().connect_address(peer).await.unwrap();
        raw.write_all(request).await.unwrap();
        raw.write_all(b"synthetic-probe").await.unwrap();
        if accepted {
            replay = Some(handshake.request().to_vec());
            origin.accepted().await;
            origin.completed().await;
            let mut client = VmessStream::new(
                Box::new(raw),
                handshake,
                tokio::time::Instant::now() + Duration::from_secs(2),
            );
            let mut ok = [0; 2];
            client.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"ok");
        } else {
            origin.not_accepted().await;
            let mut client = VmessStream::new(
                Box::new(raw),
                handshake,
                tokio::time::Instant::now() + Duration::from_millis(350),
            );
            let mut reply = [0; 1];
            assert!(
                client.read(&mut reply).await.is_err(),
                "rejected authentication returned business data"
            );
        }
    }
    event_for("native_identity_time_replay_rejection", "PASS");
}
