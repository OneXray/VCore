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

fn event_for(assertion: &str, status: &str) {
    use std::io::Write;
    let path = std::env::var("VCORE_CASE_EVENTS").expect("owned harness events");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{}", serde_json::json!({"schema_version":1,"suite":"N3-WIRE","assertion":assertion,"status":status})).unwrap();
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
                &format!("{scheme}://localhost:{}/n3-ws", peer.port()),
                http::HeaderMap::new(),
                None,
            )?;
            raw = connect_websocket(raw, &options, handshake.request(), deadline).await?;
        }
        "grpc" | "h2" => {
            let uri = format!(
                "{scheme}://localhost/{}",
                if mode == "grpc" {
                    "n3-grpc/Tun"
                } else {
                    "n3-h2"
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
                &format!("{scheme}://localhost:{}/n3-http", peer.port()),
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
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let target = listener.local_addr().unwrap().into();
                    let received = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let origin_received = received.clone();
                    let server = tokio::spawn(async move {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        stream.write_all(b"hello").await.unwrap();
                        let mut data = vec![0; PAYLOAD_BYTES];
                        let mut cursor = 0;
                        while cursor < data.len() {
                            let n = stream.read(&mut data[cursor..]).await.unwrap();
                            assert_ne!(n, 0);
                            cursor += n;
                            origin_received.store(cursor, std::sync::atomic::Ordering::SeqCst);
                        }
                        assert!(data.iter().all(|byte| *byte == 0x5a));
                        stream.write_all(&data).await.unwrap();
                        // Integrity is checked before upload EOF. Close behavior
                        // has a separate native-client differential; do not make
                        // an EOF-generated tail a requirement for every peer.
                        stream.write_all(b"trailer").await.unwrap();
                        let mut eof = [0; 1];
                        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
                        stream.shutdown().await.unwrap();
                    });
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
                        "native echo deadline: origin_bytes={} echo_bytes={}",
                        received.load(std::sync::atomic::Ordering::SeqCst),
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
                    server.await.unwrap();
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
async fn native_mihomo_close_alignment() {
    event_for("native_mihomo_close_alignment", "BEGIN");
    tokio::time::timeout(Duration::from_secs(10), async {
        let peer: SocketAddr = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(&std::env::var("VCORE_VMESS_TRANSPORT").unwrap()).unwrap();
        let mode = fixture["mode"].as_str().unwrap();
        let expected_tail = matches!(mode, "tcp" | "ws");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().into();
        let server = tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            io.write_all(b"hello").await.unwrap();
            let mut request = [0; 4];
            io.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            io.write_all(&request).await.unwrap();
            let mut eof = [0; 1];
            assert_eq!(io.read(&mut eof).await.unwrap(), 0);
            // A whole-close peer may already have closed its receiving side.
            let _ = io.write_all(b"native-after-upload-eof").await;
        });
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
        server.await.unwrap();
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination: Destination = listener.local_addr().unwrap().into();
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
            let (mut origin, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut probe = [0; 15];
            origin.read_exact(&mut probe).await.unwrap();
            assert_eq!(&probe, b"synthetic-probe");
            origin.write_all(b"ok").await.unwrap();
            let mut client = VmessStream::new(
                Box::new(raw),
                handshake,
                tokio::time::Instant::now() + Duration::from_secs(2),
            );
            let mut ok = [0; 2];
            client.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"ok");
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(350), listener.accept())
                    .await
                    .is_err(),
                "rejected authentication reached origin"
            );
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
