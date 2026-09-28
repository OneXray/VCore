#![cfg(all(feature = "outbound-vless", feature = "interop-test"))]
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "requires the owned container harness"]
async fn native_vision_inner_tls() {
    use vcore::security::{
        SecurityContext, StandardTlsClient, TlsCertificatePolicy, TlsClientOptions,
    };
    let name = "native_vision_inner_tls";
    event(name, "BEGIN");
    let fixture = fixture();
    assert_eq!(fixture["vision_probe"], true);
    let mut fingerprint = [0; 32];
    let pin = fixture["origin_pin"].as_str().unwrap();
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&pin[index * 2..index * 2 + 2], 16).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(120), async {
        for (mode, version) in [(16, 0x13), (18, 0x12)] {
            // Keep one real node across destination families, so Encryption's
            // 0-RTT mode also exercises Vision on reused native tickets.
            let outbound = node(&fixture, None);
            for family in ["ipv4", "ipv6", "domain"] {
                let (mut control, target) = origin(&fixture, mode, family).await;
                let before = outbound.vision_raw_bytes();
                let stream = outbound
                    .connect_stream(session(target), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                let inner = StandardTlsClient::with_options(
                    &SecurityContext::new(),
                    "localhost",
                    TlsClientOptions {
                        certificate: TlsCertificatePolicy {
                            fingerprint: Some(fingerprint),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    0,
                    65536,
                )
                .unwrap();
                let mut stream =
                    tokio::time::timeout(Duration::from_secs(10), inner.connect(stream))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(control.read_u8().await.unwrap(), b'A');
                assert_eq!(control.read_u8().await.unwrap(), version);
                let mut hello = [0; 5];
                stream.read_exact(&mut hello).await.unwrap();
                assert_eq!(&hello, b"hello");
                let payload = vec![0x5a; 10 * 1024 * 1024];
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut response = vec![0; payload.len() + 7];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response[..payload.len()], payload.as_slice());
                assert_eq!(&response[payload.len()..], b"trailer");
                let (read, written) = outbound.vision_raw_bytes();
                let (read, written) = (read - before.0, written - before.1);
                if version == 0x13 {
                    assert!(
                        read > 9 * 1024 * 1024 && written > 9 * 1024 * 1024,
                        "no actual bidirectional direct-mode IO"
                    );
                } else {
                    assert_eq!(
                        (read, written),
                        (0, 0),
                        "TLS 1.2 must remain inside outer TLS"
                    );
                }
                stream.shutdown().await.unwrap();
                assert_eq!(control.read_u8().await.unwrap(), b'D');
                drop(stream);
            }
            outbound.shutdown().await;
        }
    })
    .await
    .unwrap();
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "official isolated container peer required"]
async fn native_vision_direct_close_alignment() {
    use rustls::pki_types::{CertificateDer, ServerName};
    let name = "native_vision_direct_close_alignment";
    event(name, "BEGIN");
    let fixture = fixture();
    assert_eq!(fixture["vision_probe"], true);
    let reference = &fixture["direct_close_reference"];
    assert_eq!(reference["scope"], "same-mode");
    assert_eq!(reference["variant"], "vision-direct");
    assert_eq!(reference["terminated"], true);
    let cert: Vec<u8> = serde_json::from_value(fixture["origin_root_der"].clone()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert)).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    tokio::time::timeout(Duration::from_secs(40), async {
        let outbound = node(&fixture, None);
        for family in ["ipv4", "ipv6"] {
            let (mut control, target) = origin(&fixture, 21, family).await;
            let before = outbound.vision_raw_bytes();
            let io = outbound
                .connect_stream(session(target), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            let mut tls = connector
                .connect(ServerName::try_from("localhost").unwrap(), io)
                .await
                .unwrap();
            assert_eq!(control.read_u8().await.unwrap(), b'A');
            assert_eq!(control.read_u8().await.unwrap(), 0x13);
            let mut greeting = [0; 5];
            tls.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"hello");
            let payload = vec![b'Z'; 65536];
            tls.write_all(&payload).await.unwrap();
            tls.flush().await.unwrap();
            let mut echo = vec![0; payload.len()];
            tls.read_exact(&mut echo).await.unwrap();
            assert_eq!(echo, payload);
            let after = outbound.vision_raw_bytes();
            assert!(after.0 - before.0 > 32768 && after.1 - before.1 > 32768);
            // Upload EOF below the real inner TLS session, without adding a
            // TLS close_notify. The independent client does exactly the same.
            tls.get_mut().0.shutdown().await.unwrap();
            let mut tail = Vec::new();
            let _terminal = tls.read_to_end(&mut tail).await;
            let hex: String = tail.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, reference["tail_hex"].as_str().unwrap());
            assert_eq!(control.read_u8().await.unwrap(), b'D');
            drop(tls);
        }
        outbound.shutdown().await;
    })
    .await
    .expect("direct close did not terminate");
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "official isolated container peer required"]
async fn native_mihomo_close_alignment() {
    let fixture = fixture();
    let node = &fixture["node"];
    let jls_grpc_without_profile = node["network"] == "grpc"
        && node["jls-opts"].is_object()
        && matches!(
            node["client-fingerprint"].as_str(),
            None | Some("" | "none")
        );
    let ech_safari_grpc = node["network"] == "grpc"
        && node["ech-opts"]["enable"] == true
        && matches!(
            node["client-fingerprint"].as_str(),
            Some("safari" | "safari16")
        );
    let scope = if jls_grpc_without_profile || ech_safari_grpc {
        assert_eq!(fixture["close_reference"]["client_fingerprint"], "chrome");
        assert_eq!(
            fixture["close_reference"]["dut_client_fingerprint"],
            node["client-fingerprint"]
        );
        if jls_grpc_without_profile {
            "jls-grpc-chrome-baseline"
        } else {
            "ech-safari-chrome-baseline"
        }
    } else {
        "same-mode"
    };
    compare_native_close("native_mihomo_close_alignment", scope).await;
}

#[tokio::test]
#[ignore = "official isolated peers required; layered reference, not same-mode"]
async fn native_ws_reality_close_boundary() {
    compare_native_close(
        "native_ws_reality_close_boundary",
        "ws-standard-tls-baseline",
    )
    .await;
}

async fn compare_native_close(name: &str, scope: &str) {
    event(name, "BEGIN");
    let fixture = fixture();
    assert_eq!(fixture["close_reference"]["scope"], scope);
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut control, target) = origin(&fixture, 11, "ipv4").await;
        let outbound = node(&fixture, None);
        let mut io = outbound
            .connect_stream(session(target), &EstablishContext::default())
            .await
            .unwrap()
            .io;
        let mut hello = [0; 5];
        io.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        io.write_all(b"ping").await.unwrap();
        io.flush().await.unwrap();
        let mut echo = [0; 4];
        io.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        io.shutdown().await.unwrap();
        let mut tail = Vec::new();
        let _terminal = io.read_to_end(&mut tail).await;
        let hex: String = tail.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(fixture["close_reference"]["terminated"], true);
        assert_eq!(
            hex,
            fixture["close_reference"]["tail_hex"].as_str().unwrap(),
            "explicitly scoped close reference"
        );
        assert_eq!(control.read_u8().await.unwrap(), b'A');
        assert_eq!(control.read_u8().await.unwrap(), b'D');
        drop(io);
        outbound.shutdown().await;
    })
    .await
    .expect("close did not terminate");
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "official isolated container peer required"]
async fn native_grpc_pool_thresholds() {
    use vcore::resources::observation::{ResourceKind, ResourceProbe};
    let name = "native_grpc_pool_thresholds";
    event(name, "BEGIN");
    let original = fixture();
    for (max, min, streams, expected) in [
        (1, 0, 0, [1, 1, 1, 1]),
        (2, 2, 0, [1, 1, 2, 2]),
        (2, 0, 0, [1, 2, 2, 2]),
        (0, 0, 2, [1, 1, 2, 2]),
        (0, 2, 0, [1, 2, 3, 4]),
    ] {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut fixture = original.clone();
                fixture["node"]["grpc-opts"]["max-connections"] = json!(max);
                fixture["node"]["grpc-opts"]["min-streams"] = json!(min);
                fixture["node"]["grpc-opts"]["max-streams"] = json!(streams);
                let outbound = node(&fixture, None);
                let mut held = Vec::new();
                for connections in expected {
                    let (mut observer, target) = origin(&fixture, 13, "ipv4").await;
                    let mut io = outbound
                        .connect_stream(session(target), &EstablishContext::default())
                        .await
                        .unwrap()
                        .io;
                    io.write_all(b"a").await.unwrap();
                    io.flush().await.unwrap();
                    assert_eq!(io.read_u8().await.unwrap(), b'a');
                    assert_eq!(observer.read_u8().await.unwrap(), b'A');
                    assert_eq!(
                        probe.snapshot().current(ResourceKind::Socket),
                        connections,
                        "actual native physical socket count"
                    );
                    held.push((io, observer));
                }
                for (mut io, mut observer) in held {
                    io.shutdown().await.unwrap();
                    drop(io);
                    assert_eq!(observer.read_u8().await.unwrap(), b'D');
                }
                outbound.shutdown().await;
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            })
            .await;
    }
    event(name, "PASS");
}
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vcore::{
    config::{Config, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint, Resolver},
    dispatch::DatagramBudget,
    dns::resolution::ResolutionContext,
    outbound::{DatagramRequest, EstablishContext, OutboundConnector, VlessOutbound},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

fn fixture() -> Value {
    let value: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_VLESS_INPUT").expect("container harness required"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["isolation"], "containers");
    value
}
fn event(name: &str, status: &str) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(std::env::var("VCORE_CASE_EVENTS").unwrap())
        .unwrap();
    writeln!(
        file,
        "{}",
        json!({"schema_version":1,"suite":if std::env::var("VCORE_PROTOCOL_STAGE").as_deref() == Ok("SECURITY") {"SECURITY-WIRE"} else {"VLESS-WIRE"},"assertion":name,"status":status})
    )
    .unwrap();
}
fn node(fixture: &Value, encoding: Option<&str>) -> VlessOutbound {
    let mut node = fixture["node"].clone();
    if let Some(encoding) = encoding {
        node["packet-encoding"] = json!(encoding);
    }
    let config = Config::parse_yaml(
        json!({"socks-port":1080,"proxies":[node],"rules":[format!("MATCH,{}",node["name"].as_str().unwrap())]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let config = config.clone();
    let endpoint = ResolvedEndpoint {
        logical_host: config.address.clone(),
        port: config.port,
        addresses: vec![SocketAddr::new(
            config.address.parse().unwrap(),
            config.port,
        )],
    };
    let download_endpoint = config.download().map(|download| ResolvedEndpoint {
        logical_host: download.address.clone(),
        port: download.port,
        addresses: vec![SocketAddr::new(
            download.address.parse().unwrap(),
            download.port,
        )],
    });
    if matches!(config.security, vcore::config::SecurityConfig::Tls(_)) {
        let root: Vec<u8> = serde_json::from_value(fixture["root_der"].clone()).unwrap();
        VlessOutbound::new_with_test_tls_roots_and_endpoints(
            &config,
            endpoint,
            download_endpoint,
            Dialer::default(),
            [root],
        )
        .unwrap()
    } else {
        VlessOutbound::new_with_endpoints(&config, endpoint, download_endpoint, Dialer::default())
            .unwrap()
    }
}

#[test]
fn native_fixture_prepares_the_independent_download_endpoint() {
    let f = json!({"node": {
        "name": "peer", "type": "vless", "server": "192.0.2.1", "port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001", "network": "xhttp",
        "tls": true, "servername": "fixture.test",
        "reality-opts": {
            "public-key": "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "support-x25519mlkem768": true
        },
        "xhttp-opts": {
            "mode": "stream-up", "path": "/x",
            "download-settings": {"port": 444}
        }
    }});
    let _outbound = node(&f, None);
}

async fn origin(fixture: &Value, mode: u8, family: &str) -> (tokio::net::TcpStream, Destination) {
    let mut control = tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
        .await
        .unwrap();
    control.set_nodelay(true).unwrap();
    control
        .write_u8(if family == "ipv6" && mode >= 10 {
            mode | 0x80
        } else if mode < 10 {
            if family == "ipv6" { 6 } else { 4 }
        } else {
            mode
        })
        .await
        .unwrap();
    let port = control.read_u16().await.unwrap();
    let ip: IpAddr = fixture[if family == "ipv6" {
        "origin_ipv6"
    } else {
        "origin_ipv4"
    }]
    .as_str()
    .unwrap()
    .parse()
    .unwrap();
    assert!(!ip.is_loopback() && !ip.is_unspecified());
    let target = if family == "domain" {
        Destination::domain("vcore-fixture.test", port).unwrap()
    } else {
        SocketAddr::new(ip, port).into()
    };
    (control, target)
}
fn session(target: Destination) -> StreamSession {
    StreamSession {
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: target,
        sniffed_domain: None,
    }
}

#[tokio::test]
#[ignore = "isolated SECURITY JLS runner"]
async fn native_jls_fail_closed() {
    let name = "native_jls_fail_closed";
    event(name, "BEGIN");
    let original = fixture();
    let split = original["node"]["xhttp-opts"]["download-settings"].is_object();
    for download in [false, true]
        .into_iter()
        .filter(|download| !download || split)
    {
        for field in ["username", "password"] {
            let mut f = original.clone();
            let credentials = f["node"]["jls-opts"].clone();
            let leg = if download {
                let leg = &mut f["node"]["xhttp-opts"]["download-settings"];
                leg["jls-opts"] = credentials;
                leg
            } else {
                &mut f["node"]
            };
            leg["jls-opts"][field] = json!("incorrect-credential");
            let (mut control, destination) = origin(&f, 13, "ipv4").await;
            let outbound = node(&f, None);
            let failure = tokio::time::timeout(Duration::from_secs(5), async {
                let mut io = outbound
                    .connect_stream(session(destination), &EstablishContext::default())
                    .await
                    .map_err(|_| std::io::Error::other("connection rejected"))?
                    .io;
                io.write_all(b"must-not-arrive").await?;
                io.flush().await?;
                io.read_u8().await
            })
            .await
            .expect("JLS rejection must not be a timeout");
            assert!(
                failure.is_err(),
                "invalid JLS identity admitted a business stream"
            );
            outbound.shutdown().await;
            assert!(
                tokio::time::timeout(Duration::from_millis(200), control.read_u8())
                    .await
                    .is_err(),
                "JLS rejection must open no origin connection"
            );
        }
    }
    // Use the same public node factory after failures; no fallback or stale identity.
    let (mut control, destination) = origin(&original, 13, "ipv4").await;
    let outbound = node(&original, None);
    let mut io = outbound
        .connect_stream(session(destination), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    io.write_all(b"authenticated").await.unwrap();
    io.flush().await.unwrap();
    let mut response = [0; 13];
    io.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"authenticated");
    assert_eq!(control.read_u8().await.unwrap(), b'A');
    drop(io);
    outbound.shutdown().await;
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "isolated SECURITY ECH runner"]
async fn native_ech_fail_closed() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let name = "native_ech_fail_closed";
    event(name, "BEGIN");
    let original = fixture();
    let split = original["node"]["xhttp-opts"]["download-settings"].is_object();
    for download in [false, true]
        .into_iter()
        .filter(|download| !download || split)
    {
        let mut f = original.clone();
        let ech = f["node"]["ech-opts"].clone();
        if split {
            f["node"]["xhttp-opts"]["download-settings"]["ech-opts"] = ech.clone();
        }
        let leg = if download {
            &mut f["node"]["xhttp-opts"]["download-settings"]
        } else {
            &mut f["node"]
        };
        let mut wrong = STANDARD.decode(ech["config"].as_str().unwrap()).unwrap();
        // A well-formed but stale public key must fail during ECH, not parsing.
        wrong[11..43].fill(7);
        leg["ech-opts"] = json!({"enable":true,"config":STANDARD.encode(wrong)});
        let (mut control, destination) = origin(&f, 13, "ipv4").await;
        let outbound = node(&f, None);
        let failure = tokio::time::timeout(Duration::from_secs(5), async {
            let mut io = outbound
                .connect_stream(session(destination), &EstablishContext::default())
                .await
                .map_err(|_| std::io::Error::other("connection rejected"))?
                .io;
            io.write_all(b"must-not-arrive").await?;
            io.flush().await?;
            io.read_u8().await
        })
        .await
        .expect("ECH rejection must not be a timeout");
        assert!(failure.is_err(), "rejected ECH admitted a business stream");
        outbound.shutdown().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), control.read_u8())
                .await
                .is_err(),
            "ECH rejection opened an origin connection"
        );
    }
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "isolated SECURITY hybrid REALITY runner"]
async fn native_hybrid_fail_closed() {
    use vcore::{config::SecurityConfig, security::SecurityClient};
    let name = "native_hybrid_fail_closed";
    event(name, "BEGIN");
    let original = fixture();
    let (mut observer, target) = origin(&original, 13, "ipv4").await;
    let outbound = node(&original, None);
    let mut io = outbound
        .connect_stream(session(target), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    io.write_all(b"control").await.unwrap();
    io.flush().await.unwrap();
    let mut reply = [0; 7];
    io.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"control");
    assert_eq!(observer.read_u8().await.unwrap(), b'A');
    drop(io);
    outbound.shutdown().await;
    assert_eq!(observer.read_u8().await.unwrap(), b'D');

    let split = original["node"]["xhttp-opts"]["download-settings"].is_object();
    for download in [false, true]
        .into_iter()
        .filter(|download| !download || split)
    {
        for fault in ["public-key", "short-id", "servername"] {
            let mut f = original.clone();
            let base_reality = f["node"]["reality-opts"].clone();
            let target = if download {
                let leg = &mut f["node"]["xhttp-opts"]["download-settings"];
                leg["reality-opts"] = base_reality;
                leg
            } else {
                &mut f["node"]
            };
            match fault {
                "public-key" => {
                    target["reality-opts"][fault] =
                        json!("CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                }
                "short-id" => target["reality-opts"][fault] = json!("ffffffffffffffff"),
                _ => target[fault] = json!("wrong.fixture.test"),
            }
            let (mut control, destination) = origin(&f, 13, "ipv4").await;
            let outbound = node(&f, None);
            let failed = tokio::time::timeout(Duration::from_secs(5), async {
                let mut io = outbound
                    .connect_stream(session(destination), &EstablishContext::default())
                    .await
                    .map_err(|_| std::io::Error::other("connection rejected"))?
                    .io;
                io.write_all(b"must-not-arrive").await?;
                io.flush().await?;
                io.read_u8().await
            })
            .await
            .expect("authentication failure must not be a timeout");
            assert!(
                failed.is_err(),
                "REALITY {fault} accepted on download={download}"
            );
            outbound.shutdown().await;
            assert!(
                tokio::time::timeout(Duration::from_millis(200), control.read_u8())
                    .await
                    .is_err(),
                "rejected identity reached the origin"
            );
        }
    }

    let config = Config::parse_yaml(
        json!({"socks-port":1080,"proxies":[original["node"]],"rules":["MATCH,peer"]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ProxyProtocol::Vless(proxy) = &config.proxies[0].protocol else {
        panic!()
    };
    let mut legs = vec![&proxy.security];
    if let Some(download) = proxy.download() {
        legs.push(&download.security);
    }
    for security in legs {
        assert!(matches!(security, SecurityConfig::Reality(r) if r.support_x25519mlkem768));
        for field in [
            "downgrade_port",
            "hrr_port",
            "ordinary_tls_port",
            "tls12_port",
        ] {
            let port = original[field].as_u64().unwrap() as u16;
            let stream = tokio::net::TcpStream::connect((
                original["node"]["server"].as_str().unwrap(),
                port,
            ))
            .await
            .unwrap();
            let client = SecurityClient::from_security(security).unwrap();
            let result =
                tokio::time::timeout(Duration::from_secs(5), client.connect(Box::new(stream)))
                    .await
                    .expect("peer rejection must not be a timeout");
            assert!(result.is_err(), "required hybrid security accepted {field}");
        }
    }
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "official isolated container peer required"]
async fn native_tcp_integrity_and_server_first() {
    let name = "native_tcp_integrity_and_server_first";
    event(name, "BEGIN");
    let fixture = fixture();
    tokio::time::timeout(Duration::from_secs(120), async {
        for family in ["ipv4", "ipv6", "domain"] {
            let (mut control, target) = origin(&fixture, 10, family).await;
            let outbound = node(&fixture, None);
            let mut stream = outbound
                .connect_stream(session(target), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            let mut first = [0; 5];
            stream.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"hello");
            assert_eq!(control.read_u8().await.unwrap(), b'A');
            let body = vec![0x5a; 10 * 1024 * 1024];
            stream.write_all(&body).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0; body.len() + 7];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..body.len()], body);
            assert_eq!(&reply[body.len()..], b"trailer");
            stream.shutdown().await.unwrap();
            drop(stream);
            outbound.shutdown().await;
            assert_eq!(control.read_u8().await.unwrap(), b'D');
        }
    })
    .await
    .unwrap();
    event(name, "PASS");
}

struct FixtureResolver(IpAddr);
#[async_trait::async_trait]
impl Resolver for FixtureResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        if host != "vcore-fixture.test" {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(ResolvedEndpoint {
            logical_host: host.into(),
            port,
            addresses: vec![SocketAddr::new(self.0, port)],
        })
    }
}
#[tokio::test]
#[ignore = "official isolated container peer required"]
async fn native_three_udp_encodings() {
    udp_encodings("native_three_udp_encodings", false).await;
}

#[tokio::test]
#[ignore = "requires the owned container harness"]
async fn native_vision_xudp() {
    udp_encodings("native_vision_xudp", true).await;
}

async fn udp_encodings(name: &str, vision: bool) {
    event(name, "BEGIN");
    let fixture = fixture();
    assert_eq!(fixture["vision_probe"].as_bool().unwrap_or(false), vision);
    tokio::time::timeout(Duration::from_secs(120), async {
        let resolution = ResolutionContext::measurement(
            Arc::new(FixtureResolver(
                fixture["origin_ipv4"].as_str().unwrap().parse().unwrap(),
            )),
            true,
        );
        for encoding in [None, Some("none"), Some("packetaddr")] {
            if vision && encoding.is_some() {
                continue;
            }
            for family in ["ipv4", "ipv6", "domain"] {
                let (mut control, target) = origin(&fixture, 4, family).await;
                let outbound = node(&fixture, encoding);
                // V2Ray's UDP response writer uses a 2048-byte buffer and
                // needs room for the length prefix / packetaddr address.
                // This fixture-specific cap does not reduce VCore's budget.
                let cap = if fixture["peer_kind"] == "V2" {
                    if encoding.is_none() {
                        2048
                    } else if encoding == Some("packetaddr") {
                        2027
                    } else {
                        2046
                    }
                } else {
                    15000
                };
                let budget = DatagramBudget::new(cap, cap);
                let request = DatagramRequest::new(DatagramSession::new(
                    InboundKind::InternalMeasure,
                    "127.0.0.1:1".parse().unwrap(),
                ))
                .with_budget(budget);
                let mut io = outbound
                    .open_datagram(
                        request,
                        &EstablishContext::with_resolution(
                            Duration::from_secs(10),
                            resolution.clone(),
                        ),
                    )
                    .await
                    .unwrap();
                for size in [1, 64, 512, 1200, cap as usize] {
                    for index in 0..100 {
                        let payload: Vec<u8> = (0..size).map(|i| (i + index) as u8).collect();
                        io.send(Datagram {
                            remote: target.clone(),
                            payload: payload.clone().into(),
                            sniffed_domain: None,
                        })
                        .await
                        .unwrap();
                        let count = control.read_u16().await.unwrap() as usize;
                        let _source = control.read_u16().await.unwrap();
                        assert_eq!(count, size);
                        let mut observed = vec![0; count];
                        control.read_exact(&mut observed).await.unwrap();
                        assert_eq!(observed, payload);
                        let reply = io.receive().await.unwrap();
                        assert_eq!(reply.payload, payload);
                        assert_eq!(reply.remote.port(), target.port());
                    }
                }
                assert!(
                    io.send(Datagram {
                        remote: target,
                        payload: vec![0; cap as usize + 1].into(),
                        sniffed_domain: None
                    })
                    .await
                    .is_err()
                );
                io.close().await.unwrap();
                outbound.shutdown().await;
            }
        }
    })
    .await
    .unwrap();
    event(name, "PASS");
}
