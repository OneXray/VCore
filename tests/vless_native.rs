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
            for family in ["ipv4", "ipv6", "domain"] {
                let (mut control, target) = origin(&fixture, mode, family).await;
                let outbound = node(&fixture, None);
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
                outbound.shutdown().await;
            }
        }
    })
    .await
    .unwrap();
    event(name, "PASS");
}

#[tokio::test]
#[ignore = "official isolated container peer required"]
async fn native_mihomo_close_alignment() {
    compare_native_close("native_mihomo_close_alignment", "same-mode").await;
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
        json!({"schema_version":1,"suite":"N4-WIRE","assertion":name,"status":status})
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
    if matches!(config.security, vcore::config::SecurityConfig::Tls(_)) {
        let root: Vec<u8> = serde_json::from_value(fixture["root_der"].clone()).unwrap();
        VlessOutbound::new_with_test_tls_roots(&config, endpoint, Dialer::default(), [root])
            .unwrap()
    } else {
        VlessOutbound::new(&config, endpoint, Dialer::default()).unwrap()
    }
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
