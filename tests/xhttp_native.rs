#![cfg(all(feature = "outbound-vless", feature = "interop-test"))]

use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vcore::{
    config::{Config, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint, Resolver},
    dispatch::DatagramBudget,
    outbound::{DatagramRequest, EstablishContext, OutboundConnector, VlessOutbound},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

#[path = "xhttp_native/close.rs"]
mod close;
#[path = "xhttp_native/keepalive.rs"]
mod keepalive;
#[path = "xhttp_native/lifecycle.rs"]
mod lifecycle;
#[path = "xhttp_native/security.rs"]
mod security;

fn node(fixture: &Value, encoding: Option<&str>) -> VlessOutbound {
    let mut raw = fixture["node"].clone();
    if let Some(encoding) = encoding {
        raw["packet-encoding"] = encoding.into();
    }
    let config = Config::parse_yaml(
        json!({"socks-port":1080,"proxies":[raw],"rules":["MATCH,peer"]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let endpoint_for = |address: &str, port| ResolvedEndpoint {
        logical_host: address.into(),
        port,
        addresses: vec![SocketAddr::new(
            address
                .parse()
                .unwrap_or_else(|_| fixture["server_ipv4"].as_str().unwrap().parse().unwrap()),
            port,
        )],
    };
    let endpoint = endpoint_for(&config.address, config.port);
    let download = config
        .download()
        .map(|leg| endpoint_for(&leg.address, leg.port));
    if fixture["root_der"].is_array() {
        let root: Vec<u8> = serde_json::from_value(fixture["root_der"].clone()).unwrap();
        VlessOutbound::new_with_test_tls_roots_and_endpoints(
            config,
            endpoint,
            download,
            Dialer::default(),
            [root],
        )
        .unwrap()
    } else {
        VlessOutbound::new_with_endpoints(config, endpoint, download, Dialer::default()).unwrap()
    }
}

#[tokio::test]
#[ignore = "owned isolated Mihomo and origin containers required"]
async fn native_xhttp_request_fields() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_XHTTP_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    let case =
        vcore::resources::case_events::Case::new("XHTTP-XHTTP", "native_xhttp_request_fields");
    tokio::time::timeout(Duration::from_secs(120), async {
        let outbound = node(&fixture, None);
        let tiny = fixture["tiny"].as_bool().unwrap_or(false);
        for family in ["ipv4", "ipv6", "domain"] {
            let mut control =
                tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                    .await
                    .unwrap();
            control.set_nodelay(true).unwrap();
            control
                .write_u8((if tiny { 13 } else { 10 }) | if family == "ipv6" { 0x80 } else { 0 })
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
            let mut io = outbound
                .connect_stream(
                    StreamSession {
                        inbound: InboundKind::InternalMeasure,
                        source: "127.0.0.1:1".parse().unwrap(),
                        destination: target,
                        sniffed_domain: None,
                    },
                    &EstablishContext::default(),
                )
                .await
                .unwrap()
                .io;
            if !tiny {
                let mut greeting = [0; 5];
                io.read_exact(&mut greeting).await.unwrap();
                assert_eq!(&greeting, b"hello");
            }
            let payload = vec![0x5a; if tiny { 256 } else { 10 * 1024 * 1024 }];
            let mut reply = vec![0; payload.len() + if tiny { 0 } else { 7 }];
            // The tiny-POST origin echoes as it reads. Drain both directions,
            // like the real runtime: intentionally withholding all reads can
            // exhaust h2's bounded count of buffered small DATA frames.
            let (mut reader, mut writer) = tokio::io::split(&mut io);
            tokio::try_join!(
                async {
                    writer.write_all(&payload).await?;
                    writer.flush().await
                },
                async { reader.read_exact(&mut reply).await.map(|_| ()) }
            )
            .unwrap();
            drop((reader, writer));
            assert_eq!(control.read_u8().await.unwrap(), b'A');
            assert_eq!(&reply[..payload.len()], payload);
            if !tiny {
                assert_eq!(&reply[payload.len()..], b"trailer");
            }
            io.shutdown().await.unwrap();
            drop(io);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), control.read_u8())
                    .await
                    .expect("origin did not observe whole-connection close")
                    .unwrap(),
                b'D'
            );
        }
        outbound.shutdown().await;
    })
    .await
    .unwrap();
    drop(case);
}

struct FixtureResolver(IpAddr);
#[async_trait::async_trait]
impl Resolver for FixtureResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<ResolvedEndpoint> {
        if host != "vcore-fixture.test" {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        Ok(ResolvedEndpoint {
            logical_host: host.into(),
            port,
            addresses: vec![SocketAddr::new(self.0, port)],
        })
    }
}

#[tokio::test]
#[ignore = "owned isolated Mihomo and origin containers required"]
async fn native_xhttp_udp_encodings() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_XHTTP_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    let case =
        vcore::resources::case_events::Case::new("XHTTP-XHTTP", "native_xhttp_udp_encodings");
    tokio::time::timeout(Duration::from_secs(120), async {
        let resolution = vcore::dns::resolution::ResolutionContext::measurement(
            Arc::new(FixtureResolver(
                fixture["origin_ipv4"].as_str().unwrap().parse().unwrap(),
            )),
            true,
        );
        for encoding in [None, Some("none"), Some("packetaddr")] {
            let outbound = node(&fixture, encoding);
            for family in ["ipv4", "ipv6", "domain"] {
                let mut control =
                    tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                        .await
                        .unwrap();
                control.set_nodelay(true).unwrap();
                control
                    .write_u8(if family == "ipv6" { 6 } else { 4 })
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
                let request = DatagramRequest::new(DatagramSession::new(
                    InboundKind::InternalMeasure,
                    "127.0.0.1:1".parse().unwrap(),
                ))
                .with_budget(DatagramBudget::new(15000, 15000));
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
                for size in [1, 64, 512, 1200, 15000] {
                    for index in 0..100 {
                        let payload: Vec<u8> = (0..size).map(|i| (i + index) as u8).collect();
                        io.send(Datagram {
                            remote: target.clone(),
                            payload: payload.clone().into(),
                            sniffed_domain: None,
                        })
                        .await
                        .unwrap();
                        assert_eq!(usize::from(control.read_u16().await.unwrap()), size);
                        let _source = control.read_u16().await.unwrap();
                        let mut received = vec![0; size];
                        control.read_exact(&mut received).await.unwrap();
                        assert_eq!(received, payload);
                        let reply = io.receive().await.unwrap();
                        assert_eq!(reply.payload, payload);
                        assert_eq!(reply.remote.port(), port);
                    }
                }
                assert!(
                    io.send(Datagram {
                        remote: target,
                        payload: vec![0; 15001].into(),
                        sniffed_domain: None
                    })
                    .await
                    .is_err()
                );
                io.close().await.unwrap();
            }
            outbound.shutdown().await;
        }
    })
    .await
    .unwrap();
    drop(case);
}
