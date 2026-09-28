// These probes exercise the Unix fd protector. Windows uses its separate
// physical-interface binding contract, not this callback.
#![cfg(all(unix, feature = "outbound-trojan", feature = "interop-test"))]

use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vcore::{
    config::{Config, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint, SocketProtector},
    outbound::{EstablishContext, OutboundConnector, UpstreamPath, trojan::TrojanOutbound},
    resources::{
        case_events::Case,
        observation::{ResourceKind, ResourceProbe},
    },
    session::{Destination, InboundKind, StreamSession},
};

#[derive(Default)]
struct Protect {
    calls: AtomicUsize,
    reject: bool,
}

#[tokio::test]
#[ignore = "requires the owned TROJAN native-peer runner"]
async fn trojan_native_owned_resources() {
    use bytes::Bytes;
    use vcore::{
        outbound::DatagramRequest,
        session::{Datagram, DatagramSession},
    };
    let _case = Case::new("TROJAN-NATIVE", "trojan_native_owned_resources");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::env::var("VCORE_TROJAN_FIXTURE").unwrap()).unwrap();
    let node = &fixture["node"];
    let config = Config::parse_yaml(
        json!({"socks-port":1080,"proxies":[node],"rules":["MATCH,peer"]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ProxyProtocol::Trojan(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    for _ in 0..20 {
        let mut cycle = Case::new("TROJAN-OWNED-CYCLE", "stop_and_remain_quiet");
        let probe = ResourceProbe::default();
        cycle.checkpoint("baseline", probe.snapshot());
        probe
            .scope(async {
                let address = std::net::SocketAddr::new(
                    node["server"].as_str().unwrap().parse().unwrap(),
                    node["port"].as_u64().unwrap() as u16,
                );
                let endpoint = ResolvedEndpoint {
                    logical_host: node["server"].as_str().unwrap().into(),
                    port: address.port(),
                    addresses: vec![address],
                };
                let protect = Arc::new(Protect::default());
                let outbound = TrojanOutbound::new_with_path(
                    config,
                    UpstreamPath::direct(
                        endpoint,
                        Dialer::default().with_protector(protect.clone()),
                    ),
                )
                .unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut request = session();
                request.destination = Destination::Ip(listener.local_addr().unwrap());
                let mut first = outbound
                    .connect_stream(request.clone(), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                first.write_all(b"one").await.unwrap();
                first.flush().await.unwrap();
                let (mut remote1, _) = listener.accept().await.unwrap();
                assert_eq!(&remote1.read_u8().await.unwrap(), &b'o');
                let mut second = outbound
                    .connect_stream(request, &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                second.write_all(b"two").await.unwrap();
                second.flush().await.unwrap();
                let (mut remote2, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 3];
                remote2.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"two");
                drop(first);
                remote2.write_all(b"live").await.unwrap();
                let mut reply = [0; 4];
                second.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"live");
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let datagram = DatagramRequest::new(DatagramSession::new(
                    InboundKind::InternalMeasure,
                    "127.0.0.1:1".parse().unwrap(),
                ));
                let mut udp = outbound
                    .open_datagram(datagram, &EstablishContext::default())
                    .await
                    .unwrap();
                udp.send(Datagram {
                    remote: Destination::Ip(origin.local_addr().unwrap()),
                    payload: Bytes::from_static(b"udp"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let (n, source) = origin.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..n], b"udp");
                origin.send_to(b"udp", source).await.unwrap();
                assert_eq!(udp.receive().await.unwrap().payload.as_ref(), b"udp");
                assert!(probe.snapshot().peak(ResourceKind::Association) > 0);
                assert!(probe.snapshot().peak(ResourceKind::Session) > 0);
                assert!(probe.snapshot().peak(ResourceKind::Socket) > 0);
                if node["network"] == "grpc" {
                    assert!(probe.snapshot().peak(ResourceKind::Task) > 0);
                }
                // RunningCore first cancels and joins inbound owners, dropping
                // their streams/associations, then joins protocol-owned drivers.
                outbound.begin_shutdown();
                assert!(second.read_u8().await.is_err());
                drop(second);
                udp.close().await.unwrap();
                drop(udp);
                tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                    .await
                    .unwrap();
                assert!(
                    probe.snapshot().is_idle(),
                    "Stop retained owned resources: {:?}",
                    probe.snapshot()
                );
                cycle.checkpoint("after-stop", probe.snapshot());
                let calls = protect.calls.load(Ordering::SeqCst);
                assert_eq!(calls, 3);
                let stopped = probe.snapshot();
                let quiet = tokio::time::Instant::now();
                while quiet.elapsed() < Duration::from_secs(5) {
                    assert_eq!(probe.snapshot(), stopped);
                    assert_eq!(protect.calls.load(Ordering::SeqCst), calls);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                cycle.checkpoint("quiet", probe.snapshot());
                drop(outbound);
                assert_eq!(Arc::strong_count(&protect), 1);
            })
            .await;
        cycle.resources(probe.snapshot());
    }
}
impl SocketProtector for Protect {
    fn protect(&self, _: i32) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }
}

fn session() -> StreamSession {
    StreamSession {
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: Destination::Ip("127.0.0.1:9".parse().unwrap()),
        sniffed_domain: None,
    }
}

#[tokio::test]
async fn trojan_handshake_deadlines_cancel_tls_ws_and_grpc_without_retaining_io() {
    let mut case = Case::new(
        "TROJAN-CANCEL",
        "trojan_handshake_deadlines_cancel_tls_ws_and_grpc_without_retaining_io",
    );
    for mode in ["tls", "ws", "grpc"] {
        let probe = ResourceProbe::default();
        probe.scope(async {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["fixture.invalid".into()]).unwrap().self_signed(&key).unwrap();
            let pin: String = Sha256::digest(cert.der().as_ref()).iter().map(|byte|format!("{byte:02x}")).collect();
            let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()],rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into())).unwrap();
            tls.alpn_protocols = vec![if mode == "grpc" {b"h2".to_vec()} else {b"http/1.1".to_vec()}];
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (mut raw,_) = listener.accept().await.unwrap();
                if mode == "tls" {
                    let mut bytes = [0;4096];
                    assert!(raw.read(&mut bytes).await.unwrap() > 0);
                    assert_eq!(raw.read(&mut bytes).await.unwrap(),0);
                    return;
                }
                let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls)).accept(raw).await.unwrap();
                if mode == "ws" {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") { request.push(stream.read_u8().await.unwrap()); }
                    let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                    assert!(request.starts_with("get /edge?q=1 http/1.1"));
                    assert!(request.contains("host: cover.example:443\r\n"));
                    assert!(request.contains("x-fixture: exact-value\r\n"));
                    // Withhold the Upgrade, exercising cancellation after the
                    // actual protocol consumer wrote its configured request.
                    let mut bytes = Vec::new();
                    let _ = stream.read_to_end(&mut bytes).await;
                } else {
                    let mut h2 = h2::server::handshake(stream).await.unwrap();
                    let (request,_response) = h2.accept().await.unwrap().unwrap();
                    assert_eq!(request.uri().path(),"/custom/Tun");
                    // No response headers: the gRPC response deadline must
                    // still be the original setup deadline, not a fresh one.
                    while let Some(result) = h2.accept().await { if result.is_err() { break; } }
                }
            });
            let mut node = json!({"name":"peer","type":"trojan","server":"127.0.0.1","port":address.port(),"password":"fixture","sni":"fixture.invalid","fingerprint":pin});
            match mode {
                "ws" => { node["network"] = json!("ws"); node["ws-opts"] = json!({"path":"/edge?q=1","headers":{"Host":"cover.example:443","X-Fixture":"exact-value"}}); },
                "grpc" => { node["network"] = json!("grpc"); node["grpc-opts"] = json!({"grpc-service-name":"/custom/Tun"}); },
                _ => {},
            }
            let parsed = Config::parse_yaml(json!({"socks-port":1080,"proxies":[node],"rules":["MATCH,peer"]}).to_string().as_bytes()).unwrap();
            let ProxyProtocol::Trojan(config) = &parsed.proxies[0].protocol else { unreachable!() };
            let protect = Arc::new(Protect::default());
            let endpoint = ResolvedEndpoint { logical_host:"127.0.0.1".into(),port:address.port(),addresses:vec![address] };
            let outbound = TrojanOutbound::new_with_path(config,UpstreamPath::direct(endpoint,Dialer::default().with_protector(protect.clone()))).unwrap();
            let started = tokio::time::Instant::now();
            let context = EstablishContext::with_timeout(Duration::from_millis(150));
            let connected = outbound.connect_stream(session(),&context).await;
            if mode == "grpc" {
                let mut stream = connected.unwrap().io;
                assert!(tokio::time::timeout(Duration::from_secs(1),stream.read_u8()).await.unwrap().is_err());
                drop(stream);
            } else { assert!(connected.is_err()); }
            assert!(started.elapsed() < Duration::from_secs(1));
            tokio::time::timeout(Duration::from_secs(5),outbound.shutdown()).await.unwrap();
            drop(outbound);
            tokio::time::timeout(Duration::from_secs(1),peer).await.unwrap().unwrap();
            assert_eq!(protect.calls.load(Ordering::SeqCst),1);
            assert_eq!(Arc::strong_count(&protect),1);
            assert!(probe.snapshot().is_idle(),"mode={mode}: {:?}",probe.snapshot());
            assert_eq!(probe.snapshot().peak(ResourceKind::Socket),1);
        }).await;
        case.checkpoint("after-stop", probe.snapshot());
        case.resources(probe.snapshot());
    }
}

#[tokio::test]
async fn trojan_protect_rejection_and_expired_deadline_send_no_network_bytes() {
    let mut case = Case::new(
        "TROJAN-CANCEL",
        "trojan_protect_rejection_and_expired_deadline_send_no_network_bytes",
    );
    let probe = ResourceProbe::default();
    probe.scope(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let parsed = Config::parse_yaml(json!({"socks-port":1080,"proxies":[{"name":"peer","type":"trojan","server":"127.0.0.1","port":address.port(),"password":"fixture"}],"rules":["MATCH,peer"]}).to_string().as_bytes()).unwrap();
        let ProxyProtocol::Trojan(config) = &parsed.proxies[0].protocol else { unreachable!() };
        let protect = Arc::new(Protect {reject:true,..Default::default()});
        let endpoint = ResolvedEndpoint {logical_host:"127.0.0.1".into(),port:address.port(),addresses:vec![address]};
        let outbound = TrojanOutbound::new_with_path(config,UpstreamPath::direct(endpoint,Dialer::default().with_protector(protect.clone()))).unwrap();
        assert!(outbound.connect_stream(session(),&EstablishContext::default()).await.is_err());
        assert_eq!(protect.calls.load(Ordering::SeqCst),1);
        assert!(outbound.connect_stream(session(),&EstablishContext::with_timeout(Duration::ZERO)).await.is_err());
        assert_eq!(protect.calls.load(Ordering::SeqCst),1);
        assert!(tokio::time::timeout(Duration::from_millis(20),listener.accept()).await.is_err());
        outbound.shutdown().await;
        drop(outbound);
    }).await;
    assert!(probe.snapshot().is_idle());
    case.resources(probe.snapshot());
}
