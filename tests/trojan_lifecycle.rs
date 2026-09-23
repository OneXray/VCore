#![cfg(all(feature = "outbound-trojan", feature = "interop-test"))]

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
use tokio::io::AsyncReadExt;
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
        "N2-CANCEL",
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
        "N2-CANCEL",
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
