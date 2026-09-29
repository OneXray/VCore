use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use vcore::{
    config::{Config, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint, SocketProtector},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        AnyTlsOutbound, ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector,
        ShadowsocksOutbound, Socks5Outbound, UpstreamPath, VlessOutbound,
        hysteria2::Hysteria2Outbound, trojan::TrojanOutbound, vmess::VmessOutbound,
    },
    security::{SecurityContext, StandardTlsClient, TlsCertificatePolicy, TlsClientOptions},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

pub(super) fn node(
    raw: &Value,
    upstream: Option<Arc<dyn OutboundConnector>>,
    dialer: Dialer,
) -> Arc<dyn OutboundConnector> {
    let mut raw = raw.clone();
    raw["name"] = json!("peer");
    raw.as_object_mut().unwrap().remove("dialer-proxy");
    let parsed = Config::parse_yaml(config(raw, 1080).to_string().as_bytes()).unwrap();
    let proxy = &parsed.proxies[0];
    let path = upstream.map(UpstreamPath::proxy).unwrap_or_else(|| {
        UpstreamPath::direct(
            ResolvedEndpoint {
                logical_host: proxy.address().into(),
                port: proxy.port(),
                addresses: vec![SocketAddr::new(
                    proxy.address().parse().unwrap(),
                    proxy.port(),
                )],
            },
            dialer,
        )
    });
    match &proxy.protocol {
        ProxyProtocol::Socks5(c) => Arc::new(Socks5Outbound::new_with_path(c, path).unwrap()),
        ProxyProtocol::Shadowsocks(c) => {
            Arc::new(ShadowsocksOutbound::new_with_path(c, path).unwrap())
        }
        ProxyProtocol::Trojan(c) => Arc::new(TrojanOutbound::new_with_path(c, path).unwrap()),
        ProxyProtocol::Vmess(c) => Arc::new(VmessOutbound::new_with_path(c, path).unwrap()),
        ProxyProtocol::Vless(c) => Arc::new(VlessOutbound::new_with_path(c, path).unwrap()),
        ProxyProtocol::Hysteria2(c) => Arc::new(Hysteria2Outbound::new_with_path(c, path).unwrap()),
        ProxyProtocol::Tuic(c) => {
            #[cfg(feature = "outbound-tuic")]
            {
                Arc::new(vcore::outbound::tuic::TuicOutbound::new_with_path(c, path).unwrap())
            }
            #[cfg(not(feature = "outbound-tuic"))]
            {
                let _ = c;
                panic!("TUIC is not compiled");
            }
        }
        ProxyProtocol::AnyTls(c) => {
            let tls = StandardTlsClient::with_options(
                &SecurityContext::new(),
                &c.server_name,
                TlsClientOptions {
                    alpn: c.tls.alpn.clone(),
                    client_fingerprint: c.tls.client_fingerprint,
                    certificate: TlsCertificatePolicy {
                        verification_name: None,
                        skip_cert_verify: c.tls.skip_cert_verify,
                        fingerprint: c.tls.fingerprint,
                    },
                    ..Default::default()
                },
                0,
                65536,
            )
            .unwrap();
            Arc::new(
                AnyTlsOutbound::new(
                    vcore::outbound::server_destination(&c.address, c.port).unwrap(),
                    path,
                    &c.password,
                    Arc::new(tls),
                    65536,
                )
                .unwrap(),
            )
        }
    }
}

fn request() -> DatagramRequest {
    DatagramRequest::new(DatagramSession::new(
        InboundKind::Socks5,
        "127.0.0.1:1".parse().unwrap(),
    ))
}
fn session(destination: Destination) -> StreamSession {
    StreamSession {
        inbound: InboundKind::Socks5,
        source: "127.0.0.1:1".parse().unwrap(),
        destination,
        sniffed_domain: None,
    }
}

pub(super) fn budget_pair(f: &Value) -> Value {
    let mut case = RecordedCase::new("INTEGRATION-PAIR", "directional_budget");
    let probe = ResourceProbe::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(probe.scope(async {
        let first = node(&f["first"],None,Dialer::default());
        let last = node(&f["last"],Some(first.clone()),Dialer::default());
        let mut observations = Vec::new();
        for (transmit,receive) in [(128,128),(512,256)] {
            let mut udp = last.open_datagram(request().with_budget(DatagramBudget::new(transmit,receive)),&EstablishContext::default()).await.unwrap();
            let mut origin = Origin::new(f,4,false);
            let remote = Destination::Ip(origin.target);
            let budget = udp.payload_budget(&remote);
            assert_eq!(budget,DatagramBudget::new(transmit,receive));
            let packet = |size| Datagram { remote:remote.clone(),payload:vec![7;size].into(),sniffed_domain:None };
            assert!(udp.send(packet(usize::from(transmit)+1)).await.is_err());
            origin.quiet();
            let size = usize::from(transmit.min(receive));
            for _ in 0..100 {
                udp.send(packet(size)).await.unwrap();
                let reply = tokio::time::timeout(TIMEOUT,udp.receive()).await.unwrap().unwrap();
                assert_eq!(reply.remote,remote);
                assert_eq!(reply.payload,vec![7;size]);
                origin.udp(&vec![7;size]);
            }
            udp.close().await.unwrap();
            observations.push(json!({"transmit":transmit,"receive":receive,"roundtrip_size":size,"packets":100,"oversize_rejected_before_origin":true}));
        }
        last.begin_shutdown(); first.begin_shutdown();
        last.shutdown().await; first.shutdown().await;
        drop((last,first));
        observations
    }));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    case.resources(probe.snapshot());
    json!(result)
}

struct RejectProtect(AtomicUsize);

struct NoDatagrams {
    inner: Arc<dyn OutboundConnector>,
    rejected: AtomicUsize,
}
#[async_trait::async_trait]
impl OutboundConnector for NoDatagrams {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.inner.connect_stream(session, context).await
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.rejected.fetch_add(1, Ordering::SeqCst);
        Err(DispatchError::NotAllowed)
    }
}

pub(super) fn carrier_pair(f: &Value) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut case = RecordedCase::new("INTEGRATION-PAIR", "carrier_capability");
    let probe = ResourceProbe::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let kind = f["last"]["type"].as_str().unwrap();
    let tcp_allowed = !matches!(kind, "hysteria2" | "tuic");
    let udp_allowed = !matches!(kind, "socks5" | "ss" | "hysteria2" | "tuic");
    runtime.block_on(probe.scope(async {
        let first = node(&f["first"], None, Dialer::default());
        let controlled = Arc::new(NoDatagrams {
            inner: first.clone(),
            rejected: AtomicUsize::new(0),
        });
        let last = node(&f["last"], Some(controlled.clone()), Dialer::default());
        let mut origin = Origin::new(f, 13, false);
        let stream = last
            .connect_stream(session(origin.target.into()), &EstablishContext::default())
            .await;
        if tcp_allowed {
            let mut stream = stream.unwrap().io;
            stream.write_all(b"tcp-carrier").await.unwrap();
            // AsyncWrite may buffer (notably VMess); this direct caller must
            // flush before waiting for the peer, just like the public relay.
            stream.flush().await.unwrap();
            let mut bytes = [0; 11];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"tcp-carrier");
            origin.marker(b'A');
            drop(stream);
        } else {
            assert!(stream.is_err());
            origin.quiet();
        }
        let mut origin = Origin::new(f, 4, false);
        let datagram = last
            .open_datagram(request(), &EstablishContext::default())
            .await;
        if udp_allowed {
            let mut datagram = datagram.unwrap();
            datagram
                .send(Datagram {
                    remote: origin.target.into(),
                    payload: bytes::Bytes::from_static(b"stream-carried-udp"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            let response = tokio::time::timeout(TIMEOUT, datagram.receive())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response.payload[..], b"stream-carried-udp");
            origin.udp(b"stream-carried-udp");
            datagram.close().await.unwrap();
        } else {
            assert!(datagram.is_err());
            origin.quiet();
        }
        let rejected = controlled.rejected.load(Ordering::SeqCst);
        assert_eq!(
            rejected,
            usize::from(!tcp_allowed) + usize::from(!udp_allowed)
        );
        last.begin_shutdown();
        first.begin_shutdown();
        last.shutdown().await;
        first.shutdown().await;
        drop((last, controlled, first));
    }));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    case.resources(probe.snapshot());
    json!({"upstream_datagrams":"rejected","tcp_allowed":tcp_allowed,"udp_allowed":udp_allowed,"no_bypass":true})
}
impl SocketProtector for RejectProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
#[ignore = "owned INTEGRATION container fixture required"]
fn protect_failure() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let f = fixture();
    initialize(&f);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for protocol in PROTOCOLS {
        let mut case = RecordedCase::new("INTEGRATION-FAILURES", protocol);
        let probe = ResourceProbe::default();
        let mut origin = Origin::new(&f, 13, false);
        runtime.block_on(probe.scope(async {
            let protector = Arc::new(RejectProtect(AtomicUsize::new(0)));
            let outbound = node(
                &f["nodes"][protocol],
                None,
                Dialer::default().with_protector(protector.clone()),
            );
            let rejected = outbound
                .connect_stream(session(origin.target.into()), &EstablishContext::default())
                .await;
            assert!(rejected.is_err());
            assert!(protector.0.load(Ordering::SeqCst) > 0);
            origin.quiet();
            outbound.begin_shutdown();
            outbound.shutdown().await;
            drop(outbound);
        }));
        assert!(probe.snapshot().is_idle());
        case.resources(probe.snapshot());
        {
            let _case = RecordedCase::new("INTEGRATION-FAILURES-AUTH", protocol);
            let mut bad = f["nodes"][protocol].clone();
            if matches!(protocol, "vmess" | "vless") {
                bad["uuid"] = json!("08080808-0808-0808-0808-080808080808");
            } else if protocol == "ss" {
                bad["password"] = json!(STANDARD.encode([23; 16]));
            } else {
                bad["password"] = json!("invalid-synthetic-identity");
            }
            shadowsocks::rejected(bad, &f);
            if !matches!(protocol, "socks5" | "ss") {
                let mut bad = f["nodes"][protocol].clone();
                bad["fingerprint"] = json!("00".repeat(32));
                bad["skip-cert-verify"] = json!(true);
                shadowsocks::rejected(bad, &f);
            }
        }
        {
            let mut case = RecordedCase::new("INTEGRATION-FAILURES-SOURCE", protocol);
            let port = free_port();
            let probe = ResourceProbe::default();
            if protocol == "tuic" {
                runtime.block_on(probe.scope(transmit_budget(&f["nodes"][protocol], &f)));
                assert!(probe.snapshot().is_idle());
            }
            let core =
                probe.scope_sync(|| Core::start(&config(f["nodes"][protocol].clone(), port)));
            let mut first = Association::new(&f, port, false, false);
            let mut second = Association::new(&f, port, false, false);
            first.exchange(b"first-association");
            second.exchange(b"sibling-association");
            let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            rogue
                .send_to(&first.packet(b"unauthorized-source"), first.relay)
                .unwrap();
            first.origin.quiet();
            // Retain the older codecs' wire-limit negative. TUIC fragments
            // this otherwise valid payload: 65245 is the SOCKS reply limit,
            // not a universal transmit cap. Its explicit budget is tested above.
            if protocol != "tuic" {
                first
                    .client
                    .send_to(&first.packet(&vec![0; 65246]), first.relay)
                    .unwrap();
                first.origin.quiet();
            }
            second.exchange(b"survives-foreign-and-oversize");
            drop(first);
            second.exchange(b"survives-single-association-cancel");
            core.stop();
            runtime::assert_closed(&mut second.control);
            assert!(probe.snapshot().is_idle());
            case.resources(probe.snapshot());
        }
    }
    observe(
        json!({"protect_rejected":PROTOCOLS,"auth_rejected":PROTOCOLS,"certificate_pin_rejected":["anytls","trojan","vmess","vless","hysteria2","tuic"],"source_and_oversize_isolated":PROTOCOLS,"tuic_transmit_budget":{"limit":128,"rejected":129,"following_roundtrip":128},"cancel_preserves_sibling":PROTOCOLS,"no_origin_bytes":true,"stop_idle":true}),
    );
}

async fn transmit_budget(raw: &Value, f: &Value) {
    let outbound = node(raw, None, Dialer::default());
    let mut udp = outbound
        .open_datagram(
            request().with_budget(DatagramBudget::new(128, 128)),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
    let mut origin = Origin::new(f, 4, false);
    let target = origin.target;
    let packet = |size| Datagram {
        remote: target.into(),
        payload: vec![7; size].into(),
        sniffed_domain: None,
    };
    assert_eq!(
        udp.payload_budget(&origin.target.into()),
        DatagramBudget::new(128, 128)
    );
    assert!(udp.send(packet(129)).await.is_err());
    origin.quiet();
    udp.send(packet(128)).await.unwrap();
    let response = tokio::time::timeout(TIMEOUT, udp.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.remote, origin.target.into());
    assert_eq!(&response.payload[..], &[7; 128]);
    origin.udp(&[7; 128]);
    udp.close().await.unwrap();
    drop(udp);
    outbound.begin_shutdown();
    outbound.shutdown().await;
}
