use super::*;
use vcore::resources::{
    case_events::Case,
    observation::{ResourceKind, ResourceProbe},
};

async fn origin(f: &Value, mode: u8) -> (tokio::net::TcpStream, Destination) {
    let mut control = tokio::net::TcpStream::connect(f["origin_control"].as_str().unwrap())
        .await
        .unwrap();
    control.set_nodelay(true).unwrap();
    control.write_u8(mode).await.unwrap();
    let port = control.read_u16().await.unwrap();
    let ip = f["origin_ipv4"].as_str().unwrap().parse().unwrap();
    (control, Destination::Ip(SocketAddr::new(ip, port)))
}

async fn tcp(outbound: &VlessOutbound, target: Destination) -> vcore::dispatch::BoxStream {
    outbound
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
        .io
}
async fn exchange(io: &mut vcore::dispatch::BoxStream, byte: u8) {
    io.write_u8(byte).await.unwrap();
    io.flush().await.unwrap();
    assert_eq!(io.read_u8().await.unwrap(), byte);
}

#[tokio::test]
#[ignore = "owned isolated protocol peers and origins required"]
async fn native_xhttp_owned_resources() {
    let f: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_XHTTP_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(f["isolation"], "containers");
    let _case = Case::new("XHTTP-XHTTP", "lifecycle::native_xhttp_owned_resources");
    tokio::time::timeout(Duration::from_secs(220), async {
        for _ in 0..20 {
            let mut cycle = Case::new("XHTTP-OWNED", "stop_and_remain_quiet");
            let probe = ResourceProbe::default();
            cycle.checkpoint("baseline", probe.snapshot());
            probe
                .scope(async {
                    let outbound = node(&f, None);
                    let (mut control1, target1) = origin(&f, 13).await;
                    let (mut control2, target2) = origin(&f, 13).await;
                    let (mut control_udp, target_udp) = origin(&f, 4).await;
                    let mut first = tcp(&outbound, target1).await;
                    let mut sibling = tcp(&outbound, target2).await;
                    exchange(&mut first, b'a').await;
                    exchange(&mut sibling, b'b').await;
                    assert_eq!(control1.read_u8().await.unwrap(), b'A');
                    assert_eq!(control2.read_u8().await.unwrap(), b'A');
                    first.shutdown().await.unwrap();
                    drop(first);
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(5), control1.read_u8())
                            .await
                            .unwrap()
                            .unwrap(),
                        b'D'
                    );
                    exchange(&mut sibling, b'c').await;
                    let mut udp = outbound
                        .open_datagram(
                            DatagramRequest::new(DatagramSession::new(
                                InboundKind::InternalMeasure,
                                "127.0.0.1:1".parse().unwrap(),
                            )),
                            &EstablishContext::default(),
                        )
                        .await
                        .unwrap();
                    udp.send(Datagram {
                        remote: target_udp,
                        payload: bytes::Bytes::from_static(b"owned"),
                        sniffed_domain: None,
                    })
                    .await
                    .unwrap();
                    assert_eq!(udp.receive().await.unwrap().payload.as_ref(), b"owned");
                    assert_eq!(control_udp.read_u16().await.unwrap(), 5);
                    assert_ne!(control_udp.read_u16().await.unwrap(), 0);
                    let mut observed = [0; 5];
                    control_udp.read_exact(&mut observed).await.unwrap();
                    assert_eq!(&observed, b"owned");
                    for kind in [
                        ResourceKind::Association,
                        ResourceKind::Session,
                        ResourceKind::Socket,
                        ResourceKind::Task,
                    ] {
                        assert!(
                            probe.snapshot().peak(kind) > 0,
                            "unobserved resource: {kind:?}"
                        );
                    }
                    outbound.begin_shutdown();
                    assert!(
                        tokio::time::timeout(Duration::from_secs(5), sibling.read_u8())
                            .await
                            .unwrap()
                            .is_err()
                    );
                    drop(sibling);
                    let _ = udp.close().await;
                    drop(udp);
                    tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                        .await
                        .expect("node Stop exceeded five seconds");
                    assert!(
                        probe.snapshot().is_idle(),
                        "Stop retained owned resources: {:?}",
                        probe.snapshot()
                    );
                    cycle.checkpoint("after-stop", probe.snapshot());
                    let stopped = probe.snapshot();
                    let quiet = tokio::time::Instant::now();
                    while quiet.elapsed() < Duration::from_secs(5) {
                        assert_eq!(probe.snapshot(), stopped);
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    cycle.checkpoint("quiet", probe.snapshot());
                })
                .await;
            cycle.resources(probe.snapshot());
        }
    })
    .await
    .unwrap();
}
