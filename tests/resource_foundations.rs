#![cfg(all(feature = "interop-test", feature = "quic-transport"))]
use quinn::AsyncUdpSocket;
use std::{sync::Arc, time::Duration};
use vcore::{
    dialer::Dialer,
    dispatch::DatagramBudget,
    outbound::{DatagramRequest, DirectOutbound, EstablishContext, OutboundConnector},
    resources::observation::{ResourceKind, ResourceProbe},
    session::{DatagramSession, InboundKind},
    transport::quic::attach,
};

#[tokio::test]
async fn twenty_quic_lifetimes_return_owned_resources_to_zero_then_remain_quiet() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "N1-RESOURCES",
        "twenty_quic_lifetimes_return_owned_resources_to_zero_then_remain_quiet",
    );
    let probe = ResourceProbe::default();
    _case.checkpoint("baseline", probe.snapshot());
    for _ in 0..20 {
        probe
            .scope(async {
                let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let address = peer.local_addr().unwrap();
                let transport = DirectOutbound::new(Dialer::default())
                    .open_datagram(
                        DatagramRequest::new(DatagramSession::new(
                            InboundKind::InternalMeasure,
                            address,
                        )),
                        &EstablishContext::default(),
                    )
                    .await
                    .unwrap();
                let (socket, driver) =
                    attach(transport, address, DatagramBudget::new(1400, 1400)).unwrap();
                socket
                    .try_send(&quinn::udp::Transmit {
                        destination: address,
                        ecn: None,
                        contents: b"lifetime",
                        segment_size: None,
                        src_ip: None,
                    })
                    .unwrap();
                let mut bytes = [0; 16];
                peer.recv_from(&mut bytes).await.unwrap();
                assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
                assert_eq!(probe.snapshot().current(ResourceKind::Socket), 1);
                driver.stop().await.unwrap();
                drop(socket);
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    let stopped = probe.snapshot();
    assert_eq!(stopped.peak(ResourceKind::Task), 1);
    assert_eq!(stopped.peak(ResourceKind::Socket), 1);
    _case.checkpoint("after-stop", stopped.clone());
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(probe.snapshot(), stopped);
    _case.checkpoint("quiet", probe.snapshot());
    _case.resources(stopped);
}

#[tokio::test]
async fn physical_tcp_guard_survives_connect_and_releases_on_stream_drop() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "N1-RESOURCES",
        "physical_tcp_guard_survives_connect_and_releases_on_stream_drop",
    );
    let probe = Arc::new(ResourceProbe::default());
    _case.checkpoint("baseline", probe.snapshot());
    probe
        .scope(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dialer = Dialer::default();
            let (client, peer) = tokio::join!(
                dialer.connect_address(listener.local_addr().unwrap()),
                listener.accept()
            );
            let client = client.unwrap();
            let _peer = peer.unwrap();
            assert_eq!(probe.snapshot().current(ResourceKind::Socket), 1);
            drop(client);
            assert!(probe.snapshot().is_idle());
        })
        .await;
    _case.checkpoint("after-stop", probe.snapshot());
    _case.resources(probe.snapshot());
}

#[cfg(feature = "stream-transport")]
#[tokio::test]
async fn twenty_stream_lifetimes_and_cancelled_setups_remain_quiet() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut case = vcore::resources::case_events::Case::new(
        "N1-RESOURCES",
        "twenty_stream_lifetimes_and_cancelled_setups_remain_quiet",
    );
    let probe = ResourceProbe::default();
    case.checkpoint("baseline", probe.snapshot());
    for _ in 0..20 {
        for is_grpc in [true, false] {
            tokio::time::timeout(
                Duration::from_secs(5),
                probe.scope(async {
                    let (client, peer) = tokio::io::duplex(1024);
                    let peer = tokio::spawn(async move {
                        let mut connection = h2::server::handshake(peer).await.unwrap();
                        let (_, mut respond) = connection.accept().await.unwrap().unwrap();
                        let _response = respond
                            .send_response(http::Response::new(()), false)
                            .unwrap();
                        while let Some(result) = connection.accept().await {
                            if result.is_err() {
                                break;
                            }
                        }
                    });
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                    let (mut stream, owner) = if is_grpc {
                        vcore::transport::grpc(
                            Box::new(client),
                            "https://fixture.invalid/s/Tun",
                            deadline,
                        )
                        .await
                    } else {
                        vcore::transport::legacy_h2(
                            Box::new(client),
                            "https://fixture.invalid/h2",
                            deadline,
                        )
                        .await
                    }
                    .unwrap();
                    stream.write_all(b"active stream").await.unwrap();
                    stream.flush().await.unwrap();
                    assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
                    assert_eq!(probe.snapshot().current(ResourceKind::Session), 1);
                    drop(stream);
                    owner.stop().await.unwrap();
                    peer.await.unwrap();
                }),
            )
            .await
            .unwrap();
            assert!(probe.snapshot().is_idle());
        }
        // Cancellation before an Upgrade reply drops the supplied IO and creates
        // no detached task; the peer observes EOF without a process exit.
        probe
            .scope(async {
                let (client, mut peer) = tokio::io::duplex(1024);
                let result = tokio::time::timeout(
                    Duration::from_millis(2),
                    vcore::transport::websocket(
                        Box::new(client),
                        "ws://fixture.invalid/",
                        tokio::time::Instant::now() + Duration::from_secs(2),
                    ),
                )
                .await;
                assert!(result.is_err());
                let mut input = Vec::new();
                tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut input))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(input.starts_with(b"GET / HTTP/1.1"));
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    let stopped = probe.snapshot();
    assert_eq!(stopped.peak(ResourceKind::Task), 1);
    assert_eq!(stopped.peak(ResourceKind::Session), 1);
    case.checkpoint("after-stop", stopped.clone());
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(probe.snapshot(), stopped);
    case.checkpoint("quiet", probe.snapshot());
    case.resources(stopped);
}
