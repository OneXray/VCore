use super::*;

#[tokio::test]
#[ignore = "owned isolated Xray H3 handler required"]
async fn native_h3_keepalive_observes_each_leg_and_stop() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_XHTTP_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    let _case = vcore::resources::case_events::Case::new(
        "XHTTP-XHTTP",
        "keepalive::native_h3_keepalive_observes_each_leg_and_stop",
    );
    for (upload, download, seconds) in [(0, -1, 11), (-1, 1, 3), (1, 0, 11)] {
        let mut f = fixture.clone();
        f["node"]["xhttp-opts"]["reuse-settings"] = json!({"h-keep-alive-period":upload});
        f["node"]["xhttp-opts"]["download-settings"] =
            json!({"reuse-settings":{"h-keep-alive-period":download}});
        let outbound = node(&f, None);
        let mut control = tokio::net::TcpStream::connect(f["origin_control"].as_str().unwrap())
            .await
            .unwrap();
        control.write_u8(13).await.unwrap();
        let port = control.read_u16().await.unwrap();
        let mut io = outbound
            .connect_stream(
                StreamSession {
                    inbound: InboundKind::InternalMeasure,
                    source: "127.0.0.1:1".parse().unwrap(),
                    destination: SocketAddr::new(
                        f["origin_ipv4"].as_str().unwrap().parse().unwrap(),
                        port,
                    )
                    .into(),
                    sniffed_domain: None,
                },
                &EstablishContext::default(),
            )
            .await
            .unwrap()
            .io;
        io.write_all(b"ping").await.unwrap();
        io.flush().await.unwrap();
        let mut data = [0; 4];
        io.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        assert_eq!(control.read_u8().await.unwrap(), b'A');
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before = outbound.xhttp_quic_ping_counts();
        assert_eq!((before.0.len(), before.1.len()), (1, 1));
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        let after = outbound.xhttp_quic_ping_counts();
        for (period, first, last) in [
            (upload, &before.0, &after.0),
            (download, &before.1, &after.1),
        ] {
            assert_eq!(first.len(), last.len());
            if period < 0 {
                assert_eq!(first, last, "disabled leg sent idle PING");
            } else {
                assert!(last[0] > first[0], "configured/default leg sent no PING");
            }
        }
        io.write_all(b"pong").await.unwrap();
        io.flush().await.unwrap();
        io.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pong");
        io.shutdown().await.unwrap();
        drop(io);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), control.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'D'
        );
        tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
            .await
            .unwrap();
        assert_eq!(outbound.xhttp_quic_ping_counts(), (vec![], vec![]));
    }
}
