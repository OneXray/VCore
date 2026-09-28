use super::*;

#[tokio::test]
#[ignore = "owned isolated native handler and Mihomo client required"]
async fn native_mihomo_xhttp_close() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_XHTTP_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    let _case =
        vcore::resources::case_events::Case::new("XHTTP-XHTTP", "close::native_mihomo_xhttp_close");
    assert_eq!(fixture["close_reference"]["scope"], "same-mode");
    assert_eq!(fixture["close_reference"]["terminated"], true);
    tokio::time::timeout(Duration::from_secs(15), async {
        let outbound = node(&fixture, None);
        let mut control =
            tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                .await
                .unwrap();
        control.write_u8(11).await.unwrap();
        let port = control.read_u16().await.unwrap();
        let mut stream = outbound
            .connect_stream(
                StreamSession {
                    inbound: InboundKind::InternalMeasure,
                    source: "127.0.0.1:1".parse().unwrap(),
                    destination: SocketAddr::new(
                        fixture["origin_ipv4"].as_str().unwrap().parse().unwrap(),
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
        let mut hello = [0; 5];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");
        stream.shutdown().await.unwrap();
        let mut tail = Vec::new();
        let _terminal = stream.read_to_end(&mut tail).await;
        let hex: String = tail.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            fixture["close_reference"]["tail_hex"].as_str().unwrap()
        );
        assert_eq!(control.read_u8().await.unwrap(), b'A');
        assert_eq!(control.read_u8().await.unwrap(), b'D');
        drop(stream);
        outbound.shutdown().await;
    })
    .await
    .unwrap();
}
