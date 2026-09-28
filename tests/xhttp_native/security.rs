//! Authentication is checked against native container peers, never a host TLS server.
use super::*;
use vcore::resources::{case_events::Case, observation::ResourceProbe};

#[tokio::test]
#[ignore = "owned isolated authentication peers required"]
async fn native_xhttp_security() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_XHTTP_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    let case = Case::new("XHTTP-XHTTP", "security::native_xhttp_security");
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let outbound = node(&fixture, None);
            let mut control =
                tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                    .await
                    .unwrap();
            control.set_nodelay(true).unwrap();
            // Mode 12 records any connection before returning an acknowledgement;
            // mode 10 sends first and checks both directions independently.
            let reject = fixture["reject"].as_bool().unwrap();
            control
                .write_u8(if reject { 12 } else { 10 })
                .await
                .unwrap();
            let port = control.read_u16().await.unwrap();
            let destination = SocketAddr::new(
                fixture["origin_ipv4"].as_str().unwrap().parse().unwrap(),
                port,
            )
            .into();
            let context = EstablishContext::with_timeout(Duration::from_secs(4));
            let outcome =
                tokio::time::timeout(Duration::from_secs(if reject { 5 } else { 120 }), async {
                    let connected = outbound
                        .connect_stream(
                            StreamSession {
                                inbound: InboundKind::InternalMeasure,
                                source: "127.0.0.1:1".parse().unwrap(),
                                destination,
                                sniffed_domain: None,
                            },
                            &context,
                        )
                        .await
                        .map_err(std::io::Error::other)?;
                    let mut io = connected.io;
                    if reject {
                        io.write_all(b"synthetic-probe").await?;
                        io.flush().await?;
                        let mut reply = [0; 2];
                        io.read_exact(&mut reply).await?;
                        return Ok::<_, std::io::Error>(());
                    }
                    let mut first = [0; 5];
                    io.read_exact(&mut first).await?;
                    assert_eq!(&first, b"hello");
                    assert_eq!(control.read_u8().await?, b'A');
                    let payload = vec![0x5a; 10 * 1024 * 1024];
                    io.write_all(&payload).await?;
                    io.flush().await?;
                    let mut reply = vec![0; payload.len() + 7];
                    io.read_exact(&mut reply).await?;
                    assert_eq!(&reply[..payload.len()], payload);
                    assert_eq!(&reply[payload.len()..], b"trailer");
                    io.shutdown().await?;
                    drop(io);
                    assert_eq!(control.read_u8().await?, b'D');
                    Ok(())
                })
                .await
                .expect("native authentication/data path exceeded its deadline");
            if reject {
                assert!(outcome.is_err(), "invalid native identity exchanged data");
                assert!(
                    tokio::time::timeout(Duration::from_millis(300), control.read_u8())
                        .await
                        .is_err(),
                    "origin accepted traffic on a rejected path"
                );
            } else {
                outcome.unwrap();
            }
            outbound.begin_shutdown();
            tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                .await
                .unwrap();
            drop(outbound);
            assert!(
                probe.snapshot().is_idle(),
                "resources remain after shutdown"
            );
        })
        .await;
    drop(case);
}
