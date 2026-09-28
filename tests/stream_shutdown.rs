//! Shutdown must flush accepted writes, without requiring a half-close response.
#![cfg(feature = "stream-transport")]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use vcore::{
    config::GrpcOptions,
    dispatch::BoxStream,
    transport::{GrpcPool, grpc, legacy_h2},
};

#[tokio::test]
async fn whole_stream_shutdown_sends_the_last_write_before_closing() {
    for mode in ["grpc", "legacy-h2", "pooled-grpc"] {
        for buffered in [false, true] {
            for explicit_flush in [false, true] {
                tokio::time::timeout(Duration::from_secs(3), async {
                    let (client, mut peer) = tokio::io::duplex(64);
                    // A raw in-memory HTTP/2 peer observes actual DATA before reset
                    // or physical EOF, independently of h2's receive-side buffering.
                    let (ready, started) = tokio::sync::oneshot::channel();
                    let reader = tokio::spawn(async move {
                        let mut preface = [0; 24];
                        peer.read_exact(&mut preface).await.unwrap();
                        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
                        let mut ready = Some(ready);
                        let mut received = Vec::new();
                        loop {
                            let mut header = [0; 9];
                            if peer.read_exact(&mut header).await.is_err() {
                                break;
                            }
                            let size =
                                u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                            assert!(size <= 16384);
                            let mut data = vec![0; size];
                            peer.read_exact(&mut data).await.unwrap();
                            match header[3] {
                                0 => received.extend_from_slice(&data),
                                1 => {
                                    if let Some(ready) = ready.take() {
                                        ready.send(()).unwrap();
                                    }
                                }
                                3 => break,
                                4 if header[4] & 1 == 0 => {
                                    peer.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.unwrap();
                                }
                                _ => {}
                            }
                        }
                        received
                    });
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                    let raw: BoxStream = if buffered {
                        Box::new(BufWriter::new(client))
                    } else {
                        Box::new(client)
                    };
                    let pool = GrpcPool::new(GrpcOptions::default());
                    let (mut stream, owner) = if mode == "pooled-grpc" {
                        (
                            pool.open("https://fixture.invalid/stream/Tun", deadline, || async {
                                Ok(raw)
                            })
                            .await
                            .unwrap(),
                            None,
                        )
                    } else {
                        let (stream, owner) = if mode == "legacy-h2" {
                            legacy_h2(raw, "https://fixture.invalid/stream", deadline).await
                        } else {
                            grpc(raw, "https://fixture.invalid/stream/Tun", deadline).await
                        }
                        .unwrap();
                        (stream, Some(owner))
                    };
                    started.await.unwrap();
                    let payload = [b'x'; 1024];
                    stream.write_all(&payload).await.unwrap();
                    if explicit_flush {
                        stream.flush().await.unwrap();
                    }
                    stream.shutdown().await.unwrap();
                    stream.shutdown().await.unwrap();
                    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
                    let received = reader.await.unwrap();
                    if let Some(owner) = owner {
                        owner.stop().await.unwrap();
                    }
                    pool.shutdown().await;
                    let expected = if mode == "legacy-h2" {
                        payload.to_vec()
                    } else {
                        let mut frame = vec![0, 0, 0, 4, 3, 0x0a, 0x80, 0x08];
                        frame.extend_from_slice(&payload);
                        frame
                    };
                    assert_eq!(
                        received.len(),
                        expected.len(),
                        "mode={mode}, buffered={buffered}, explicit_flush={explicit_flush}"
                    );
                    assert_eq!(received, expected);
                })
                .await
                .unwrap();
            }
        }
    }
}

#[tokio::test]
async fn owner_stop_cancels_a_shutdown_blocked_on_the_physical_writer() {
    use std::{future::poll_fn, pin::Pin, task::Poll};
    for pooled in [false, true] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (raw, _unread_peer) = tokio::io::duplex(4096);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            let pool = GrpcPool::new(GrpcOptions::default());
            let (mut stream, owner) = if pooled {
                (
                    pool.open("https://fixture.invalid/stream/Tun", deadline, || async {
                        Ok(Box::new(raw) as BoxStream)
                    })
                    .await
                    .unwrap(),
                    None,
                )
            } else {
                let (stream, owner) = grpc(
                    Box::new(raw),
                    "https://fixture.invalid/stream/Tun",
                    deadline,
                )
                .await
                .unwrap();
                (stream, Some(owner))
            };
            stream.write_all(&[b'x'; 16384]).await.unwrap();
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_shutdown(cx)))
                    .await
                    .is_pending()
            );
            let shutdown = tokio::spawn(async move { stream.shutdown().await });
            tokio::task::yield_now().await;
            if let Some(owner) = owner {
                owner.stop().await.unwrap();
            }
            pool.shutdown().await;
            assert!(shutdown.await.unwrap().is_err());
        })
        .await
        .expect("stop must wake a pending flush/shutdown");
    }
}
