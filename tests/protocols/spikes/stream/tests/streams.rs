use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::{Instant, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use vcore_n0_stream_spike::{grpc, tls, websocket};

fn certificates() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(identity.cert.der().clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert.der().clone()],
            PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    (Arc::new(client), Arc::new(server))
}

#[tokio::test]
async fn tls_wraps_the_supplied_stream_and_preserves_server_first_and_reply() {
    let (client, server) = certificates();
    let (outgoing, incoming) = tokio::io::duplex(128);
    let peer = tokio::spawn(async move {
        let mut stream = TlsAcceptor::from(server).accept(incoming).await.unwrap();
        stream.write_all(b"ready").await.unwrap();
        stream.flush().await.unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut stream = tls(
        Box::new(outgoing),
        client,
        "localhost",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    let mut greeting = [0; 5];
    timeout(Duration::from_secs(2), stream.read_exact(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&greeting, b"ready");
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"pong");
    drop(stream);
    peer.await.unwrap();
}

struct Observed {
    io: DuplexStream,
    shutdown: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Observed {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for Observed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Observed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown.store(true, Ordering::SeqCst);
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn tls_close_notify_keeps_the_underlay_open_for_the_eof_triggered_reply() {
    let (client, server) = certificates();
    let (outgoing, incoming) = tokio::io::duplex(128);
    let shutdown = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let peer = tokio::spawn(async move {
        let mut stream = TlsAcceptor::from(server).accept(incoming).await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        stream.write_all(b"reply-after-eof").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let raw = Observed {
        io: outgoing,
        shutdown: shutdown.clone(),
        dropped: dropped.clone(),
    };
    let mut stream = tls(
        Box::new(raw),
        client,
        "localhost",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    stream.write_all(b"request").await.unwrap();
    timeout(Duration::from_secs(2), stream.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !shutdown.load(Ordering::SeqCst),
        "Mihomo TLS CloseWrite only emits close_notify"
    );
    assert!(stream.write_all(b"forbidden").await.is_err());
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"reply-after-eof");
    drop(stream);
    assert!(dropped.load(Ordering::SeqCst));
    peer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn tls_shutdown_bounds_a_blocked_notify_flush() {
    let (client, server) = certificates();
    let (outgoing, incoming) = tokio::io::duplex(128);
    let peer = tokio::spawn(async move {
        let _stream = TlsAcceptor::from(server).accept(incoming).await.unwrap();
        std::future::pending::<()>().await;
    });
    let mut stream = tls(
        Box::new(outgoing),
        client,
        "localhost",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(stream.write(&[0; 32768]).await.unwrap() > 0);
    let start = Instant::now();
    assert_eq!(
        stream.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(Instant::now() - start, Duration::from_secs(5));
    drop(stream);
    peer.abort();
    assert!(peer.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn ws_partial_writes_empty_frames_ping_and_half_close_preserve_every_byte() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let expected: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
    let request = expected.clone();
    let peer = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
        ws.send(Message::Binary(bytes::Bytes::new())).await.unwrap();
        ws.send(Message::Ping(b"ping".as_slice().into()))
            .await
            .unwrap();
        ws.send(Message::Text("ready".into())).await.unwrap();
        let mut received = Vec::new();
        while received.len() < request.len() {
            match ws.next().await.unwrap().unwrap() {
                Message::Binary(data) => received.extend_from_slice(&data),
                Message::Pong(_) => {}
                message => panic!("unexpected fixture message type: {}", message.is_close()),
            }
        }
        assert_eq!(received, request);
        let mut byte = [0];
        // Read raw EOF, not a WS Close frame. The public server library marks
        // itself terminated on that EOF, so leave its WS state intact to reply.
        assert_eq!(ws.get_mut().read(&mut byte).await.unwrap(), 0);
        ws.send(Message::Binary(received.into())).await.unwrap();
        ws.send(Message::Close(None)).await.unwrap();
    });
    let mut stream = websocket(
        Box::new(outgoing),
        "ws://fixture.invalid/n0",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    let mut greeting = [0; 5];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"ready");
    stream.write_all(&expected).await.unwrap();
    stream.shutdown().await.unwrap();
    assert!(stream.write_all(b"forbidden").await.is_err());
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, expected);
    drop(stream);
    peer.await.unwrap();
}

#[tokio::test]
async fn grpc_handles_response_after_upload_fragmented_records_and_owned_stop() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let dropped = Arc::new(AtomicBool::new(false));
    let raw = Observed {
        io: outgoing,
        shutdown: Arc::new(AtomicBool::new(false)),
        dropped: dropped.clone(),
    };
    let peer = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(128)
            .handshake(incoming)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/n0/Tun");
        let session = async move {
            let mut body = request.into_body();
            let mut wire = Vec::new();
            // Sending response headers only after request bytes is deliberate:
            // eagerly awaiting the response in the connector would deadlock.
            while wire.len() < 11 {
                let data = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                wire.extend_from_slice(&data);
            }
            assert_eq!(&wire, b"\x00\x00\x00\x00\x06\x0a\x04ping");
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut tx = respond.send_response(response, false).unwrap();
            for byte in b"\x00\x00\x00\x00\x06\x0a\x04pong" {
                tx.send_data(bytes::Bytes::copy_from_slice(&[*byte]), false)
                    .unwrap();
            }
            // Keep the response open: local shutdown must wake a pending read.
            std::future::pending::<()>().await;
        };
        tokio::pin!(session);
        loop {
            tokio::select! {
                _ = &mut session => break,
                result = connection.accept() => if result.is_none() || result.is_some_and(|r| r.is_err()) { break; },
            }
        }
    });
    let (mut stream, owner) = grpc(
        Box::new(raw),
        "https://fixture.invalid/n0/Tun",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 4];
    timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"pong");
    let (mut read, mut write) = tokio::io::split(stream);
    let waiting = tokio::spawn(async move { read.read_u8().await });
    tokio::task::yield_now().await;
    write.shutdown().await.unwrap();
    assert!(
        timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    owner.stop().await.unwrap();
    assert!(
        dropped.load(Ordering::SeqCst),
        "Stop must join the task which owns IO"
    );
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

async fn stalled_handshake(kind: &str, raw: Observed, deadline: Instant) -> io::Result<()> {
    match kind {
        "tls" => {
            tls(Box::new(raw), certificates().0, "localhost", deadline).await?;
        }
        "ws" => {
            websocket(Box::new(raw), "ws://fixture.invalid/n0", deadline).await?;
        }
        "grpc" => {
            let (mut stream, owner) =
                grpc(Box::new(raw), "https://fixture.invalid/n0/Tun", deadline).await?;
            let result = stream.read_u8().await;
            drop(stream);
            owner.stop().await?;
            result?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[tokio::test]
async fn setup_deadline_releases_supplied_io_in_all_three_adapters() {
    for kind in ["tls", "ws", "grpc"] {
        let (outgoing, mut incoming) = tokio::io::duplex(128);
        let dropped = Arc::new(AtomicBool::new(false));
        let raw = Observed {
            io: outgoing,
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        };
        let peer = tokio::spawn(async move {
            let mut sink = Vec::new();
            incoming.read_to_end(&mut sink).await.unwrap();
            assert!(sink.len() < 4096);
        });
        let result = timeout(
            Duration::from_secs(2),
            stalled_handshake(kind, raw, Instant::now() + Duration::from_millis(30)),
        )
        .await
        .unwrap();
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "{kind}"
        );
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst), "{kind}");
    }
}

#[tokio::test]
async fn cancelled_setup_releases_supplied_io_without_a_detached_task() {
    for kind in ["tls", "ws", "grpc"] {
        let (outgoing, mut incoming) = tokio::io::duplex(128);
        let dropped = Arc::new(AtomicBool::new(false));
        let raw = Observed {
            io: outgoing,
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        };
        let peer = tokio::spawn(async move {
            let mut sink = Vec::new();
            incoming.read_to_end(&mut sink).await.unwrap();
        });
        assert!(
            timeout(
                Duration::from_millis(20),
                stalled_handshake(kind, raw, Instant::now() + Duration::from_secs(10))
            )
            .await
            .is_err()
        );
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst), "{kind}");
    }
}

#[tokio::test]
async fn ws_rejects_oversized_and_truncated_frames_instead_of_reporting_eof() {
    for frame in [
        vec![0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 1],
        vec![0x82, 3, b'x'],
        vec![0x02, 1, b'x'],
        vec![0x82],
    ] {
        let (outgoing, incoming) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
            ws.get_mut().write_all(&frame).await.unwrap();
            ws.get_mut().shutdown().await.unwrap();
        });
        let mut stream = websocket(
            Box::new(outgoing),
            "ws://fixture.invalid/n0",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(stream);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn ws_accepts_mihomo_clean_underlay_eof_only_at_complete_message_boundaries() {
    for frame in [
        b"\x82\x04tail".as_slice(),
        b"\x02\x02ta\x80\x02il".as_slice(),
    ] {
        let (outgoing, incoming) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
            ws.get_mut().write_all(frame).await.unwrap();
            ws.get_mut().shutdown().await.unwrap();
        });
        let mut stream = websocket(
            Box::new(outgoing),
            "ws://fixture.invalid/n0",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut tail = Vec::new();
        timeout(Duration::from_secs(1), stream.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, b"tail");
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn dropping_an_established_ws_releases_its_only_io_owner() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let dropped = Arc::new(AtomicBool::new(false));
    let raw = Observed {
        io: outgoing,
        shutdown: Arc::new(AtomicBool::new(false)),
        dropped: dropped.clone(),
    };
    let peer = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
        assert_eq!(ws.get_mut().read(&mut [0; 1]).await.unwrap(), 0);
    });
    let mut stream = websocket(
        Box::new(raw),
        "ws://fixture.invalid/n0",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_millis(20), stream.read_u8())
            .await
            .is_err()
    );
    drop(stream);
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn grpc_rejects_oversized_truncated_and_invalid_records() {
    for wire in [
        b"\x00\x00\x10\x00\x00".to_vec(),
        b"\x00\x00\x00\x00\x06\x0a\x04x".to_vec(),
        b"\x01\x00\x00\x00\x02\x0a\x00".to_vec(),
        b"\x00\x00\x00\x00\x02\x0b\x00".to_vec(),
    ] {
        let (outgoing, incoming) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(incoming).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(wire.into(), true).unwrap();
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let (mut stream, owner) = grpc(
            Box::new(outgoing),
            "https://fixture.invalid/n0/Tun",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(stream);
        owner.stop().await.unwrap();
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn grpc_large_writes_obey_small_http2_windows_and_keep_byte_integrity() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let expected: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
    let peer = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(128)
            .max_send_buffer_size(128)
            .handshake(incoming)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let exchange = async move {
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let mut receive = request.into_body();
            while let Some(data) = receive.data().await {
                let mut data = data.unwrap();
                let consumed = data.len();
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    let count = capacity.min(data.len());
                    if count > 0 {
                        send.send_data(data.split_to(count), false).unwrap();
                    }
                }
                receive.flow_control().release_capacity(consumed).unwrap();
            }
        };
        tokio::pin!(exchange);
        loop {
            tokio::select! {
                _ = &mut exchange => break,
                result = connection.accept() => if result.is_none() || result.is_some_and(|r| r.is_err()) { break; },
            }
        }
    });
    let (stream, owner) = grpc(
        Box::new(outgoing),
        "https://fixture.invalid/n0/Tun",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let upload = async {
        write.write_all(&expected).await.unwrap();
        write.flush().await.unwrap();
    };
    let download = async {
        let mut received = vec![0; expected.len()];
        read.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(upload, download);
    })
    .await
    .unwrap();
    drop(read);
    drop(write);
    owner.stop().await.unwrap();
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}
