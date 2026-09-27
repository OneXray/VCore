#![cfg(feature = "outbound-shadowsocks")]
//! Connector contract with bounded in-memory IO, not a host protocol server.
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use shadowsocks::{
    config::ServerType, context::Context, relay::tcprelay::proxy_stream::ProxyServerStream,
};
use std::{
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use vcore::{
    config::{ShadowsocksCipher, ShadowsocksOutboundConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, ShadowsocksOutbound,
        UpstreamPath,
    },
    session::{Destination, InboundKind, StreamSession},
};

struct MemoryUpstream(Mutex<Option<BoxStream>>);
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: self.0.lock().unwrap().take().unwrap(),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test]
async fn growing_caller_buffer_after_backpressure_never_loses_plaintext() {
    #[cfg(feature = "interop-test")]
    let _case = vcore::resources::case_events::Case::new("N9-ADAPTER", "growing_caller_buffer");
    for (cipher, initial) in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ]
    .into_iter()
    .flat_map(|cipher| [4096, 32768].map(|size| (cipher, size)))
    {
        let key = vec![7; cipher.key_len()];
        let config = ShadowsocksOutboundConfig {
            address: "fixture.invalid".into(),
            port: 443,
            cipher,
            password: STANDARD.encode(&key),
        };
        let (client, peer) = tokio::io::duplex(4096);
        let outbound = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(client)))))),
        )
        .unwrap();
        let target = Destination::domain("target.invalid", 80).unwrap();
        let session = StreamSession {
            inbound: InboundKind::Socks5,
            source: "127.0.0.1:1234".parse().unwrap(),
            destination: target,
            sniffed_domain: None,
        };
        let mut stream = outbound
            .connect_stream(session, &EstablishContext::default())
            .await
            .unwrap()
            .io;
        let mut payload = vec![0x5a; initial * 2];
        payload[initial..].fill(0xa5);
        // Tokio copy tops up its caller buffer after a pending write. Exercise
        // that public AsyncWrite pattern rather than assuming a fixed retry length.
        let first =
            poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_write(cx, &payload[..initial])))
                .await;
        let accepted = match first {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => 0,
        };
        assert_eq!(
            accepted,
            initial.min(vcore::limits::SHADOWSOCKS_WRITE_CHUNK)
        );
        let mut decoder = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            peer,
            cipher.as_str().parse().unwrap(),
            &key,
        );
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            let ((), decoded) = tokio::join!(
                async {
                    stream.write_all(&payload[accepted..]).await.unwrap();
                    stream.shutdown().await.unwrap();
                },
                async {
                    decoder.handshake().await.unwrap();
                    let mut decoded = Vec::new();
                    decoder.read_to_end(&mut decoded).await.unwrap();
                    decoded
                }
            );
            decoded
        })
        .await
        .unwrap();
        assert_eq!(
            received.len(),
            payload.len(),
            "{cipher:?}: acknowledged bytes were lost"
        );
        assert_eq!(received, payload);
    }
}

#[tokio::test]
async fn server_first_over_buffered_upstream_delivers_handshake() {
    #[cfg(feature = "interop-test")]
    let _case =
        vcore::resources::case_events::Case::new("N9-ADAPTER", "server_first_buffered_upstream");
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let key = vec![7; cipher.key_len()];
        let config = ShadowsocksOutboundConfig {
            address: "fixture.invalid".into(),
            port: 443,
            cipher,
            password: STANDARD.encode(&key),
        };
        let (client, peer) = tokio::io::duplex(4096);
        // Buffered carriers may acknowledge the complete SS header before
        // delivering it. A read-first application has no payload to flush it.
        let outbound = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(
                BufWriter::new(client),
            )))))),
        )
        .unwrap();
        let mut stream = outbound
            .connect_stream(
                StreamSession {
                    inbound: InboundKind::Socks5,
                    source: "127.0.0.1:1234".parse().unwrap(),
                    destination: Destination::domain("target.invalid", 80).unwrap(),
                    sniffed_domain: None,
                },
                &EstablishContext::default(),
            )
            .await
            .unwrap()
            .io;
        let mut decoder = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            peer,
            cipher.as_str().parse().unwrap(),
            &key,
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                async {
                    let mut greeting = [0; 5];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(&greeting, b"hello");
                },
                async {
                    decoder.handshake().await.unwrap();
                    decoder.write_all(b"hello").await.unwrap();
                    decoder.flush().await.unwrap();
                }
            );
        })
        .await
        .expect("server-first greeting must arrive without application writes");
    }
}
