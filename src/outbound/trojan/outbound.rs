use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    config::{TrojanOutboundConfig, TrojanTransport},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    resources::observation::{self, ResourceKind},
    security::{
        SecurityContext, StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsCertificatePolicy,
        TlsClientOptions,
    },
    session::{Destination, StreamSession},
    transport::{WebSocketOptions, connect_websocket, grpc_duplex},
};

use super::{TrojanAuth, TrojanCommand, TrojanDatagram};

pub struct TrojanOutbound {
    server: Destination,
    upstream: UpstreamPath,
    auth: TrojanAuth,
    tls: StandardTlsClient,
    cancellation: CancellationToken,
    transport: Transport,
    tasks: TaskTracker,
}

enum Transport {
    Tcp,
    WebSocket(Box<WebSocketOptions>),
    Grpc(String),
}

impl std::fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanOutbound").finish_non_exhaustive()
    }
}

impl TrojanOutbound {
    pub fn new_with_path(
        config: &TrojanOutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        Self::with_shared_security(
            config,
            upstream,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            64 * 1024,
        )
    }

    pub(crate) fn with_shared_security(
        config: &TrojanOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            transport: match &config.transport {
                TrojanTransport::Tcp => Transport::Tcp,
                TrojanTransport::WebSocket { .. } => Transport::WebSocket(Box::new(
                    config
                        .transport
                        .websocket_options()?
                        .expect("WebSocket config"),
                )),
                TrojanTransport::Grpc { uri } => Transport::Grpc(uri.clone()),
            },
            tasks: TaskTracker::new(),
            server: server_destination(&config.address, config.port)?,
            upstream,
            auth: TrojanAuth::new(&config.password)?,
            tls: StandardTlsClient::with_options(
                security,
                &config.server_name,
                TlsClientOptions {
                    alpn: config.tls.alpn.clone(),
                    required_alpn: config.transport.required_alpn().map(<[u8]>::to_vec),
                    certificate: TlsCertificatePolicy {
                        skip_cert_verify: config.tls.skip_cert_verify,
                        fingerprint: config.tls.fingerprint,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                resumption_sessions,
                buffer_limit,
            )?,
            cancellation: CancellationToken::new(),
        })
    }

    async fn connect(
        &self,
        session: StreamSession,
        command: TrojanCommand,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        // timeout_at may poll an immediately-ready future before its timer.
        // A previously expired chain deadline must not even create a socket.
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let request = self.auth.request(command, &session.destination)?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(DispatchError::NotAllowed),
            connected = async {
                let raw = self.upstream.connect_server(session, &self.server, context).await?;
                let stream = context.run_io("Trojan TLS handshake", self.tls.connect(raw.io)).await?;
                let token = self.cancellation.child_token();
                let setup_guard = token.clone().drop_guard();
                let stream = match &self.transport {
                    Transport::Tcp => stream,
                    Transport::WebSocket(options) => context.run_io("Trojan WebSocket upgrade",connect_websocket(stream,options,&request,context.deadline())).await?,
                    Transport::Grpc(uri) => {
                        let (stream, driver) = context.run_io("Trojan gRPC handshake",grpc_duplex(stream,uri,context.deadline())).await?;
                        let token = token.clone();
                        let observation = observation::track(ResourceKind::Task);
                        self.tasks.spawn(observation::bind(async move {
                            let _observation = observation;
                            token.cancelled().await;
                            let _ = driver.stop().await;
                        }));
                        stream
                    },
                };
                let mut stream = OwnedStream::new(stream, token);
                setup_guard.disarm();
                if !matches!(self.transport,Transport::WebSocket(_)) {
                    context.run_io("Trojan request header", async {
                    stream.write_all(&request).await?;
                    stream.flush().await
                    }).await?;
                }
                Ok(Box::new(stream) as BoxStream)
            } => connected,
        }
    }
}

#[async_trait]
impl OutboundConnector for TrojanOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        Ok(ConnectedStream {
            io: self.connect(session, TrojanCommand::Tcp, context).await?,
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        // UDP destinations live in individual frames, not this request header.
        let session = StreamSession {
            inbound: request.session.inbound,
            source: request.session.source,
            destination: Destination::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 1))),
            sniffed_domain: None,
        };
        let stream = self.connect(session, TrojanCommand::Udp, context).await?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(TrojanDatagram::new(stream, request.budget())),
            request.budget(),
        ))
    }

    fn begin_shutdown(&self) {
        self.cancellation.cancel();
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.close();
        self.tasks.wait().await;
    }
}

impl Drop for TrojanOutbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct OwnedStream {
    stream: Option<BoxStream>,
    cancellation: CancellationToken,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    _observation: observation::Guard,
}

impl OwnedStream {
    fn new(stream: BoxStream, cancellation: CancellationToken) -> Self {
        Self {
            stream: Some(stream),
            cancelled: Box::pin(cancellation.clone().cancelled_owned()),
            cancellation,
            _observation: observation::track(ResourceKind::Session),
        }
    }
    fn open(&mut self, cx: &mut Context<'_>) -> io::Result<&mut BoxStream> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.stream.take();
        }
        self.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "Trojan session stopped")
        })
    }
}

impl Drop for OwnedStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl AsyncRead for OwnedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.open(cx)?).poll_read(cx, buf)
    }
}
impl AsyncWrite for OwnedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.open(cx)?).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.open(cx)?).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.open(cx)?).poll_shutdown(cx)
    }
}
