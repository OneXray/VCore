//! Opt-in interoperability coverage against the local `anytls-go` reference
//! server.
//!
//! Run with `bash tests/run_anytls_interop.sh`. The test is ignored by default
//! and only compiles with `interop-test`. Its certificate verifier intentionally
//! trusts the reference server's dynamically generated self-signed certificate,
//! but still verifies the TLS handshake signature. This verifier lives only in
//! this integration-test binary and cannot enter the VCore release library.

#![cfg(feature = "interop-test")]

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::{TLS12, TLS13},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use vcore::{
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{BoxStream, Dispatcher as _},
    outbound::{AnyTlsOutbound, AnyTlsTlsConnector, ConnectorDispatcher, UpstreamPath},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

const IO_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug)]
struct InteropOnlyCertificateVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for InteropOnlyCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
struct InteropOnlyTlsConnector {
    connector: TlsConnector,
}

impl InteropOnlyTlsConnector {
    fn new() -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InteropOnlyCertificateVerifier { provider }))
            .with_no_client_auth();
        assert!(
            config.alpn_protocols.is_empty(),
            "AnyTLS interoperability TLS must not advertise ALPN"
        );
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

#[async_trait]
impl AnyTlsTlsConnector for InteropOnlyTlsConnector {
    async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        let server_name = ServerName::try_from("anytls-interop.invalid".to_owned())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.connector
            .connect(server_name, stream)
            .await
            .map(|stream| Box::new(stream) as BoxStream)
            .map_err(io::Error::other)
    }
}

struct CountingForwarder {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    task: JoinHandle<io::Result<()>>,
}

impl CountingForwarder {
    async fn start(upstream: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let cancellation = CancellationToken::new();
        let task_accepts = accepts.clone();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut relays = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = task_cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        let (mut inbound, _) = accepted?;
                        task_accepts.fetch_add(1, Ordering::AcqRel);
                        relays.spawn(async move {
                            let mut outbound = TcpStream::connect(upstream).await?;
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
                            Ok::<_, io::Error>(())
                        });
                    }
                    completed = relays.join_next(), if !relays.is_empty() => {
                        if let Some(result) = completed {
                            result.map_err(io::Error::other)??;
                        }
                    }
                }
            }
            relays.abort_all();
            while relays.join_next().await.is_some() {}
            Ok(())
        });
        Ok(Self {
            address,
            accepts,
            cancellation,
            task,
        })
    }

    fn accepted_connections(&self) -> usize {
        self.accepts.load(Ordering::Acquire)
    }

    async fn shutdown(self) -> io::Result<()> {
        self.cancellation.cancel();
        self.task.await.map_err(io::Error::other)?
    }
}

fn stream_session(destination: Destination, source_port: u16) -> StreamSession {
    StreamSession {
        inbound: InboundKind::Http,
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), source_port),
        destination,
        sniffed_domain: None,
    }
}

fn require_one_session(forwarder: &CountingForwarder, stage: &str) -> io::Result<()> {
    let connections = forwarder.accepted_connections();
    if connections == 1 {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "AnyTLS did not reuse one physical session after {stage}: observed {connections} connections"
    )))
}

async fn check_tcp_echo(
    dispatcher: &ConnectorDispatcher,
    payload: &'static [u8],
    source_port: u16,
) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = listener.local_addr()?;

    let server = async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = vec![0_u8; payload.len()];
        stream.read_exact(&mut received).await?;
        if received != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP echo target received a different payload",
            ));
        }
        stream.write_all(&received).await?;
        stream.shutdown().await
    };
    let client = async {
        let mut stream = dispatcher
            .connect_tcp(stream_session(Destination::Ip(target), source_port))
            .await
            .map_err(io::Error::other)?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        let mut received = vec![0_u8; payload.len()];
        stream.read_exact(&mut received).await?;
        if received != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AnyTLS TCP echo response differs from the request",
            ));
        }
        stream.shutdown().await
    };

    tokio::time::timeout(IO_TIMEOUT, async {
        tokio::try_join!(server, client)?;
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS TCP echo timed out"))?
}

async fn check_uot_v2_echo(dispatcher: &ConnectorDispatcher) -> io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = socket.local_addr()?;
    let expected = [
        Bytes::from_static(b"vcore-anytls-uot-v2-one"),
        Bytes::from_static(b"vcore-anytls-uot-v2-two"),
    ];
    let server_expected = expected.clone();

    let server = async move {
        let mut buffer = [0_u8; 256];
        for payload in &server_expected {
            let (length, peer) = socket.recv_from(&mut buffer).await?;
            if &buffer[..length] != payload.as_ref() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP echo target received a different payload",
                ));
            }
            socket.send_to(&buffer[..length], peer).await?;
        }
        Ok::<_, io::Error>(())
    };
    let client = async {
        let mut transport = dispatcher
            .open_datagram(DatagramSession::new(
                InboundKind::Http,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19003),
            ))
            .await
            .map_err(io::Error::other)?;
        for payload in &expected {
            let sent = Datagram {
                remote: Destination::Ip(target),
                payload: payload.clone(),
                sniffed_domain: None,
            };
            transport
                .send(sent.clone())
                .await
                .map_err(io::Error::other)?;
            let received = transport.receive().await.map_err(io::Error::other)?;
            if received != sent {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AnyTLS UoT v2 echo response differs from the request",
                ));
            }
        }
        transport.close().await.map_err(io::Error::other)
    };

    tokio::time::timeout(IO_TIMEOUT, async {
        tokio::try_join!(server, client)?;
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS UoT v2 echo timed out"))?
}

async fn run_interop() -> io::Result<()> {
    let server = std::env::var("ANYTLS_INTEROP_ADDRESS")
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ANYTLS_INTEROP_ADDRESS is missing; run tests/run_anytls_interop.sh",
            )
        })?
        .parse::<SocketAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let password = std::env::var("ANYTLS_INTEROP_PASSWORD").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ANYTLS_INTEROP_PASSWORD is missing; run tests/run_anytls_interop.sh",
        )
    })?;

    let forwarder = CountingForwarder::start(server).await?;
    let endpoint = ResolvedEndpoint {
        logical_host: forwarder.address.ip().to_string(),
        port: forwarder.address.port(),
        addresses: vec![forwarder.address],
    };
    let outbound = Arc::new(AnyTlsOutbound::new(
        Destination::Ip(forwarder.address),
        UpstreamPath::direct(
            endpoint,
            Dialer::default().with_timeout(Duration::from_secs(3)),
        ),
        password,
        Arc::new(InteropOnlyTlsConnector::new()?),
        64 * 1024,
    )?);
    let lifecycle = outbound.lifecycle();
    let dispatcher = ConnectorDispatcher::new(outbound);

    check_tcp_echo(&dispatcher, b"vcore-anytls-first-stream", 19001).await?;
    require_one_session(&forwarder, "the first TCP stream")?;
    check_tcp_echo(&dispatcher, b"vcore-anytls-reused-stream", 19002).await?;
    require_one_session(&forwarder, "the reused TCP stream")?;
    check_uot_v2_echo(&dispatcher).await?;
    require_one_session(&forwarder, "the UoT v2 association")?;
    check_tcp_echo(&dispatcher, b"vcore-anytls-after-uot", 19004).await?;
    require_one_session(&forwarder, "the TCP stream following UoT")?;

    lifecycle.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(3), lifecycle.shutdown())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS shutdown timed out"))?;

    let post_shutdown = dispatcher
        .connect_tcp(stream_session(
            Destination::domain("example.invalid", 443)?,
            19005,
        ))
        .await;
    if post_shutdown.is_ok() {
        return Err(io::Error::other(
            "AnyTLS accepted a new stream after shutdown",
        ));
    }
    if forwarder.accepted_connections() != 1 {
        return Err(io::Error::other(
            "AnyTLS opened a physical connection during shutdown",
        ));
    }

    forwarder.shutdown().await
}

#[tokio::test]
#[ignore = "requires the local anytls-go reference server; run tests/run_anytls_interop.sh"]
async fn anytls_go_tcp_uot_v2_reuse_and_shutdown() {
    tokio::time::timeout(Duration::from_secs(45), run_interop())
        .await
        .expect("AnyTLS interoperability test timed out")
        .expect("AnyTLS interoperability test failed");
}
