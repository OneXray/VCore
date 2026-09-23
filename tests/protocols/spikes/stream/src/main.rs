//! Synthetic N0 transport probe. Never a production VLESS configuration path.

use std::{
    io::{self, BufReader},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use vcore::{
    config::Socks5OutboundConfig,
    dialer::{Dialer, ResolvedEndpoint, SocketProtector},
    outbound::{DirectOutbound, EstablishContext, OutboundConnector, Socks5Outbound},
    session::{InboundKind, StreamSession},
};
use vcore_n0_stream_spike::{BoxStream, grpc, tls, websocket};

const GREETING: &[u8] = b"N0-server-first\n";
const TRAILER: &[u8] = b"N0-half-close\n";
const UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];

struct Protector {
    calls: AtomicUsize,
    reject: bool,
}
impl SocketProtector for Protector {
    fn protect(&self, _socket: i32) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }
}

fn field<'a>(config: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    config[name].as_str().ok_or("invalid_fixture")
}

fn tls_config(config: &Value, mode: &str) -> Result<Arc<rustls::ClientConfig>, &'static str> {
    let file = std::fs::File::open(field(config, "ca")?).map_err(|_| "fixture_ca")?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut BufReader::new(file)) {
        roots
            .add(certificate.map_err(|_| "fixture_ca")?)
            .map_err(|_| "fixture_ca")?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| "tls_config")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = if mode == "grpc-tls" {
        vec![b"h2".to_vec()]
    } else if mode == "wss" {
        vec![b"http/1.1".to_vec()]
    } else {
        vec![]
    };
    Ok(Arc::new(tls))
}

async fn exchange(
    stream: &mut BoxStream,
    config: &Value,
    mode: &str,
) -> Result<Value, &'static str> {
    let target: SocketAddr = field(config, "target")?
        .parse()
        .map_err(|_| "invalid_fixture")?;
    let mut preface = vec![0];
    preface.extend_from_slice(&UUID);
    preface.extend_from_slice(&[0, 1]); // no addons, TCP
    preface.extend_from_slice(&target.port().to_be_bytes());
    preface.push(1); // fixture IPv4
    preface.extend_from_slice(&[127, 0, 0, 1]);
    stream
        .write_all(&preface)
        .await
        .map_err(|_| "preface_write")?;
    stream.flush().await.map_err(|_| "preface_flush")?;
    let mut response = [0; 2];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| "response")?;
    if response != [0, 0] {
        return Err("response");
    }
    let mut greeting = vec![0; GREETING.len()];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|_| "greeting")?;
    if greeting != GREETING {
        return Err("greeting");
    }
    let payload: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
    for fragment in payload.chunks(4096) {
        stream.write_all(fragment).await.map_err(|_| "upload")?;
        stream.flush().await.map_err(|_| "flush")?;
        let mut echo = vec![0; fragment.len()];
        stream.read_exact(&mut echo).await.map_err(|_| "download")?;
        if echo != fragment {
            return Err("integrity");
        }
    }
    let close = config["close"].as_bool().unwrap_or(false);
    let mut tail = Vec::new();
    if close {
        stream.shutdown().await.map_err(|_| "shutdown")?;
        timeout(
            Duration::from_secs(3),
            stream.take(256).read_to_end(&mut tail),
        )
        .await
        .map_err(|_| "close_timeout")?
        .map_err(|_| "close_read")?;
        if mode.starts_with("grpc") {
            if !tail.is_empty() {
                return Err("unexpected_tail");
            }
        } else if tail != TRAILER {
            return Err("tail");
        }
    } else {
        tail.resize(TRAILER.len(), 0);
        stream
            .read_exact(&mut tail)
            .await
            .map_err(|_| "tail_read")?;
        if tail != TRAILER {
            return Err("tail");
        }
    }
    Ok(
        json!({"outcome":"pass", "payload_bytes":payload.len(), "server_first":true, "tail_bytes":tail.len(), "close":close}),
    )
}

async fn run(config: Value) -> Value {
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        reject: config["reject"].as_bool().unwrap_or(false),
    });
    let mut driver = None;
    let result = timeout(Duration::from_secs(12), async {
        let mode = field(&config, "mode")?;
        let server: SocketAddr = field(&config, "server")?
            .parse()
            .map_err(|_| "invalid_fixture")?;
        let dialer = Dialer::default().with_protector(protector.clone());
        let connector: Box<dyn OutboundConnector> =
            if let Some(upstream) = config["socks5"].as_str() {
                let address: SocketAddr = upstream.parse().map_err(|_| "invalid_fixture")?;
                Box::new(
                    Socks5Outbound::new(
                        &Socks5OutboundConfig {
                            address: address.ip().to_string(),
                            port: address.port(),
                            username: None,
                            password: None,
                        },
                        ResolvedEndpoint {
                            logical_host: address.ip().to_string(),
                            port: address.port(),
                            addresses: vec![address],
                        },
                        dialer,
                    )
                    .map_err(|_| "socks_config")?,
                )
            } else {
                Box::new(DirectOutbound::new(dialer))
            };
        let context = EstablishContext::with_timeout(Duration::from_secs(4));
        let mut stream = connector
            .connect_stream(
                StreamSession {
                    inbound: InboundKind::Socks5,
                    source: "127.0.0.1:0".parse().unwrap(),
                    destination: server.into(),
                    sniffed_domain: None,
                },
                &context,
            )
            .await
            .map_err(|_| "connect")?
            .io;
        if matches!(mode, "tls" | "wss" | "grpc-tls") {
            stream = tls(
                stream,
                tls_config(&config, mode)?,
                config["sni"].as_str().unwrap_or("localhost"),
                context.deadline(),
            )
            .await
            .map_err(|_| "tls")?;
        }
        if matches!(mode, "ws" | "wss") {
            let path = config["path"].as_str().unwrap_or("/n0-ws");
            stream = websocket(stream, &format!("ws://localhost{path}"), context.deadline())
                .await
                .map_err(|_| "ws")?;
        }
        if mode.starts_with("grpc") {
            let service = config["service"].as_str().unwrap_or("n0-grpc");
            let (io, owner) = grpc(
                stream,
                &format!("https://localhost/{service}/Tun"),
                context.deadline(),
            )
            .await
            .map_err(|_| "grpc")?;
            stream = io;
            driver = Some(owner);
        }
        exchange(&mut stream, &config, mode).await
    })
    .await
    .unwrap_or(Err("case_timeout"));
    let stopped = if let Some(owner) = driver {
        owner.stop().await.is_ok()
    } else {
        true
    };
    let mut report = result.unwrap_or_else(|stage| json!({"outcome":stage}));
    report["driver_joined"] = json!(stopped);
    report["protect_calls"] = json!(protector.calls.load(Ordering::SeqCst));
    report
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = std::env::args()
        .nth(1)
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let report = match config {
        Some(config) => run(config).await,
        None => json!({"outcome":"invalid_fixture"}),
    };
    println!("{report}");
}
