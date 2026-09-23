//! N1 shared transport probe. Synthetic VLESS framing is test-only; this is
//! not a production protocol/configuration registration.

use std::{
    io,
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
use vcore::{
    dispatch::BoxStream,
    security::{SecurityContext, StandardTlsClient, TlsCertificatePolicy, TlsClientOptions},
    transport::{
        HttpObfsOptions, WebSocketEarlyData, WebSocketOptions, connect_websocket, grpc, http_obfs,
        legacy_h2,
    },
};

const GREETING: &[u8] = b"N1-server-first\n";
const TRAILER: &[u8] = b"N1-half-close\n";
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

fn tls_client(config: &Value, mode: &str) -> Result<StandardTlsClient, &'static str> {
    let pin = field(config, "pin")?;
    if pin.len() != 64 {
        return Err("invalid_fixture");
    }
    let mut fingerprint = [0; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&pin[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid_fixture")?;
    }
    let alpn = if matches!(mode, "grpc-tls" | "h2") {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    };
    StandardTlsClient::with_options(
        &SecurityContext::new(),
        "localhost",
        TlsClientOptions {
            alpn: vec![alpn.clone()],
            required_alpn: Some(alpn),
            certificate: TlsCertificatePolicy {
                fingerprint: Some(fingerprint),
                ..Default::default()
            },
            ..Default::default()
        },
        0,
        65536,
    )
    .map_err(|_| "tls_options")
}

fn preface(config: &Value) -> Result<Vec<u8>, &'static str> {
    let target: SocketAddr = field(config, "target")?
        .parse()
        .map_err(|_| "invalid_fixture")?;
    let mut preface = vec![0];
    preface.extend_from_slice(&UUID);
    preface.extend_from_slice(&[0, 1]);
    preface.extend_from_slice(&target.port().to_be_bytes());
    preface.push(1);
    preface.extend_from_slice(&[127, 0, 0, 1]);
    Ok(preface)
}

async fn exchange(
    stream: &mut BoxStream,
    config: &Value,
    mode: &str,
) -> Result<Value, &'static str> {
    if !matches!(mode, "ws" | "wss" | "ws-header" | "ws-path" | "http") {
        stream
            .write_all(&preface(config)?)
            .await
            .map_err(|_| "preface_write")?;
        stream.flush().await.map_err(|_| "preface_flush")?;
    }
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
        if mode.starts_with("grpc") || mode == "h2" {
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
        if matches!(mode, "tls" | "wss" | "grpc-tls" | "h2") {
            stream = context
                .run_io("TLS", tls_client(&config, mode)?.connect(stream))
                .await
                .map_err(|_| "tls")?;
        }
        if matches!(mode, "ws" | "wss" | "ws-header" | "ws-path") {
            let path = config["path"].as_str().unwrap_or("/n1-ws");
            let early = match mode {
                "ws-header" => Some(WebSocketEarlyData::Header {
                    name: config["ed_header"]
                        .as_str()
                        .unwrap_or("x-vcore-ed")
                        .parse()
                        .map_err(|_| "invalid_fixture")?,
                    max_bytes: config["ed_max"].as_u64().unwrap_or(2048) as usize,
                }),
                "ws-path" => Some(WebSocketEarlyData::Path {
                    max_bytes: config["ed_max"].as_u64().unwrap_or(2048) as usize,
                }),
                _ => None,
            };
            let options =
                WebSocketOptions::new(&format!("ws://localhost{path}"), Default::default(), early)
                    .map_err(|_| "ws_options")?;
            stream = connect_websocket(stream, &options, &preface(&config)?, context.deadline())
                .await
                .map_err(|_| "ws")?;
        }
        if mode == "http" {
            let options = HttpObfsOptions::new(
                http::Method::GET,
                "http://localhost/n1-http",
                Default::default(),
            )
            .map_err(|_| "http_options")?;
            stream = http_obfs(stream, &options, &preface(&config)?, context.deadline())
                .await
                .map_err(|_| "http")?;
        }
        if mode.starts_with("grpc") || mode == "h2" {
            let uri = if mode == "h2" {
                "https://localhost/n1-h2"
            } else {
                "https://localhost/n1-grpc/Tun"
            };
            let (io, owner) = if mode == "h2" {
                legacy_h2(stream, uri, context.deadline()).await
            } else {
                grpc(stream, uri, context.deadline()).await
            }
            .map_err(|_| "h2")?;
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
    let resources = vcore::resources::observation::ResourceProbe::default();
    let mut report = match config {
        Some(config) => resources.scope(run(config)).await,
        None => json!({"outcome":"invalid_fixture"}),
    };
    let stopped = resources.snapshot();
    report["resources_idle"] = json!(stopped.is_idle());
    report["resources"] = serde_json::to_value(stopped).unwrap();
    println!("{report}");
    if report["outcome"] != "pass"
        || report["driver_joined"] != true
        || report["resources_idle"] != true
    {
        std::process::exit(1);
    }
}
