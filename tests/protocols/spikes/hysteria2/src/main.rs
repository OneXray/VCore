//! Native-peer feasibility probe. No YAML surface or production protocol code.

use std::{
    io::{self, BufReader},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, Endpoint};
use quinn_proto::congestion::{BbrConfig, Controller, ControllerFactory};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use vcore::{
    config::Socks5OutboundConfig,
    dialer::{Dialer, ResolvedEndpoint, SocketProtector},
    outbound::{
        DatagramRequest, DirectOutbound, EstablishContext, OutboundConnector, Socks5Outbound,
    },
    session::{DatagramSession, InboundKind},
};
use vcore_n0_hysteria2_spike::{datagram, wire};

mod xhttp;

const PAYLOAD_BYTES: usize = 65536;
const GREETING: &[u8] = b"N0-server-first\n";
const TRAILER: &[u8] = b"N0-half-close\n";

struct Protector {
    calls: AtomicUsize,
    reject_at: usize,
}

impl SocketProtector for Protector {
    fn protect(&self, _socket: i32) -> io::Result<()> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.reject_at {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
struct ObservedBbr(AtomicUsize);

impl ControllerFactory for ObservedBbr {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Arc::new(BbrConfig::default()).build(now, mtu)
    }
}

fn field<'a>(config: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    config[name].as_str().ok_or("invalid_fixture")
}

fn datagram_request() -> DatagramRequest {
    DatagramRequest::new(DatagramSession::new(
        InboundKind::Socks5,
        "127.0.0.1:0".parse().unwrap(),
    ))
    .with_max_response_payload_size(datagram::PACKET_LIMIT as u16)
}

struct Hop<'a> {
    connector: &'a dyn OutboundConnector,
    context: &'a EstablishContext,
    resource: Option<(Arc<datagram::DatagramSocket>, datagram::DatagramDriver)>,
    rebinds: usize,
    connect_calls: usize,
    auth_requests: usize,
}

impl Hop<'_> {
    async fn rebind(
        &mut self,
        endpoint: &Endpoint,
        logical_peer: SocketAddr,
        port: u16,
    ) -> Result<(), &'static str> {
        let transport = self
            .connector
            .open_datagram(datagram_request(), self.context)
            .await
            .map_err(|_| "hop_open")?;
        let mut physical_peer = logical_peer;
        physical_peer.set_port(port);
        let (socket, driver) = datagram::attach_mapped(transport, logical_peer, physical_peer);
        // Retain both owners until the QUIC endpoint is idle, including errors.
        self.resource = Some((socket.clone(), driver));
        endpoint.rebind_abstract(socket).map_err(|_| "hop_rebind")?;
        self.rebinds += 1;
        Ok(())
    }
}

fn client_config(
    config: &Value,
    bbr: Arc<ObservedBbr>,
) -> Result<quinn::ClientConfig, &'static str> {
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
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut transport = quinn::TransportConfig::default();
    transport
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(None)
        .max_idle_timeout(Some(
            Duration::from_secs(10)
                .try_into()
                .map_err(|_| "quic_config")?,
        ))
        .stream_receive_window(65536_u32.into())
        .receive_window(262144_u32.into())
        .send_window(262144)
        .max_concurrent_uni_streams(8_u32.into())
        .max_concurrent_bidi_streams(4_u32.into())
        .datagram_receive_buffer_size(Some(65536))
        .congestion_controller_factory(bbr);
    let mut client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| "tls_config")?,
    ));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

async fn exercise(
    endpoint: &Endpoint,
    peer: SocketAddr,
    config: &Value,
    h3_task: &mut Option<JoinHandle<()>>,
    phase: &mut &'static str,
    hop: &mut Hop<'_>,
) -> Result<Value, &'static str> {
    let started = Instant::now();
    *phase = "quic_handshake";
    hop.connect_calls += 1;
    let connection = endpoint
        .connect(peer, field(config, "server_name")?)
        .map_err(|_| "connect_setup")?
        .await
        .map_err(|error| match error {
            quinn::ConnectionError::TransportError(error) if u64::from(error.code) == 0x12a => {
                "tls_rejected"
            }
            _ => "quic_connect",
        })?;
    *phase = "h3_setup";
    if config["protocol"] == "xray-h3" {
        return xhttp::exercise(connection, config, h3_task, phase).await;
    }
    let (mut control, mut requests) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|_| "h3_setup")?;
    // Owning and continuously polling this driver is required after auth too.
    *h3_task = Some(tokio::spawn(async move {
        let _ = control.wait_idle().await;
    }));
    let request = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", field(config, "password")?)
        .header("Hysteria-CC-RX", "0")
        .body(())
        .map_err(|_| "auth_request")?;
    *phase = "h3_auth";
    hop.auth_requests += 1;
    let mut auth = requests
        .send_request(request)
        .await
        .map_err(|_| "auth_send")?;
    auth.finish().await.map_err(|_| "auth_finish")?;
    let response = auth.recv_response().await.map_err(|_| "auth_response")?;
    if response.status().as_u16() != 233 {
        return Err("auth_rejected");
    }
    let udp_enabled = match response
        .headers()
        .get("Hysteria-UDP")
        .and_then(|value| value.to_str().ok())
    {
        Some("true") => true,
        Some("false") => false,
        _ => return Err("udp_capability"),
    };
    let rx = response
        .headers()
        .get("Hysteria-CC-RX")
        .and_then(|value| value.to_str().ok())
        .ok_or("cc_capability")?;
    if rx != "auto" && rx.parse::<u64>().is_err() {
        return Err("cc_capability");
    }
    let setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    *phase = "tcp_open";
    let (mut send, mut receive) = connection.open_bi().await.map_err(|_| "tcp_open")?;
    let connection_id = connection.stable_id();
    let stream_id = send.id();
    send.write_all(&wire::tcp_request(field(config, "target")?).map_err(|_| "tcp_request")?)
        .await
        .map_err(|_| "tcp_header_send")?;
    wire::tcp_response(&mut receive)
        .await
        .map_err(|_| "tcp_response")?;
    *phase = "server_first";
    let mut greeting = [0; GREETING.len()];
    receive
        .read_exact(&mut greeting)
        .await
        .map_err(|_| "server_first_read")?;
    if greeting != GREETING {
        return Err("server_first_mismatch");
    }
    let payload: Vec<u8> = (0..PAYLOAD_BYTES)
        .map(|index| (index % 251) as u8)
        .collect();
    *phase = "tcp_data";
    let data_started = Instant::now();
    let mut output = Vec::new();
    if let Some(port) = config["hop_port"].as_u64() {
        let port = u16::try_from(port).map_err(|_| "invalid_fixture")?;
        if port == 0 || port == peer.port() || config["half_close"] != false {
            return Err("invalid_hop_fixture");
        }
        let midpoint = PAYLOAD_BYTES / 2;
        send.write_all(&payload[..midpoint])
            .await
            .map_err(|_| "pre_hop_send")?;
        output.resize(midpoint, 0);
        receive
            .read_exact(&mut output)
            .await
            .map_err(|_| "pre_hop_receive")?;
        if output != payload[..midpoint] {
            return Err("pre_hop_mismatch");
        }
        *phase = "rebind";
        hop.rebind(endpoint, peer, port).await?;
    }
    *phase = "tcp_data";
    send.write_all(&payload[output.len()..])
        .await
        .map_err(|_| "tcp_data_send")?;
    let half_close = config["half_close"].as_bool().unwrap_or(true);
    if half_close {
        send.finish().map_err(|_| "tcp_half_close")?;
    }
    let suffix = receive
        .read_to_end(PAYLOAD_BYTES + TRAILER.len() - output.len())
        .await
        .map_err(|_| "tcp_data_receive")?;
    output.extend_from_slice(&suffix);
    if output.len() != PAYLOAD_BYTES + TRAILER.len()
        || output[..PAYLOAD_BYTES] != payload
        || &output[PAYLOAD_BYTES..] != TRAILER
    {
        return Ok(
            json!({"outcome": "tcp_data_mismatch", "udp_enabled": udp_enabled,
            "expected_bytes": PAYLOAD_BYTES + TRAILER.len(), "received_bytes": output.len(),
            "payload_prefix_matches": output.iter().zip(&payload).all(|(a, b)| a == b),
            "half_close_requested": half_close}),
        );
    }
    if !half_close {
        // Native capability probe: response/EOF precedes local stream closure.
        // This is deliberately not evidence of TCP half-close support.
        let _ = send.finish();
    }
    let transfer_ms = data_started.elapsed().as_secs_f64() * 1000.0;
    // Retain the last SendRequest until business streams finish: its Drop closes QUIC.
    drop(auth);
    drop(requests);
    Ok(
        json!({"outcome": "pass", "udp_enabled": udp_enabled, "setup_ms": setup_ms,
        "payload_bytes": PAYLOAD_BYTES, "transfer_ms": transfer_ms,
        "same_connection": connection_id == connection.stable_id(),
        "same_stream": stream_id == send.id() && stream_id == receive.id(),
        "tcp_half_close": half_close, "server_first": true}),
    )
}

async fn run(config: Value) -> Result<Value, &'static str> {
    let peer: SocketAddr = field(&config, "peer")?
        .parse()
        .map_err(|_| "invalid_fixture")?;
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        reject_at: config["reject_at"].as_u64().unwrap_or(0) as usize,
    });
    let dialer = Dialer::default().with_protector(protector.clone());
    let connector: Box<dyn OutboundConnector> = if let Some(upstream) = config["socks5"].as_str() {
        let upstream: SocketAddr = upstream.parse().map_err(|_| "invalid_fixture")?;
        Box::new(
            Socks5Outbound::new(
                &Socks5OutboundConfig {
                    address: upstream.ip().to_string(),
                    port: upstream.port(),
                    username: None,
                    password: None,
                },
                ResolvedEndpoint {
                    logical_host: upstream.ip().to_string(),
                    port: upstream.port(),
                    addresses: vec![upstream],
                },
                dialer,
            )
            .map_err(|_| "socks_config")?,
        )
    } else {
        Box::new(DirectOutbound::new(dialer))
    };
    let context = EstablishContext::with_timeout(Duration::from_secs(10));
    let transport = connector.open_datagram(datagram_request(), &context).await;
    let transport = match transport {
        Ok(transport) => transport,
        Err(error) => {
            return Ok(
                json!({"outcome": if matches!(error, vcore::dispatch::DispatchError::NotAllowed) {
            "protect_rejected"
        } else { "datagram_open" }, "protect_calls": protector.calls.load(Ordering::SeqCst),
            "controller_builds": 0, "sent_packets": 0, "stopped": true}),
            );
        }
    };
    let bbr = Arc::new(ObservedBbr::default());
    let client = client_config(&config, bbr.clone())?;
    let (socket, driver) = datagram::attach(transport, peer);
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(datagram::PACKET_LIMIT as u16)
        .map_err(|_| "quic_config")?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config,
        None,
        socket.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|_| "endpoint_setup")?;
    endpoint.set_default_client_config(client);
    let mut h3_task = None;
    let mut phase = "setup";
    let mut hop = Hop {
        connector: &*connector,
        context: &context,
        resource: None,
        rebinds: 0,
        connect_calls: 0,
        auth_requests: 0,
    };
    let result = tokio::time::timeout_at(
        context.deadline(),
        exercise(&endpoint, peer, &config, &mut h3_task, &mut phase, &mut hop),
    )
    .await;
    let mut report = match result {
        Ok(Ok(report)) => report,
        Ok(Err(reason)) => json!({"outcome": reason}),
        Err(_) => json!({"outcome": "deadline"}),
    };
    report["phase"] = json!(phase);
    report["rebinds"] = json!(hop.rebinds);
    report["connect_calls"] = json!(hop.connect_calls);
    report["auth_requests"] = json!(hop.auth_requests);
    let stop_started = Instant::now();
    let stop_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    endpoint.close(0_u32.into(), b"N0 complete");
    let h3_stopped = if let Some(mut task) = h3_task {
        match tokio::time::timeout_at(stop_deadline, &mut task).await {
            Ok(Ok(())) => true,
            _ => {
                task.abort();
                let _ = task.await;
                false
            }
        }
    } else {
        true
    };
    let idle = tokio::time::timeout_at(stop_deadline, endpoint.wait_idle())
        .await
        .is_ok();
    let mut stopped = h3_stopped && idle;
    let mut stats = datagram::Stats::default();
    for (index, (socket, driver)) in std::iter::once((socket, driver))
        .chain(hop.resource)
        .enumerate()
    {
        let driver_result = tokio::time::timeout_at(stop_deadline, driver.stop()).await;
        if let Ok(Err(error)) = &driver_result {
            report["outcome"] = json!(if error.kind() == io::ErrorKind::PermissionDenied {
                "protect_rejected"
            } else {
                "datagram_driver"
            });
        }
        stopped &= driver_result.is_ok()
            && socket
                .try_send(&quinn::udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: b"after-stop",
                    segment_size: None,
                    src_ip: None,
                })
                .is_err();
        let current = socket.stats();
        if index == 1 {
            report["post_hop_sent_packets"] = json!(current.sent);
            report["post_hop_received_packets"] = json!(current.received);
        }
        stats.sent += current.sent;
        stats.received += current.received;
        stats.peak_outgoing = stats.peak_outgoing.max(current.peak_outgoing);
        stats.peak_incoming = stats.peak_incoming.max(current.peak_incoming);
        stats.rejected_source += current.rejected_source;
        stats.dropped_full += current.dropped_full;
    }
    report["stopped"] = json!(stopped);
    report["stop_ms"] = json!(stop_started.elapsed().as_secs_f64() * 1000.0);
    report["protect_calls"] = json!(protector.calls.load(Ordering::SeqCst));
    report["controller_builds"] = json!(bbr.0.load(Ordering::Relaxed));
    report["sent_packets"] = json!(stats.sent);
    report["received_packets"] = json!(stats.received);
    report["peak_outgoing"] = json!(stats.peak_outgoing);
    report["peak_incoming"] = json!(stats.peak_incoming);
    report["rejected_source"] = json!(stats.rejected_source);
    report["dropped_full"] = json!(stats.dropped_full);
    Ok(report)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = async {
        let path = std::env::args().nth(1).ok_or("fixture_path")?;
        let bytes = std::fs::read(path).map_err(|_| "fixture_read")?;
        let config = serde_json::from_slice(&bytes).map_err(|_| "fixture_json")?;
        run(config).await
    }
    .await;
    println!(
        "{}",
        result.unwrap_or_else(|reason| json!({"outcome": reason, "stopped": false}))
    );
}
