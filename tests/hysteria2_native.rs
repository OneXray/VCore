#![cfg(all(feature = "outbound-hysteria2", feature = "interop-test"))]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vcore::{
    config::{Config, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint},
    outbound::{EstablishContext, OutboundConnector, UpstreamPath, hysteria2::Hysteria2Outbound},
    session::{InboundKind, StreamSession},
};

fn fixture() -> Value {
    let value: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_VLESS_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(value["isolation"], "containers");
    value
}
fn node(raw: Value) -> Hysteria2Outbound {
    node_with_dialer(raw, Dialer::default())
}
fn node_with_dialer(raw: Value, dialer: Dialer) -> Hysteria2Outbound {
    let config = Config::parse_yaml(
        json!({"socks-port":1080, "proxies":[raw], "rules":["MATCH,peer"]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ProxyProtocol::Hysteria2(node) = &config.proxies[0].protocol else {
        panic!("wrong protocol")
    };
    Hysteria2Outbound::new_with_path(
        node,
        UpstreamPath::direct(
            ResolvedEndpoint {
                logical_host: node.address.clone(),
                port: node.port,
                addresses: vec![SocketAddr::new(node.address.parse().unwrap(), node.port)],
            },
            dialer,
        ),
    )
    .unwrap()
}

struct Protector {
    count: std::sync::atomic::AtomicUsize,
    reject_after: usize,
}
impl vcore::dialer::SocketProtector for Protector {
    fn protect(&self, _: i32) -> std::io::Result<()> {
        let index = self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if index >= self.reject_after {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}
async fn origin(f: &Value, mode: u8, ipv6: bool) -> (tokio::net::TcpStream, SocketAddr) {
    let mut control = tokio::net::TcpStream::connect(f["origin_control"].as_str().unwrap())
        .await
        .unwrap();
    control
        .write_u8(if mode >= 10 && ipv6 { mode | 128 } else { mode })
        .await
        .unwrap();
    let port = control.read_u16().await.unwrap();
    (
        control,
        SocketAddr::new(
            f[if ipv6 { "origin_ipv6" } else { "origin_ipv4" }]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            port,
        ),
    )
}
fn stream_request(target: SocketAddr) -> StreamSession {
    StreamSession {
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: target.into(),
        sniffed_domain: None,
    }
}
fn datagram_request() -> vcore::outbound::DatagramRequest {
    vcore::outbound::DatagramRequest::new(vcore::session::DatagramSession::new(
        InboundKind::InternalMeasure,
        "127.0.0.1:1".parse().unwrap(),
    ))
}

#[tokio::test]
#[ignore = "official Hysteria in an owned NET_ADMIN container required"]
async fn native_hopping() {
    use std::sync::{Arc, atomic::Ordering};
    use vcore::resources::observation::{ResourceKind, ResourceProbe};
    let mut event = vcore::resources::case_events::Case::new("N6-HOP", "native_hopping");
    let f = fixture();
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let protector = Arc::new(Protector {
                count: 0.into(),
                reject_after: usize::MAX,
            });
            let outbound = node_with_dialer(
                f["node"].clone(),
                Dialer::default().with_protector(protector.clone()),
            );
            let (mut tcp_control, target) = origin(&f, 13, false).await;
            let mut stream = outbound
                .connect_stream(stream_request(target), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            assert_eq!(tcp_control.read_u8().await.unwrap(), b'A');
            let mut associations = Vec::new();
            for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
                let (control, target) = origin(&f, if ipv6 { 6 } else { 4 }, ipv6).await;
                let remote = if domain {
                    vcore::session::Destination::domain("vcore-fixture.test", target.port())
                        .unwrap()
                } else {
                    target.into()
                };
                let udp = outbound
                    .open_datagram(datagram_request(), &EstablishContext::default())
                    .await
                    .unwrap();
                // Native Hysteria's response buffer includes the protocol header.
                // Mihomo separately passes the full 4096-byte application payload.
                let peer_maximum = 4096 - 9 - target.to_string().len();
                associations.push((control, target, remote, peer_maximum, udp));
            }
            let started = tokio::time::Instant::now();
            let mut sent_hash = Sha256::new();
            let mut recv_hash = Sha256::new();
            let mut bytes = vec![0; SIZE];
            for sequence in 0..1500 {
                let payload = record(sequence);
                tokio::time::timeout(Duration::from_secs(5), async {
                    stream.write_all(&payload).await.unwrap();
                    stream.read_exact(&mut bytes).await.unwrap();
                })
                .await
                .unwrap();
                sent_hash.update(&payload);
                recv_hash.update(&bytes);
                let (udp_control, udp_target, remote, peer_maximum, udp) =
                    &mut associations[sequence as usize % 3];
                let size = [1, 64, 512, 1200, *peer_maximum][sequence as usize / 3 % 5];
                let payload = bytes::Bytes::from(vec![(sequence % 251) as u8; size]);
                udp.send(vcore::session::Datagram {
                    remote: remote.clone(),
                    payload: payload.clone(),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let reply = tokio::time::timeout(Duration::from_secs(5), udp.receive())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("UDP response deadline: sequence={sequence}, size={size}")
                    })
                    .unwrap();
                assert_eq!(reply.remote, (*udp_target).into());
                assert_eq!(reply.payload, payload);
                assert_eq!(udp_control.read_u16().await.unwrap() as usize, size);
                assert_ne!(udp_control.read_u16().await.unwrap(), 0);
                let mut observed = vec![0; size];
                udp_control.read_exact(&mut observed).await.unwrap();
                assert_eq!(observed, payload);
                if started.elapsed() > Duration::from_secs(9) {
                    assert!(
                        protector.count.load(Ordering::SeqCst) > 1,
                        "port hopping has not created a protected new socket"
                    );
                }
                tokio::time::sleep_until(started + Duration::from_millis((sequence + 1) * 40))
                    .await;
            }
            assert!(started.elapsed() >= Duration::from_secs(60));
            let digest = sent_hash.finalize();
            assert_eq!(digest, recv_hash.finalize());
            assert!(protector.count.load(Ordering::SeqCst) >= 9);
            if let Ok(path) = std::env::var("VCORE_HOP_OBSERVATIONS") {
                let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                let data = json!({"seconds":started.elapsed().as_secs_f64(),"protected_sockets":protector.count.load(Ordering::SeqCst),"tcp_bytes_per_direction":1500*SIZE,"tcp_sha256":hash,"udp_packets":1500,"udp_target_kinds":3,"udp_maximums":associations.iter().map(|v| v.3).collect::<Vec<_>>(),"socket_peak":probe.snapshot().peak(ResourceKind::Socket)});
                std::fs::write(path, data.to_string()).unwrap();
            }
            assert!(
                probe.snapshot().peak(ResourceKind::Socket) <= 2,
                "old socket not bounded"
            );
            for (mut observer, _, remote, maximum, mut udp) in associations {
                // Preserve the native peer limitation as an explicit observation:
                // max+1 reaches the origin but its reply is silently discarded.
                let payload = bytes::Bytes::from(vec![9; maximum + 1]);
                udp.send(vcore::session::Datagram {
                    remote,
                    payload: payload.clone(),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                assert_eq!(observer.read_u16().await.unwrap() as usize, maximum + 1);
                assert_ne!(observer.read_u16().await.unwrap(), 0);
                let mut observed = vec![0; maximum + 1];
                observer.read_exact(&mut observed).await.unwrap();
                assert_eq!(observed, payload);
                assert!(
                    tokio::time::timeout(Duration::from_millis(150), udp.receive())
                        .await
                        .is_err()
                );
                udp.close().await.unwrap();
            }
            drop(stream);
            tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                .await
                .unwrap();
            drop(outbound);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(probe.snapshot().is_idle());
        })
        .await;
    event.resources(probe.snapshot());
}
const SIZE: usize = 65536;
fn record(sequence: u64) -> Vec<u8> {
    let mut bytes = vec![(sequence % 251) as u8; SIZE];
    bytes[..8].copy_from_slice(&sequence.to_be_bytes());
    bytes
}

async fn bandwidth(f: &Value, direction: u8, up: u64, down: u64, port: u16, expected: u64) -> f64 {
    let mut raw = f["node"].clone();
    raw["up"] = json!(up);
    raw["down"] = json!(down);
    raw["port"] = json!(port);
    let outbound = node(raw);
    let mut control = tokio::net::TcpStream::connect(f["bandwidth_control"].as_str().unwrap())
        .await
        .unwrap();
    control.write_u8(direction).await.unwrap();
    let target_port = control.read_u16().await.unwrap();
    let mut stream = outbound
        .connect_stream(
            StreamSession {
                inbound: InboundKind::InternalMeasure,
                source: "127.0.0.1:1".parse().unwrap(),
                destination: SocketAddr::new(
                    f["bandwidth_ipv4"].as_str().unwrap().parse().unwrap(),
                    target_port,
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
    assert_eq!(&hello, b"ready");
    assert_eq!(outbound.congestion_observation().await.unwrap().0, expected);
    let before = outbound.congestion_observation().await.unwrap().1;
    let observation = tokio::spawn(async move {
        let mut buckets = [0_u64; 30];
        let mut last = 0;
        loop {
            match control.read_u8().await.unwrap() {
                b'P' => {
                    let sequence = control.read_u64().await.unwrap();
                    assert_eq!(sequence, last + 1);
                    last = sequence;
                    let second = control.read_u64().await.unwrap() / 1_000_000_000;
                    if (10..40).contains(&second) {
                        buckets[(second - 10) as usize] += SIZE as u64;
                    }
                }
                b'D' => {
                    let sequence = control.read_u64().await.unwrap();
                    let mut digest = [0; 32];
                    control.read_exact(&mut digest).await.unwrap();
                    return (buckets, sequence, digest);
                }
                _ => panic!("invalid origin observation"),
            }
        }
    });
    let started = tokio::time::Instant::now();
    let mut digest = Sha256::new();
    let mut sequence = 0;
    let mut download_buckets = [0_u64; 30];
    if direction == b'U' {
        while started.elapsed() < Duration::from_secs(40) {
            let bytes = record(sequence);
            stream.write_all(&bytes).await.unwrap();
            digest.update(&bytes);
            sequence += 1;
        }
        stream.write_all(&record(u64::MAX)).await.unwrap();
        let mut done = [0; 5];
        stream.read_exact(&mut done).await.unwrap();
        assert_eq!(&done, b"done!");
    } else {
        stream.write_u8(b'S').await.unwrap();
        let mut stopped = false;
        let mut bytes = vec![0; SIZE];
        loop {
            stream.read_exact(&mut bytes).await.unwrap();
            let number = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            if number == u64::MAX {
                break;
            }
            assert_eq!(bytes, record(sequence));
            digest.update(&bytes);
            sequence += 1;
            let second = started.elapsed().as_secs();
            if (10..40).contains(&second) {
                download_buckets[(second - 10) as usize] += SIZE as u64;
            }
            if second >= 40 && !stopped {
                stream.write_u8(b'X').await.unwrap();
                stopped = true;
            }
        }
    }
    let (upload_buckets, received, remote_digest) = observation.await.unwrap();
    assert_eq!(received, sequence);
    assert_eq!(digest.finalize().as_slice(), remote_digest);
    let after = outbound.congestion_observation().await.unwrap().1;
    let buckets = if direction == b'U' {
        upload_buckets
    } else {
        download_buckets
    };
    let throughput = buckets.iter().sum::<u64>() as f64 / 30.0;
    let evidence = json!({"direction":char::from(direction), "up_mbps":up, "down_mbps":down,
        "listener_port":port,"controller_bps":expected,"payload_bps":throughput,"buckets":buckets,
        "udp_tx_bytes":after.udp_tx.bytes - before.udp_tx.bytes,"udp_rx_bytes":after.udp_rx.bytes - before.udp_rx.bytes,
        "rtt_ms":after.path.rtt.as_secs_f64()*1000.0,"cwnd":after.path.cwnd,"lost_packets":after.path.lost_packets});
    println!("N6-BANDWIDTH {evidence}");
    if let Ok(path) = std::env::var("VCORE_BANDWIDTH_OBSERVATIONS") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(file, "{evidence}").unwrap();
        file.flush().unwrap();
    }
    drop(stream);
    tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
        .await
        .unwrap();
    throughput
}

#[tokio::test]
#[ignore = "owned isolated N6 peers required"]
async fn native_bandwidth_matrix() {
    let _case = vcore::resources::case_events::Case::new("N6-BANDWIDTH", "native_bandwidth_matrix");
    let f = fixture();
    for direction in *b"UD" {
        let baseline = bandwidth(&f, direction, 0, 0, 23000, 0).await;
        assert!(
            baseline >= 750000.0,
            "environment cannot measure: baseline below 6 Mbit/s"
        );
        let mut measured = Vec::new();
        for rate in [1, 2] {
            let (up, down, expected) = if direction == b'U' {
                (rate, 100, rate * 125000)
            } else {
                (0, rate, 0)
            };
            let value = bandwidth(&f, direction, up, down, 23000, expected).await;
            assert!(
                value <= rate as f64 * 125000.0 * 1.1,
                "configured bandwidth is not enforced"
            );
            measured.push(value);
        }
        assert!(
            measured[1] >= measured[0] * 1.5,
            "two configured rates do not scale"
        );
        let (up, down, port, expected) = if direction == b'U' {
            (2, 100, 23002, 125000)
        } else {
            (0, 2, 23003, 0)
        };
        let lower = bandwidth(&f, direction, up, down, port, expected).await;
        assert!(
            lower <= 125000.0 * 1.1,
            "lower server bandwidth is not enforced"
        );
    }
    // Mihomo returns RxAuto when client down=0; a configured up must not override it.
    assert!(bandwidth(&f, b'U', 2, 0, 23000, 0).await > 0.0);
    assert!(bandwidth(&f, b'U', 2, 2, 23004, 0).await > 0.0);
}

#[tokio::test]
#[ignore = "owned isolated Mihomo client and server required"]
async fn native_mihomo_close_alignment() {
    let _case =
        vcore::resources::case_events::Case::new("N6-NATIVE", "native_mihomo_close_alignment");
    let f = fixture();
    assert_eq!(f["close_reference"]["scope"], "same-mode");
    assert_eq!(f["close_reference"]["terminated"], true);
    let outbound = node(f["node"].clone());
    let (mut observer, target) = origin(&f, 11, false).await;
    let mut io = outbound
        .connect_stream(stream_request(target), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    let mut hello = [0; 5];
    io.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    io.write_all(b"ping").await.unwrap();
    io.flush().await.unwrap();
    let mut ping = [0; 4];
    io.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");
    io.shutdown().await.unwrap();
    let mut tail = Vec::new();
    let _terminal = tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut tail))
        .await
        .expect("close must end pending reads");
    let hex: String = tail.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, f["close_reference"]["tail_hex"].as_str().unwrap());
    assert_eq!(observer.read_u8().await.unwrap(), b'A');
    assert_eq!(observer.read_u8().await.unwrap(), b'D');
    drop(io);
    tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "owned isolated N6 peers required"]
async fn native_security_matrix() {
    use vcore::resources::{case_events::Case, observation::ResourceProbe};
    let f = fixture();
    let mut case = Case::new("N6-SECURITY", "native_security_matrix");
    let probe = ResourceProbe::default();
    const IDS: &[&str] = &[
        "root-pin",
        "leaf-pin",
        "root-pin-wrong-name",
        "leaf-pin-is-trust",
        "unknown-ca",
        "explicit-skip",
        "wrong-pin",
        "skip-does-not-override-pin",
        "wrong-password",
        "empty-password",
        "raw-password",
        "empty-alpn-default",
        "custom-alpn",
        "wrong-alpn",
        "mtls-valid",
        "mtls-absent",
        "mtls-expired",
        "mtls-wrong-ca",
        "salamander",
        "salamander-client-only",
        "salamander-server-only",
        "salamander-wrong-key",
        "salamander-wrong-auth",
    ];
    assert_eq!(f["security"].as_array().unwrap().len(), IDS.len());
    for sample in f["security"].as_array().unwrap() {
        let id = sample["id"].as_str().unwrap();
        let _sample = Case::new(
            "N6-SECURITY-CASE",
            IDS.iter().copied().find(|name| *name == id).unwrap(),
        );
        let success = sample["success"].as_bool().unwrap();
        probe
            .scope(async {
                let outbound = node(sample["node"].clone());
                let (mut control, target) = origin(&f, 12, false).await;
                let outcome = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut io = outbound
                        .connect_stream(
                            stream_request(target),
                            &EstablishContext::with_timeout(Duration::from_secs(4)),
                        )
                        .await
                        .map_err(std::io::Error::other)?
                        .io;
                    io.write_all(b"synthetic-probe").await?;
                    let mut reply = [0; 2];
                    io.read_exact(&mut reply).await?;
                    assert_eq!(&reply, b"ok");
                    Ok::<_, std::io::Error>(())
                })
                .await
                .expect("bounded security operation");
                assert_eq!(outcome.is_ok(), success, "{id}");
                if success {
                    assert_eq!(control.read_u8().await.unwrap(), b'A');
                    assert_eq!(control.read_u8().await.unwrap(), b'D');
                } else {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(100), control.read_u8())
                            .await
                            .is_err(),
                        "rejected security reached origin: {id}"
                    );
                }
                tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                    .await
                    .unwrap();
            })
            .await;
        assert!(probe.snapshot().is_idle(), "{id}: {:?}", probe.snapshot());
        println!("N6-SECURITY {id} PASS");
    }
    for identity in f["invalid_identities"].as_array().unwrap() {
        let mut raw = f["node"].clone();
        raw["certificate"] = identity["certificate"].clone();
        raw["private-key"] = identity["private-key"].clone();
        assert!(
            Config::parse_yaml(
                json!({"socks-port":1080,"proxies":[raw],"rules":["MATCH,peer"]})
                    .to_string()
                    .as_bytes()
            )
            .is_err()
        );
    }
    case.resources(probe.snapshot());
}

#[tokio::test]
#[ignore = "official Hysteria with disableUDP required"]
async fn native_udp_disabled() {
    let _case = vcore::resources::case_events::Case::new("N6-UDP-DISABLED", "native_udp_disabled");
    let f = fixture();
    let outbound = node(f["node"].clone());
    let (mut control, target) = origin(&f, 10, false).await;
    let mut io = outbound
        .connect_stream(stream_request(target), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    let mut hello = [0; 5];
    io.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    assert_eq!(control.read_u8().await.unwrap(), b'A');
    let sent = vec![0x5a; 10 * 1024 * 1024];
    io.write_all(&sent).await.unwrap();
    let mut received = vec![0; sent.len()];
    io.read_exact(&mut received).await.unwrap();
    assert_eq!(Sha256::digest(&sent), Sha256::digest(&received));
    let mut tail = [0; 7];
    io.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"trailer");
    assert!(matches!(
        outbound
            .open_datagram(datagram_request(), &EstablishContext::default())
            .await,
        Err(vcore::dispatch::DispatchError::NotAllowed)
    ));
    drop(io);
    tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
        .await
        .unwrap();
}

async fn hop_interrupt(reject: bool) {
    use std::sync::{Arc, atomic::Ordering};
    use vcore::resources::{
        case_events::Case,
        observation::{ResourceKind, ResourceProbe},
    };
    let mut event = Case::new(
        "N6-HOP",
        if reject {
            "native_hop_protect_rejection"
        } else {
            "native_stop_during_hop"
        },
    );
    let f = fixture();
    let probe = ResourceProbe::default();
    event.checkpoint("baseline", probe.snapshot());
    probe
        .scope(async {
            let protector = Arc::new(Protector {
                count: 0.into(),
                reject_after: if reject { 1 } else { usize::MAX },
            });
            let outbound = node_with_dialer(
                f["node"].clone(),
                Dialer::default().with_protector(protector.clone()),
            );
            let (mut control, target) = origin(&f, 13, false).await;
            let mut io = outbound
                .connect_stream(stream_request(target), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            io.write_all(b"before-hop").await.unwrap();
            let mut bytes = [0; 10];
            io.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"before-hop");
            assert_eq!(control.read_u8().await.unwrap(), b'A');
            tokio::time::timeout(Duration::from_secs(9), async {
                while protector.count.load(Ordering::SeqCst) < 2 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            if reject {
                assert!(
                    tokio::time::timeout(Duration::from_secs(2), io.read_u8())
                        .await
                        .unwrap()
                        .is_err()
                );
            } else {
                // The second protected socket exists, inside the one-second old
                // socket grace window. Stop must join both rather than abort/leak.
                assert!(probe.snapshot().current(ResourceKind::Socket) >= 2);
                outbound.begin_shutdown();
                assert!(io.read_u8().await.is_err());
            }
            drop(io);
            let count = protector.count.load(Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                .await
                .unwrap();
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            event.checkpoint("after-stop", probe.snapshot());
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert_eq!(
                protector.count.load(Ordering::SeqCst),
                count,
                "late unrequested reconnect"
            );
            assert!(probe.snapshot().is_idle());
            event.checkpoint("quiet", probe.snapshot());
        })
        .await;
    event.resources(probe.snapshot());
}

#[tokio::test]
#[ignore = "official Hysteria in an owned NET_ADMIN container required"]
async fn native_hop_protect_rejection() {
    hop_interrupt(true).await;
}

#[tokio::test]
#[ignore = "official Hysteria in an owned NET_ADMIN container required"]
async fn native_stop_during_hop() {
    hop_interrupt(false).await;
}

#[tokio::test]
#[ignore = "owned isolated N6 peers required"]
async fn native_deadline_and_udp_budget() {
    use vcore::resources::{case_events::Case, observation::ResourceProbe};
    let mut event = Case::new("N6-NATIVE", "native_deadline_and_udp_budget");
    let f = fixture();
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let (mut observer, blackhole) = origin(&f, 20, false).await;
            let mut raw = f["node"].clone();
            raw["server"] = json!(blackhole.ip().to_string());
            raw["port"] = json!(blackhole.port());
            let outbound = node(raw);
            let context = EstablishContext::default();
            let started = tokio::time::Instant::now();
            // Consume part of the same ten-second budget before the outer handshake.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let result = tokio::time::timeout(
                Duration::from_secs(9),
                outbound.connect_stream(stream_request(blackhole), &context),
            )
            .await
            .unwrap();
            assert!(matches!(
                result,
                Err(vcore::dispatch::DispatchError::TimedOut)
            ));
            assert!(
                (Duration::from_millis(9900)..Duration::from_secs(11)).contains(&started.elapsed())
            );
            assert_eq!(observer.read_u8().await.unwrap(), b'A');
            tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                .await
                .unwrap();
            assert!(probe.snapshot().is_idle());
            let outbound = node(f["node"].clone());
            let (mut observer, target) = origin(&f, 4, false).await;
            let mut udp = outbound
                .open_datagram(
                    datagram_request().with_budget(vcore::dispatch::DatagramBudget::new(128, 128)),
                    &EstablishContext::default(),
                )
                .await
                .unwrap();
            let packet = |size| vcore::session::Datagram {
                remote: target.into(),
                payload: bytes::Bytes::from(vec![7; size]),
                sniffed_domain: None,
            };
            assert_eq!(udp.payload_budget(&target.into()).transmit(), 128);
            assert!(udp.send(packet(129)).await.is_err());
            assert!(
                tokio::time::timeout(Duration::from_millis(100), observer.read_u8())
                    .await
                    .is_err()
            );
            udp.send(packet(128)).await.unwrap();
            assert_eq!(udp.receive().await.unwrap().payload, vec![7; 128]);
            assert_eq!(observer.read_u16().await.unwrap(), 128);
            assert_ne!(observer.read_u16().await.unwrap(), 0);
            let mut observed = [0; 128];
            observer.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed, [7; 128]);
            udp.close().await.unwrap();
            drop(udp);
            tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                .await
                .unwrap();
        })
        .await;
    assert!(probe.snapshot().is_idle());
    event.resources(probe.snapshot());
}

#[tokio::test]
#[ignore = "owned isolated N6 peers required"]
async fn native_owned_lifecycle() {
    use std::sync::{Arc, atomic::Ordering};
    use vcore::resources::{
        case_events::Case,
        observation::{ResourceKind, ResourceProbe},
    };
    let f = fixture();
    for cycle in 0..20 {
        let mut case = Case::new("N6-LIFE", "native_owned_lifecycle");
        let probe = ResourceProbe::default();
        case.checkpoint("baseline", probe.snapshot());
        probe.scope(async {
            let protector=Arc::new(Protector {count:0.into(),reject_after:usize::MAX});
            if cycle%5==2 {
                let (mut control,blackhole)=origin(&f,20,false).await;
                let mut raw=f["node"].clone();raw["server"]=json!(blackhole.ip().to_string());raw["port"]=json!(blackhole.port());
                let outbound=node_with_dialer(raw,Dialer::default().with_protector(protector.clone()));
                // Dropping the user's future cancels only the pending auth owner.
                let context = EstablishContext::default();
                tokio::select! {
                    result=outbound.connect_stream(stream_request(blackhole),&context) => panic!("unexpected blackhole outcome: {:?}",result.err()),
                    marker=control.read_u8()=>assert_eq!(marker.unwrap(),b'A'),
                }
                tokio::time::timeout(Duration::from_secs(5),outbound.shutdown()).await.unwrap();
                assert!(tokio::time::timeout(Duration::from_millis(100),control.read_u8()).await.is_err());
            } else {
                let outbound=node_with_dialer(f["node"].clone(),Dialer::default().with_protector(protector.clone()));
                let (mut a,target)=origin(&f,13,false).await;
                if cycle%5==3 {
                    assert!(matches!(outbound.connect_stream(stream_request(target),&EstablishContext::with_timeout(Duration::ZERO)).await,Err(vcore::dispatch::DispatchError::TimedOut)));
                    assert_eq!(protector.count.load(Ordering::SeqCst),0);
                } else {
                    let mut first=outbound.connect_stream(stream_request(target),&EstablishContext::default()).await.unwrap().io;
                    first.write_all(b"a").await.unwrap();assert_eq!(first.read_u8().await.unwrap(),b'a');assert_eq!(a.read_u8().await.unwrap(),b'A');
                    let (mut b,target)=origin(&f,13,false).await;
                    let mut second=outbound.connect_stream(stream_request(target),&EstablishContext::default()).await.unwrap().io;
                    second.write_all(b"b").await.unwrap();assert_eq!(second.read_u8().await.unwrap(),b'b');assert_eq!(b.read_u8().await.unwrap(),b'A');
                    drop(first);assert_eq!(a.read_u8().await.unwrap(),b'D');
                    second.write_all(b"sibling").await.unwrap();let mut reply=[0;7];second.read_exact(&mut reply).await.unwrap();assert_eq!(&reply,b"sibling");
                    let (mut u,target)=origin(&f,4,false).await;
                    let mut udp=outbound.open_datagram(datagram_request(),&EstablishContext::default()).await.unwrap();
                    udp.send(vcore::session::Datagram {remote:target.into(),payload:bytes::Bytes::from_static(b"udp"),sniffed_domain:None}).await.unwrap();
                    assert_eq!(udp.receive().await.unwrap().payload,b"udp"[..]);
                    assert_eq!(u.read_u16().await.unwrap(),3);assert_ne!(u.read_u16().await.unwrap(),0);
                    let mut observed=[0;3];u.read_exact(&mut observed).await.unwrap();assert_eq!(&observed,b"udp");
                    for kind in [ResourceKind::Socket,ResourceKind::Session,ResourceKind::Task,ResourceKind::Pool,ResourceKind::Handshake,ResourceKind::Association] {assert!(probe.snapshot().peak(kind)>0);}
                    outbound.begin_shutdown();assert!(second.read_u8().await.is_err());drop(second);
                    assert!(udp.receive().await.is_err());udp.close().await.unwrap();drop(udp);
                }
                tokio::time::timeout(Duration::from_secs(5),outbound.shutdown()).await.unwrap();
            }
            assert!(probe.snapshot().is_idle(),"cycle {cycle}: {:?}",probe.snapshot());
            case.checkpoint("after-stop",probe.snapshot());
            let snapshot=probe.snapshot();let until=tokio::time::Instant::now()+Duration::from_secs(5);
            while tokio::time::Instant::now()<until {assert_eq!(probe.snapshot(),snapshot);tokio::time::sleep(Duration::from_millis(25)).await;}
            case.checkpoint("quiet",probe.snapshot());
        }).await;
        case.resources(probe.snapshot());
    }
}
