//! Diagnostic only: the same packet loop drives VCore and an official Mihomo client.
//! SOCKS5 below is a small fixture adapter, not VCore's SOCKS implementation.
use super::*;
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write};
use vcore::{
    dispatch::{DatagramBudget, DatagramTransport},
    dns::resolution::ResolutionContext,
    outbound::vmess::VmessDatagram,
    session::Datagram,
};

enum Client {
    Vcore(Box<dyn DatagramTransport>),
    Mihomo {
        _control: tokio::net::TcpStream,
        socket: tokio::net::UdpSocket,
        relay: SocketAddr,
    },
}

struct ContainerOrigin {
    observer: tokio::net::TcpStream,
    address: SocketAddr,
}

impl ContainerOrigin {
    async fn connect(fixture: &Value, family: &str) -> io::Result<Self> {
        let control = fixture["origin_control"]
            .as_str()
            .ok_or_else(|| io::Error::other("isolated origin required"))?;
        let mut observer = tokio::net::TcpStream::connect(control).await?;
        observer.set_nodelay(true)?;
        let ipv6 = family == "ipv6";
        observer.write_u8(if ipv6 { 6 } else { 4 }).await?;
        let port = observer.read_u16().await?;
        let ip = fixture[if ipv6 { "origin_ipv6" } else { "origin_ipv4" }]
            .as_str()
            .ok_or_else(|| io::Error::other("isolated origin address missing"))?
            .parse::<std::net::IpAddr>()
            .map_err(|_| io::Error::other("invalid isolated origin address"))?;
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(io::Error::other("host origin fallback forbidden"));
        }
        Ok(Self {
            observer,
            address: SocketAddr::new(ip, port),
        })
    }

    async fn receive(&mut self) -> io::Result<(Vec<u8>, u16)> {
        let length = self.observer.read_u16().await? as usize;
        let source_port = self.observer.read_u16().await?;
        if length > 20000 {
            return Err(io::Error::other("origin observation exceeds bound"));
        }
        let mut packet = vec![0; length];
        self.observer.read_exact(&mut packet).await?;
        Ok((packet, source_port))
    }
}

impl Client {
    async fn send(&mut self, target: &Destination, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Vcore(io) => io
                .send(Datagram {
                    remote: target.clone(),
                    payload: payload.to_vec().into(),
                    sniffed_domain: None,
                })
                .await
                .map_err(io::Error::other),
            Self::Mihomo { socket, relay, .. } => {
                let mut frame = vec![0, 0, 0];
                match target {
                    Destination::Ip(address) => match address.ip() {
                        std::net::IpAddr::V4(ip) => {
                            frame.push(1);
                            frame.extend(ip.octets());
                        }
                        std::net::IpAddr::V6(ip) => {
                            frame.push(4);
                            frame.extend(ip.octets());
                        }
                    },
                    Destination::Domain { host, .. } => {
                        frame.extend([3, host.len() as u8]);
                        frame.extend(host.as_bytes());
                    }
                }
                frame.extend(target.port().to_be_bytes());
                frame.extend(payload);
                let sent = socket.send_to(&frame, *relay).await?;
                if sent != frame.len() {
                    return Err(io::Error::other("fixture short UDP send"));
                }
                Ok(())
            }
        }
    }

    async fn receive(&mut self, target_port: u16) -> io::Result<Vec<u8>> {
        match self {
            Self::Vcore(io) => {
                let packet = io.receive().await.map_err(io::Error::other)?;
                if packet.remote.port() != target_port {
                    return Err(io::Error::other("response target port"));
                }
                Ok(packet.payload.to_vec())
            }
            Self::Mihomo { socket, relay, .. } => {
                let mut frame = vec![0; 20000];
                let (length, source) = socket.recv_from(&mut frame).await?;
                frame.truncate(length);
                if source != *relay || frame.len() < 4 || frame[..3] != [0, 0, 0] {
                    return Err(io::Error::other("fixture invalid SOCKS UDP response"));
                }
                let offset = match frame[3] {
                    1 => 8,
                    4 => 20,
                    3 if frame.len() >= 5 => 5 + frame[4] as usize,
                    _ => return Err(io::Error::other("fixture address type")),
                };
                if frame.len() < offset + 2
                    || u16::from_be_bytes([frame[offset], frame[offset + 1]]) != target_port
                {
                    return Err(io::Error::other("fixture response port"));
                }
                Ok(frame[offset + 2..].to_vec())
            }
        }
    }
}

async fn connect(
    kind: &str,
    option: &Value,
    target: &Destination,
    maximum: u16,
) -> io::Result<(Client, Option<StreamDriver>)> {
    if kind == "mihomo" {
        let port = option["socks_port"].as_u64().unwrap() as u16;
        let host = option["socks_host"].as_str().unwrap_or("127.0.0.1");
        let mut control = tokio::net::TcpStream::connect((host, port)).await?;
        control.write_all(&[5, 1, 0]).await?;
        let mut reply = [0; 2];
        control.read_exact(&mut reply).await?;
        if reply != [5, 0] {
            return Err(io::Error::other("SOCKS fixture method"));
        }
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut reply = [0; 4];
        control.read_exact(&mut reply).await?;
        if reply[..3] != [5, 0, 0] || reply[3] != 1 {
            return Err(io::Error::other("SOCKS fixture associate"));
        }
        let mut address = [0; 6];
        control.read_exact(&mut address).await?;
        let peer_ip = control.peer_addr()?.ip();
        let bound_ip = std::net::IpAddr::from([address[0], address[1], address[2], address[3]]);
        if !bound_ip.is_unspecified() && bound_ip != peer_ip {
            return Err(io::Error::other("unexpected SOCKS fixture relay address"));
        }
        let relay = SocketAddr::new(peer_ip, u16::from_be_bytes([address[4], address[5]]));
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        // Only the probe-owned ingress socket: leave peer and host settings alone.
        socket2::SockRef::from(&socket).set_send_buffer_size(65536)?;
        socket.set_nonblocking(true)?;
        return Ok((
            Client::Mihomo {
                _control: control,
                socket: tokio::net::UdpSocket::from_std(socket)?,
                relay,
            },
            None,
        ));
    }
    let cipher = match option["cipher"].as_str().unwrap() {
        "none" => BodyCipher::None,
        "auto" => BodyCipher::Auto,
        "aes-128-gcm" => BodyCipher::Aes128Gcm,
        "chacha20-poly1305" => BodyCipher::Chacha20Poly1305,
        _ => panic!("fixture cipher"),
    };
    let codec = option["codec"].as_str().unwrap();
    let (command, destination) = match codec {
        "raw" => (Command::Udp, target.clone()),
        "xudp" => (Command::Mux, Destination::domain("v1.mux.cool", 443)?),
        "packetaddr" => (
            Command::Udp,
            Destination::domain("sp.packet-addr.v2fly.arpa", 443)?,
        ),
        _ => panic!("fixture codec"),
    };
    let peer = std::env::var("VCORE_VMESS_PEER").unwrap().parse().unwrap();
    let (stream, driver) = wire_stream(
        peer,
        destination,
        cipher,
        option["padding"].as_bool().unwrap(),
        option["length"].as_bool().unwrap(),
        command,
    )
    .await?;
    let budget = DatagramBudget::new(maximum, maximum);
    let io: Box<dyn DatagramTransport> = match codec {
        "raw" => Box::new(VmessDatagram::raw(stream, target.clone(), budget)),
        "xudp" => Box::new(vcore::xudp::XudpTransport::new(
            Box::new(stream),
            [0; 8],
            maximum,
        )),
        _ => Box::new(VmessDatagram::packet_addr(
            stream,
            budget,
            ResolutionContext::measurement(
                std::sync::Arc::new(FixtureResolver(std::sync::atomic::AtomicUsize::new(0))),
                true,
            ),
        )),
    };
    Ok((Client::Vcore(io), driver))
}

#[tokio::test]
#[ignore = "requires owned official Mihomo client and server; diagnostic only"]
async fn matched_clients() {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("VCORE_VMESS_AB_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture["isolation"], "containers",
        "native server fallback forbidden"
    );
    let events = std::env::var("VCORE_VMESS_AB_EVENTS").unwrap();
    let mut events = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(events)
        .unwrap();
    let sizes = fixture["sizes"].as_array().unwrap();
    let maximum = if fixture["include_boundary"].as_bool().unwrap_or(false) {
        vcore::outbound::vmess::MAX_PACKET_BYTES as u16
    } else {
        sizes.iter().map(|v| v.as_u64().unwrap()).max().unwrap() as u16
    };
    let repeats = fixture["packets_per_size"].as_u64().unwrap();
    let rounds = fixture["rounds"].as_u64().unwrap();
    let mut ordinal = 0usize;
    let mut failures = 0;
    // Mihomo's SOCKS NAT key is only the incoming UDP source tuple. Keep each
    // probe-owned socket reserved until this transport ends so another case
    // cannot inherit an earlier case's codec/destination. No peer setting changes.
    let mut retired_sources = Vec::new();
    for round in 0..rounds {
        for (index, option) in fixture["options"].as_array().unwrap().iter().enumerate() {
            for (family_index, family) in fixture["families"].as_array().unwrap().iter().enumerate()
            {
                let family = family.as_str().unwrap();
                let mut case_sizes: Vec<usize> = sizes
                    .iter()
                    .map(|size| size.as_u64().unwrap() as usize)
                    .collect();
                if fixture["include_boundary"].as_bool().unwrap_or(false) {
                    let overhead = if option["codec"] == "packetaddr" {
                        if family == "ipv4" { 7 } else { 19 }
                    } else {
                        0
                    };
                    case_sizes.push(vcore::outbound::vmess::MAX_PACKET_BYTES - overhead);
                }
                let clients = if (round as usize + index + family_index).is_multiple_of(2) {
                    ["vcore", "mihomo"]
                } else {
                    ["mihomo", "vcore"]
                };
                for kind in clients {
                    ordinal += 1;
                    let mut origin = tokio::time::timeout(
                        Duration::from_secs(5),
                        ContainerOrigin::connect(&fixture, family),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    let address = origin.address;
                    let target = if family == "domain" {
                        Destination::domain("vcore-fixture.test", address.port()).unwrap()
                    } else {
                        address.into()
                    };
                    let mut record = json!({"ordinal":ordinal,"round":round,"client":kind,"option":index,"family":family,"origin_port":address.port(),"completed":0,"status":"FAIL","phase":"setup"});
                    let mut client = None;
                    let mut driver = None;
                    let started = std::time::Instant::now();
                    let outcome: io::Result<()> = async {
                        let connected = tokio::time::timeout(
                            Duration::from_secs(10),
                            connect(kind, option, &target, maximum),
                        )
                        .await??;
                        client = Some(connected.0);
                        driver = connected.1;
                        let client = client.as_mut().unwrap();
                        if let Client::Mihomo { socket, .. } = &*client {
                            record["fixture_source_port"] = socket.local_addr()?.port().into();
                        }
                        for &size in &case_sizes {
                            for sequence in 0..repeats {
                                record["size"] = size.into();
                                record["sequence"] = sequence.into();
                                let packet = vec![sequence as u8; size];
                                record["phase"] = "send".into();
                                tokio::time::timeout(
                                    Duration::from_secs(1),
                                    client.send(&target, &packet),
                                )
                                .await??;
                                record["phase"] = "origin".into();
                                let (received, source_port) =
                                    tokio::time::timeout(Duration::from_secs(1), origin.receive())
                                        .await??;
                                record["server_udp_port"] = source_port.into();
                                if received != packet {
                                    return Err(io::Error::other("origin content"));
                                }
                                // The isolated origin sends its own echo, not the host.
                                record["phase"] = "reply".into();
                                let echo = tokio::time::timeout(
                                    Duration::from_secs(1),
                                    client.receive(address.port()),
                                )
                                .await??;
                                if echo != packet {
                                    return Err(io::Error::other("response content"));
                                }
                                record["completed"] =
                                    (record["completed"].as_u64().unwrap() + 1).into();
                            }
                        }
                        Ok(())
                    }
                    .await;
                    if let Err(error) = outcome {
                        failures += 1;
                        record["error_kind"] = format!("{:?}", error.kind()).into();
                        println!(
                            "UDP-AB failure: client={kind} round={round} option={index} family={family} phase={} size={} sequence={}",
                            record["phase"], record["size"], record["sequence"]
                        );
                    } else {
                        record["status"] = "PASS".into();
                        record["phase"] = "complete".into();
                    }
                    record["elapsed_ms"] = (started.elapsed().as_millis() as u64).into();
                    if let Some(Client::Mihomo { socket, .. }) = client.take() {
                        retired_sources.push(socket);
                    }
                    if let Some(driver) = driver {
                        record["driver_joined"] = driver.stop().await.is_ok().into();
                    }
                    writeln!(events, "{record}").unwrap();
                    events.flush().unwrap();
                }
            }
        }
    }
    let ports: std::collections::HashSet<_> = retired_sources
        .iter()
        .map(|socket| socket.local_addr().unwrap().port())
        .collect();
    assert_eq!(
        ports.len(),
        retired_sources.len(),
        "fixture source port reused"
    );
    drop(retired_sources);
    assert_eq!(
        failures, 0,
        "matched UDP client associations failed; inspect structured observations"
    );
}

/// Change only the SOCKS ingress source tuple: a retained native NAT entry can
/// send a later fixture case to the earlier raw-UDP destination. All service
/// roles and both origins remain in containers.
#[tokio::test]
#[ignore = "requires isolated official peer and origins; expected-failure diagnostic"]
async fn socks_nat_source_reuse() {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("VCORE_VMESS_AB_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["isolation"], "containers");
    let mut events = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(std::env::var("VCORE_VMESS_AB_EVENTS").unwrap())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut first = ContainerOrigin::connect(&fixture, "ipv4").await.unwrap();
        let mut second = ContainerOrigin::connect(&fixture, "ipv4").await.unwrap();
        let a: Destination = first.address.into();
        let b: Destination = second.address.into();
        let (mut seed, _) = connect("mihomo", &fixture["options"][0], &a, 1200)
            .await
            .unwrap();
        seed.send(&a, &[0x41]).await.unwrap();
        assert_eq!(first.receive().await.unwrap().0, [0x41]);
        assert_eq!(seed.receive(first.address.port()).await.unwrap(), [0x41]);
        let seed_port = match &seed {
            Client::Mihomo { socket, .. } => socket.local_addr().unwrap().port(),
            _ => unreachable!(),
        };
        writeln!(
            events,
            "{}",
            json!({"ordinal":1,"client":"mihomo","phase":"seed",
            "status":"PASS","completed":1,"fixture_source_port":seed_port})
        )
        .unwrap();

        let (mut reused, _) = connect("mihomo", &fixture["options"][13], &b, 1200)
            .await
            .unwrap();
        match (&mut seed, &mut reused) {
            (Client::Mihomo { socket: old, .. }, Client::Mihomo { socket: new, .. }) => {
                std::mem::swap(old, new)
            }
            _ => unreachable!(),
        }
        reused.send(&b, &[0x42]).await.unwrap();
        let stale = tokio::time::timeout(Duration::from_secs(1), first.receive()).await;
        let misdirected = matches!(stale, Ok(Ok((ref packet, _))) if packet == &[0x42]);
        let absent = tokio::time::timeout(Duration::from_secs(1), second.receive())
            .await
            .is_err();
        writeln!(
            events,
            "{}",
            json!({"ordinal":2,"client":"mihomo","phase":"source-reused",
            "status":if misdirected && absent {"REPRODUCED"} else {"FAIL"},
            "completed":0,"fixture_source_port":seed_port,
            "old_origin_received_new_payload":misdirected,"new_origin_received_nothing":absent})
        )
        .unwrap();
        events.flush().unwrap();
        assert!(
            misdirected && absent,
            "native NAT source reuse was not reproduced"
        );

        let (mut fresh, _) = connect("mihomo", &fixture["options"][13], &b, 1200)
            .await
            .unwrap();
        let fresh_port = match &fresh {
            Client::Mihomo { socket, .. } => socket.local_addr().unwrap().port(),
            _ => unreachable!(),
        };
        assert_ne!(fresh_port, seed_port);
        fresh.send(&b, &[0x43]).await.unwrap();
        assert_eq!(second.receive().await.unwrap().0, [0x43]);
        assert_eq!(fresh.receive(second.address.port()).await.unwrap(), [0x43]);
        writeln!(
            events,
            "{}",
            json!({"ordinal":3,"client":"mihomo","phase":"unique-source-control",
            "status":"PASS","completed":1,"fixture_source_port":fresh_port})
        )
        .unwrap();
        events.flush().unwrap();
    })
    .await
    .unwrap();
}
