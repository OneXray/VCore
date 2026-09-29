use super::*;

#[test]
#[ignore = "isolated VLESS runner"]
fn public_udp_isolation() {
    let _case = Case::start("VLESS-PUBLIC", "runtime::public_udp_isolation");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    for codec in if f["node"]["flow"] == "xtls-rprx-vision" {
        vec!["xudp"]
    } else {
        vec!["none", "xudp", "packetaddr"]
    } {
        let mut node = f["node"].clone();
        node["packet-encoding"] = json!(codec);
        let core = Core::start(&config(node, port));
        let mut first = Association::new(&f, port, false, false);
        let mut second = Association::new(&f, port, false, false);
        for n in 0..100 {
            first.exchange(&[1, n]);
            second.exchange(&[2, n]);
        }
        let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        rogue
            .send_to(&first.packet(b"unauthorized"), first.relay)
            .unwrap();
        first.origin.quiet();
        // Public SOCKS ingress budget is independent of the native peer's
        // smaller path limit. Reject before contacting the real origin.
        let cap = 65245;
        first
            .client
            .send_to(&first.packet(&vec![0; cap + 1]), first.relay)
            .unwrap();
        first.origin.quiet();
        second.exchange(b"oversize-isolated");
        // A different target in the same association must not be delivered to
        // the original raw target. Encoded transports carry the new target.
        let mut other = Origin::new(&f, 4, false);
        let mut packet = vec![0, 0, 0];
        packet.extend(address(other.target, false));
        packet.extend(b"other-target");
        second.client.send_to(&packet, second.relay).unwrap();
        if codec == "none"
            && !(f["node"]["smux"]["enabled"] == true && f["node"]["smux"]["only-tcp"] != true)
        {
            other.quiet();
        } else {
            other.udp(b"other-target");
            let mut response = [0; 128];
            let (n, _) = second.client.recv_from(&mut response).unwrap();
            assert!(response[..n].ends_with(b"other-target"));
        }
        second.origin.quiet();
        core.stop();
    }
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "isolated VLESS runner"]
fn public_entrypoints() {
    let _case = Case::start("VLESS-PUBLIC", "runtime::public_entrypoints");
    let f = fixture();
    entrypoints(&f);
}

#[cfg(target_os = "macos")]
pub(super) fn entrypoints(f: &Value) {
    use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
    initialize(f);
    let port = free_port();
    let yaml = json!({"port":port,"proxies":[f["node"]],"rules":["MATCH,peer"]});
    let core = Core::start(&yaml);
    let mut origin = Origin::new(f, 14, false);
    let mut client = socket((Ipv4Addr::LOCALHOST, port).into());
    write!(
        client,
        "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        origin.target, origin.target
    )
    .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    origin.marker(b'A');
    origin.marker(b'D');
    let mut origin = Origin::new(f, 13, false);
    let mut client = socket((Ipv4Addr::LOCALHOST, port).into());
    write!(
        client,
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nhttp-connect",
        origin.target, origin.target
    )
    .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        header.extend(byte);
        assert!(header.len() < 4096);
    }
    assert!(header.starts_with(b"HTTP/1.1 200"));
    let mut response = [0; 12];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"http-connect");
    origin.marker(b'A');
    core.stop();
    assert_closed(&mut client);
    origin.marker(b'D');
    drop((client, origin));
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut dns_origin = Origin::new(f, 17, false);
    let mut yaml = json!({"tun":{"enable":true},"proxies":[f["node"]],"rules":["MATCH,peer"]});
    dns(&mut yaml, &dns_origin, "peer");
    let core = Core::prepare(&yaml);
    invoke(
        "start",
        core.0.as_deref(),
        json!({"tunFd":host.as_raw_fd(),"tunFraming":"utun"}),
    );
    let mut udp = Origin::new(f, 4, false);
    peer.send(&tun::packet(udp.target, 17, (0, 0, 0), b"tun-udp"))
        .unwrap();
    udp.udp(b"tun-udp");
    assert_eq!(&tun::receive(&peer, 17)[28..], b"tun-udp");
    let mut origin = Origin::new(f, 13, false);
    peer.send(&tun::packet(origin.target, 6, (1, 0, 2), &[]))
        .unwrap();
    let syn = tun::receive(&peer, 6);
    assert_eq!(syn[33] & 0x12, 0x12);
    let ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    peer.send(&tun::packet(origin.target, 6, (2, ack, 0x18), b"tun-tcp"))
        .unwrap();
    let mut reply = Vec::new();
    while reply.len() < 7 {
        let packet = tun::receive(&peer, 6);
        let offset = 20 + usize::from(packet[32] >> 4) * 4;
        reply.extend_from_slice(&packet[offset..]);
    }
    assert_eq!(reply, b"tun-tcp");
    origin.marker(b'A');
    let query=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0dvcore-fixture\x04test\x00\x00\x01\x00\x01";
    peer.send(&tun::packet(
        "198.18.0.1:53".parse().unwrap(),
        17,
        (0, 0, 0),
        query,
    ))
    .unwrap();
    // DNS rewrites the query ID; observe the question on the native peer path.
    let mut size = [0; 4];
    dns_origin.observer.read_exact(&mut size).unwrap();
    let mut observed = vec![0; u16::from_be_bytes([size[0], size[1]]) as usize];
    dns_origin.observer.read_exact(&mut observed).unwrap();
    assert_eq!(&observed[12..], &query[12..]);
    let response = tun::receive(&peer, 17);
    assert_eq!(&response[28..30], &query[..2]);
    assert!(response.ends_with(&match udp.target.ip() {
        IpAddr::V4(ip) => ip.octets(),
        _ => unreachable!(),
    }));
    core.stop();
    origin.marker(b'D');
    assert!(unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK != 0);
}

fn fd_count() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}
pub(super) fn assert_closed(client: &mut TcpStream) {
    match client.read(&mut [0; 32]) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("stream not closed: {other:?}"),
    }
}
pub(super) fn live(port: u16, f: &Value) -> (TcpStream, Origin) {
    let mut origin = Origin::new(f, 13, false);
    let mut client = connect_with_initial(port, origin.target, false, b"live");
    let mut response = [0; 4];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"live");
    origin.marker(b'A');
    (client, origin)
}
pub(super) fn exchange(client: &mut TcpStream, bytes: &[u8]) {
    client.write_all(bytes).unwrap();
    let mut result = vec![0; bytes.len()];
    client.read_exact(&mut result).unwrap();
    assert_eq!(result, bytes);
}

#[test]
#[ignore = "isolated VLESS runner"]
fn public_lifecycle() {
    let _case = Case::start("VLESS-PUBLIC", "runtime::public_lifecycle");
    let f = fixture();
    initialize(&f);
    Core::start(&config(f["node"].clone(), free_port())).stop();
    for cycle in 0..20 {
        let _cycle = Case::start("VLESS-LIFE", "stop_and_remain_quiet");
        let baseline = fd_count();
        let port = free_port();
        let mut held = None;
        let mut udp = None;
        let mut blackholes = Vec::new();
        match cycle % 5 {
            0 => {
                let core = Core::start(&config(f["node"].clone(), port));
                echo(port, &f);
                core.stop();
            }
            3 => {
                let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
                let core = Core::prepare(&config(f["node"].clone(), port));
                assert_eq!(
                    invoke_response("start", core.0.as_deref(), json!({}))["success"],
                    false
                );
                core.stop();
                drop(occupied);
            }
            2 => {
                let h3 = f["node"]["alpn"] == json!(["h3"]);
                let origin = Origin::new(&f, if h3 { 20 } else { 15 }, false);
                let mut node = f["node"].clone();
                node["server"] = json!(origin.target.ip().to_string());
                node["port"] = json!(origin.target.port());
                let target = origin.target;
                blackholes.push((origin, h3));
                // Explicit XHTTP legs start concurrently. Give each its own
                // observer: the serial TCP blackhole otherwise reports the
                // second queued accept only after the first connection closes.
                if node["network"] == "xhttp" && node["xhttp-opts"]["download-settings"].is_object()
                {
                    let download = &mut node["xhttp-opts"]["download-settings"];
                    let down_h3 = download.get("alpn").map_or(h3, |v| *v == json!(["h3"]));
                    let origin = Origin::new(&f, if down_h3 { 20 } else { 15 }, false);
                    download["server"] = json!(origin.target.ip().to_string());
                    download["port"] = json!(origin.target.port());
                    blackholes.push((origin, down_h3));
                }
                let core = Core::start(&config(node, port));
                let mut client = login(port);
                let mut request = vec![5, 1, 0];
                request.extend(address(target, false));
                client.write_all(&request).unwrap();
                // Prove every physical handshake is in flight before Stop.
                for (origin, _) in &mut blackholes {
                    origin.marker(b'A');
                }
                core.stop();
                let _ = client.read(&mut [0; 32]);
                drop(client);
                for (origin, quic) in &mut blackholes {
                    if !*quic {
                        origin.marker(b'D');
                    }
                }
            }
            _ => {
                let core = Core::start(&config(f["node"].clone(), port));
                let (first, mut origin1) = live(port, &f);
                let (mut second, origin2) = live(port, &f);
                let mut one = Association::new(&f, port, false, false);
                let mut two = Association::new(&f, port, false, false);
                one.exchange(b"association-1");
                two.exchange(b"association-2");
                drop(first);
                origin1.marker(b'D');
                exchange(&mut second, b"sibling-survives");
                one.exchange(b"udp-survives");
                two.exchange(b"udp-other");
                drop(origin1);
                core.stop();
                assert_closed(&mut second);
                let mut origin2 = origin2;
                origin2.marker(b'D');
                assert_closed(&mut one.control);
                assert_closed(&mut two.control);
                held = Some((second, origin2));
                udp = Some((one, two));
            }
        }
        // All retained descriptors belong to the test, never the runtime. Check
        // immediately on Stop return, not after giving cleanup a grace period.
        let retained =
            usize::from(held.is_some()) * 2 + usize::from(udp.is_some()) * 6 + blackholes.len();
        assert!(
            fd_count() <= baseline + retained,
            "descriptors retained at Stop return"
        );
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        let udp_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        let quiet = Instant::now();
        while quiet.elapsed() < Duration::from_secs(5) {
            assert!(fd_count() <= baseline + retained + 2);
            if let Some((first, second)) = &mut udp {
                for item in [first, second] {
                    item.client.set_nonblocking(true).unwrap();
                    assert_eq!(
                        item.client.recv(&mut [0; 64]).unwrap_err().kind(),
                        io::ErrorKind::WouldBlock
                    );
                    item.origin.observer.set_nonblocking(true).unwrap();
                    assert_eq!(
                        item.origin.observer.read(&mut [0]).unwrap_err().kind(),
                        io::ErrorKind::WouldBlock
                    );
                }
            }
            for (origin, _) in &mut blackholes {
                origin.observer.set_nonblocking(true).unwrap();
                let mut marker = [0; 2];
                let result = origin.observer.read(&mut marker);
                assert!(
                    matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
                    "blackhole event after Stop: {result:?}, {marker:?}"
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
        drop((held, udp, blackholes, tcp, udp_guard));
        assert!(fd_count() <= baseline);
    }
}

pub(super) fn select(controller: u16, name: &str) {
    let body = json!({"name":name}).to_string();
    let mut client = socket((Ipv4Addr::LOCALHOST, controller).into());
    write!(client,"PUT /proxies/inner HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-only\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204"));
}

#[test]
#[ignore = "isolated VLESS runner"]
fn grpc_pool_keeps_physical_selection_until_new_transport() {
    let _case = Case::start(
        "VLESS-PUBLIC",
        "runtime::grpc_pool_keeps_physical_selection_until_new_transport",
    );
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let controller = free_port();
    let mut node = f["node"].clone();
    node["dialer-proxy"] = json!("inner");
    let mut yaml = config(node, port);
    yaml["proxies"]
        .as_array_mut()
        .unwrap()
        .push(f["hop"].clone());
    yaml["external-controller"] = json!(format!("127.0.0.1:{controller}"));
    yaml["secret"] = json!("fixture-only");
    yaml["proxy-groups"] = json!([{"name":"inner","type":"select","proxies":["hop","REJECT"]}]);
    let core = Core::start(&yaml);
    let (mut old, mut origin) = live(port, &f);
    select(controller, "REJECT");
    if f["node"]["network"] == "xhttp"
        && f["node"]["alpn"] == json!(["http/1.1"])
        && f["node"]["smux"]["enabled"] != true
    {
        // H1 can recycle a completed POST, but an active download GET cannot
        // carry another logical session. Its new physical connection must see
        // the new REJECT selection; the old session keeps its original path.
        let mut unused = Origin::new(&f, 13, false);
        let mut denied = login(port);
        let mut request = vec![5, 1, 0];
        request.extend(address(unused.target, false));
        denied.write_all(&request).unwrap();
        let mut reply = [0; 10];
        denied.read_exact(&mut reply).unwrap();
        if reply[1] == 0 {
            // A lazily opened XHTTP request can report its failure after the
            // local SOCKS handshake, but must never reach the target.
            denied.write_all(b"must-not-reach-origin").unwrap();
            assert_closed(&mut denied);
        }
        unused.quiet();
    } else {
        // Multiplexed transports can reuse the original authenticated hop.
        echo(port, &f);
    }
    exchange(&mut old, b"same-transport");
    core.stop();
    assert_closed(&mut old);
    origin.marker(b'D');
}
#[test]
#[ignore = "isolated VLESS runner"]
fn public_graph() {
    let _case = Case::start("VLESS-PUBLIC", "runtime::public_graph");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let controller = free_port();
    let mut node = f["node"].clone();
    if node["network"] == "grpc" {
        // Force expansion for an active stream to distinguish new physical
        // selection from existing-pool snapshot reuse (tested separately).
        node["grpc-opts"]["max-connections"] = json!(0);
        node["grpc-opts"]["max-streams"] = json!(1);
    }
    if node["network"] == "xhttp" {
        node["xhttp-opts"]["reuse-settings"] = json!({"h-max-request-times":"1"});
        if node["xhttp-opts"]["download-settings"].is_object() {
            node["xhttp-opts"]["download-settings"]["reuse-settings"] =
                json!({"h-max-request-times":"1"});
        }
    }
    if node["smux"]["enabled"] == true {
        node["smux"]["max-connections"] = json!(0);
        node["smux"]["max-streams"] = json!(1);
    }
    node["dialer-proxy"] = json!("hop");
    node["server"] = json!("peer.fixture.test");
    let mut yaml = config(node.clone(), port);
    let mut dns_origin = Origin::new(&f, 19, false);
    dns_origin
        .observer
        .write_all(
            &f["node"]["server"]
                .as_str()
                .unwrap()
                .parse::<Ipv4Addr>()
                .unwrap()
                .octets(),
        )
        .unwrap();
    dns(&mut yaml, &dns_origin, "DIRECT");
    yaml["proxies"]
        .as_array_mut()
        .unwrap()
        .push(f["hop"].clone());
    let core = Core::start(&yaml);
    echo(port, &f);
    let mut a = Association::new(&f, port, false, false);
    a.exchange(b"concrete-hop");
    core.stop();
    drop(a);
    node["server"] = f["node"]["server"].clone();
    node["dialer-proxy"] = json!("outer");
    yaml["proxies"][0] = node;
    yaml["external-controller"] = json!(format!("127.0.0.1:{controller}"));
    yaml["secret"] = json!("fixture-only");
    yaml["proxy-groups"] = json!([{"name":"outer","type":"select","proxies":["inner"]},{"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}]);
    let core = Core::start(&yaml);
    let (mut stream, mut origin) = live(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"before-switch");
    select(controller, "REJECT");
    exchange(&mut stream, b"old-stream-snapshot");
    udp.exchange(b"old-udp-snapshot");
    let mut unused = Origin::new(&f, 13, false);
    let mut denied = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(unused.target, false));
    denied.write_all(&request).unwrap();
    let mut result = [0; 10];
    denied.read_exact(&mut result).unwrap();
    assert_ne!(result[1], 0);
    unused.quiet();
    drop((denied, unused));
    select(controller, "DIRECT");
    echo(port, &f);
    exchange(&mut stream, b"still-old-snapshot");
    core.stop();
    assert_closed(&mut stream);
    origin.marker(b'D');
    drop((stream, origin, udp));
    // Even an unselected cycle is rejected before any start/socket creation.
    yaml["proxy-groups"][1]["proxies"] = json!(["DIRECT", "peer"]);
    assert_eq!(
        invoke_response(
            "validateConfig",
            None,
            json!({"configYaml":yaml.to_string()})
        )["success"],
        false
    );
    // A failing selected concrete upstream never switches to DIRECT.
    let mut broken = f["hop"].clone();
    broken["port"] = json!(1);
    yaml["proxies"][1] = broken;
    yaml["proxy-groups"][1]["proxies"] = json!(["hop", "DIRECT"]);
    let core = Core::start(&yaml);
    let mut unused = Origin::new(&f, 13, false);
    let mut denied = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(unused.target, false));
    denied.write_all(&request).unwrap();
    denied.read_exact(&mut result).unwrap();
    assert_ne!(result[1], 0);
    unused.quiet();
    core.stop();
}

#[test]
#[ignore = "isolated VLESS runner"]
fn public_ipv6_and_gates() {
    let _case = Case::start("VLESS-PUBLIC", "runtime::public_ipv6_and_gates");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let mut node = f["node"].clone();
    node["server"] = f["server_ipv6"].clone();
    let core = Core::start(&config(node, port));
    echo(port, &f);
    let mut udp = Association::new(&f, port, true, false);
    udp.exchange(b"outer-inner-ipv6");
    core.stop();
    drop(udp);
    let mut node = f["node"].clone();
    node["udp"] = json!(false);
    let mut yaml = config(node, port);
    yaml["ipv6"] = json!(false);
    let core = Core::start(&yaml);
    echo(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.client
        .send_to(&udp.packet(b"disabled"), udp.relay)
        .unwrap();
    udp.origin.quiet();
    let mut origin = Origin::new(&f, 13, true);
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    client.write_all(&request).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    assert_ne!(response[1], 0);
    origin.quiet();
    core.stop();
}

#[tokio::test]
#[ignore = "isolated VLESS runner"]
async fn owned_resources() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vcore::{
        config::{Config, ProxyProtocol},
        dialer::{Dialer, ResolvedEndpoint},
        outbound::{DatagramRequest, EstablishContext, OutboundConnector, VlessOutbound},
        resources::observation::{ResourceKind, ResourceProbe},
        session::{Datagram, DatagramSession, InboundKind, StreamSession},
    };
    let _case = Case::start("VLESS-PUBLIC", "runtime::owned_resources");
    let f = fixture();
    let parsed =
        Config::parse_yaml(config(f["node"].clone(), 1080).to_string().as_bytes()).unwrap();
    let ProxyProtocol::Vless(node) = &parsed.proxies[0].protocol else {
        unreachable!()
    };
    for _ in 0..20 {
        let mut case = Case::start("VLESS-OWNED", "stop_and_remain_quiet");
        let probe = ResourceProbe::default();
        case.checkpoint("baseline", probe.snapshot());
        probe
            .scope(async {
                let endpoint = ResolvedEndpoint {
                    logical_host: node.address.clone(),
                    port: node.port,
                    addresses: vec![SocketAddr::new(node.address.parse().unwrap(), node.port)],
                };
                let download_endpoint = node.download().map(|download| ResolvedEndpoint {
                    logical_host: download.address.clone(),
                    port: download.port,
                    addresses: vec![SocketAddr::new(
                        download.address.parse().unwrap(),
                        download.port,
                    )],
                });
                let outbound = VlessOutbound::new_with_endpoints(
                    node,
                    endpoint,
                    download_endpoint,
                    Dialer::default(),
                )
                .unwrap();
                let mut origin1 = Origin::new(&f, 13, false);
                let mut origin2 = Origin::new(&f, 13, false);
                let mut udp_origin = Origin::new(&f, 4, false);
                let session = |target| StreamSession {
                    inbound: InboundKind::InternalMeasure,
                    source: "127.0.0.1:1".parse().unwrap(),
                    destination: vcore::session::Destination::Ip(target),
                    sniffed_domain: None,
                };
                let mut first = outbound
                    .connect_stream(session(origin1.target), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                first.write_all(b"a").await.unwrap();
                first.flush().await.unwrap();
                assert_eq!(first.read_u8().await.unwrap(), b'a');
                origin1.marker(b'A');
                let mut second = outbound
                    .connect_stream(session(origin2.target), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                second.write_all(b"b").await.unwrap();
                second.flush().await.unwrap();
                assert_eq!(second.read_u8().await.unwrap(), b'b');
                origin2.marker(b'A');
                drop(first);
                tokio::task::spawn_blocking(move || origin1.marker(b'D'))
                    .await
                    .unwrap();
                second.write_all(b"c").await.unwrap();
                second.flush().await.unwrap();
                assert_eq!(second.read_u8().await.unwrap(), b'c');
                let request = DatagramRequest::new(DatagramSession::new(
                    InboundKind::InternalMeasure,
                    "127.0.0.1:1".parse().unwrap(),
                ));
                let mut udp = outbound
                    .open_datagram(request, &EstablishContext::default())
                    .await
                    .unwrap();
                udp.send(Datagram {
                    remote: udp_origin.target.into(),
                    payload: bytes::Bytes::from_static(b"owned"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                assert_eq!(udp.receive().await.unwrap().payload.as_ref(), b"owned");
                udp_origin.udp(b"owned");
                for kind in [
                    ResourceKind::Association,
                    ResourceKind::Session,
                    ResourceKind::Socket,
                ] {
                    assert!(probe.snapshot().peak(kind) > 0);
                }
                if matches!(
                    &node.transport,
                    vcore::config::VlessTransport::Stream(
                        vcore::config::StreamTransport::Grpc { .. }
                            | vcore::config::StreamTransport::H2 { .. }
                    )
                ) {
                    assert!(probe.snapshot().peak(ResourceKind::Task) > 0);
                }
                outbound.begin_shutdown();
                assert!(second.read_u8().await.is_err());
                drop(second);
                // Stop already cancelled the owned IO; XUDP's final END write
                // may report that cancellation. Resource release is mandatory.
                let _ = udp.close().await;
                drop(udp);
                tokio::time::timeout(Duration::from_secs(5), outbound.shutdown())
                    .await
                    .unwrap();
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
                case.checkpoint("after-stop", probe.snapshot());
                let snapshot = probe.snapshot();
                let quiet = tokio::time::Instant::now();
                while quiet.elapsed() < Duration::from_secs(5) {
                    assert_eq!(probe.snapshot(), snapshot);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                case.checkpoint("quiet", probe.snapshot());
            })
            .await;
        case.resources(probe.snapshot());
    }
}
