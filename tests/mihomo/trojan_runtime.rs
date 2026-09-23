//! Consumer entrypoints and lifecycle against a real owned Mihomo listener.
use super::*;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

struct Association {
    control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
    origin: UdpSocket,
    peer: Option<SocketAddr>,
}

impl Association {
    fn open(proxy: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        let mut control = socks_login(proxy, false);
        let mut request = vec![5, 3, 0];
        request.extend_from_slice(&socks_address(socket.local_addr().unwrap()));
        control.write_all(&request).unwrap();
        let relay = socks_reply(&mut control);
        let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
        origin.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        Self {
            control,
            socket,
            relay,
            origin,
            peer: None,
        }
    }

    fn request(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&socks_address(self.origin.local_addr().unwrap()));
        packet.extend_from_slice(payload);
        packet
    }

    fn exchange(&mut self, payload: &[u8]) {
        let packet = self.request(payload);
        self.socket.send_to(&packet, self.relay).unwrap();
        let mut buffer = [0; 9000];
        let (n, peer) = self.origin.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], payload);
        self.peer = Some(peer);
        self.origin.send_to(&buffer[..n], peer).unwrap();
        let (n, source) = self.socket.recv_from(&mut buffer).unwrap();
        assert_eq!(source, self.relay);
        assert_eq!(&buffer[..n], packet);
    }

    fn assert_quiet(&self) {
        let mut bytes = [0; 9000];
        self.socket.set_nonblocking(true).unwrap();
        self.origin.set_nonblocking(true).unwrap();
        assert_eq!(
            self.socket.recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            self.origin.recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
#[ignore = "requires the owned N2 native-peer runner"]
fn public_trojan_native_lifecycle() {
    let _case = Case::new("N2-NATIVE", "runtime::public_trojan_native_lifecycle");
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    // The process-wide Invoke worker is lazily created by the first instance;
    // it is not owned by a Running Session. Establish that baseline once.
    Core::start(&config(fixture["node"].clone(), free_port()).to_string()).stop();
    for cycle in 0..20 {
        let cycle_case = Case::new("N2-LIFE-CYCLE", "stop_and_remain_quiet");
        let baseline = ss_lifecycle::open_fd_count();
        let port = free_port();
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let yaml = config(fixture["node"].clone(), port).to_string();
        let mut associations = Vec::new();
        let mut stalled = None;
        if cycle % 5 == 0 {
            let core = Core::start(&yaml);
            probe_socks_tcp(proxy, false, false);
            probe_socks_udp(proxy, false, false);
            core.stop();
        } else if cycle % 5 == 3 {
            let occupied = UdpSocket::bind(proxy).unwrap();
            let id = invoke("createInstance", None, json!({}))["instanceId"]
                .as_str()
                .unwrap()
                .to_owned();
            let core = Core(Some(id));
            invoke("prepare", core.0.as_deref(), json!({"configYaml":yaml}));
            assert_eq!(
                invoke_response("start", core.0.as_deref(), json!({}))["success"],
                false
            );
            assert_ne!(
                invoke("getState", core.0.as_deref(), json!({}))["state"],
                "running"
            );
            core.stop();
            drop(occupied);
        } else if cycle % 5 == 2 {
            let blackhole = TcpListener::bind("127.0.0.1:0").unwrap();
            blackhole.set_nonblocking(true).unwrap();
            let mut node = fixture["node"].clone();
            node["port"] = json!(blackhole.local_addr().unwrap().port());
            let core = Core::start(&config(node, port).to_string());
            let mut client = socks_login(proxy, false);
            client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 9]).unwrap();
            let mut remote = accept_until(&blackhole);
            assert!(remote.read(&mut [0; 8192]).unwrap() > 0);
            core.stop();
            let mut bytes = Vec::new();
            remote.read_to_end(&mut bytes).unwrap();
            drop((remote, client));
            // Keep the blackhole listening: any resumed/retried handshake is
            // detected during the post-Stop window, not merely dropped.
            stalled = Some(blackhole);
        } else {
            let core = Core::start(&yaml);
            let mut first = groups::TcpFlow::open(proxy);
            let mut second = groups::TcpFlow::open(proxy);
            first.exchange(1);
            second.exchange(2);
            let mut udp1 = Association::open(proxy);
            let mut udp2 = Association::open(proxy);
            udp1.exchange(b"association-one");
            udp2.exchange(b"association-two");
            if cycle % 5 == 4 {
                drop(first);
                second.exchange(3);
                udp1.exchange(b"after-one-tcp-cancelled");
                udp2.exchange(b"other-association-still-live");
            } else {
                first.exchange(4);
                drop(first);
            }
            core.stop();
            second.assert_closed();
            for udp in [&mut udp1, &mut udp2] {
                assert_eq!(udp.control.read(&mut [0; 1]).unwrap(), 0);
                udp.origin
                    .send_to(b"late-after-stop", udp.peer.unwrap())
                    .unwrap();
            }
            drop(second);
            associations.extend([udp1, udp2]);
        }
        // Only caller-owned fixture fds remain: each association has two
        // dual-family UDP sockets (four fds) and its TCP control (one fd).
        let retained_fixture_fds = associations.len() * 5 + usize::from(stalled.is_some());
        ss_lifecycle::assert_fd_returned(baseline.map(|count| count + retained_fixture_fds));
        // Port rebind occurs immediately at Stop return, before any quiet wait.
        let tcp_guard = TcpListener::bind(proxy).unwrap();
        let udp_guard = UdpSocket::bind(proxy).unwrap();
        let quiet = Instant::now();
        while quiet.elapsed() < Duration::from_secs(5) {
            ss_lifecycle::assert_fd_returned(
                baseline.map(|count| count + retained_fixture_fds + 3),
            );
            for association in &associations {
                association.assert_quiet();
            }
            if let Some(listener) = &stalled {
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
        drop((tcp_guard, udp_guard, associations, stalled));
        ss_lifecycle::assert_fd_returned(baseline);
        drop(cycle_case);
    }
}

#[test]
#[ignore = "requires the owned N2 native-peer runner"]
fn public_trojan_native_certificate_names() {
    let _case = Case::new(
        "N2-NATIVE",
        "runtime::public_trojan_native_certificate_names",
    );
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let node = fixture["node"].clone();
    let port = free_port();
    let core = Core::start(&config(node.clone(), port).to_string());
    probe_socks_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), false, false);
    core.stop();
    let mut wrong_name = node.clone();
    wrong_name["sni"] = json!("wrong.example");
    assert_no_origin_bytes(wrong_name.clone());
    wrong_name["skip-cert-verify"] = json!(true);
    // A non-leaf pin keeps chain/name validation even when skip is enabled.
    assert_no_origin_bytes(wrong_name.clone());
    wrong_name.as_object_mut().unwrap().remove("fingerprint");
    let core = Core::start(&config(wrong_name, port).to_string());
    probe_socks_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), false, false);
    core.stop();
    let mut wrong_pin = node;
    wrong_pin["fingerprint"] = json!("11".repeat(32));
    assert_no_origin_bytes(wrong_pin);
}

#[test]
#[ignore = "requires the owned N2 native-peer runner"]
fn public_trojan_native_udp_isolation_and_limit() {
    let _case = Case::new(
        "N2-NATIVE",
        "runtime::public_trojan_native_udp_isolation_and_limit",
    );
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let port = free_port();
    let core = Core::start(&config(fixture["node"].clone(), port).to_string());
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut first = Association::open(proxy);
    let mut second = Association::open(proxy);
    for n in 0..100u8 {
        first.exchange(&[1, n]);
        second.exchange(&[2, n]);
    }
    // Unauthorised source must not enter either association.
    let rogue = UdpSocket::bind("127.0.0.1:0").unwrap();
    rogue
        .send_to(&first.request(b"rogue"), first.relay)
        .unwrap();
    first
        .origin
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(first.origin.recv_from(&mut [0; 9000]).is_err());
    first
        .socket
        .send_to(&first.request(&[7; 8193]), first.relay)
        .unwrap();
    assert!(first.origin.recv_from(&mut [0; 9000]).is_err());
    second.exchange(b"oversize-on-other-association-did-not-leak");
    core.stop();
}

#[test]
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[ignore = "requires the owned N2 native-peer runner"]
fn public_trojan_native_entrypoints() {
    let _case = Case::new("N2-NATIVE", "runtime::public_trojan_native_entrypoints");
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let port = free_port();
    let yaml = json!({"port":port,"proxies":[fixture["node"]],"rules":["MATCH,peer"]});
    let core = Core::start(&yaml.to_string());
    for mode in [Mode::Forward, Mode::Chunked, Mode::Connect, Mode::Upgrade] {
        probe(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), false, mode);
    }
    core.stop();
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    dns.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let yaml = json!({"tun":{"enable":true},"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":[fixture["node"]],"rules":["MATCH,peer"],"dns":{"enable":true,"ipv6":false,"nameserver":[format!("udp://{}#peer",dns.local_addr().unwrap())]}});
    let core = Core::start_with(
        &yaml.to_string(),
        json!({"tunFd":host.as_raw_fd(),"tunFraming":"utun"}),
    );
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    peer.send(&tun::packet(
        origin.local_addr().unwrap(),
        17,
        (0, 0, 0),
        b"tun-udp",
    ))
    .unwrap();
    let mut bytes = [0; 1500];
    let (n, source) = origin.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"tun-udp");
    origin.send_to(b"tun-reply", source).unwrap();
    assert_eq!(&tun::receive(&peer, 17)[28..], b"tun-reply");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = listener.local_addr().unwrap();
    peer.send(&tun::packet(target, 6, (1, 0, 2), &[])).unwrap();
    let syn_ack = tun::receive(&peer, 6);
    assert_eq!(syn_ack[33] & 0x12, 0x12);
    let seq = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap()).wrapping_add(1);
    peer.send(&tun::packet(target, 6, (2, seq, 0x18), b"tun-tcp"))
        .unwrap();
    let mut remote = accept_until(&listener);
    remote.read_exact(&mut bytes[..7]).unwrap();
    assert_eq!(&bytes[..7], b"tun-tcp");
    remote.write_all(b"tun-tcp-reply").unwrap();
    let mut received = Vec::new();
    while received.len() < 13 {
        let packet = tun::receive(&peer, 6);
        let offset = 20 + usize::from(packet[32] >> 4) * 4;
        received.extend_from_slice(&packet[offset..]);
    }
    assert_eq!(received, b"tun-tcp-reply");
    // Synthetic DNS A question through the TUN DNS interception path. No host
    // resolver, route, firewall or network service is modified.
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x07invalid\x00\x00\x01\x00\x01";
    peer.send(&tun::packet(
        "198.18.0.1:53".parse().unwrap(),
        17,
        (0, 0, 0),
        query,
    ))
    .unwrap();
    let (n, source) = dns.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[12..n], &query[12..]);
    let mut response = bytes[..n].to_vec();
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    response[6..8].copy_from_slice(&[0, 1]);
    response.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01");
    dns.send_to(&response, source).unwrap();
    let response = tun::receive(&peer, 17);
    assert_eq!(&response[28..30], &query[..2]);
    assert!(response.ends_with(&[192, 0, 2, 1]));
    let traffic = tun::traffic(controller);
    assert!(traffic["upTotal"].as_u64().unwrap() > 0);
    assert!(traffic["downTotal"].as_u64().unwrap() > 0);
    core.stop();
    assert_eq!(remote.read(&mut [0; 1]).unwrap(), 0);
    assert!(unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK != 0);
    drop(TcpListener::bind(controller).unwrap());
}
