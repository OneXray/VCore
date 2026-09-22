//! Host-fd/netstack interop only: no real interface, route or system proxy.
use super::*;
use std::os::{fd::AsRawFd as _, unix::net::UnixDatagram};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet(
    target: SocketAddr,
    protocol: u8,
    seq_ack_flags: (u32, u32, u8),
    payload: &[u8],
) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 fixture");
    };
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let mut segment = vec![0; if protocol == 6 { 20 } else { 8 }];
    segment[..2].copy_from_slice(&12000_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&target.port().to_be_bytes());
    if protocol == 6 {
        segment[4..8].copy_from_slice(&seq_ack_flags.0.to_be_bytes());
        segment[8..12].copy_from_slice(&seq_ack_flags.1.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = seq_ack_flags.2;
        segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    } else {
        segment[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    segment.extend_from_slice(payload);
    let mut pseudo = source.octets().to_vec();
    pseudo.extend_from_slice(&target.ip().octets());
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let offset = if protocol == 6 { 16 } else { 6 };
    let value = checksum(&pseudo);
    segment[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + segment.len()) as u16).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&source.octets());
    ip[16..20].copy_from_slice(&target.ip().octets());
    let value = checksum(&ip);
    ip[10..12].copy_from_slice(&value.to_be_bytes());
    ip.extend_from_slice(&segment);
    let mut framed = 2_u32.to_be_bytes().to_vec(); // Darwin AF_INET PI header.
    framed.extend_from_slice(&ip);
    framed
}

fn receive(peer: &UnixDatagram, protocol: u8) -> Vec<u8> {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "TUN packet deadline");
        let mut bytes = [0; 1504];
        let size = peer.recv(&mut bytes).unwrap();
        assert!(size >= 24);
        assert_eq!(&bytes[..4], 2_u32.to_be_bytes());
        let ip = &bytes[4..size];
        assert_eq!(checksum(&ip[..20]), 0);
        if ip[9] == protocol {
            return ip.to_vec();
        }
    }
}

fn traffic(controller: SocketAddr) -> Value {
    let mut stream = buffered(TcpStream::connect_timeout(&controller, IO_TIMEOUT).unwrap());
    stream.get_mut().write_all(b"GET /traffic HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-controller-only\r\nConnection: close\r\n\r\n").unwrap();
    assert!(head(&mut stream).starts_with("HTTP/1.1 200"));
    let mut body = Vec::new();
    stream.take(1024).read_to_end(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

pub(super) fn probe(controller_port: u16, socks_port: u16, fixtures: &Value) {
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, controller_port));
    let IpAddr::V4(origin_ip) = origin_address(false).ip() else {
        panic!("IPv4 fixture origin");
    };
    for fixture in fixtures["last"].as_array().unwrap() {
        combinations::close_peer_connections(fixtures);
        let baseline = ss_lifecycle::open_fd_count();
        let mut node = fixture.clone();
        node["name"] = json!("peer");
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        peer.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let config = json!({"tun":{"enable":true},"socks-port":socks_port,"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":[node],"proxy-groups":[{"name":"inner","type":"select","proxies":["peer","REJECT"]}],"rules":["MATCH,inner"]});
        let core = Core::start_with(
            &config.to_string(),
            json!({"tunFd":host.as_raw_fd(),"tunFraming":"utun"}),
        );
        groups::select(controller, "REJECT");
        groups::select(controller, "peer");
        // Business-proxy traffic must not be included in TUN counters.
        probe_socks_tcp(
            SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port)),
            false,
            false,
        );
        probe_socks_udp(
            SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port)),
            false,
            false,
        );
        let before = traffic(controller);
        assert_eq!(before, json!({"up":0,"down":0,"upTotal":0,"downTotal":0}));
        let origin = UdpSocket::bind(origin_address(false)).unwrap();
        origin.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        origin.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let target = origin.local_addr().unwrap();
        peer.send(&packet(target, 17, (0, 0, 0), b"tun-udp-forward"))
            .unwrap();
        let mut bytes = [0; 128];
        let (length, source) = origin.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..length], b"tun-udp-forward");
        origin.send_to(b"tun-udp-reply", source).unwrap();
        let response = receive(&peer, 17);
        assert_eq!(&response[12..16], origin_ip.octets());
        assert_eq!(&response[16..20], [192, 0, 2, 10]);
        assert_eq!(&response[20..22], target.port().to_be_bytes());
        assert_eq!(&response[22..24], 12000_u16.to_be_bytes());
        assert_eq!(&response[28..], b"tun-udp-reply");
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = listener.local_addr().unwrap();
        peer.send(&packet(target, 6, (1, 0, 2), &[])).unwrap();
        let syn_ack = receive(&peer, 6);
        assert_eq!(syn_ack[33] & 0x12, 0x12);
        let server_seq = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap()).wrapping_add(1);
        peer.send(&packet(
            target,
            6,
            (2, server_seq, 0x18),
            b"tun-tcp-forward",
        ))
        .unwrap();
        let mut remote = accept_until(&listener);
        remote.read_exact(&mut bytes[..15]).unwrap();
        assert_eq!(&bytes[..15], b"tun-tcp-forward");
        remote.write_all(b"tun-tcp-reply").unwrap();
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut received = Vec::new();
        while received.len() < 13 {
            assert!(Instant::now() < deadline, "TUN TCP payload deadline");
            let response = receive(&peer, 6);
            assert_eq!(&response[12..16], origin_ip.octets());
            assert_eq!(&response[16..20], [192, 0, 2, 10]);
            assert_eq!(&response[20..22], target.port().to_be_bytes());
            let offset = 20 + usize::from(response[32] >> 4) * 4;
            received.extend_from_slice(&response[offset..]);
        }
        assert_eq!(received, b"tun-tcp-reply");
        let totals = traffic(controller);
        assert!(totals["upTotal"].as_u64().unwrap() > 0);
        assert!(totals["downTotal"].as_u64().unwrap() > 0);
        core.stop();
        assert_eq!(remote.read(&mut [0; 1]).unwrap(), 0);
        // Caller-owned fd survives Stop and still has its original flags.
        assert!(unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK != 0);
        drop((host, peer, origin, listener, remote));
        drop(TcpListener::bind(controller).unwrap());
        drop(TcpListener::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        ss_lifecycle::assert_fd_returned(baseline);
        println!(
            "PASS I01/I04/I05 synthetic utun fd -> {} TCP/UDP; proxy traffic excluded, fd ownership and Stop",
            fixture["type"].as_str().unwrap()
        );
    }
    combinations::close_peer_connections(fixtures);
}
