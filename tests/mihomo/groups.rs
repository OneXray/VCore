//! Public Controller selection against real, separately owned mihomo hops.
use super::*;

pub(super) struct TcpFlow {
    client: TcpStream,
    remote: TcpStream,
}

impl TcpFlow {
    pub(super) fn open(proxy: SocketAddr) -> Self {
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = socks_login(proxy, false);
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(&socks_address(listener.local_addr().unwrap()));
        request.extend_from_slice(b"ready");
        client.write_all(&request).unwrap();
        socks_reply(&mut client);
        let mut remote = accept_until(&listener);
        let mut payload = [0; 5];
        remote.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ready");
        remote.write_all(&payload).unwrap();
        client.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ready");
        Self { client, remote }
    }

    pub(super) fn exchange(&mut self, marker: u8) {
        let data = [marker; 257];
        self.client.write_all(&data).unwrap();
        let mut received = [0; 257];
        self.remote.read_exact(&mut received).unwrap();
        assert_eq!(received, data);
        received.reverse();
        self.remote.write_all(&received).unwrap();
        self.client.read_exact(&mut received).unwrap();
        assert_eq!(received, data);
    }

    fn finish(mut self) {
        self.client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(self.remote.read(&mut [0; 1]).unwrap(), 0);
    }

    pub(super) fn assert_closed(&mut self) {
        match self.client.read(&mut [0; 1]) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("closed peer left a live TCP flow: {other:?}"),
        }
    }
}

pub(super) struct UdpFlow {
    _control: TcpStream,
    client: UdpSocket,
    remote: UdpSocket,
    relay: SocketAddr,
}

impl UdpFlow {
    pub(super) fn open(proxy: SocketAddr) -> Self {
        let remote = UdpSocket::bind(origin_address(false)).unwrap();
        remote.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        remote.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        client.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let mut control = socks_login(proxy, false);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let relay = socks_reply(&mut control);
        Self {
            _control: control,
            client,
            remote,
            relay,
        }
    }

    pub(super) fn exchange(&mut self, marker: u8) {
        let data = [marker; 257];
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&socks_address(self.remote.local_addr().unwrap()));
        packet.extend_from_slice(&data);
        self.client.send_to(&packet, self.relay).unwrap();
        let mut bytes = [0; 512];
        let (length, peer) = self.remote.recv_from(&mut bytes).unwrap_or_else(|error| {
            sockets::report_udp_sockets();
            panic!(
                "fixture UDP request: marker={marker}, client={}, relay={}, origin={}: {error}",
                self.client.local_addr().unwrap(),
                self.relay,
                self.remote.local_addr().unwrap(),
            )
        });
        assert_eq!(&bytes[..length], data);
        self.remote.send_to(&bytes[..length], peer).unwrap();
        let (length, source) = self.client.recv_from(&mut bytes).unwrap_or_else(|error| {
            sockets::report_udp_sockets();
            panic!(
                "fixture UDP response: marker={marker}, client={}, relay={}, origin={}, origin_observed_peer={peer}: {error}",
                self.client.local_addr().unwrap(),
                self.relay,
                self.remote.local_addr().unwrap(),
            )
        });
        assert_eq!(
            source,
            self.relay,
            "fixture UDP response: client={}, origin={}, origin_observed_peer={peer}, length={length}",
            self.client.local_addr().unwrap(),
            self.remote.local_addr().unwrap(),
        );
        assert_eq!(&bytes[..length], packet);
    }
}

pub(super) fn select(controller: SocketAddr, name: &str) {
    let body = json!({"name":name}).to_string();
    let mut client = buffered(TcpStream::connect_timeout(&controller, IO_TIMEOUT).unwrap());
    write!(client.get_mut(), "PUT /proxies/inner HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-controller-only\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    assert!(head(&mut client).starts_with("HTTP/1.1 204"));
}

pub(super) fn probe(controller_port: u16, socks_port: u16, fixtures: &Value) {
    combinations::close_peer_connections(fixtures);
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, controller_port));
    let mut hop = fixtures["first"][0].clone();
    hop["name"] = json!("hop");
    let mut node = fixtures["last"][1].clone();
    node["name"] = json!("peer");
    node["dialer-proxy"] = json!("outer");
    let config = json!({"socks-port":socks_port,"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":[node,hop],"proxy-groups":[{"name":"outer","type":"select","proxies":["inner"]},{"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}],"rules":["MATCH,peer"]});
    let core = Core::start(&config.to_string());
    let mut first = TcpFlow::open(proxy);
    let mut old_udp = UdpFlow::open(proxy);
    old_udp.exchange(1);
    assert_eq!(
        combinations::peer_connection_count(fixtures, 0),
        2,
        "the first mihomo hop must own both transports"
    );
    select(controller, "REJECT");
    first.exchange(2);
    old_udp.exchange(3);
    // No idle session exists: a new physical connection must honor REJECT.
    let origin = TcpListener::bind(origin_address(false)).unwrap();
    origin.set_nonblocking(true).unwrap();
    let mut denied = socks_login(proxy, false);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&socks_address(origin.local_addr().unwrap()));
    denied.write_all(&request).unwrap();
    let mut response = [0; 10];
    denied.read_exact(&mut response).unwrap();
    assert_ne!(
        response[1], 0,
        "fresh session must not bypass upstream REJECT"
    );
    assert_eq!(
        origin.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    first.finish();
    // FIN was delivered to the origin; the physical AnyTLS session stays on
    // its old SOCKS path. REJECT must not invalidate reuse of that transport.
    let mut reused = TcpFlow::open(proxy);
    reused.exchange(4);
    select(controller, "DIRECT");
    let mut fresh = TcpFlow::open(proxy);
    let mut new_udp = UdpFlow::open(proxy);
    fresh.exchange(5);
    new_udp.exchange(6);
    reused.exchange(7);
    old_udp.exchange(8);
    assert_eq!(
        combinations::peer_connection_count(fixtures, 0),
        2,
        "DIRECT must not create extra first-hop transports"
    );
    // Stop while all four flows remain owned by the test.
    core.stop();
    assert_eq!(reused.client.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(fresh.client.read(&mut [0; 1]).unwrap(), 0);
    drop((reused, fresh, old_udp, new_udp, denied, origin));
    drop(TcpListener::bind(proxy).unwrap());
    drop(UdpSocket::bind(proxy).unwrap());
    drop(TcpListener::bind(controller).unwrap());
    combinations::close_peer_connections(fixtures);
    println!(
        "PASS I03/I04 public nested-group switch: live TCP/UDP, REJECT, AnyTLS idle reuse, fresh DIRECT and active Stop"
    );
}
