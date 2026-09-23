//! Actual process interop through public YAML + Invoke, not a test-only dispatcher.
//! Run `bash tests/run_mihomo_interop.sh`; use loopback or an owned host-only network.
#![cfg(all(
    feature = "ffi",
    feature = "inbound-http",
    feature = "inbound-socks5",
    feature = "outbound-socks5"
))]

use serde_json::{Value, json};
use std::{
    env,
    ffi::{CStr, CString},
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const BASIC: &str = "Basic Zml4dHVyZTpwYXNzd29yZA==";

fn peer_ip(index: usize) -> Ipv4Addr {
    env::var("VCORE_MIHOMO_PEER_HOSTS").map_or(Ipv4Addr::LOCALHOST, |value| {
        let hosts: Vec<Ipv4Addr> = serde_json::from_str(&value).unwrap();
        hosts[index]
    })
}

fn origin_address(ipv6: bool) -> SocketAddr {
    let variable = if ipv6 {
        "VCORE_MIHOMO_ORIGIN_V6"
    } else {
        "VCORE_MIHOMO_ORIGIN_V4"
    };
    let fallback = if ipv6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(
        env::var(variable).map_or(fallback, |value| value.parse().unwrap()),
        0,
    )
}

#[path = "mihomo/combinations.rs"]
mod combinations;
#[path = "mihomo/eih.rs"]
mod eih;
#[path = "mihomo/groups.rs"]
mod groups;
#[path = "mihomo/host.rs"]
mod host;
#[path = "mihomo/soak.rs"]
mod soak;
#[path = "mihomo/sockets.rs"]
mod sockets;
#[path = "mihomo/ss_lifecycle.rs"]
mod ss_lifecycle;
use sockets::GuardedUdpSocket as UdpSocket;
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "mihomo/tun.rs"]
mod tun;

fn accept_until(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return buffered(stream).into_inner(),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    }
}

fn invoke(method: &str, instance: Option<&str>, payload: Value) -> Value {
    let result = invoke_response(method, instance, payload);
    assert_eq!(
        result["success"], true,
        "Invoke {method}: {}",
        result["error"]
    );
    result["data"].clone()
}

fn invoke_response(method: &str, instance: Option<&str>, payload: Value) -> Value {
    let mut message =
        json!({"apiVersion": vcore::INVOKE_API_VERSION, "method": method, "payload": payload});
    if let Some(instance) = instance {
        message["instanceId"] = json!(instance);
    }
    let input = CString::new(message.to_string()).unwrap();
    // SAFETY: the input remains a live NUL-terminated allocation for this call.
    let output = unsafe { vcore::ffi::VCoreInvoke(input.as_ptr()) };
    assert!(!output.is_null());
    // SAFETY: Invoke returns a live NUL-terminated allocation, freed once below.
    let bytes = unsafe { CStr::from_ptr(output) }.to_bytes().to_vec();
    // SAFETY: output came from Invoke and has not yet been freed.
    unsafe { vcore::ffi::VCoreFree(output) };
    serde_json::from_slice(&bytes).unwrap()
}

struct Core(Option<String>);

impl Core {
    fn start(yaml: &str) -> Self {
        Self::start_with(yaml, json!({}))
    }
    fn start_with(yaml: &str, payload: Value) -> Self {
        invoke("validateConfig", None, json!({"configYaml": yaml}));
        let id = invoke("createInstance", None, json!({}))["instanceId"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner = Self(Some(id));
        invoke("prepare", owner.0.as_deref(), json!({"configYaml": yaml}));
        invoke("start", owner.0.as_deref(), payload);
        owner
    }
    fn stop(mut self) {
        let id = self.0.take().unwrap();
        cleanup(id);
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        if let Some(id) = self.0.take() {
            // Exercise the same cleanup on failed assertions without double panic.
            let _ = std::panic::catch_unwind(|| {
                cleanup(id);
            });
        }
    }
}

fn cleanup(id: String) {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            invoke("stop", Some(&id), json!({}));
            invoke("destroyInstance", Some(&id), json!({}));
        });
        let _ = sender.send(result);
    });
    let result = receiver
        .recv_timeout(IO_TIMEOUT)
        .expect("Invoke cleanup exceeded 5-second watchdog (FAIL)");
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Forward,
    Chunked,
    Connect,
    Upgrade,
}

struct Origin {
    address: SocketAddr,
    task: Option<JoinHandle<()>>,
}

impl Origin {
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let task = thread::spawn(move || {
            let deadline = Instant::now() + IO_TIMEOUT;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("origin accept: {error}"),
                }
            };
            let mut peer = buffered(stream);
            let request = head(&mut peer);
            assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
            assert!(!request.to_ascii_lowercase().contains("x-vcore-"));
            assert!(request.starts_with(if matches!(mode, Mode::Chunked) {
                "POST /probe "
            } else {
                "GET /probe "
            }));
            if matches!(mode, Mode::Upgrade) {
                peer.get_mut().write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello").unwrap();
                exact(&mut peer, b"echo");
                peer.get_mut().write_all(b"echo").unwrap();
            } else if matches!(mode, Mode::Chunked) {
                // Independent framing oracle accepts a client's legal chunk sizes.
                let mut total = Vec::new();
                loop {
                    let mut line = String::new();
                    peer.read_line(&mut line).unwrap();
                    let size =
                        usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
                    if size == 0 {
                        loop {
                            line.clear();
                            peer.read_line(&mut line).unwrap();
                            if line == "\r\n" {
                                break;
                            }
                        }
                        break;
                    }
                    assert!(size <= 1024);
                    let mut body = vec![0; size];
                    peer.read_exact(&mut body).unwrap();
                    total.extend_from_slice(&body);
                    exact(&mut peer, b"\r\n");
                }
                assert_eq!(total, b"ping");
                peer.get_mut()
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
                    )
                    .unwrap();
            } else {
                peer.get_mut()
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
                    )
                    .unwrap();
            }
        });
        Self {
            address,
            task: Some(task),
        }
    }
    fn finish(mut self) {
        self.task.take().unwrap().join().unwrap();
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn buffered(stream: TcpStream) -> BufReader<TcpStream> {
    // Darwin can inherit O_NONBLOCK from the listening socket; this fixture uses
    // blocking I/O with finite OS timeouts after the bounded accept loop.
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    BufReader::new(stream)
}

fn head(peer: &mut BufReader<TcpStream>) -> String {
    let mut result = String::new();
    loop {
        let mut line = String::new();
        assert!(
            peer.read_line(&mut line).unwrap() > 0,
            "truncated response: {result}"
        );
        result.push_str(&line);
        assert!(result.len() <= 32768);
        if line == "\r\n" {
            return result;
        }
    }
}

fn exact(peer: &mut BufReader<TcpStream>, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
}

fn probe(proxy: SocketAddr, authenticated: bool, mode: Mode) {
    let origin = Origin::start(mode);
    let target = origin.address;
    let mut peer = buffered(TcpStream::connect_timeout(&proxy, IO_TIMEOUT).unwrap());
    let auth = if authenticated {
        format!("Proxy-Authorization: {BASIC}\r\n")
    } else {
        String::new()
    };
    if matches!(mode, Mode::Connect) {
        // The inner request is sent before the CONNECT response to exercise read-ahead.
        peer.get_mut().write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\nGET /probe HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        assert!(head(&mut peer).starts_with("HTTP/1.1 200"));
    } else {
        let (method, fields, body) = match mode {
            Mode::Chunked => (
                "POST",
                "Transfer-Encoding: chunked\r\nConnection: close\r\n",
                "4\r\nping\r\n0\r\n\r\n",
            ),
            Mode::Upgrade => ("GET", "Connection: Upgrade\r\nUpgrade: websocket\r\n", ""),
            _ => ("GET", "Connection: close\r\n", ""),
        };
        peer.get_mut().write_all(format!("{method} http://{target}/probe HTTP/1.1\r\nHost: {target}\r\n{auth}{fields}\r\n{body}").as_bytes()).unwrap();
    }
    if matches!(mode, Mode::Upgrade) {
        assert!(head(&mut peer).starts_with("HTTP/1.1 101"));
        exact(&mut peer, b"hello");
        peer.get_mut().write_all(b"echo").unwrap();
        exact(&mut peer, b"echo");
    } else {
        assert!(head(&mut peer).starts_with("HTTP/1.1 200"));
        exact(&mut peer, b"pong");
    }
    drop(peer);
    origin.finish();
}

fn port(variable: &str) -> u16 {
    env::var(variable)
        .expect("run tests/run_mihomo_interop.sh")
        .parse()
        .unwrap()
}

#[test]
#[ignore = "requires managed mihomo processes; run tests/run_mihomo_interop.sh"]
fn public_client_inbounds_interoperate_with_mihomo_in_both_directions() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "N1-REGRESSION",
        "public_client_inbounds_interoperate_with_mihomo_in_both_directions",
    );
    let upstream = port("VCORE_MIHOMO_UPSTREAM");
    let upstream_host = peer_ip(0);
    let downstream = port("VCORE_MIHOMO_DOWNSTREAM");
    let core_port = port("VCORE_MIHOMO_HTTP_PORT");
    let directory = tempfile::tempdir().unwrap();
    invoke("initialize", None, json!({"dataDir": directory.path()}));
    for via_upstream in [true, false] {
        let route = if via_upstream { "mihomo" } else { "local" };
        let yaml = format!(
            "port: {core_port}\nipv6: false\nauthentication: [fixture:password]\nproxies:\n  - {{name: mihomo, type: socks5, server: {upstream_host}, port: {upstream}, username: fixture, password: password}}\nproxy-groups:\n  - {{name: local, type: select, proxies: [DIRECT]}}\nrules: ['MATCH,{route}']\n"
        );
        let core = Core::start(&yaml);
        let proxy = SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            if via_upstream { core_port } else { downstream },
        ));
        for mode in [Mode::Forward, Mode::Chunked, Mode::Connect, Mode::Upgrade] {
            probe(proxy, via_upstream, mode);
            println!(
                "PASS {mode:?}: {}",
                if via_upstream {
                    "VCore HTTP -> VCore SOCKS5 -> mihomo -> origin"
                } else {
                    "mihomo HTTP -> mihomo HTTP outbound -> VCore CONNECT -> origin"
                }
            );
        }
        core.stop();
        drop(TcpListener::bind((Ipv4Addr::LOCALHOST, core_port)).unwrap());
    }
    let socks_port = port("VCORE_MIHOMO_SOCKS_PORT");
    let downstream = port("VCORE_MIHOMO_SOCKS_DOWNSTREAM");
    for via_upstream in [true, false] {
        let route = if via_upstream { "mihomo" } else { "local" };
        let yaml = format!(
            "socks-port: {socks_port}\nipv6: true\nauthentication: [fixture:password]\nproxies:\n  - {{name: mihomo, type: socks5, server: {upstream_host}, port: {upstream}, username: fixture, password: password, udp: true}}\nproxy-groups:\n  - {{name: local, type: select, proxies: [DIRECT]}}\nrules: ['MATCH,{route}']\n"
        );
        let core = Core::start(&yaml);
        let proxy = SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            if via_upstream { socks_port } else { downstream },
        ));
        for ipv6 in [false, true] {
            probe_socks_tcp(proxy, via_upstream, ipv6);
            probe_socks_udp(proxy, via_upstream, ipv6);
            println!(
                "PASS SOCKS5 TCP + UDP (IPv6={ipv6}): {}",
                if via_upstream {
                    "VCore SOCKS5 -> mihomo -> origin"
                } else {
                    "mihomo SOCKS5 -> VCore SOCKS5 -> origin"
                }
            );
        }
        core.stop();
        drop(TcpListener::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
    }
    probe_anytls(socks_port);
    probe_shadowsocks(socks_port);
    if let Ok(fixtures) = env::var("VCORE_MIHOMO_CHAIN_FIXTURES") {
        let fixtures = serde_json::from_str(&fixtures).unwrap();
        combinations::probe(core_port, socks_port, &fixtures);
        groups::probe(core_port, socks_port, &fixtures);
        host::probe(core_port, socks_port, &fixtures);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        tun::probe(core_port, socks_port, &fixtures);
        for round in 0..25 {
            for node in fixtures["last"].as_array().unwrap() {
                combinations::close_peer_connections(&fixtures);
                ss_lifecycle::probe(socks_port, std::slice::from_ref(node));
            }
            println!(
                "PASS lifecycle round {round}: four protocols, active Stop + failed-start + measurement"
            );
        }
        combinations::close_peer_connections(&fixtures);
        #[cfg(target_os = "macos")]
        soak::recovery_probe(core_port, socks_port, &fixtures);
        let seconds = env::var("VCORE_MIHOMO_SOAK_SECONDS")
            .unwrap()
            .parse()
            .unwrap();
        if seconds > 0 {
            soak::probe(core_port, socks_port, &fixtures, seconds);
        }
    }
}

fn probe_shadowsocks(socks_port: u16) {
    let fixtures: Vec<Value> =
        serde_json::from_str(&env::var("VCORE_MIHOMO_SS_FIXTURES").unwrap()).unwrap();
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    for fixture in &fixtures {
        let mut node = fixture.clone();
        node["name"] = json!("peer");
        node["type"] = json!("ss");
        node["server"] = json!(peer_ip(3));
        node["udp"] = json!(true);
        let config = json!({"socks-port": socks_port, "proxies": [node], "rules": ["MATCH,peer"]});
        let core = Core::start(&config.to_string());
        for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
            probe_socks_tcp_target(proxy, false, ipv6, domain, false);
            println!(
                "PASS SS {} TCP: IPv6={ipv6}, domain={domain}",
                fixture["cipher"].as_str().unwrap()
            );
            probe_socks_udp_target(proxy, false, ipv6, domain);
            println!(
                "PASS SS {} UDP: IPv6={ipv6}, domain={domain}",
                fixture["cipher"].as_str().unwrap()
            );
        }
        probe_socks_tcp_target(proxy, false, false, false, true);
        core.stop();
        drop(TcpListener::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        println!(
            "PASS SS {}: TCP + UDP, IPv4 + IPv6 + domain, server-first",
            fixture["cipher"].as_str().unwrap()
        );
    }
    let upstream = port("VCORE_MIHOMO_UPSTREAM");
    for nested in [false, true] {
        for direct in [false, true] {
            if !nested && direct {
                continue; // DIRECT is exercised as a group leaf, not a duplicate hop.
            }
            let mut node = fixtures[0].clone();
            node["name"] = json!("peer");
            node["type"] = json!("ss");
            node["server"] = json!(if direct {
                peer_ip(3).to_string()
            } else {
                "vcore-peer.test".to_owned()
            });
            node["udp"] = json!(true);
            node["dialer-proxy"] = json!(if nested { "outer" } else { "hop" });
            let hop = json!({"name":"hop", "type":"socks5", "server":peer_ip(0), "port":upstream, "username":"fixture", "password":"password", "udp":true});
            let leaf = if direct { "DIRECT" } else { "hop" };
            let config = json!({
                "socks-port":socks_port, "proxies":[node, hop],
                "proxy-groups":[{"name":"outer", "type":"select", "proxies":["inner"]}, {"name":"inner", "type":"select", "proxies":[leaf]}],
                "rules":["MATCH,peer"]
            });
            let core = Core::start(&config.to_string());
            probe_socks_tcp(proxy, false, false);
            probe_socks_udp(proxy, false, false);
            core.stop();
            println!(
                "PASS SS chained TCP + UDP: nested={nested}, direct={}",
                nested && direct
            );
        }
    }
    eih::probe(socks_port, &fixtures);
    ss_lifecycle::probe(socks_port, &fixtures);
}

fn probe_anytls(socks_port: u16) {
    let peer_port = port("VCORE_MIHOMO_ANYTLS_PORT");
    let peer_host = peer_ip(0);
    let fingerprint = env::var("VCORE_MIHOMO_ANYTLS_PIN").unwrap();
    for fields in [
        "skip-cert-verify: true".to_owned(),
        format!("fingerprint: '{fingerprint}'"),
        format!("fingerprint: '{fingerprint}', skip-cert-verify: true, alpn: [h2, http/1.1]"),
    ] {
        let node = format!(
            "{{name: peer, type: anytls, server: {peer_host}, port: {peer_port}, password: password, sni: fixture.invalid, udp: true, {fields}}}"
        );
        let yaml = format!(
            "socks-port: {socks_port}\nauthentication: [fixture:password]\nproxies: [{node}]\nrules: ['MATCH,peer']\n"
        );
        let core = Core::start(&yaml);
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
        for ipv6 in [false, true] {
            probe_socks_tcp(proxy, true, ipv6);
            probe_socks_udp(proxy, true, ipv6);
        }
        core.stop();
        drop(TcpListener::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, socks_port)).unwrap());
        println!("PASS AnyTLS public config: TCP + UoT v2, IPv4 + IPv6");
        // Measurement constructs a private graph through the same normalized
        // fields and must finish its pool/reader tasks before returning.
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let task = thread::spawn(move || {
            let deadline = Instant::now() + IO_TIMEOUT;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("measurement origin accept: {error}"),
                }
            };
            let mut stream = buffered(stream);
            assert!(head(&mut stream).starts_with("HEAD /"));
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let data = invoke(
            "measureDelay",
            None,
            json!({"configYamls": [format!("proxies: [{node}]")], "timeout": 5, "url": format!("http://{address}/")}),
        );
        task.join().unwrap();
        assert_eq!(data["results"][0]["success"], true);
    }
    for fields in [
        "".to_owned(),
        format!(
            ", fingerprint: '{}', skip-cert-verify: true",
            "00".repeat(32)
        ),
    ] {
        let yaml = format!(
            "socks-port: {socks_port}\nproxies: [{{name: peer, type: anytls, server: {peer_host}, port: {peer_port}, password: password, sni: fixture.invalid{fields}}}]\nrules: ['MATCH,peer']\n"
        );
        let core = Core::start(&yaml);
        let mut client = socks_login(SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port)), false);
        client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 9]).unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_ne!(reply[1], 0, "untrusted or wrong pin must not CONNECT");
        core.stop();
    }
    println!(
        "PASS AnyTLS public config rejects untrusted certificate and incorrect pin even with skip-cert-verify"
    );
}

fn socks_login(proxy: SocketAddr, authenticated: bool) -> TcpStream {
    let mut stream = buffered(TcpStream::connect_timeout(&proxy, IO_TIMEOUT).unwrap()).into_inner();
    let method = if authenticated { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, method]);
    if authenticated {
        stream.write_all(b"\x01\x07fixture\x08password").unwrap();
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [1, 0]);
    }
    stream
}

fn socks_address(address: SocketAddr) -> Vec<u8> {
    let mut bytes = match address.ip() {
        std::net::IpAddr::V4(ip) => {
            let mut b = vec![1];
            b.extend_from_slice(&ip.octets());
            b
        }
        std::net::IpAddr::V6(ip) => {
            let mut b = vec![4];
            b.extend_from_slice(&ip.octets());
            b
        }
    };
    bytes.extend_from_slice(&address.port().to_be_bytes());
    bytes
}

fn socks_reply(stream: &mut TcpStream) -> SocketAddr {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[..3], &[5, 0, 0]);
    let ip = match header[3] {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).unwrap();
            std::net::IpAddr::from(b)
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).unwrap();
            std::net::IpAddr::from(b)
        }
        _ => panic!("expected literal SOCKS5 reply"),
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port).unwrap();
    SocketAddr::new(ip, u16::from_be_bytes(port))
}

fn probe_socks_tcp(proxy: SocketAddr, authenticated: bool, ipv6: bool) {
    probe_socks_tcp_target(proxy, authenticated, ipv6, false, false);
}

fn fixture_address(target: SocketAddr, domain: bool) -> Vec<u8> {
    if !domain {
        return socks_address(target);
    }
    let name = b"vcore-fixture.test";
    let mut address = vec![3, name.len() as u8];
    address.extend_from_slice(name);
    address.extend_from_slice(&target.port().to_be_bytes());
    address
}

fn probe_socks_tcp_target(
    proxy: SocketAddr,
    authenticated: bool,
    ipv6: bool,
    domain: bool,
    server_first: bool,
) {
    let listener = TcpListener::bind(origin_address(ipv6)).unwrap();
    let target = listener.local_addr().unwrap();
    let mut client = socks_login(proxy, authenticated);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&fixture_address(target, domain));
    if !server_first {
        request.extend_from_slice(b"early-data");
    }
    client.write_all(&request).unwrap();
    socks_reply(&mut client);
    // A successful SOCKS reply can precede the ultimate server's accept in
    // mihomo; bound the accept independently and always join/drop its owner.
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + IO_TIMEOUT;
    let (remote, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("SOCKS origin accept: {error}"),
        }
    };
    let mut remote = buffered(remote);
    if server_first {
        remote.get_mut().write_all(b"hello").unwrap();
        let mut greeting = [0; 5];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, b"hello");
        client.write_all(b"early-data").unwrap();
    }
    exact(&mut remote, b"early-data");
    remote.get_mut().write_all(b"reply-data").unwrap();
    exact(&mut buffered(client), b"reply-data");
}

fn probe_socks_udp(proxy: SocketAddr, authenticated: bool, ipv6: bool) {
    probe_socks_udp_target(proxy, authenticated, ipv6, false);
}

fn probe_socks_udp_target(proxy: SocketAddr, authenticated: bool, ipv6: bool, domain: bool) {
    let origin = UdpSocket::bind(origin_address(ipv6)).unwrap();
    origin.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    origin.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let target = origin.local_addr().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let mut control = socks_login(proxy, authenticated);
    // Port-zero learning exercises ordinary SOCKS clients, including mihomo.
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let relay = socks_reply(&mut control);
    let mut request = vec![0, 0, 0];
    request.extend_from_slice(&fixture_address(target, domain));
    request.extend_from_slice(b"udp-wire");
    socket.send_to(&request, relay).unwrap();
    let mut buffer = [0; 512];
    let (length, peer) = origin
        .recv_from(&mut buffer)
        .expect("mihomo did not deliver the UDP request to the fixture origin");
    assert_eq!(&buffer[..length], b"udp-wire");
    origin.send_to(&buffer[..length], peer).unwrap();
    let (length, from) = socket.recv_from(&mut buffer).unwrap_or_else(|error| {
        panic!(
            "fixture UDP response: client={}, relay={relay}, origin={target}, origin_observed_peer={peer}: {error}",
            socket.local_addr().unwrap(),
        )
    });
    assert_eq!(
        from,
        relay,
        "fixture UDP response: client={}, origin={target}, origin_observed_peer={peer}, length={length}",
        socket.local_addr().unwrap(),
    );
    let mut expected = vec![0, 0, 0];
    expected.extend_from_slice(&socks_address(target));
    expected.extend_from_slice(b"udp-wire");
    assert_eq!(&buffer[..length], expected);
    // The control socket remains owned until all UDP replies are validated.
    drop(control);
}
