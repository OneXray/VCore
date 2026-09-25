//! Public VMess consumer gate. Every origin/peer is owned by the container runner.
#![cfg(all(feature = "ffi", feature = "outbound-vmess", feature = "interop-test"))]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    thread,
    time::{Duration, Instant},
};
use vcore::resources::case_events::Case;
const TIMEOUT: Duration = Duration::from_secs(10);
const DOMAIN: &str = "vcore-fixture.test";

#[path = "vmess_public/runtime.rs"]
mod runtime;
#[cfg(target_os = "macos")]
#[path = "vmess_public/tun.rs"]
mod tun;

fn fixture() -> Value {
    let value: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_VMESS_AB_INPUT").expect("use isolated N3 runner"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["isolation"], "containers");
    value
}
fn initialize(f: &Value) {
    invoke("initialize", None, json!({"dataDir": f["data_dir"]}));
}
fn invoke(method: &str, id: Option<&str>, payload: Value) -> Value {
    let response = invoke_response(method, id, payload);
    assert_eq!(
        response["success"], true,
        "Invoke {method}: {}",
        response["error"]
    );
    response["data"].clone()
}
fn invoke_response(method: &str, id: Option<&str>, payload: Value) -> Value {
    let mut input =
        json!({"apiVersion":vcore::INVOKE_API_VERSION,"method":method,"payload":payload});
    if let Some(id) = id {
        input["instanceId"] = json!(id);
    }
    let input = CString::new(input.to_string()).unwrap();
    // SAFETY: NUL-terminated input lives for the call; returned allocation is freed once.
    let result = unsafe { vcore::ffi::VCoreInvoke(input.as_ptr()) };
    assert!(!result.is_null());
    let bytes = unsafe { CStr::from_ptr(result) }.to_bytes().to_vec();
    unsafe { vcore::ffi::VCoreFree(result) };
    serde_json::from_slice(&bytes).unwrap()
}
struct Core(Option<String>);
impl Core {
    fn prepare(config: &Value) -> Self {
        invoke(
            "validateConfig",
            None,
            json!({"configYaml":config.to_string()}),
        );
        let id = invoke("createInstance", None, json!({}))["instanceId"]
            .as_str()
            .unwrap()
            .to_owned();
        let core = Self(Some(id));
        invoke(
            "prepare",
            core.0.as_deref(),
            json!({"configYaml":config.to_string()}),
        );
        core
    }
    fn start(config: &Value) -> Self {
        let core = Self::prepare(config);
        invoke("start", core.0.as_deref(), json!({}));
        core
    }
    fn stop(mut self) {
        stop(self.0.take().unwrap());
    }
}
fn stop(id: String) {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            invoke("stop", Some(&id), json!({}));
            invoke("destroyInstance", Some(&id), json!({}));
        });
        tx.send(result).unwrap();
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Stop exceeds 5 seconds");
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
impl Drop for Core {
    fn drop(&mut self) {
        if let Some(id) = self.0.take() {
            let _ = std::panic::catch_unwind(|| stop(id));
        }
    }
}
fn free_port() -> u16 {
    for _ in 0..32 {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        if let (Ok(_v6), Ok(_udp), Ok(_udp6)) = (
            TcpListener::bind((Ipv6Addr::LOCALHOST, port)),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, port)),
            UdpSocket::bind((Ipv6Addr::LOCALHOST, port)),
        ) {
            return port;
        }
    }
    panic!("cannot reserve fixture port");
}
fn socket(address: SocketAddr) -> TcpStream {
    let io = TcpStream::connect_timeout(&address, TIMEOUT).unwrap();
    io.set_read_timeout(Some(TIMEOUT)).unwrap();
    io.set_write_timeout(Some(TIMEOUT)).unwrap();
    io.set_nodelay(true).unwrap();
    io
}
fn config(node: Value, port: u16) -> Value {
    json!({"socks-port":port,"ipv6":true,"proxies":[node],"rules":["MATCH,peer"]})
}
fn login(port: u16) -> TcpStream {
    let mut client = socket((Ipv4Addr::LOCALHOST, port).into());
    client.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    client
}
fn address(target: SocketAddr, domain: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if domain {
        bytes.extend([3, DOMAIN.len() as u8]);
        bytes.extend(DOMAIN.as_bytes());
    } else {
        match target.ip() {
            IpAddr::V4(ip) => {
                bytes.push(1);
                bytes.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes.push(4);
                bytes.extend(ip.octets());
            }
        }
    }
    bytes.extend(target.port().to_be_bytes());
    bytes
}
fn reply(client: &mut TcpStream) -> SocketAddr {
    let mut header = [0; 4];
    client.read_exact(&mut header).unwrap();
    assert_eq!(&header[..3], &[5, 0, 0]);
    let ip = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            client.read_exact(&mut bytes).unwrap();
            IpAddr::from(bytes)
        }
        4 => {
            let mut bytes = [0; 16];
            client.read_exact(&mut bytes).unwrap();
            IpAddr::from(bytes)
        }
        _ => panic!("SOCKS response address"),
    };
    let mut port = [0; 2];
    client.read_exact(&mut port).unwrap();
    SocketAddr::new(ip, u16::from_be_bytes(port))
}
fn connect(port: u16, target: SocketAddr, domain: bool) -> TcpStream {
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(target, domain));
    client.write_all(&request).unwrap();
    reply(&mut client);
    client
}
struct Origin {
    observer: TcpStream,
    target: SocketAddr,
}
impl Origin {
    fn new(f: &Value, mode: u8, ipv6: bool) -> Self {
        let mut observer = socket(f["origin_control"].as_str().unwrap().parse().unwrap());
        observer
            .write_all(&[mode | if ipv6 && mode >= 10 { 128 } else { 0 }])
            .unwrap();
        let mut port = [0; 2];
        observer.read_exact(&mut port).unwrap();
        let ip: IpAddr = f[if ipv6 { "origin_ipv6" } else { "origin_ipv4" }]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(!ip.is_loopback() && !ip.is_unspecified());
        Self {
            observer,
            target: SocketAddr::new(ip, u16::from_be_bytes(port)),
        }
    }
    fn marker(&mut self, expected: u8) {
        let mut byte = [0];
        self.observer.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], expected);
    }
    fn quiet(&mut self) {
        self.observer
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let error = self.observer.read(&mut [0; 1]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        self.observer.set_read_timeout(Some(TIMEOUT)).unwrap();
    }
    fn udp(&mut self, expected: &[u8]) {
        let mut header = [0; 4];
        self.observer.read_exact(&mut header).unwrap();
        assert_ne!(&header[2..], &[0, 0]);
        let length = u16::from_be_bytes([header[0], header[1]]) as usize;
        assert_eq!(length, expected.len());
        let mut bytes = vec![0; length];
        self.observer.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
}
struct Association {
    control: TcpStream,
    client: UdpSocket,
    relay: SocketAddr,
    origin: Origin,
    domain: bool,
}
impl Association {
    fn new(f: &Value, port: u16, ipv6: bool, domain: bool) -> Self {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket2::SockRef::from(&client)
            .set_send_buffer_size(65536)
            .unwrap();
        let mut control = login(port);
        let mut request = vec![5, 3, 0];
        request.extend(address(client.local_addr().unwrap(), false));
        control.write_all(&request).unwrap();
        let relay = reply(&mut control);
        Self {
            control,
            client,
            relay,
            origin: Origin::new(f, if ipv6 { 6 } else { 4 }, ipv6),
            domain,
        }
    }
    fn packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 0, 0];
        packet.extend(address(self.origin.target, self.domain));
        packet.extend(payload);
        packet
    }
    fn exchange(&mut self, payload: &[u8]) {
        let packet = self.packet(payload);
        assert_eq!(
            self.client.send_to(&packet, self.relay).unwrap(),
            packet.len()
        );
        self.origin.udp(payload);
        let mut bytes = [0; 20000];
        let (size, source) = self.client.recv_from(&mut bytes).unwrap();
        assert_eq!(source, self.relay);
        assert_eq!(&bytes[..3], &[0, 0, 0]);
        let offset = match bytes[3] {
            1 => 8,
            4 => 20,
            3 => 5 + bytes[4] as usize,
            _ => panic!("UDP response type"),
        };
        assert_eq!(
            &bytes[offset..offset + 2],
            &self.origin.target.port().to_be_bytes()
        );
        let literal = address(self.origin.target, false);
        let named = address(self.origin.target, self.domain);
        assert!(bytes[3..offset + 2] == literal || bytes[3..offset + 2] == named);
        assert_eq!(&bytes[offset + 2..size], payload);
    }
}
fn echo(port: u16, f: &Value) {
    let mut origin = Origin::new(f, 13, false);
    let mut client = connect(port, origin.target, false);
    client.write_all(b"client-first").unwrap();
    let mut bytes = [0; 12];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"client-first");
    origin.marker(b'A');
    drop(client);
    origin.marker(b'D');
}
fn bulk(port: u16, f: &Value, ipv6: bool, domain: bool) {
    let _case = Case::new("N3-BASE", "tcp_10mib_both_directions");
    let mut origin = Origin::new(f, 10, ipv6);
    let mut client = connect(port, origin.target, domain);
    let mut hello = [0; 5];
    client.read_exact(&mut hello).unwrap();
    assert_eq!(&hello, b"hello");
    origin.marker(b'A');
    let data = vec![0x5a; 10 * 1024 * 1024];
    for fragment in data.chunks(4093) {
        client.write_all(fragment).unwrap();
    }
    let mut hash = Sha256::new();
    let mut remaining = data.len();
    let mut bytes = [0; 6151];
    while remaining > 0 {
        let size = bytes.len().min(remaining);
        let n = client.read(&mut bytes[..size]).unwrap();
        assert_ne!(n, 0);
        hash.update(&bytes[..n]);
        remaining -= n;
    }
    assert_eq!(hash.finalize(), Sha256::digest(&data));
    let mut trailer = [0; 7];
    client.read_exact(&mut trailer).unwrap();
    assert_eq!(&trailer, b"trailer");
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    origin.marker(b'D');
}
fn dns(config: &mut Value, origin: &Origin, via: &str) {
    config["dns"] =
        json!({"enable":true,"ipv6":false,"nameserver":[format!("udp://{}#{via}",origin.target)]});
}
#[test]
#[ignore = "isolated N3 runner"]
fn public_base() {
    let _case = Case::new("N3-PUBLIC", "public_base");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let mut dns_origin = Origin::new(&f, 17, false);
    let mut yaml = config(f["node"].clone(), port);
    dns(&mut yaml, &dns_origin, "DIRECT");
    let core = Core::start(&yaml);
    for (v6, domain) in [(false, false), (true, false), (false, true)] {
        bulk(port, &f, v6, domain);
    }
    echo(port, &f);
    core.stop();
    for codec in ["", "xudp", "packetaddr"] {
        let _codec = Case::new("N3-BASE", "udp_each_codec_and_family");
        let mut node = f["node"].clone();
        node["packet-encoding"] = json!(codec);
        let mut yaml = config(node, port);
        dns(&mut yaml, &dns_origin, "DIRECT");
        let core = Core::start(&yaml);
        // Keep source sockets alive across all three cases, preventing peer NAT
        // source-tuple reuse from aliasing a previous association.
        let mut associations = Vec::new();
        for (v6, domain) in [(false, false), (true, false), (false, true)] {
            let mut association = Association::new(&f, port, v6, domain);
            let cap = if f["peer_kind"] == "V2" {
                if codec == "xudp" {
                    2048
                } else {
                    2030 - (if codec == "packetaddr" {
                        if v6 || domain { 19 } else { 7 }
                    } else {
                        0
                    })
                }
            } else {
                15000
                    - (if codec == "packetaddr" {
                        if v6 || domain { 19 } else { 7 }
                    } else {
                        0
                    })
            };
            for size in [1, 64, 512, 1200, cap] {
                for sequence in 0..100u8 {
                    let payload = vec![sequence; size];
                    association.exchange(&payload);
                }
            }
            associations.push(association);
        }
        core.stop();
        drop(associations);
    }
    // packetaddr's business-domain lookup was answered by this controlled DNS
    // endpoint. Magic names cause the fixture to close, never a system lookup.
    let mut header = [0; 4];
    dns_origin.observer.read_exact(&mut header).unwrap();
    let n = u16::from_be_bytes([header[0], header[1]]) as usize;
    let mut query = vec![0; n];
    dns_origin.observer.read_exact(&mut query).unwrap();
    assert_eq!(&query[12..], b"\x0dvcore-fixture\x04test\0\0\x01\0\x01");
    let mut origin = Origin::new(&f, 14, false);
    let result = invoke(
        "measureDelay",
        None,
        json!({"configYamls":[json!({"proxies":[f["node"]]}).to_string()],"timeout":5,"url":format!("http://{}/",origin.target)}),
    );
    assert_eq!(result["results"][0]["success"], true);
    origin.marker(b'A');
    origin.marker(b'D');
}

fn denied(node: Value, f: &Value) {
    let mut origin = Origin::new(f, 13, false);
    let port = free_port();
    let core = Core::start(&config(node, port));
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    request.extend(b"no-origin-bytes");
    client.write_all(&request).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut response = [0; 4];
    if client.read_exact(&mut response).is_ok() && response[1] == 0 {
        let mut tail = vec![0; if response[3] == 1 { 6 } else { 18 }];
        client.read_exact(&mut tail).unwrap();
        assert!(
            !matches!(client.read(&mut [0;32]),Ok(n) if n>0),
            "rejected session delivered business data"
        );
    }
    drop(client);
    origin.quiet();
    core.stop();
}
#[test]
#[ignore = "isolated N3 runner"]
fn public_negative() {
    let _case = Case::new("N3-PUBLIC", "public_negative");
    let f = fixture();
    initialize(&f);
    let original = f["node"].clone();
    let port = free_port();
    let core = Core::start(&config(original.clone(), port));
    echo(port, &f);
    core.stop();
    let mut bad = original.clone();
    bad["uuid"] = json!("08080808-0808-0808-0808-080808080808");
    denied(bad, &f);
    if original["tls"] == true {
        let mut untrusted = original.clone();
        untrusted.as_object_mut().unwrap().remove("fingerprint");
        denied(untrusted.clone(), &f);
        let mut bad = original.clone();
        bad["fingerprint"] = json!("00".repeat(32));
        bad["skip-cert-verify"] = json!(true);
        denied(bad, &f);
        let mut bad = original.clone();
        bad["servername"] = json!("wrong.invalid");
        denied(bad.clone(), &f);
        bad["skip-cert-verify"] = json!(true);
        denied(bad, &f);
        if original["network"] == "ws" {
            let mut fallback = original.clone();
            fallback.as_object_mut().unwrap().remove("servername");
            let port = free_port();
            let core = Core::start(&config(fallback, port));
            echo(port, &f);
            core.stop();
        }
        // No pin: skip-cert-verify is observable, not silently ignored.
        untrusted["skip-cert-verify"] = json!(true);
        let port = free_port();
        let core = Core::start(&config(untrusted, port));
        echo(port, &f);
        core.stop();
        // A matching leaf pin intentionally replaces PKI/name checks, per the
        // existing StandardTlsClient contract. A nonmatching pin cannot bypass.
    }
    let mut bad = original.clone();
    match original["network"].as_str().unwrap() {
        "ws" => bad["ws-opts"]["path"] = json!("/wrong"),
        "grpc" => bad["grpc-opts"]["grpc-service-name"] = json!("wrong"),
        "h2" => bad["h2-opts"]["host"] = json!(["wrong.invalid"]),
        "http" => bad["http-opts"]["path"] = json!(["/wrong"]),
        _ => return,
    };
    denied(bad, &f);
    if original["network"] == "h2" {
        let mut bad = original;
        bad["h2-opts"]["path"] = json!("/wrong");
        denied(bad, &f);
    }
}

#[test]
#[ignore = "isolated N3 runner"]
fn public_alpn_rejection() {
    let _case = Case::new("N3-PUBLIC", "public_alpn_rejection");
    let f = fixture();
    initialize(&f);
    // The official listener advertises h2 when its gRPC entrance is enabled.
    // A valid gRPC control proves authentication/origin readiness first.
    let mut control = f["node"].clone();
    control["network"] = json!("grpc");
    control["alpn"] = json!(["h2"]);
    control.as_object_mut().unwrap().remove("ws-opts");
    control["grpc-opts"] = json!({"grpc-service-name":"n3-alpn"});
    let port = free_port();
    let core = Core::start(&config(control, port));
    echo(port, &f);
    core.stop();
    denied(f["node"].clone(), &f);
}

#[test]
#[ignore = "isolated N3 runner"]
fn public_udp_first_response() {
    let _case = Case::new("N3-PUBLIC", "public_udp_first_response");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    let mut association = Association::new(&f, port, false, false);
    association.exchange(&vec![1; 15000]);
    core.stop();
}

#[test]
#[ignore = "isolated N3 runner"]
fn public_body_options() {
    let _case = Case::new("N3-PUBLIC", "public_body_options");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    for cipher in ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"] {
        for flags in 0..if cipher == "none" || cipher == "zero" {
            1
        } else {
            4
        } {
            let _body = Case::new("N3-BODY", "config_controls_aead_body");
            let mut node = f["node"].clone();
            node["cipher"] = json!(cipher);
            node["global-padding"] = json!(flags & 1 != 0);
            node["authenticated-length"] = json!(flags & 2 != 0);
            let core = Core::start(&config(node, port));
            echo(port, &f);
            let mut udp = Association::new(&f, port, false, false);
            udp.exchange(b"configured-body-options");
            core.stop();
        }
    }
}

#[test]
#[ignore = "isolated N3 runner"]
fn public_legacy_regression() {
    let _case = Case::new("N3-PUBLIC", "public_legacy_regression");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    echo(port, &f);
    bulk(port, &f, false, false);
    let mut udp = Association::new(&f, port, false, false);
    for size in [1, 64, 512, 1200, 8192] {
        for n in 0..100u8 {
            udp.exchange(&vec![n; size]);
        }
    }
    core.stop();
}
