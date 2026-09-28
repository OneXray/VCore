//! Public VLESS consumer gate. Every origin/peer is owned by the container runner.
#![cfg(all(feature = "ffi", feature = "outbound-vless", feature = "interop-test"))]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    thread,
    time::{Duration, Instant},
};
use vcore::resources::case_events::Case as RecordedCase;
// The same public consumers are reused by XHTTP. Keep their evidence separate
// instead of letting a current XHTTP run masquerade as historical VLESS evidence.
struct Case;
impl Case {
    fn start(suite: &'static str, assertion: &'static str) -> RecordedCase {
        let suite = if std::env::var("VCORE_PROTOCOL_STAGE").as_deref() == Ok("XHTTP") {
            match suite {
                "VLESS-PUBLIC" => "XHTTP-PUBLIC",
                "VLESS-BASE" => "XHTTP-BASE",
                "VLESS-LIFE" => "XHTTP-LIFE",
                "VLESS-OWNED" => "XHTTP-OWNED",
                _ => panic!("unknown public consumer suite"),
            }
        } else if std::env::var("VCORE_PROTOCOL_STAGE").as_deref() == Ok("HYSTERIA2") {
            match suite {
                "VLESS-PUBLIC" => "HYSTERIA2-PUBLIC",
                "VLESS-BASE" => "HYSTERIA2-BASE",
                "VLESS-LIFE" => "HYSTERIA2-LIFE",
                "VLESS-OWNED" => "HYSTERIA2-OWNED",
                _ => panic!("unknown public consumer suite"),
            }
        } else if std::env::var("VCORE_PROTOCOL_STAGE").as_deref() == Ok("SECURITY") {
            match suite {
                "VLESS-PUBLIC" => "SECURITY-PUBLIC",
                "VLESS-BASE" => "SECURITY-BASE",
                "VLESS-LIFE" => "SECURITY-LIFE",
                "VLESS-OWNED" => "SECURITY-OWNED",
                _ => panic!("unknown public consumer suite"),
            }
        } else if std::env::var("VCORE_PROTOCOL_STAGE").as_deref() == Ok("INTEGRATION") {
            match suite {
                "VLESS-PUBLIC" => "INTEGRATION-PUBLIC",
                "VLESS-BASE" => "INTEGRATION-BASE",
                "VLESS-LIFE" => "INTEGRATION-LIFE",
                "VLESS-OWNED" => "INTEGRATION-OWNED",
                _ => panic!("unknown public consumer suite"),
            }
        } else {
            suite
        };
        RecordedCase::new(suite, assertion)
    }
}
const TIMEOUT: Duration = Duration::from_secs(10);
const DOMAIN: &str = "vcore-fixture.test";

#[cfg(feature = "outbound-hysteria2")]
#[path = "vless_public/hysteria2.rs"]
mod hysteria2;
#[path = "vless_public/integration/mod.rs"]
mod integration;
#[path = "vless_public/runtime.rs"]
mod runtime;
#[cfg(feature = "shadow-tls-v3")]
#[path = "vless_public/shadowtls.rs"]
mod shadowtls;
#[cfg(feature = "outbound-tuic")]
#[path = "vless_public/tuic.rs"]
mod tuic;
#[cfg(target_os = "macos")]
#[path = "vmess_public/tun.rs"]
mod tun;
#[cfg(feature = "outbound-shadowsocks")]
#[path = "vless_public/uot.rs"]
mod uot;

fn fixture() -> Value {
    let value: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("VCORE_VLESS_INPUT").expect("use isolated VLESS runner"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["isolation"], "containers");
    value
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
#[ignore = "isolated HYSTERIA2 runner"]
fn hysteria2_client_first() {
    let _case = RecordedCase::new("HYSTERIA2-BASE", "client_first");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    echo(port, &f);
    core.stop();
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
#[ignore = "isolated HYSTERIA2 runner"]
fn hysteria2_udp_base() {
    let _case = RecordedCase::new("HYSTERIA2-BASE", "udp_ipv4_ipv6_domain_fragmentation");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        let mut association = Association::new(&f, port, ipv6, domain);
        for size in [1, 64, 512, 1200, 4096] {
            for sequence in 0..100_u8 {
                let mut bytes = vec![sequence; size];
                if size > 1 {
                    bytes[1] = size as u8;
                }
                association.exchange(&bytes);
            }
        }
        drop(association);
    }
    core.stop();
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
#[ignore = "isolated HYSTERIA2 runner"]
fn hysteria2_tcp_base() {
    let _case = RecordedCase::new("HYSTERIA2-BASE", "tcp_ipv4_ipv6_domain_and_measure");
    let f = fixture();
    assert_eq!(f["node"]["type"], "hysteria2");
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        bulk(port, &f, ipv6, domain);
    }
    echo(port, &f);
    core.stop();
    let mut origin = Origin::new(&f, 14, false);
    let result = invoke(
        "measureDelay",
        None,
        json!({"configYamls":[json!({"proxies":[f["node"]]}).to_string()], "timeout":5,
        "url":format!("http://{}/",origin.target)}),
    );
    assert_eq!(result["results"][0]["success"], true);
    origin.marker(b'A');
    origin.marker(b'D');
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
    let _case = Case::start("VLESS-BASE", "tcp_10mib_both_directions");
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
        let n = client.read(&mut bytes[..size]).unwrap_or_else(|error| {
            panic!("bulk receive failed with {remaining} bytes remaining: {error}")
        });
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
#[ignore = "isolated VLESS runner"]
fn public_base() {
    let _case = Case::start("VLESS-PUBLIC", "public_base");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let dns_origin = Origin::new(&f, 17, false);
    let mut yaml = config(f["node"].clone(), port);
    dns(&mut yaml, &dns_origin, "DIRECT");
    let core = Core::start(&yaml);
    for (v6, domain) in [(false, false), (true, false), (false, true)] {
        bulk(port, &f, v6, domain);
    }
    echo(port, &f);
    core.stop();
    drop(dns_origin);
    for codec in if f["node"]["flow"] == "xtls-rprx-vision" {
        vec!["xudp"]
    } else {
        vec!["none", "xudp", "packetaddr"]
    } {
        let _codec = Case::start("VLESS-BASE", "udp_each_codec_and_family");
        // Each runtime owns a fresh DNS fixture. A previous TCP bulk transfer
        // must not consume this container origin's bounded idle lifetime.
        let mut dns_origin = Origin::new(&f, 17, false);
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
                    2046 - (if codec == "packetaddr" {
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
        // packetaddr's domain lookup must use this controlled endpoint. Magic
        // names close the fixture; there is no system resolver fallback.
        if codec == "packetaddr" {
            let mut header = [0; 4];
            dns_origin.observer.read_exact(&mut header).unwrap();
            let n = u16::from_be_bytes([header[0], header[1]]) as usize;
            let mut query = vec![0; n];
            dns_origin.observer.read_exact(&mut query).unwrap();
            assert_eq!(&query[12..], b"\x0dvcore-fixture\x04test\0\0\x01\0\x01");
        }
    }
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
#[ignore = "isolated SECURITY JLS runner"]
fn public_jls_download_identity() {
    let _case = Case::start("VLESS-PUBLIC", "public_jls_download_identity");
    let f = fixture();
    initialize(&f);
    let original = f["node"].clone();
    assert!(original["xhttp-opts"]["download-settings"].is_object());
    let port = free_port();
    let core = Core::start(&config(original.clone(), port));
    echo(port, &f);
    core.stop();
    let mut replaced = original.clone();
    replaced["xhttp-opts"]["download-settings"]["jls-opts"] = f["jls_download_credentials"].clone();
    replaced["xhttp-opts"]["download-settings"]["client-fingerprint"] = json!("firefox");
    let core = Core::start(&config(replaced.clone(), port));
    bulk(port, &f, false, false);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"independent-jls-download");
    core.stop();
    for field in ["username", "password"] {
        let mut bad = replaced.clone();
        bad["xhttp-opts"]["download-settings"]["jls-opts"][field] = json!("incorrect-credential");
        denied(bad, &f);
    }
    // An explicit clear must remove JLS, even though the peer still requires it.
    let mut cleared = original.clone();
    cleared["xhttp-opts"]["download-settings"]["jls-opts"] = json!({});
    denied(cleared, &f);
    // A failed independently authenticated leg cannot poison a new valid node.
    let core = Core::start(&config(original, port));
    echo(port, &f);
    core.stop();
}

#[test]
#[ignore = "isolated SECURITY ECH runner"]
fn public_ech_download_identity() {
    let _case = Case::start("VLESS-PUBLIC", "public_ech_download_identity");
    let f = fixture();
    initialize(&f);
    let original = f["node"].clone();
    assert!(original["xhttp-opts"]["download-settings"].is_object());
    let port = free_port();
    let core = Core::start(&config(original.clone(), port));
    echo(port, &f);
    core.stop();
    let mut replaced = original.clone();
    replaced["xhttp-opts"]["download-settings"]["ech-opts"] =
        json!({"enable":true,"config":f["ech_download_config"]});
    replaced["xhttp-opts"]["download-settings"]["client-fingerprint"] = json!("firefox");
    let core = Core::start(&config(replaced.clone(), port));
    bulk(port, &f, false, false);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"independent-ech-download");
    core.stop();
    // Only an explicit clear permits the download leg to use ordinary TLS.
    replaced["xhttp-opts"]["download-settings"]["ech-opts"] = json!({});
    let core = Core::start(&config(replaced, port));
    echo(port, &f);
    core.stop();
    let core = Core::start(&config(original, port));
    echo(port, &f);
    core.stop();
}

#[test]
#[ignore = "isolated VLESS runner"]
fn public_negative() {
    let _case = Case::start("VLESS-PUBLIC", "public_negative");
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
    if original["tls"] == true && original["network"].as_str().unwrap_or("tcp") == "tcp" {
        let mut bad = original.clone();
        if original["flow"] == "xtls-rprx-vision" {
            bad["port"] = json!(f["flow_reject_port"].as_u64().unwrap());
            denied(bad, &f);
            // The official listener accepts an explicitly empty flow for a
            // Vision user. This is a user choice, never automatic fallback.
            let mut plain = original.clone();
            plain["flow"] = json!("");
            let port = free_port();
            let core = Core::start(&config(plain, port));
            echo(port, &f);
            core.stop();
        } else {
            bad["flow"] = json!("xtls-rprx-vision");
            denied(bad, &f);
        }
    }
    if original.get("reality-opts").is_some() {
        let mut bad = original.clone();
        bad["reality-opts"]["public-key"] = json!("CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        denied(bad, &f);
        let mut bad = original.clone();
        bad["reality-opts"]["short-id"] = json!("ffffffffffffffff");
        denied(bad, &f);
        let mut bad = original.clone();
        bad["servername"] = json!("rejected.fixture.test");
        denied(bad, &f);
    }
    if original["tls"] == true && original.get("reality-opts").is_none() {
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
    match original["network"].as_str().unwrap_or("tcp") {
        "ws" => bad["ws-opts"]["path"] = json!("/wrong"),
        "grpc" => bad["grpc-opts"]["grpc-service-name"] = json!("wrong"),
        "h2" => bad["h2-opts"]["host"] = json!(["wrong.invalid"]),
        "http" => bad["http-opts"]["path"] = json!(["/wrong"]),
        "xhttp" => bad["xhttp-opts"]["path"] = json!("/wrong"),
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
#[ignore = "isolated VLESS runner"]
fn public_tls_identity_and_verification_name() {
    let _case = Case::start("VLESS-PUBLIC", "public_tls_identity_and_verification_name");
    let f = fixture();
    initialize(&f);
    let original = f["node"].clone();
    let port = free_port();
    let core = Core::start(&config(original.clone(), port));
    echo(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"valid-client-identity");
    core.stop();
    // The CA pin checks certificate names; SNI can differ independently.
    let mut named = original.clone();
    named["servername"] = json!("independent-sni.invalid");
    named["name-cert-verify"] = json!("localhost");
    let core = Core::start(&config(named, port));
    echo(port, &f);
    core.stop();
    let mut bad = original.clone();
    bad["name-cert-verify"] = json!("wrong.invalid");
    bad["skip-cert-verify"] = json!(true);
    denied(bad, &f);
    for name in ["missing", "wrong-ca", "expired"] {
        let mut bad = original.clone();
        bad.as_object_mut().unwrap().remove("certificate");
        bad.as_object_mut().unwrap().remove("private-key");
        if name != "missing" {
            bad.as_object_mut()
                .unwrap()
                .extend(f["identities"][name].as_object().unwrap().clone());
        }
        denied(bad, &f);
    }
    // New node/client after bad identities cannot inherit another node's TLS
    // session or mTLS credentials, and a failure does not poison valid identity.
    let core = Core::start(&config(original, port));
    echo(port, &f);
    core.stop();
}

#[test]
#[ignore = "isolated VLESS runner"]
fn public_alpn_rejection() {
    let _case = Case::start("VLESS-PUBLIC", "public_alpn_rejection");
    let f = fixture();
    initialize(&f);
    // The official listener advertises h2 when its gRPC entrance is enabled.
    // A valid gRPC control proves authentication/origin readiness first.
    let mut control = f["node"].clone();
    control["network"] = json!("grpc");
    control["alpn"] = json!(["h2"]);
    control.as_object_mut().unwrap().remove("ws-opts");
    control["grpc-opts"] = json!({"grpc-service-name":"vless-alpn"});
    let port = free_port();
    let core = Core::start(&config(control, port));
    echo(port, &f);
    core.stop();
    denied(f["node"].clone(), &f);
}

#[test]
#[ignore = "isolated VLESS runner"]
fn public_udp_first_response() {
    let _case = Case::start("VLESS-PUBLIC", "public_udp_first_response");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    let mut association = Association::new(&f, port, false, false);
    association.exchange(&vec![1; 15000]);
    core.stop();
}

#[test]
#[ignore = "isolated VLESS runner"]
fn public_legacy_regression() {
    let _case = Case::start("VLESS-PUBLIC", "public_legacy_regression");
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

#[test]
#[ignore = "owned isolated native peer required"]
fn public_legacy_tcp() {
    let _case = Case::start("VLESS-PUBLIC", "public_legacy_tcp");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let core = Core::start(&config(f["node"].clone(), port));
    echo(port, &f);
    // The gate is the legacy TLS transport, not a new UDP size contract for V2Ray.
    bulk(port, &f, false, false);
    core.stop();
}
