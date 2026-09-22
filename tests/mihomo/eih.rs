//! Test-only SIP022 EIH relay. It verifies and strips identity layers without
//! decrypting the payload; the final payload is handled by independent mihomo.
//! This is a wire-format fixture, not a VCore inbound or a production codec.
//! Specification: Shadowsocks-NET/shadowsocks-specs, 2022-2 extensible identity headers.
use super::*;
use aes::{
    Aes128, Aes256, Block,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn block(key: &[u8], input: &[u8], decrypt: bool) -> [u8; 16] {
    let mut value = Block::default();
    value.copy_from_slice(input);
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).unwrap();
            if decrypt {
                cipher.decrypt_block(&mut value);
            } else {
                cipher.encrypt_block(&mut value);
            }
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).unwrap();
            if decrypt {
                cipher.decrypt_block(&mut value);
            } else {
                cipher.encrypt_block(&mut value);
            }
        }
        _ => panic!("fixture only accepts AES keys"),
    }
    value[..].try_into().unwrap()
}

fn peel_tcp(wire: &mut Vec<u8>, keys: &[Vec<u8>]) -> bool {
    let salt_size = keys[0].len();
    for pair in keys.windows(2) {
        let material = [&pair[0][..], &wire[..salt_size]].concat();
        let subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
        let identity = block(&subkey[..salt_size], &wire[salt_size..salt_size + 16], true);
        if identity != blake3::hash(&pair[1]).as_bytes()[..16] {
            return false;
        }
        wire.drain(salt_size..salt_size + 16);
    }
    true
}

fn peel_udp(wire: &mut Vec<u8>, keys: &[Vec<u8>]) -> bool {
    if wire.len() < 16 + 16 * (keys.len() - 1) {
        return false;
    }
    for pair in keys.windows(2) {
        let session_packet = block(&pair[0], &wire[..16], true);
        let mut identity = block(&pair[0], &wire[16..32], true);
        for (value, mask) in identity.iter_mut().zip(session_packet) {
            *value ^= mask;
        }
        if identity != blake3::hash(&pair[1]).as_bytes()[..16] {
            return false;
        }
        wire.drain(16..32);
        wire[..16].copy_from_slice(&block(&pair[1], &session_packet, false));
    }
    true
}

struct Relay {
    port: u16,
    tasks: Vec<JoinHandle<bool>>,
}

impl Relay {
    fn start(peer_port: u16, keys: &[Vec<u8>], tcp: bool, udp: bool) -> Self {
        // TCP ephemeral allocation does not reserve the same UDP port. Select
        // a jointly free pair before starting either task; do not retry traffic.
        let (listener, socket) = reserve_port_pair();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let peer = SocketAddr::from((peer_ip(3), peer_port));
        let mut tasks = Vec::new();
        if tcp {
            let keys = keys.to_vec();
            tasks.push(thread::spawn(move || {
                let mut client = accept_until(&listener);
                let mut prefix = vec![0; keys[0].len() + 16 * (keys.len() - 1) + 27];
                client.read_exact(&mut prefix).unwrap();
                if !peel_tcp(&mut prefix, &keys) {
                    return false; // No final socket is created on identity failure.
                }
                let mut remote =
                    buffered(TcpStream::connect_timeout(&peer, IO_TIMEOUT).unwrap()).into_inner();
                // Forward the complete fixed header in one write (SIP022).
                remote.write_all(&prefix).unwrap();
                let mut remote_read = remote.try_clone().unwrap();
                let mut client_write = client.try_clone().unwrap();
                let receive = thread::spawn(move || {
                    io::copy(&mut remote_read, &mut client_write).unwrap();
                    let _ = client_write.shutdown(std::net::Shutdown::Write);
                });
                io::copy(&mut client, &mut remote).unwrap();
                let _ = remote.shutdown(std::net::Shutdown::Write);
                receive.join().unwrap();
                true
            }));
        }
        if udp {
            let keys = keys.to_vec();
            tasks.push(thread::spawn(move || {
                let mut buffer = vec![0; 65_507];
                let (length, client) = socket.recv_from(&mut buffer).unwrap();
                let mut wire = buffer[..length].to_vec();
                if !peel_udp(&mut wire, &keys) {
                    return false;
                }
                socket.send_to(&wire, peer).unwrap();
                let (length, source) = socket.recv_from(&mut buffer).unwrap();
                assert_eq!(source, peer);
                socket.send_to(&buffer[..length], client).unwrap();
                true
            }));
        }
        Self { port, tasks }
    }

    fn finish(mut self, accepted: bool) {
        for task in self.tasks.drain(..) {
            assert_eq!(task.join().unwrap(), accepted);
        }
    }
}

fn reserve_port_pair() -> (TcpListener, UdpSocket) {
    for _ in 0..32 {
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        match UdpSocket::bind(listener.local_addr().unwrap()) {
            Ok(socket) => return (listener, socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("EIH fixture UDP bind: {error}"),
        }
    }
    panic!("EIH fixture could not reserve a TCP/UDP port pair");
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Each owner has bounded I/O even if a public-path assertion fails.
        for task in self.tasks.drain(..) {
            let _ = task.join();
        }
    }
}

pub(super) fn probe(socks_port: u16, fixtures: &[Value]) {
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    for fixture in &fixtures[..2] {
        let cipher = fixture["cipher"].as_str().unwrap();
        let final_key = STANDARD
            .decode(fixture["password"].as_str().unwrap())
            .unwrap();
        for identities in [1, 2] {
            let keys: Vec<Vec<u8>> = (1..=identities)
                .map(|id| vec![id; final_key.len()])
                .chain([final_key.clone()])
                .collect();
            let relay = Relay::start(fixture["port"].as_u64().unwrap() as u16, &keys, true, true);
            let node = json!({"name":"peer", "type":"ss", "server":origin_address(false).ip(), "port":relay.port, "cipher":cipher, "udp":true, "password":keys.iter().map(|key| STANDARD.encode(key)).collect::<Vec<_>>().join(":")});
            let config = json!({"socks-port":socks_port, "proxies":[node], "rules":["MATCH,peer"]});
            let core = Core::start(&config.to_string());
            probe_socks_tcp(proxy, false, false);
            probe_socks_udp(proxy, false, false);
            core.stop();
            relay.finish(true);
            println!(
                "PASS EIH {cipher}: {identities} verified identity layers -> final mihomo, TCP + UDP"
            );
        }
        for udp in [false, true] {
            let keys = vec![vec![1; final_key.len()], final_key.clone()];
            let relay = Relay::start(fixture["port"].as_u64().unwrap() as u16, &keys, !udp, udp);
            let node = json!({"name":"peer", "type":"ss", "server":origin_address(false).ip(), "port":relay.port, "cipher":cipher, "udp":true, "password":format!("{}:{}", STANDARD.encode(vec![2;final_key.len()]), STANDARD.encode(&final_key))});
            let config = json!({"socks-port":socks_port, "proxies":[node], "rules":["MATCH,peer"]});
            let core = Core::start(&config.to_string());
            probe_denied_payload(proxy, udp);
            core.stop();
            relay.finish(false);
        }
        println!("PASS EIH {cipher}: incorrect identity rejects TCP + UDP without forwarding");
    }
    for fixture in fixtures {
        let key_length = STANDARD
            .decode(fixture["password"].as_str().unwrap())
            .unwrap()
            .len();
        for bad_cipher in [false, true] {
            let mut node = fixture.clone();
            node["name"] = json!("peer");
            node["type"] = json!("ss");
            node["server"] = json!(peer_ip(3));
            node["udp"] = json!(true);
            if bad_cipher {
                node["cipher"] = json!(if key_length == 16 {
                    "2022-blake3-aes-256-gcm"
                } else {
                    "2022-blake3-aes-128-gcm"
                });
                node["password"] =
                    json!(STANDARD.encode(vec![7; if key_length == 16 { 32 } else { 16 }]));
            } else {
                node["password"] = json!(STANDARD.encode(vec![8; key_length]));
            }
            let config = json!({"socks-port":socks_port, "proxies":[node], "rules":["MATCH,peer"]});
            let core = Core::start(&config.to_string());
            probe_denied_payload(proxy, false);
            probe_denied_payload(proxy, true);
            core.stop();
        }
        println!(
            "PASS SS {}: incorrect key / cipher gives no TCP or UDP response",
            fixture["cipher"].as_str().unwrap()
        );
    }
}

fn probe_denied_payload(proxy: SocketAddr, udp: bool) {
    if udp {
        let origin = UdpSocket::bind(origin_address(false)).unwrap();
        origin
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut control = socks_login(proxy, false);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let relay = socks_reply(&mut control);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut request = vec![0, 0, 0];
        request.extend_from_slice(&socks_address(origin.local_addr().unwrap()));
        request.extend_from_slice(b"private-negative-payload");
        socket.send_to(&request, relay).unwrap();
        assert!(
            matches!(origin.recv_from(&mut [0;128]), Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
        );
    } else {
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = socks_login(proxy, false);
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(&socks_address(listener.local_addr().unwrap()));
        request.extend_from_slice(b"private-negative-payload");
        client.write_all(&request).unwrap();
        socks_reply(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        assert!(!matches!(client.read(&mut [0;128]), Ok(n) if n > 0));
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    }
}
