//! Trojan consumer checks through public YAML and Invoke, owned by the TROJAN runner.
use super::*;
use sha2::{Digest, Sha256};
use vcore::resources::case_events::Case;

#[path = "trojan_runtime.rs"]
mod runtime;

fn fixture() -> Value {
    serde_json::from_str(&env::var("VCORE_TROJAN_FIXTURE").expect("use the TROJAN runner")).unwrap()
}

fn free_port() -> u16 {
    for _ in 0..32 {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        match reserve_runtime_families(tcp) {
            Ok(_reservation) => return port,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("runtime fixture port reservation: {error}"),
        }
        // Only pre-traffic reservation retries, never failed runtime starts.
    }
    panic!("could not reserve a dual-family TCP/UDP runtime fixture port");
}

fn reserve_runtime_families(tcp: TcpListener) -> io::Result<(TcpListener, TcpListener, UdpSocket)> {
    let address = tcp.local_addr()?;
    let tcp_v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, address.port()))?;
    let udp = UdpSocket::bind(address)?;
    Ok((tcp, tcp_v6, udp))
}

#[test]
fn fixture_runtime_port_rejects_occupied_udp_and_ipv6_tcp() {
    for udp_busy in [true, false] {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        if udp_busy {
            let _occupied = UdpSocket::bind(address).unwrap();
            assert!(reserve_runtime_families(tcp).is_err());
        } else {
            let _occupied = TcpListener::bind((Ipv6Addr::LOCALHOST, address.port())).unwrap();
            assert!(reserve_runtime_families(tcp).is_err());
        }
    }
}

fn config(node: Value, port: u16) -> Value {
    json!({"socks-port":port,"ipv6":true,"proxies":[node],"rules":["MATCH,peer"]})
}

fn tcp_base(proxy: SocketAddr, ipv6: bool, domain: bool) {
    let listener = TcpListener::bind(origin_address(ipv6)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = listener.local_addr().unwrap();
    let mut client = socks_login(proxy, false);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&fixture_address(target, domain));
    client.write_all(&request).unwrap();
    socks_reply(&mut client);
    let mut remote = accept_until(&listener);
    remote.write_all(b"server-first").unwrap();
    let mut greeting = [0; 12];
    client.read_exact(&mut greeting).unwrap();
    assert_eq!(&greeting, b"server-first");
    let payload: Vec<u8> = (0..10 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let expected = Sha256::digest(&payload);
    let origin = thread::spawn(move || {
        let mut hash = Sha256::new();
        let mut received = 0;
        let mut buffer = [0; 8191];
        while received < 10 * 1024 * 1024 {
            let n = remote.read(&mut buffer).unwrap();
            assert_ne!(n, 0, "truncated upload");
            received += n;
            hash.update(&buffer[..n]);
            remote.write_all(&buffer[..n]).unwrap();
        }
        assert_eq!(hash.finalize(), expected);
        assert_eq!(remote.read(&mut [0; 1]).unwrap(), 0, "upload EOF");
        remote.write_all(b"half-close-tail").unwrap();
        remote.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let mut upload = client.try_clone().unwrap();
    let writer = thread::spawn(move || {
        for fragment in payload.chunks(4093) {
            upload.write_all(fragment).unwrap();
        }
        upload.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let mut hash = Sha256::new();
    let mut remaining = 10 * 1024 * 1024;
    let mut buffer = [0; 6151];
    while remaining > 0 {
        let size = buffer.len().min(remaining);
        let n = client.read(&mut buffer[..size]).unwrap();
        assert_ne!(n, 0, "truncated download");
        remaining -= n;
        hash.update(&buffer[..n]);
    }
    assert_eq!(hash.finalize(), expected);
    let mut tail = Vec::new();
    client.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, b"half-close-tail");
    writer.join().unwrap();
    origin.join().unwrap();
}

fn udp_base(proxy: SocketAddr, ipv6: bool, domain: bool) {
    let remote = UdpSocket::bind(origin_address(ipv6)).unwrap();
    remote.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let target = remote.local_addr().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let mut control = socks_login(proxy, false);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let relay = socks_reply(&mut control);
    let mut request_header = vec![0, 0, 0];
    request_header.extend_from_slice(&fixture_address(target, domain));
    let mut response_header = vec![0, 0, 0];
    // Native Xray preserves the domain-form source; Mihomo literal cases
    // preserve the literal source. Neither may be silently rewritten by VCore.
    response_header.extend_from_slice(&fixture_address(target, domain));
    let mut buffer = [0; 9000];
    // Xray's Trojan writer uses an 8192-byte total-frame buffer (address +
    // length + CRLF + payload). Mihomo's literal path permits 8192 payload.
    // Exercise each real path's maximum; VCore's 8192/8193 codec boundary is
    // separately tested, never inferred from a peer's smaller buffer.
    let maximum = fixture()["udp_payload_max"].as_u64().unwrap() as usize;
    for size in [1, 64, 512, 1200, maximum] {
        for sequence in 0..100u8 {
            let payload: Vec<u8> = (0..size)
                .map(|n| (n as u8).wrapping_add(sequence))
                .collect();
            let mut request = request_header.clone();
            request.extend_from_slice(&payload);
            socket.send_to(&request, relay).unwrap();
            let (n, peer) = remote.recv_from(&mut buffer).unwrap_or_else(|error| panic!("Trojan UDP upload ipv6={ipv6} domain={domain} size={size} sequence={sequence}: {error}"));
            assert_eq!(&buffer[..n], payload);
            remote.send_to(&buffer[..n], peer).unwrap();
            let (n, from) = socket.recv_from(&mut buffer).unwrap_or_else(|error| panic!("Trojan UDP download ipv6={ipv6} domain={domain} size={size} sequence={sequence}: {error}"));
            assert_eq!(from, relay);
            assert_eq!(&buffer[..response_header.len()], response_header);
            assert_eq!(
                n - response_header.len(),
                payload.len(),
                "UDP response length size={size} sequence={sequence}"
            );
            assert_eq!(
                Sha256::digest(&buffer[response_header.len()..n]),
                Sha256::digest(&payload),
                "UDP response content size={size} sequence={sequence}"
            );
        }
    }
}

fn measurement(node: &Value) {
    let listener = TcpListener::bind(origin_address(false)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let origin = thread::spawn(move || {
        let mut peer = buffered(accept_until(&listener));
        assert!(head(&mut peer).starts_with("HEAD /"));
        peer.get_mut()
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let response = invoke(
        "measureDelay",
        None,
        json!({"configYamls":[json!({"proxies":[node]}).to_string()],"timeout":5,"url":format!("http://{address}/")}),
    );
    origin.join().unwrap();
    assert_eq!(response["results"][0]["success"], true);
}

#[test]
#[ignore = "requires the owned TROJAN native-peer runner"]
fn public_trojan_native_base() {
    let _case = Case::new("TROJAN-NATIVE", "public_trojan_native_base");
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let port = free_port();
    let node = &fixture["node"];
    let core = Core::start(&config(node.clone(), port).to_string());
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        tcp_base(proxy, ipv6, domain);
        if !domain {
            udp_base(proxy, ipv6, domain);
        }
    }
    core.stop();
    drop(TcpListener::bind(proxy).unwrap());
    drop(UdpSocket::bind(proxy).unwrap());
    measurement(node);
}

#[test]
#[ignore = "requires the owned TROJAN native-peer runner"]
fn public_trojan_native_udp_domain() {
    let _case = Case::new("TROJAN-NATIVE", "public_trojan_native_udp_domain");
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let port = free_port();
    let core = Core::start(&config(fixture["node"].clone(), port).to_string());
    udp_base(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), false, true);
    core.stop();
    drop(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
    drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
}

#[test]
#[ignore = "requires the owned TROJAN native-peer runner"]
fn public_trojan_native_extended_early_data() {
    let _case = Case::new("TROJAN-NATIVE", "public_trojan_native_extended_early_data");
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let port = free_port();
    let core = Core::start(&config(fixture["node"].clone(), port).to_string());
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        for server_first in [false, true] {
            probe_socks_tcp_target(proxy, false, ipv6, domain, server_first);
        }
        udp_base(proxy, ipv6, domain);
    }
    core.stop();
    measurement(&fixture["node"]);
}

#[test]
#[ignore = "requires the owned TROJAN native-peer runner"]
fn public_trojan_native_transport_negative() {
    let _case = Case::new("TROJAN-NATIVE", "public_trojan_native_transport_negative");
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let mut node = fixture["node"].clone();
    match fixture["mode"].as_str().unwrap() {
        "ws" => {
            node["ws-opts"]["path"] = json!("/wrong");
            assert_no_origin_bytes(node.clone());
            node = fixture["node"].clone();
            node["ws-opts"]["headers"]["Host"] = json!("wrong.example");
        }
        "grpc" => {
            node["grpc-opts"]["grpc-service-name"] = json!("wrong");
        }
        "ws-alpn" => {}
        _ => panic!("invalid negative fixture"),
    }
    assert_no_origin_bytes(node);
}

fn assert_no_origin_bytes(node: Value) {
    let listener = TcpListener::bind(origin_address(false)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = free_port();
    let core = Core::start(&config(node, port).to_string());
    let mut client = socks_login(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), false);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&socks_address(listener.local_addr().unwrap()));
    request.extend_from_slice(b"must-not-reach-origin");
    client.write_all(&request).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    // Trojan has no authentication ACK; a successful local CONNECT is not an
    // authenticated-peer claim. Both a rejected CONNECT and subsequent EOF
    // must fail closed without delivering business bytes to the origin.
    if response[1] == 0 {
        match client.read(&mut [0; 1]) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("authentication failure remained usable: {other:?}"),
        }
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    core.stop();
}

#[test]
#[ignore = "requires the owned TROJAN native-peer runner"]
fn public_trojan_native_policy_and_group_snapshots() {
    let _case = Case::new(
        "TROJAN-NATIVE",
        "public_trojan_native_policy_and_group_snapshots",
    );
    let fixture = fixture();
    invoke("initialize", None, json!({"dataDir":fixture["data_dir"]}));
    let original = fixture["node"].clone();
    let mut wrong_password = original.clone();
    wrong_password["password"] = json!("wrong-credential");
    assert_no_origin_bytes(wrong_password);
    let mut untrusted = original.clone();
    untrusted.as_object_mut().unwrap().remove("fingerprint");
    assert_no_origin_bytes(untrusted.clone());
    let mut wrong_pin = original.clone();
    wrong_pin["fingerprint"] = json!("00".repeat(32));
    wrong_pin["skip-cert-verify"] = json!(true);
    assert_no_origin_bytes(wrong_pin);
    // skip only bypasses PKI; a supplied pin continues to be mandatory.
    for mut node in [original.clone(), untrusted] {
        node["skip-cert-verify"] = json!(true);
        let port = free_port();
        let core = Core::start(&config(node, port).to_string());
        probe_socks_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), false, false);
        core.stop();
    }
    println!(
        "TROJAN policy: wrong password, untrusted certificate, wrong pin, skip and pin passed"
    );
    // A concrete Trojan upstream is also usable as the physical first hop.
    let port = free_port();
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let hop = fixture["hop"].clone();
    let mut leaf = original.clone();
    leaf["dialer-proxy"] = json!("hop");
    // Only the concrete upstream resolves this synthetic server name. VCore
    // must not turn it into a local direct socket or invoke system DNS.
    leaf["server"] = json!("vcore-fixture.test");
    let mut document = config(leaf.clone(), port);
    document["proxies"]
        .as_array_mut()
        .unwrap()
        .push(hop.clone());
    let core = Core::start(&document.to_string());
    println!("TROJAN policy: checking concrete upstream");
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    probe_socks_tcp(proxy, false, false);
    probe_socks_udp(proxy, false, false);
    core.stop();
    leaf["server"] = original["server"].clone();
    leaf["dialer-proxy"] = json!("outer");
    let document = json!({"socks-port":port,"ipv6":true,"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":[leaf,hop],"proxy-groups":[{"name":"outer","type":"select","proxies":["inner"]},{"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}],"rules":["MATCH,peer"]});
    let core = Core::start(&document.to_string());
    println!("TROJAN policy: checking nested group snapshots");
    let mut tcp = groups::TcpFlow::open(proxy);
    let mut udp = groups::UdpFlow::open(proxy);
    udp.exchange(1);
    groups::select(controller, "REJECT");
    tcp.exchange(2);
    udp.exchange(3);
    let listener = TcpListener::bind(origin_address(false)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut denied = socks_login(proxy, false);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&socks_address(listener.local_addr().unwrap()));
    denied.write_all(&request).unwrap();
    let mut response = [0; 10];
    denied.read_exact(&mut response).unwrap();
    assert_ne!(response[1], 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    groups::select(controller, "DIRECT");
    probe_socks_tcp(proxy, false, false);
    probe_socks_udp(proxy, false, false);
    tcp.exchange(4);
    udp.exchange(5);
    core.stop();
    tcp.assert_closed();
    drop((tcp, udp));
    drop(TcpListener::bind(proxy).unwrap());
    drop(UdpSocket::bind(proxy).unwrap());
    // Public protocol gates do not become dependent on the selected transport.
    let mut disabled = original;
    disabled["udp"] = json!(false);
    let mut document = config(disabled, port);
    document["ipv6"] = json!(false);
    let core = Core::start(&document.to_string());
    probe_socks_tcp(proxy, false, false);
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut control = socks_login(proxy, false);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let relay = socks_reply(&mut control);
    let mut packet = vec![0, 0, 0];
    packet.extend_from_slice(&socks_address(origin.local_addr().unwrap()));
    packet.push(1);
    client.send_to(&packet, relay).unwrap();
    assert!(origin.recv_from(&mut [0; 32]).is_err());
    let mut denied = socks_login(proxy, false);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&socks_address(SocketAddr::from((Ipv6Addr::LOCALHOST, 9))));
    denied.write_all(&request).unwrap();
    denied.read_exact(&mut response).unwrap();
    assert_ne!(response[1], 0);
    core.stop();
}
