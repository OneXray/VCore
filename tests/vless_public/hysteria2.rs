//! Hysteria2 consumers through public YAML/Invoke and real container peers.
use super::*;
use runtime::{assert_closed, exchange, live, select};

#[test]
#[ignore = "isolated HYSTERIA2 runner"]
fn public_concrete_upstream() {
    let _case = RecordedCase::new("HYSTERIA2-PUBLIC", "public_concrete_upstream");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let mut node = f["node"].clone();
    node["dialer-proxy"] = json!("hop");
    let mut yaml = config(node, port);
    yaml["proxies"]
        .as_array_mut()
        .unwrap()
        .push(f["hop"].clone());
    let core = Core::start(&yaml);
    echo(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"upstream-udp");
    core.stop();
}

#[test]
#[ignore = "isolated HYSTERIA2 runner"]
fn public_udp_boundaries() {
    let _case = RecordedCase::new("HYSTERIA2-PUBLIC", "public_udp_boundaries");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    for mtu in [64, 1197, 65535] {
        let mut node = f["node"].clone();
        node["udp-mtu"] = json!(mtu);
        let core = Core::start(&config(node, port));
        let mut first = Association::new(&f, port, false, false);
        let mut second = Association::new(&f, port, true, false);
        for n in 0..100 {
            first.exchange(&[1, n]);
            second.exchange(&[2, n]);
        }
        first.exchange(&vec![1; 4096]);
        // Wire format: eight fixed bytes, one-byte authority length, then
        // the authority. A tiny MTU and long IPv6 target can exhaust the
        // protocol's 255-fragment count before the 4096-byte business cap.
        let second_max = ((mtu - 9 - second.origin.target.to_string().len()) * 255).min(4096);
        second.exchange(&vec![2; second_max]);
        first
            .client
            .send_to(&first.packet(&vec![3; 4097]), first.relay)
            .unwrap();
        first.origin.quiet();
        second.exchange(b"oversize-does-not-kill-sibling");
        let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        rogue
            .send_to(&first.packet(b"unauthorized"), first.relay)
            .unwrap();
        first.origin.quiet();
        let mut other = Origin::new(&f, 4, false);
        let mut packet = vec![0, 0, 0];
        packet.extend(address(other.target, false));
        packet.extend(b"other-target");
        second.client.send_to(&packet, second.relay).unwrap();
        other.udp(b"other-target");
        let mut response = [0; 128];
        let (n, _) = second.client.recv_from(&mut response).unwrap();
        assert!(response[..n].ends_with(b"other-target"));
        second.origin.quiet();
        // A local send error may close its SOCKS association, not siblings or
        // the authenticated QUIC session. Check this association last.
        second
            .client
            .send_to(&second.packet(&vec![3; second_max + 1]), second.relay)
            .unwrap();
        second.origin.quiet();
        let mut third = Association::new(&f, port, false, false);
        third.exchange(b"shared-session-survives");
        core.stop();
    }
}

fn denied(port: u16, f: &Value, label: &str) {
    let mut unused = Origin::new(f, 13, false);
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(unused.target, false));
    client.write_all(&request).unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).unwrap();
    assert_ne!(reply[1], 0, "{label}");
    unused.quiet();
}

#[test]
#[ignore = "isolated HYSTERIA2 runner"]
fn public_graph_and_hop_snapshot() {
    let _case = RecordedCase::new("HYSTERIA2-PUBLIC", "public_graph_and_hop_snapshot");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let controller = free_port();
    let mut node = f["node"].clone();
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
    let mut udp = Association::new(&f, port, false, true);
    udp.exchange(b"concrete-upstream");
    core.stop();
    drop(udp);

    node["server"] = f["node"]["server"].clone();
    // A one-port set still creates new physical sockets. It tests selection
    // freezing independently of the native multi-port DNAT acceptance matrix.
    node["ports"] = json!(f["node"]["port"].as_u64().unwrap().to_string());
    node["hop-interval"] = json!(5);
    node["dialer-proxy"] = json!("outer");
    yaml["proxies"][0] = node;
    yaml["external-controller"] = json!(format!("127.0.0.1:{controller}"));
    yaml["secret"] = json!("fixture-only");
    yaml["proxy-groups"] = json!([
        {"name":"outer","type":"select","proxies":["inner"]},
        {"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}
    ]);
    let core = Core::start(&yaml);
    let (mut old, mut origin) = live(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"before-switch");
    select(controller, "REJECT");
    let until = Instant::now() + Duration::from_secs(12);
    while Instant::now() < until {
        exchange(&mut old, b"same-authenticated-session");
        udp.exchange(b"same-upstream-snapshot");
        thread::sleep(Duration::from_millis(100));
    }
    // New logical streams can reuse the old authenticated session, including
    // after its physical socket has hopped. They are not a new group choice.
    echo(port, &f);
    core.stop();
    assert_closed(&mut old);
    origin.marker(b'D');
    drop((old, origin, udp));

    // A fresh physical session must honor the newly selected REJECT.
    let core = Core::start(&yaml);
    select(controller, "REJECT");
    denied(port, &f, "fresh session observes REJECT");
    select(controller, "DIRECT");
    echo(port, &f);
    core.stop();
    // Unselected cycles are rejected before creating any socket.
    yaml["proxy-groups"][1]["proxies"] = json!(["DIRECT", "peer"]);
    assert_eq!(
        invoke_response(
            "validateConfig",
            None,
            json!({"configYaml":yaml.to_string()})
        )["success"],
        false
    );
    // A broken selected member must not fall back to DIRECT.
    yaml["proxy-groups"][1]["proxies"] = json!(["hop", "DIRECT"]);
    let mut broken = f["hop"].clone();
    broken["port"] = json!(1);
    yaml["proxies"][1] = broken;
    let core = Core::start(&yaml);
    denied(port, &f, "broken member has no DIRECT fallback");
    core.stop();
    // The business UDP flag is not the raw upstream carrier capability.
    let mut hop = f["hop"].clone();
    hop["udp"] = json!(false);
    yaml["proxies"][1] = hop;
    let core = Core::start(&yaml);
    echo(port, &f);
    core.stop();
}
