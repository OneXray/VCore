use super::*;

pub(super) fn probe(http_port: u16, socks_port: u16, fixtures: &Value) {
    let first = fixtures["first"].as_array().unwrap();
    let last = fixtures["last"].as_array().unwrap();
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    for fixture in last {
        close_peer_connections(fixtures);
        let mut node = fixture.clone();
        node["name"] = json!("peer");
        let config = json!({"port":http_port,"socks-port":socks_port,"proxies":[node],"rules":["MATCH,peer"]});
        let core = Core::start(&config.to_string());
        for mode in [Mode::Forward, Mode::Connect] {
            super::probe(
                SocketAddr::from((Ipv4Addr::LOCALHOST, http_port)),
                false,
                mode,
            );
        }
        probe_socks_tcp(proxy, false, false);
        probe_socks_udp(proxy, false, false);
        core.stop();
        println!(
            "PASS I01 HTTP forward/CONNECT + SOCKS TCP/UDP -> {}",
            fixture["type"].as_str().unwrap()
        );
    }
    for round in 0..8 {
        for upstream in first {
            for endpoint in last {
                close_peer_connections(fixtures);
                println!(
                    "RUN I02 round {round} nested upstream: {} -> {}",
                    upstream["type"].as_str().unwrap(),
                    endpoint["type"].as_str().unwrap()
                );
                let mut hop = upstream.clone();
                hop["name"] = json!("hop");
                let mut node = endpoint.clone();
                node["name"] = json!("peer");
                node["dialer-proxy"] = json!("outer");
                let config = json!({"socks-port":socks_port,"proxies":[node,hop],"proxy-groups":[{"name":"outer","type":"select","proxies":["inner"]},{"name":"inner","type":"select","proxies":["hop"]}],"rules":["MATCH,peer"]});
                let core = Core::start(&config.to_string());
                probe_socks_tcp(proxy, false, false);
                probe_socks_udp(proxy, false, false);
                core.stop();
                println!(
                    "PASS I02 nested upstream: {} -> {}, TCP + UDP",
                    upstream["type"].as_str().unwrap(),
                    endpoint["type"].as_str().unwrap()
                );
            }
        }
    }
    close_peer_connections(fixtures);
}

pub(super) fn close_peer_connections(fixtures: &Value) {
    // A long-lived mihomo UDP socket can have the same numeric port as a new
    // TCP/UoT source. Its loopback guard deliberately compares only source port.
    // Reclaim the *owned fixture's* old connections between cases; retain the
    // guard and never retry a failed packet or change production behavior.
    for (index, port) in fixtures["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let address = SocketAddr::from((
            peer_ip(if index == 0 { 0 } else { 3 }),
            port.as_u64().unwrap() as u16,
        ));
        let mut client = buffered(TcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap());
        client.get_mut().write_all(b"DELETE /connections HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-controller-only\r\nConnection: close\r\n\r\n").unwrap();
        assert!(head(&mut client).starts_with("HTTP/1.1 204"));
        assert_eq!(
            connection_count(address),
            0,
            "generated peer retained connections between cases"
        );
    }
}

pub(super) fn peer_connection_count(fixtures: &Value, index: usize) -> usize {
    connection_count(SocketAddr::from((
        peer_ip(if index == 0 { 0 } else { 3 }),
        fixtures["controllers"][index].as_u64().unwrap() as u16,
    )))
}

fn connection_count(address: SocketAddr) -> usize {
    let mut client = buffered(TcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap());
    client.get_mut().write_all(b"GET /connections HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-controller-only\r\nConnection: close\r\n\r\n").unwrap();
    assert!(head(&mut client).starts_with("HTTP/1.1 200"));
    let mut body = Vec::new();
    client.take(65_536).read_to_end(&mut body).unwrap();
    let snapshot: Value = serde_json::from_slice(&body).unwrap();
    let connections = snapshot
        .get("connections")
        .expect("mihomo connection snapshot");
    if connections.is_null() {
        0
    } else {
        connections.as_array().unwrap().len()
    }
}
