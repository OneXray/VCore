//! HTTP-only host lifecycle and independent, concrete measurement snapshots.
use super::*;

fn controller_get(controller: SocketAddr, path: &str) -> (String, Vec<u8>) {
    let mut client = buffered(TcpStream::connect_timeout(&controller, IO_TIMEOUT).unwrap());
    write!(client.get_mut(), "GET {path} HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-controller-only\r\nConnection: close\r\n\r\n").unwrap();
    let header = head(&mut client);
    let mut body = Vec::new();
    client.take(4096).read_to_end(&mut body).unwrap();
    (header, body)
}

fn selected(controller: SocketAddr) -> String {
    let (header, body) = controller_get(controller, "/proxies/inner");
    assert!(header.starts_with("HTTP/1.1 200"));
    let group: Value = serde_json::from_slice(&body).unwrap();
    group["now"].as_str().unwrap().to_owned()
}

pub(super) fn probe(http_port: u16, controller_port: u16, fixtures: &Value) {
    combinations::close_peer_connections(fixtures);
    let baseline = ss_lifecycle::open_fd_count();
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, http_port));
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, controller_port));
    let mut hop = fixtures["first"][0].clone();
    hop["name"] = json!("hop");
    let mut node = fixtures["last"][2].clone();
    node["name"] = json!("peer");
    node["dialer-proxy"] = json!("inner");
    let config = json!({"port":http_port,"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":[node,hop],"proxy-groups":[{"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}],"rules":["MATCH,peer"]});
    let core = Core::start(&config.to_string());
    let instance = core.0.as_ref().unwrap().clone();
    assert_eq!(
        invoke("getState", Some(&instance), json!({}))["state"],
        "running"
    );
    assert!(
        controller_get(controller, "/traffic")
            .0
            .starts_with("HTTP/1.1 404")
    );
    assert_eq!(selected(controller), "hop");
    for mode in [Mode::Forward, Mode::Connect] {
        super::probe(proxy, false, mode);
    }

    // The host resolves the selected group into an immutable concrete chain.
    let mut concrete = node.clone();
    concrete["dialer-proxy"] = json!(selected(controller));
    let chained = json!({"proxies":[concrete,hop]}).to_string();
    groups::select(controller, "DIRECT");
    assert_eq!(selected(controller), "DIRECT");
    let mut direct = node.clone();
    direct.as_object_mut().unwrap().remove("dialer-proxy");
    let direct = json!({"proxies":[direct]}).to_string();
    super::probe(proxy, false, Mode::Connect);
    groups::select(controller, "REJECT");
    assert_eq!(selected(controller), "REJECT");

    // New public traffic is denied, while previously captured node-only
    // snapshots remain independent from the Running Session's selection.
    {
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = listener.local_addr().unwrap();
        let mut client = buffered(TcpStream::connect_timeout(&proxy, IO_TIMEOUT).unwrap());
        write!(
            client.get_mut(),
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .unwrap();
        assert!(head(&mut client).starts_with("HTTP/1.1 502"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    {
        let listener = TcpListener::bind(origin_address(false)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            for _ in 0..2 {
                let mut remote = buffered(accept_until(&listener));
                assert!(head(&mut remote).starts_with("HEAD /snapshot "));
                remote
                    .get_mut()
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .unwrap();
                assert_eq!(remote.read(&mut [0; 1]).unwrap(), 0);
            }
        });
        let data = invoke(
            "measureDelay",
            None,
            json!({"configYamls":[chained,"proxies: []",direct],"timeout":5,"url":format!("http://{address}/snapshot")}),
        );
        task.join().unwrap();
        let results = data["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["success"], true);
        assert_eq!(results[1]["success"], false);
        assert_eq!(results[2]["success"], true);
        assert!(results[0]["delay"].as_u64().is_some());
        assert!(results[2]["delay"].as_u64().is_some());
        assert_eq!(selected(controller), "REJECT");
    }
    core.stop();
    assert_eq!(
        invoke_response("getState", Some(&instance), json!({}))["success"],
        false
    );
    drop(TcpListener::bind(proxy).unwrap());
    drop(TcpListener::bind(controller).unwrap());
    ss_lifecycle::assert_fd_returned(baseline);
    combinations::close_peer_connections(fixtures);
    println!(
        "PASS I04 HTTP-only host lifecycle + Controller; concrete chained/DIRECT measurement snapshots, ordered per-item failure and cleanup"
    );
}
