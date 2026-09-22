//! SS-specific public lifecycle evidence. No platform/device claims.
use super::*;

pub(super) fn probe(socks_port: u16, fixtures: &[Value]) {
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    for fixture in fixtures {
        let kind = fixture["type"].as_str().unwrap_or("ss");
        let mut node = fixture.clone();
        node["name"] = json!("peer");
        node["type"] = json!(kind);
        if node.get("server").is_none() {
            node["server"] = json!(peer_ip(3));
        }
        node["udp"] = json!(true);
        let config =
            json!({"socks-port":socks_port, "proxies":[node], "rules":["MATCH,peer"]}).to_string();
        let baseline = open_fd_count();
        {
            let core = Core::start(&config);
            let listener = TcpListener::bind(origin_address(false)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut client = socks_login(proxy, false);
            let mut request = vec![5, 1, 0];
            request.extend_from_slice(&socks_address(listener.local_addr().unwrap()));
            request.extend_from_slice(b"alive");
            client.write_all(&request).unwrap();
            socks_reply(&mut client);
            let mut remote = accept_until(&listener);
            let mut bytes = [0; 5];
            remote.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"alive");
            remote.write_all(b"alive").unwrap();
            client.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"alive");
            let origin = UdpSocket::bind(origin_address(false)).unwrap();
            origin.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            let mut control = socks_login(proxy, false);
            control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let relay = socks_reply(&mut control);
            let mut request = vec![0, 0, 0];
            request.extend_from_slice(&socks_address(origin.local_addr().unwrap()));
            request.extend_from_slice(b"alive");
            socket.send_to(&request, relay).unwrap();
            let mut bytes = [0; 128];
            let (size, peer) = origin.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], b"alive");
            origin.send_to(&bytes[..size], peer).unwrap();
            let (size, _) = socket.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], request);
            core.stop();
            assert_eq!(client.read(&mut bytes).unwrap(), 0);
            assert_eq!(control.read(&mut bytes).unwrap(), 0);
            assert_eq!(remote.read(&mut bytes).unwrap(), 0);
            // A late response must not reach the old association after Stop.
            origin.send_to(b"late", peer).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(socket.recv_from(&mut bytes).is_err());
            drop(TcpListener::bind(proxy).unwrap());
            drop(UdpSocket::bind(proxy).unwrap());
        }
        assert_fd_returned(baseline);
        // Reserve the SOCKS UDP port so startup must roll back its TCP listener.
        {
            let occupied = UdpSocket::bind(proxy).unwrap();
            let id = invoke("createInstance", None, json!({}))["instanceId"]
                .as_str()
                .unwrap()
                .to_owned();
            let owner = Core(Some(id));
            invoke("prepare", owner.0.as_deref(), json!({"configYaml":config}));
            assert_eq!(
                invoke_response("start", owner.0.as_deref(), json!({}))["success"],
                false
            );
            assert_ne!(
                invoke("getState", owner.0.as_deref(), json!({}))["state"],
                "running"
            );
            owner.stop();
            drop(TcpListener::bind(proxy).unwrap());
            drop(occupied);
            drop(UdpSocket::bind(proxy).unwrap());
        }
        assert_fd_returned(baseline);
        {
            let listener = TcpListener::bind(origin_address(false)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let task = thread::spawn(move || {
                let mut remote = buffered(accept_until(&listener));
                assert!(head(&mut remote).starts_with("HEAD /"));
                remote
                    .get_mut()
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .unwrap();
                assert_eq!(remote.read(&mut [0; 1]).unwrap(), 0);
            });
            let data = invoke(
                "measureDelay",
                None,
                json!({"configYamls":[json!({"proxies":[node]}).to_string()],"timeout":5,"url":format!("http://{address}/")}),
            );
            task.join().unwrap();
            assert_eq!(data["results"][0]["success"], true);
        }
        assert_fd_returned(baseline);
        println!(
            "PASS lifecycle {}: active TCP/UDP Stop, failed-start rollback, measurement cleanup; FD baseline={baseline:?}",
            fixture["cipher"].as_str().unwrap_or(kind)
        );
    }
}

pub(super) fn open_fd_count() -> Option<usize> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Some(std::fs::read_dir("/dev/fd").unwrap().count())
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        None
    }
}

pub(super) fn assert_fd_returned(baseline: Option<usize>) {
    if let Some(baseline) = baseline {
        assert!(
            open_fd_count().unwrap() <= baseline,
            "VCore process retained descriptors after cleanup"
        );
    }
}
