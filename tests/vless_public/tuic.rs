//! TUIC public consumers. No protocol server is started on the host.
use super::*;
use vcore::resources::observation::ResourceProbe;

fn save(value: Value) {
    std::fs::write(
        std::env::var("VCORE_TUIC_OBSERVATIONS").unwrap(),
        value.to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned TUIC UDP container fixture required"]
fn udp() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("TUIC-PUBLIC", "udp");
    let probe = ResourceProbe::default();
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    let mut associations = Vec::new();
    let mut alternates = Vec::new();
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        let mut udp = Association::new(&f, port, ipv6, domain);
        let mut other = Origin::new(&f, if ipv6 { 6 } else { 4 }, ipv6);
        for size in [0, 1, 64, 512, 1200, 4096, 16384] {
            for sequence in 0..100_u8 {
                std::mem::swap(&mut udp.origin, &mut other);
                udp.exchange(&vec![sequence; size]);
            }
        }
        associations.push(udp);
        alternates.push(other);
    }
    echo(port, &f);
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    for udp in &mut associations {
        udp.origin.quiet();
    }
    for origin in &mut alternates {
        origin.quiet();
    }
    save(
        json!({"udp_packets":2100,"udp_sizes":[0,1,64,512,1200,4096,16384],"families":["ipv4","ipv6","domain"],"alternating_origins":true,"tcp_sibling":true,"stop_idle":true}),
    );
}

#[test]
#[ignore = "owned TUIC container fixture required"]
fn tcp() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("TUIC-PUBLIC", "tcp");
    let probe = ResourceProbe::default();
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    // Keep several logical streams live on one node, across address families.
    let mut origins = Vec::new();
    let mut clients = Vec::new();
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        let mut origin = Origin::new(&f, 13, ipv6);
        let mut io = connect(port, origin.target, domain);
        let mut upload = Sha256::new();
        let mut download = Sha256::new();
        for sequence in 0..2560_u32 {
            let bytes: Vec<u8> = (0..4096).map(|i| ((i + sequence) % 251) as u8).collect();
            io.write_all(&bytes).unwrap();
            if sequence == 0 {
                origin.marker(b'A');
            }
            let mut reply = vec![0; bytes.len()];
            io.read_exact(&mut reply).unwrap();
            assert_eq!(reply, bytes);
            upload.update(bytes);
            download.update(reply);
        }
        assert_eq!(upload.finalize(), download.finalize());
        origins.push(origin);
        clients.push(io);
    }
    // One client closes, its siblings remain functional on the same pool.
    clients
        .remove(0)
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    origins.remove(0).marker(b'D');
    for client in &mut clients {
        client.write_all(b"sibling").unwrap();
        let mut bytes = [0; 7];
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"sibling");
    }
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    for client in &mut clients {
        runtime::assert_closed(client);
    }
    for origin in &mut origins {
        origin.marker(b'D');
        origin.quiet();
    }
    save(
        json!({"families":["ipv4","ipv6","domain"],"tcp_bytes_each_family_each_direction":10*1024*1024,"sibling_survives":true,"stop_idle":true}),
    );
}

#[test]
#[ignore = "owned TUIC rejection container fixture required"]
fn rejected() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("TUIC-PUBLIC", "rejected");
    let probe = ResourceProbe::default();
    let port = free_port();
    let mut yaml = config(f["node"].clone(), port);
    if let Some(upstream) = f.get("upstream") {
        yaml["proxies"]
            .as_array_mut()
            .unwrap()
            .push(upstream.clone());
        yaml["proxies"][0]["dialer-proxy"] = json!("hop");
    }
    let core = probe.scope_sync(|| Core::start(&yaml));
    let mut origin = Origin::new(&f, 13, false);
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    request.extend_from_slice(b"must-not-reach-origin");
    client.write_all(&request).unwrap();
    let mut header = [0; 3];
    match client.read_exact(&mut header) {
        Ok(_) => {
            assert_eq!(header[0], 5);
            assert_eq!(header[2], 0);
            if header[1] == 0 {
                // TUIC has no auth ACK: local SOCKS success can precede rejection.
                let mut atyp = [0];
                client.read_exact(&mut atyp).unwrap();
                let length = match atyp[0] {
                    1 => 6,
                    4 => 18,
                    _ => panic!("invalid SOCKS reply"),
                };
                client.read_exact(&mut vec![0; length]).unwrap();
                runtime::assert_closed(&mut client);
            }
        }
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        )),
    }
    origin.quiet();
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    origin.quiet();
    save(json!({"origin_connected":false,"received_business_bytes":0,"stop_idle":true}));
}

#[test]
#[ignore = "owned TUIC business UDP policy fixture required"]
fn udp_disabled() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("TUIC-PUBLIC", "udp_disabled");
    assert_eq!(f["node"]["udp"], false);
    let probe = ResourceProbe::default();
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    echo(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.client
        .send_to(&udp.packet(b"disabled"), udp.relay)
        .unwrap();
    udp.client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let error = udp.client.recv_from(&mut [0; 128]).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    udp.origin.quiet();
    core.stop();
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    udp.origin.quiet();
    save(json!({"udp_packets":0,"tcp_works":true,"stop_idle":true}));
}

#[test]
#[ignore = "owned TUIC upstream and restart fixture required"]
fn group() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("TUIC-PUBLIC", "group");
    let probe = ResourceProbe::default();
    let port = free_port();
    let controller = free_port();
    let mut yaml = config(f["node"].clone(), port);
    yaml["proxies"]
        .as_array_mut()
        .unwrap()
        .push(f["upstream"].clone());
    yaml["proxies"][0]["dialer-proxy"] = json!("outer");
    yaml["proxy-groups"] = json!([
        {"name":"outer","type":"select","proxies":["inner"]},
        {"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}
    ]);
    yaml["external-controller"] = json!(format!("127.0.0.1:{controller}"));
    yaml["secret"] = json!("fixture-only");
    let core = probe.scope_sync(|| Core::start(&yaml));
    let (mut old, mut origin) = runtime::live(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    udp.exchange(b"old-path");
    runtime::select(controller, "REJECT");
    runtime::exchange(&mut old, b"old-stream");
    // Logical flows on the already established QUIC pool retain its path.
    echo(port, &f);
    let mut pooled = Association::new(&f, port, false, false);
    pooled.exchange(b"new-logical-existing-pool");
    let mut control = socket(f["restart_control"].as_str().unwrap().parse().unwrap());
    control.write_all(b"R").unwrap();
    let mut ack = [0];
    control.read_exact(&mut ack).unwrap();
    assert_eq!(ack, [b'R']);
    old.set_read_timeout(Some(Duration::from_secs(35))).unwrap();
    runtime::assert_closed(&mut old);
    origin.marker(b'D');
    let mut denied_origin = Origin::new(&f, 13, false);
    let mut denied = login(port);
    let mut connect = vec![5, 1, 0];
    connect.extend(address(denied_origin.target, false));
    connect.extend_from_slice(b"no-fallback");
    denied.write_all(&connect).unwrap();
    let mut reply = [0; 3];
    denied.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 5);
    assert_ne!(reply[1], 0);
    denied_origin.quiet();
    runtime::select(controller, "DIRECT");
    echo(port, &f);
    let mut fresh = Association::new(&f, port, false, false);
    fresh.exchange(b"new-physical-direct");
    let start = Instant::now();
    core.stop();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    udp.origin.quiet();
    pooled.origin.quiet();
    fresh.origin.quiet();
    denied_origin.quiet();
    drop((old, origin, udp, pooled, fresh, denied, denied_origin));

    let mut measure_origin = Origin::new(&f, 14, false);
    let result=probe.scope_sync(||invoke("measureDelay",None,json!({"configYamls":[json!({"proxies":[f["node"]]}).to_string()],"timeout":5,"url":format!("http://{}/",measure_origin.target)})));
    assert_eq!(result["results"][0]["success"], true);
    measure_origin.marker(b'A');
    measure_origin.marker(b'D');
    let rejected = invoke(
        "measureDelay",
        None,
        json!({"configYamls":[json!({"proxies":[f["node"]],"proxy-groups":[{"name":"group","type":"select","proxies":["peer"]}]}).to_string()],"timeout":5,"url":format!("http://{}/",measure_origin.target)}),
    );
    assert_eq!(rejected["results"][0]["success"], false);
    measure_origin.quiet();
    assert!(probe.snapshot().is_idle());
    drop(measure_origin);
    let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    let prepared = probe.scope_sync(|| Core::prepare(&yaml));
    assert_eq!(
        probe.scope_sync(|| invoke_response("start", prepared.0.as_deref(), json!({})))["success"],
        false
    );
    prepared.stop();
    drop(occupied);
    assert!(probe.snapshot().is_idle());
    let rebuilt = probe.scope_sync(|| Core::start(&yaml));
    echo(port, &f);
    rebuilt.stop();
    assert!(probe.snapshot().is_idle());
    save(
        json!({"nested_select":true,"pooled_path_retained":true,"explicit_rebuild":true,"reject_no_fallback":true,"new_direct":true,"node_measure":true,"group_measure_rejected":true,"rollback":true,"stop_idle":true}),
    );
}
