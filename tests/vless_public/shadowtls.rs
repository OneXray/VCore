//! Public SS + ShadowTLS consumers; peers and origins belong to the container lab.
use super::*;
use vcore::resources::observation::ResourceProbe;

fn fault_counts(f: &Value) -> Value {
    let mut io = socket(f["fault_control"].as_str().unwrap().parse().unwrap());
    io.write_all(b"?").unwrap();
    serde_json::from_reader(io.take(1024)).unwrap()
}

fn await_count(f: &Value, field: &str, expected: u64) {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let count = fault_counts(f)[field].as_u64().unwrap();
        if count == expected {
            return;
        }
        assert!(
            count < expected && Instant::now() < until,
            "{field}: {count}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "owned ShadowTLS stalled handshake container fixture required"]
fn stall() {
    let f = fixture();
    initialize(&f);
    let probe = ResourceProbe::default();
    let _case = RecordedCase::new("SHADOWTLS", "stall");
    let baseline = fault_counts(&f);
    let seen = baseline["hello_seen"].as_u64().unwrap();
    let closed = baseline["client_closed"].as_u64().unwrap();
    assert_eq!(seen, closed);
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    let mut origin = Origin::new(&f, 13, false);
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    request.extend_from_slice(b"must-not-reach-origin");
    client.write_all(&request).unwrap();
    await_count(&f, "hello_seen", seen + 1);
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    await_count(&f, "client_closed", closed + 1);
    // A SOCKS failure response may precede EOF. It must never be a success.
    let mut tail = Vec::new();
    match client.take(64).read_to_end(&mut tail) {
        Ok(_) => {}
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::ConnectionReset),
    }
    assert!(tail.is_empty() || tail.len() >= 2 && tail[0] == 5 && tail[1] != 0);
    origin.quiet();

    let before = Instant::now();
    let response = probe.scope_sync(|| {
        invoke(
            "measureDelay",
            None,
            json!({"configYamls":[json!({"proxies":[f["node"]]}).to_string()],
                "timeout":1,"url":format!("http://{}/",origin.target)}),
        )
    });
    assert_eq!(response["results"][0]["success"], false);
    assert!((Duration::from_millis(800)..Duration::from_secs(3)).contains(&before.elapsed()));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    await_count(&f, "hello_seen", seen + 2);
    await_count(&f, "client_closed", closed + 2);
    origin.quiet();
    std::fs::write(
        std::env::var("VCORE_SHADOWTLS_OBSERVATIONS").unwrap(),
        json!({"stop_idle":true,"stop_handshake_cancelled":true,
            "measure_deadline":true,"origin_connected":false,"closed_handshakes":2})
        .to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned TCP-only ShadowTLS container fixture required"]
fn native_udp_disabled() {
    let f = fixture();
    initialize(&f);
    let probe = ResourceProbe::default();
    let _case = RecordedCase::new("SHADOWTLS", "native_udp_disabled");
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    echo(port, &f);
    let mut udp = Association::new(&f, port, false, false);
    let packet = udp.packet(b"no-implicit-uot");
    udp.client.send_to(&packet, udp.relay).unwrap();
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
    std::fs::write(
        std::env::var("VCORE_SHADOWTLS_OBSERVATIONS").unwrap(),
        json!({"tcp_accepted":true,"udp_delivered":false,"stop_idle":true}).to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned ShadowTLS fault container fixture required"]
fn corrupt() {
    let f = fixture();
    initialize(&f);
    let probe = ResourceProbe::default();
    let _case = RecordedCase::new("SHADOWTLS", "corrupt");
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    let mut origin = Origin::new(&f, 13, false);
    let mut client = connect(port, origin.target, false);
    client.write_all(b"must-not-be-delivered-back").unwrap();
    origin.marker(b'A');
    match client.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::BrokenPipe
        )),
        other => panic!("corrupted authenticated response was delivered: {other:?}"),
    }
    core.stop();
    assert!(probe.snapshot().is_idle());
    origin.marker(b'D');
    origin.quiet();
    std::fs::write(
        std::env::var("VCORE_SHADOWTLS_OBSERVATIONS").unwrap(),
        json!({"origin_connected":true, "delivered_bytes":0, "stop_idle":true}).to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned ShadowTLS container fixture required"]
fn policy() {
    let f = fixture();
    initialize(&f);
    let probe = ResourceProbe::default();
    let _case = RecordedCase::new("SHADOWTLS", "policy");
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    let mut origin = Origin::new(&f, 13, false);
    let success = f["expected_success"].as_bool().unwrap();
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    // Pipeline business bytes to prove that failed identity cannot reach the
    // business origin. A transport timeout is never an authentication success.
    request.extend_from_slice(b"authenticated-business");
    client.write_all(&request).unwrap();
    if success {
        reply(&mut client);
        let mut bytes = [0; 22];
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"authenticated-business");
        origin.marker(b'A');
    } else {
        let mut header = [0; 3];
        client.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 5);
        assert_ne!(
            header[1], 0,
            "authentication must fail before SOCKS success"
        );
        assert_eq!(header[2], 0);
        origin.quiet();
    }
    core.stop();
    assert!(probe.snapshot().is_idle());
    if success {
        origin.marker(b'D');
    }
    origin.quiet();
    std::fs::write(
        std::env::var("VCORE_SHADOWTLS_OBSERVATIONS").unwrap(),
        json!({"accepted":success,"origin_connected":success,"stop_idle":true}).to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned ShadowTLS container fixture required"]
fn data() {
    data_gate(true);
}

#[test]
#[ignore = "owned native ShadowTLS and SS container fixture required"]
fn native_tcp() {
    data_gate(false);
}

fn data_gate(native_udp: bool) {
    let f = fixture();
    initialize(&f);
    let probe = ResourceProbe::default();
    let _case = RecordedCase::new("SHADOWTLS", if native_udp { "data" } else { "native_tcp" });
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    // Client-first avoids the documented official SS empty-first-write padding
    // limitation. This is not used as evidence of server-first support.
    let mut origin = Origin::new(&f, 13, false);
    let mut client = connect(port, origin.target, false);
    let mut upload = Sha256::new();
    let mut download = Sha256::new();
    for sequence in 0..2560_u32 {
        let bytes: Vec<u8> = (0..4096).map(|n| ((n + sequence) % 251) as u8).collect();
        client.write_all(&bytes).unwrap();
        if sequence == 0 {
            origin.marker(b'A');
        }
        let mut reply = vec![0; bytes.len()];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, bytes);
        upload.update(&bytes);
        download.update(&reply);
    }
    assert_eq!(upload.finalize(), download.finalize());
    let mut udp = native_udp.then(|| Association::new(&f, port, false, false));
    if let Some(udp) = udp.as_mut() {
        for size in [1, 64, 512, 1200, 4096] {
            for sequence in 0..100_u8 {
                udp.exchange(&vec![sequence; size]);
            }
        }
    }
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    runtime::assert_closed(&mut client);
    origin.marker(b'D');
    origin.quiet();
    let observation = json!({"tcp_bytes_each_direction":10*1024*1024,"udp_packets":if native_udp {500} else {0},"udp_sizes":if native_udp {vec![1,64,512,1200,4096]} else {vec![]},"stop_idle":true});
    std::fs::write(
        std::env::var("VCORE_SHADOWTLS_OBSERVATIONS").unwrap(),
        observation.to_string(),
    )
    .unwrap();
}
