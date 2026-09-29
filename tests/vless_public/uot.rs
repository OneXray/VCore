//! Public UoT consumers. Every protocol peer, DNS and origin is container-owned.
use super::*;
use vcore::resources::observation::ResourceProbe;

fn no_native_udp(f: &Value) {
    let mut observer = socket(f["udp_observer"].as_str().unwrap().parse().unwrap());
    observer.write_all(b"?").unwrap();
    let counts: Value = serde_json::from_reader(observer.take(4096)).unwrap();
    assert_eq!(counts["native_udp_packets"], 0);
    assert!(
        counts["ports"]
            .as_array()
            .unwrap()
            .contains(&f["node"]["port"])
    );
}

fn save(value: Value) {
    std::fs::write(
        std::env::var("VCORE_UOT_OBSERVATIONS").unwrap(),
        value.to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned UoT container fixture required"]
fn data() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("UOT-PUBLIC", "data");
    let probe = ResourceProbe::default();
    let port = free_port();
    let mut dns_origin = Origin::new(&f, 17, false);
    let mut yaml = config(f["node"].clone(), port);
    if let Some(upstream) = f.get("upstream") {
        assert_eq!(upstream["udp"], false);
        yaml["proxies"]
            .as_array_mut()
            .unwrap()
            .push(upstream.clone());
        yaml["proxies"][0]["dialer-proxy"] = json!("hop");
    }
    dns(&mut yaml, &dns_origin, "DIRECT");
    let core = probe.scope_sync(|| Core::start(&yaml));
    echo(port, &f);
    let mut associations = Vec::new();
    let mut alternates = Vec::new();
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        let mut association = Association::new(&f, port, ipv6, domain);
        let mut alternate = Origin::new(&f, if ipv6 { 6 } else { 4 }, ipv6);
        for size in [0, 1, 64, 512, 1200, 4096, 16_384] {
            for sequence in 0..100_u8 {
                std::mem::swap(&mut association.origin, &mut alternate);
                association.exchange(&vec![sequence; size]);
            }
        }
        // The official Mihomo UoT reader uses a 16 KiB packet buffer. One byte
        // beyond it fails at that peer; this is not VCore's u16 codec ceiling.
        let oversize = vec![7; 16_385];
        association
            .client
            .send_to(&association.packet(&oversize), association.relay)
            .unwrap();
        association.origin.quiet();
        association
            .client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let error = association.client.recv_from(&mut [0; 32]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        association.client.set_read_timeout(Some(TIMEOUT)).unwrap();
        associations.push(association);
        alternates.push(alternate);
    }
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    // The controlled resolver accepts only this business name. Internal UoT
    // magic reaching DNS would make the fixture reject the request.
    let mut header = [0; 4];
    dns_origin.observer.read_exact(&mut header).unwrap();
    let mut question = vec![0; u16::from_be_bytes([header[0], header[1]]) as usize];
    dns_origin.observer.read_exact(&mut question).unwrap();
    assert_eq!(&question[12..], b"\x0dvcore-fixture\x04test\0\0\x01\0\x01");
    for association in &mut associations {
        association.origin.quiet();
    }
    for origin in &mut alternates {
        origin.quiet();
    }
    no_native_udp(&f);
    save(json!({
        "udp_packets":2100,"udp_sizes":[0,1,64,512,1200,4096,16384],
        "families":["ipv4","ipv6","domain"],"alternating_origins":true,
        "controlled_dns":true,"tcp_regression":true,"stop_idle":true,
        "tcp_only_upstream":f.get("upstream").is_some(),
        "peer_oversize_rejected":true,"native_udp_packets":0
    }));
}

#[test]
#[ignore = "owned UoT TCP-only upstream fixture required"]
fn group() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("UOT-PUBLIC", "group");
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
    let mut existing = Association::new(&f, port, false, false);
    existing.exchange(b"initial-hop");
    runtime::select(controller, "REJECT");
    existing.exchange(b"old-association-snapshot");
    let mut rejected = Association::new(&f, port, false, false);
    rejected
        .client
        .send_to(&rejected.packet(b"must-not-fallback"), rejected.relay)
        .unwrap();
    rejected.origin.quiet();
    runtime::select(controller, "DIRECT");
    let mut direct = Association::new(&f, port, false, false);
    direct.exchange(b"new-direct-association");
    existing.exchange(b"still-original-hop");
    core.stop();
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    existing.origin.quiet();
    direct.origin.quiet();
    rejected.origin.quiet();
    no_native_udp(&f);
    save(
        json!({"nested_select":true,"old_association_snapshot":true,"new_direct":true,
        "reject_no_fallback":true,"native_udp_packets":0,"stop_idle":true}),
    );
}

#[test]
#[ignore = "owned UoT negative peer fixture required"]
fn rejected() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("UOT-PUBLIC", "rejected");
    let probe = ResourceProbe::default();
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    let mut association = Association::new(&f, port, false, false);
    let bytes = association.packet(b"must-not-reach-origin");
    association
        .client
        .send_to(&bytes, association.relay)
        .unwrap();
    association
        .client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let error = association.client.recv_from(&mut [0; 128]).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    association.origin.quiet();
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    association.origin.quiet();
    no_native_udp(&f);
    save(json!({"origin_packets":0,"received_packets":0,"native_udp_packets":0,"stop_idle":true}));
}
