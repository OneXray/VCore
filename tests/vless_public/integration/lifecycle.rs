use super::*;

const NEW_PROTOCOLS: [&str; 4] = ["trojan", "vmess", "vless", "hysteria2"];

pub(super) fn fd_count() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

fn quiet_reader(stream: &mut TcpStream) {
    stream.set_nonblocking(true).unwrap();
    let result = stream.read(&mut [0; 8]);
    assert!(
        matches!(result, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "origin emitted data after Stop"
    );
}

#[test]
#[ignore = "owned INTEGRATION container fixture required; at least 500 seconds"]
fn public_lifetimes() {
    lifetimes(100);
}

#[test]
#[ignore = "owned INTEGRATION container fixture required; development subset only"]
fn lifecycle_tracer() {
    lifetimes(20);
}

fn lifetimes(count: usize) {
    let f = fixture();
    initialize(&f);
    for protocol in NEW_PROTOCOLS {
        let port = free_port();
        let core = Core::start(&config(f["nodes"][protocol].clone(), port));
        echo(port, &f);
        core.stop();
    }
    let mut observations = Vec::new();
    for cycle in 0..count {
        let protocol = NEW_PROTOCOLS[(cycle / 5) % NEW_PROTOCOLS.len()];
        let mode = cycle % 5;
        let mut case = RecordedCase::new("INTEGRATION-LIFECYCLE", "stop_and_remain_quiet");
        let probe = ResourceProbe::default();
        case.checkpoint("baseline", probe.snapshot());
        let baseline = fd_count();
        let port = free_port();
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        let mut blackhole = None;
        let mut pending_client = None;
        let mut occupied = None;
        let mut node = f["nodes"][protocol].clone();
        if mode == 2 {
            let origin = Origin::new(&f, if protocol == "hysteria2" { 20 } else { 15 }, false);
            node["server"] = json!(origin.target.ip().to_string());
            node["port"] = json!(origin.target.port());
            blackhole = Some(origin);
        }
        let yaml = config(node, port);
        let core = probe.scope_sync(|| {
            if mode == 3 {
                occupied = Some(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap());
                let core = Core::prepare(&yaml);
                assert_eq!(
                    invoke_response("start", core.0.as_deref(), json!({}))["success"],
                    false
                );
                core
            } else {
                Core::start(&yaml)
            }
        });
        match mode {
            0 => echo(port, &f),
            2 => {
                let origin = blackhole.as_mut().unwrap();
                let mut client = login(port);
                let mut request = vec![5, 1, 0];
                request.extend(address(origin.target, false));
                client.write_all(&request).unwrap();
                origin.marker(b'A');
                pending_client = Some(client);
            }
            3 => {}
            _ => {
                let (first, mut first_origin) = runtime::live(port, &f);
                let (mut second, second_origin) = runtime::live(port, &f);
                let mut one = Association::new(&f, port, false, false);
                let mut two = Association::new(&f, port, false, false);
                one.exchange(b"first-association");
                two.exchange(b"second-association");
                if mode == 4 {
                    drop(first);
                    first_origin.marker(b'D');
                    runtime::exchange(&mut second, b"sibling-survives-cancel");
                    one.exchange(b"udp-sibling-one");
                    two.exchange(b"udp-sibling-two");
                } else {
                    tcp.push((first, first_origin));
                }
                tcp.push((second, second_origin));
                udp.extend([one, two]);
            }
        }
        let active = probe.snapshot();
        case.checkpoint("active", active.clone());
        let stopping = Instant::now();
        core.stop();
        let stop_ms = stopping.elapsed().as_millis();
        assert!(stop_ms < 5000);
        let stopped = probe.snapshot();
        assert!(stopped.is_idle(), "cycle {cycle}: {stopped:?}");
        case.checkpoint("after-stop", stopped.clone());
        drop(occupied);
        drop(pending_client);
        for (client, origin) in &mut tcp {
            runtime::assert_closed(client);
            origin.marker(b'D');
        }
        for association in &mut udp {
            runtime::assert_closed(&mut association.control);
            association.client.set_nonblocking(true).unwrap();
        }
        if let Some(origin) = &mut blackhole
            && protocol != "hysteria2"
        {
            origin.marker(b'D');
        }
        let retained = 2 * tcp.len() + 3 * udp.len() + usize::from(blackhole.is_some());
        let after_stop = fd_count();
        assert!(
            after_stop <= baseline + retained,
            "cycle {cycle}: FD retained at Stop: {after_stop} > {}",
            baseline + retained
        );
        let rebound_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        let rebound_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        let quiet = Instant::now();
        while quiet.elapsed() < Duration::from_secs(5) {
            assert_eq!(probe.snapshot(), stopped, "resource activity after Stop");
            assert!(fd_count() <= baseline + retained + 2);
            for (_, origin) in &mut tcp {
                quiet_reader(&mut origin.observer);
            }
            for association in &mut udp {
                assert_eq!(
                    association.client.recv(&mut [0; 32]).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                quiet_reader(&mut association.origin.observer);
            }
            if let Some(origin) = &mut blackhole {
                quiet_reader(&mut origin.observer);
            }
            thread::sleep(Duration::from_millis(25));
        }
        let quiet_seconds = quiet.elapsed().as_secs_f64();
        case.checkpoint("quiet", probe.snapshot());
        case.resources(probe.snapshot());
        drop((tcp, udp, blackhole, rebound_tcp, rebound_udp));
        let end = fd_count();
        assert!(end <= baseline);
        observations.push(json!({"cycle":cycle,"protocol":protocol,"mode":mode,"baseline_fd":baseline,"retained_fixture_fd":retained,"after_stop_fd":after_stop,"final_fd":end,"stop_ms":stop_ms,"quiet_seconds":quiet_seconds,"active":active,"after_stop":stopped,"quiet":probe.snapshot(),"ports_rebound":true}));
        println!("INTEGRATION lifecycle: {}/{count}", cycle + 1);
    }
    observe(json!({"count":count,"cycles":observations}));
}
