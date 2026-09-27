//! N9 consumers share the established public Invoke/SOCKS/origin boundaries.
use super::*;
use vcore::resources::observation::{QueueKind, ResourceKind, ResourceProbe};

mod connector;
mod lifecycle;
#[cfg(target_os = "macos")]
mod pressure;
mod shadowsocks;

#[test]
#[ignore = "owned N9 container fixture required"]
fn resource_tracer() {
    let f = fixture();
    initialize(&f);
    for protocol in PROTOCOLS {
        let mut case = RecordedCase::new("N9-RESOURCE-TRACER", protocol);
        let probe = ResourceProbe::default();
        case.checkpoint("baseline", probe.snapshot());
        let port = free_port();
        let core = probe.scope_sync(|| Core::start(&config(f["nodes"][protocol].clone(), port)));
        let (mut tcp, mut origin) = runtime::live(port, &f);
        let mut udp = Association::new(&f, port, false, false);
        udp.exchange(b"observable");
        let active = probe.snapshot();
        assert!(
            active.current(ResourceKind::Socket) > 0,
            "missing Invoke resource scope: {protocol}"
        );
        assert!(
            active.current(ResourceKind::Task) > 0,
            "runtime tasks are not observed: {protocol}"
        );
        let queues = probe.queues();
        let udp_queue = &queues[QueueKind::SocksUdp as usize];
        assert_eq!(udp_queue.capacity, 16);
        assert!((1..=16).contains(&udp_queue.peak));
        if protocol == "hysteria2" {
            assert!(queues.iter().all(|q| q.peak > 0 && q.peak <= q.capacity));
        }
        case.checkpoint("active", active);
        core.stop();
        assert!(
            probe.snapshot().is_idle(),
            "{protocol}: {:?}",
            probe.snapshot()
        );
        case.checkpoint("after-stop", probe.snapshot());
        runtime::assert_closed(&mut tcp);
        origin.marker(b'D');
        runtime::assert_closed(&mut udp.control);
        case.resources(probe.snapshot());
    }
    observe(json!({"protocols":PROTOCOLS,"active_observed":true,"stop_idle":true}));
}

const PROTOCOLS: [&str; 7] = [
    "socks5",
    "anytls",
    "ss",
    "trojan",
    "vmess",
    "vless",
    "hysteria2",
];

fn observe(value: Value) {
    std::fs::write(
        std::env::var("VCORE_N9_OBSERVATIONS").unwrap(),
        value.to_string(),
    )
    .unwrap();
}

fn denied_target(port: u16, f: &Value) {
    let mut origin = Origin::new(f, 13, false);
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    client.write_all(&request).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    assert_ne!(response[1], 0);
    origin.quiet();
}

#[test]
#[ignore = "owned N9 container fixture required"]
fn graph() {
    let f = fixture();
    initialize(&f);
    for protocol in PROTOCOLS {
        let _case = RecordedCase::new("N9-GRAPH", protocol);
        let port = free_port();
        let controller = free_port();
        let mut node = f["nodes"][protocol].clone();
        node["dialer-proxy"] = json!("outer");
        let mut yaml = json!({"socks-port":port,"external-controller":format!("127.0.0.1:{controller}"),"secret":"fixture-only","proxies":[node,f["hop"]],"proxy-groups":[{"name":"outer","type":"select","proxies":["inner"]},{"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}],"rules":["MATCH,peer"]});
        let core = Core::start(&yaml);
        let (mut old, mut origin) = runtime::live(port, &f);
        let mut udp = Association::new(&f, port, false, false);
        udp.exchange(b"before-group-switch");
        runtime::select(controller, "REJECT");
        runtime::exchange(&mut old, b"old-transport-snapshot");
        udp.exchange(b"old-udp-snapshot");
        if protocol == "hysteria2" {
            echo(port, &f); // Reuse is allowed only on the old physical session.
        } else {
            // AnyTLS reuses idle sessions, not a session with an active stream;
            // both its TCP and UoT sessions are deliberately held active here.
            denied_target(port, &f);
        }
        runtime::select(controller, "DIRECT");
        echo(port, &f);
        runtime::exchange(&mut old, b"still-old-transport");
        core.stop();
        runtime::assert_closed(&mut old);
        origin.marker(b'D');
        drop((old, origin, udp));
        // No pool exists in a fresh session: REJECT must deny every protocol.
        yaml["proxy-groups"][1]["proxies"] = json!(["REJECT", "hop", "DIRECT"]);
        let core = Core::start(&yaml);
        denied_target(port, &f);
        core.stop();
        yaml["proxy-groups"][1]["proxies"] = json!(["DIRECT", "peer"]);
        assert_eq!(
            invoke_response(
                "validateConfig",
                None,
                json!({"configYaml":yaml.to_string()})
            )["success"],
            false
        );
        yaml["proxy-groups"][1]["proxies"] = json!(["hop", "DIRECT"]);
        yaml["proxies"][1]["port"] = json!(1);
        let core = Core::start(&yaml);
        denied_target(port, &f);
        core.stop();
    }
    observe(
        json!({"protocols":PROTOCOLS,"nested_select":true,"old_transport_snapshot":true,"cold_reject":true,"direct":true,"unselected_cycle":true,"no_fallback":true}),
    );
}

#[test]
#[ignore = "owned N9 container fixture required"]
fn dns_measure() {
    let f = fixture();
    initialize(&f);
    for protocol in PROTOCOLS {
        let _case = RecordedCase::new("N9-DNS-MEASURE", protocol);
        let node = f["nodes"][protocol].clone();
        let port = free_port();
        let mut dns_origin = Origin::new(&f, 17, false);
        let mut yaml = config(node.clone(), port);
        dns(&mut yaml, &dns_origin, "peer");
        yaml["proxy-groups"] = json!([{"name":"denied","type":"select","proxies":["REJECT"]}]);
        yaml["rules"] = json!([
            format!("IP-CIDR,{}/32,peer", f["origin_ipv4"].as_str().unwrap()),
            "MATCH,denied"
        ]);
        let core = Core::start(&yaml);
        let mut origin = Origin::new(&f, 13, false);
        let mut client = connect(port, origin.target, true);
        runtime::exchange(&mut client, b"controlled-dns-route");
        origin.marker(b'A');
        let mut header = [0; 4];
        dns_origin.observer.read_exact(&mut header).unwrap();
        let mut query = vec![0; u16::from_be_bytes([header[0], header[1]]) as usize];
        dns_origin.observer.read_exact(&mut query).unwrap();
        assert_eq!(&query[12..], b"\x0dvcore-fixture\x04test\0\0\x01\0\x01");
        core.stop();
        runtime::assert_closed(&mut client);
        origin.marker(b'D');
        drop((client, origin, dns_origin));
        let mut origin = Origin::new(&f, 14, false);
        let result = invoke(
            "measureDelay",
            None,
            json!({"configYamls":[json!({"proxies":[node]}).to_string()],"timeout":5,"url":format!("http://{}/",origin.target)}),
        );
        assert_eq!(result["results"][0]["success"], true);
        origin.marker(b'A');
        origin.marker(b'D');
        let rejected = invoke(
            "measureDelay",
            None,
            json!({"configYamls":[json!({"proxies":[node],"proxy-groups":[{"name":"group","type":"select","proxies":["peer"]}]}).to_string()],"timeout":5,"url":format!("http://{}/",origin.target)}),
        );
        assert_eq!(rejected["results"][0]["success"], false);
        origin.quiet();
    }
    observe(
        json!({"protocols":PROTOCOLS,"controlled_dns_via_proxy":true,"ip_rule_consumer":true,"node_measure":true,"group_measure_rejected":true}),
    );
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "owned N9 container fixture required"]
fn entrypoints() {
    let f = fixture();
    let mut observations = Vec::new();
    for protocol in PROTOCOLS {
        let _case = RecordedCase::new("N9-ENTRYPOINTS", protocol);
        let mut single = f.clone();
        single["node"] = f["nodes"][protocol].clone();
        runtime::entrypoints(&single);
        observations.push(json!({"protocol":protocol,"http_forward":true,"http_connect":true,"tun_tcp":true,"tun_udp":true,"tun_dns":true}));
    }
    std::fs::write(
        std::env::var("VCORE_N9_OBSERVATIONS").unwrap(),
        json!({"entrypoints":observations}).to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "owned N9 container fixture required"]
fn ss_bulk_stress() {
    let _case = RecordedCase::new("N9-SS", "bulk_stress");
    let f = fixture();
    initialize(&f);
    let port = free_port();
    let mut first = f["first"].clone();
    let mut last = f["last"].clone();
    assert_eq!(first["type"], "ss");
    assert_eq!(last["type"], "ss");
    first["name"] = json!("hop");
    last["dialer-proxy"] = json!("hop");
    let core =
        Core::start(&json!({"socks-port":port,"proxies":[last,first],"rules":["MATCH,peer"]}));
    for _ in 0..50 {
        bulk(port, &f, false, false);
    }
    core.stop();
}

#[test]
#[ignore = "owned N9 container fixture required"]
fn carrier_tracer() {
    let f = fixture();
    initialize(&f);
    observe(connector::carrier_pair(&f));
}

#[test]
#[ignore = "owned N9 container fixture required"]
fn ordered_pair() {
    let _case = RecordedCase::new("N9-PAIR", "ordered_pair");
    let f = fixture();
    initialize(&f);
    let mut observations = Vec::new();
    for outer_ipv6 in [false, true] {
        for grouped in [false, true] {
            let port = free_port();
            let mut first = f["first"].clone();
            let mut last = f["last"].clone();
            first["name"] = json!("hop");
            last["name"] = json!("peer");
            if outer_ipv6 {
                first["server"] = f["first_ipv6"].clone();
                last["server"] = f["last_ipv6"].clone();
            }
            last["dialer-proxy"] = json!(if grouped { "outer" } else { "hop" });
            let mut yaml = json!({"socks-port":port,"proxies":[last,first],"rules":["MATCH,peer"]});
            if grouped {
                yaml["proxy-groups"] = json!([
                    {"name":"outer","type":"select","proxies":["inner"]},
                    {"name":"inner","type":"select","proxies":["hop","DIRECT","REJECT"]}
                ]);
            }
            let core = Core::start(&yaml);
            for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
                bulk(port, &f, ipv6, domain);
            }
            echo(port, &f);
            // Keep source tuples alive until Stop. Trojan's documented Mihomo
            // domain-UDP gap is separately exercised with the official Xray
            // terminal below, retaining this very same first-hop protocol.
            let mut associations = Vec::new();
            let targets = if f["last"]["type"] == "trojan" {
                vec![(false, false), (true, false)]
            } else {
                vec![(false, false), (true, false), (false, true)]
            };
            let target_count = targets.len();
            for (ipv6, domain) in targets {
                let mut association = Association::new(&f, port, ipv6, domain);
                for size in [1, 64, 512, 1200] {
                    for sequence in 0..100_u8 {
                        association.exchange(&vec![sequence; size]);
                    }
                }
                associations.push(association);
            }
            core.stop();
            drop(associations);
            let _tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
            let _udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
            observations.push(json!({
                "outer_ipv6":outer_ipv6,"nested_select":grouped,
                "tcp_target_kinds":3,"tcp_bytes_each_direction":3*10*1024*1024,
                "udp_target_kinds":target_count,"udp_packets":target_count*400,"udp_sizes":[1,64,512,1200],
                "server_first":true,"client_first":true,"ports_rebound":true
            }));
        }
    }
    std::fs::write(
        std::env::var("VCORE_N9_OBSERVATIONS").unwrap(),
        json!({"first":f["first"]["type"],"last":f["last"]["type"],"paths":observations,"domain_native":domain_terminal(&f),"budgets":connector::budget_pair(&f),"routed_udp":routed_udp_pair(&f),"carrier_capability":connector::carrier_pair(&f)})
            .to_string(),
    )
    .unwrap();
}

fn routed_udp_pair(f: &Value) -> Value {
    let _case = RecordedCase::new("N9-PAIR", "routed_udp_permission");
    for enabled in [true, false] {
        let port = free_port();
        let mut first = f["first"].clone();
        first["name"] = json!("hop");
        first["udp"] = json!(false);
        let mut last = f["last"].clone();
        last["dialer-proxy"] = json!("hop");
        last["udp"] = json!(enabled);
        let core =
            Core::start(&json!({"socks-port":port,"proxies":[last,first],"rules":["MATCH,peer"]}));
        echo(port, f);
        let mut udp = Association::new(f, port, false, false);
        if enabled {
            udp.exchange(b"carrier-is-not-routed-business-udp");
        } else {
            let packet = udp.packet(b"routed-udp-denied");
            udp.client.send_to(&packet, udp.relay).unwrap();
            udp.origin.quiet();
        }
        core.stop();
    }
    json!({"upstream_business_udp_disabled":true,"carrier_tcp":true,"carrier_udp":true,"leaf_business_udp_rejected":true})
}

fn domain_terminal(f: &Value) -> Vec<Value> {
    if f["last"]["type"] != "trojan" {
        return vec![];
    }
    let _case = RecordedCase::new("N9-PAIR", "native_domain_terminal");
    let mut observations = Vec::new();
    for outer_ipv6 in [false, true] {
        for grouped in [false, true] {
            let port = free_port();
            let mut first = f["first"].clone();
            let mut last = f["domain_last"].clone();
            first["name"] = json!("hop");
            if outer_ipv6 {
                first["server"] = f["first_ipv6"].clone();
                last["server"] = f["domain_last_ipv6"].clone();
            }
            last["dialer-proxy"] = json!(if grouped { "outer" } else { "hop" });
            let mut yaml = json!({"socks-port":port,"proxies":[last,first],"rules":["MATCH,peer"]});
            if grouped {
                yaml["proxy-groups"] = json!([{"name":"outer","type":"select","proxies":["inner"]},{"name":"inner","type":"select","proxies":["hop"]}]);
            }
            let core = Core::start(&yaml);
            let mut udp = Association::new(f, port, false, true);
            for size in [1, 64, 512, 1200] {
                for sequence in 0..100_u8 {
                    udp.exchange(&vec![sequence; size]);
                }
            }
            core.stop();
            observations.push(json!({"outer_ipv6":outer_ipv6,"nested_select":grouped,"peer":"XR","udp_packets":400,"target":"domain"}));
        }
    }
    observations
}
