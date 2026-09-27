use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn cipher(node: &Value) -> &'static str {
    match node["cipher"].as_str().unwrap() {
        "2022-blake3-aes-128-gcm" => "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm" => "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305" => "2022-blake3-chacha20-poly1305",
        _ => panic!("unexpected SS algorithm"),
    }
}

pub(super) fn rejected(node: Value, f: &Value) {
    let port = free_port();
    let probe = ResourceProbe::default();
    let core = probe.scope_sync(|| Core::start(&config(node, port)));
    let mut origin = Origin::new(f, 13, false);
    let mut client = login(port);
    let mut request = vec![5, 1, 0];
    request.extend(address(origin.target, false));
    client.write_all(&request).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    if response[1] == 0 {
        let _ = client.write_all(b"invalid-identity-must-not-reach-origin");
        runtime::assert_closed(&mut client);
    }
    origin.quiet();
    core.stop();
    assert!(probe.snapshot().is_idle());
    origin.quiet();
}

#[test]
#[ignore = "owned N9 official Mihomo container required"]
fn algorithms() {
    let f = fixture();
    initialize(&f);
    let nodes = f["ss_nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 3);
    let mut observations = Vec::new();
    for node in nodes {
        let _case = RecordedCase::new("N9-SS-ALGORITHMS", cipher(node));
        let port = free_port();
        let core = Core::start(&config(node.clone(), port));
        for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
            bulk(port, &f, ipv6, domain);
            let mut udp = Association::new(&f, port, ipv6, domain);
            for size in [1, 64, 512, 1200, 4096] {
                for sequence in 0..100_u8 {
                    udp.exchange(&vec![sequence; size]);
                }
            }
        }
        core.stop();
        let mut bad = node.clone();
        let length = if node["cipher"] == "2022-blake3-aes-128-gcm" {
            16
        } else {
            32
        };
        bad["password"] = json!(STANDARD.encode(vec![23; length]));
        rejected(bad, &f);
        observations.push(json!({"cipher":node["cipher"],"tcp_targets":3,"tcp_bytes_each_direction":31457280,"udp_targets":3,"udp_packets":1500,"wrong_key_rejected":true}));
    }
    observe(json!({"algorithms":observations}));
}

#[test]
#[ignore = "owned N9 official ssserver container required"]
fn eih() {
    let f = fixture();
    initialize(&f);
    let nodes = f["eih_nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    let mut observations = Vec::new();
    for node in nodes {
        let _case = RecordedCase::new("N9-SS-EIH", cipher(node));
        for outer_ipv6 in [false, true] {
            let port = free_port();
            let mut node = node.clone();
            if outer_ipv6 {
                node["server"] = f["eih_ipv6"].clone();
            }
            let core = Core::start(&config(node, port));
            for ipv6 in [false, true] {
                bulk(port, &f, ipv6, false);
                let mut udp = Association::new(&f, port, ipv6, false);
                for size in [1, 64, 512, 1200, 4096] {
                    println!("EIH UDP: outer_ipv6={outer_ipv6}, inner_ipv6={ipv6}, size={size}");
                    for sequence in 0..100_u8 {
                        udp.exchange(&vec![sequence; size]);
                    }
                }
            }
            core.stop();
        }
        let keys: Vec<_> = node["password"].as_str().unwrap().split(':').collect();
        let length = STANDARD.decode(keys[0]).unwrap().len();
        for index in 0..2 {
            let mut keys: Vec<_> = keys.iter().map(ToString::to_string).collect();
            keys[index] = STANDARD.encode(vec![23; length]);
            let mut bad = node.clone();
            bad["password"] = json!(keys.join(":"));
            rejected(bad, &f);
        }
        observations.push(json!({"cipher":node["cipher"],"identity_depth":1,"outer_families":2,"tcp_targets":2,"tcp_bytes_each_direction":41943040,"udp_targets":2,"udp_packets":2000,"wrong_identity_rejected":true,"wrong_user_rejected":true}));
    }
    observe(json!({"native_terminal_eih":observations,"arbitrary_relay_claim":false}));
}
