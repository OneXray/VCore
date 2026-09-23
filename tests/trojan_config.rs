#![cfg(feature = "outbound-trojan")]

use serde_json::{Value, json};
use vcore::config::{Config, ProxyProtocol};

fn document(extra: Value) -> Vec<u8> {
    let mut node = json!({"name":"edge", "type":"trojan", "server":"localhost", "port":443, "password":" 密码 "});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::to_vec(&json!({"socks-port":1080,"proxies":[node],"rules":["MATCH,edge"]})).unwrap()
}

#[test]
fn trojan_tcp_configuration_and_node_graph_accept_the_approved_fields() {
    let yaml = b"socks-port: 1080\nproxies:\n  - name: edge\n    type: trojan\n    server: example.com\n    port: 443\n    password: ' password '\n    udp: true\n    sni: tls.example.com\n    alpn: [h2, http/1.1]\n    skip-cert-verify: false\n    fingerprint: '0000000000000000000000000000000000000000000000000000000000000000'\n    dialer-proxy: upstream\nproxy-groups:\n  - name: upstream\n    type: select\n    proxies: [DIRECT, REJECT]\nrules: ['MATCH,edge']\n";
    let config = Config::parse_yaml(yaml).expect("N2 Trojan TCP configuration");
    assert_eq!(config.proxies[0].address(), "example.com");
    assert_eq!(config.proxies[0].port(), 443);
    assert!(config.proxies[0].udp);
    assert!(!format!("{config:?}").contains(" password "));
}

#[test]
fn trojan_tcp_defaults_preserve_credentials_and_address_policy() {
    let parsed = Config::parse_yaml(&document(json!({}))).unwrap();
    let ProxyProtocol::Trojan(node) = &parsed.proxies[0].protocol else {
        panic!("wrong protocol")
    };
    assert_eq!(node.password, " 密码 ");
    assert_eq!(node.server_name, "localhost");
    assert!(!parsed.proxies[0].udp);
    assert!(node.tls.alpn.is_empty());
    assert!(!node.tls.skip_cert_verify);
    assert_eq!(node.tls.fingerprint, None);
    for server in ["127.0.0.1", "::1", "example.com"] {
        assert!(Config::parse_yaml(&document(json!({"server":server, "network":"tcp"}))).is_ok());
    }
    let config = Config::parse_yaml(&document(json!({"alpn":["second","first"],"skip-cert-verify":true,"fingerprint":"AB:".repeat(31)+"AB"}))).unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.tls.alpn, [b"second".to_vec(), b"first".to_vec()]);
    assert!(node.tls.skip_cert_verify);
    assert_eq!(node.tls.fingerprint, Some([0xab; 32]));
}

#[test]
fn trojan_invalid_configuration_is_rejected_without_exposing_credentials() {
    for extra in [
        json!({"password":""}),
        json!({"password":null}),
        json!({"password":123}),
        json!({"udp":null}),
        json!({"udp":"true"}),
        json!({"tls":true}),
        json!({"port":0}),
        json!({"port":65536}),
        json!({"port":null}),
        json!({"port":"443"}),
        json!({"server":"https://localhost"}),
        json!({"server":"localhost:443"}),
        json!({"server":null}),
        json!({"network":"invalid"}),
        json!({"network":null}),
        json!({"sni":""}),
        json!({"sni":"https://localhost"}),
        json!({"sni":null}),
        json!({"alpn":null}),
        json!({"alpn":[""]}),
        json!({"alpn":["x".repeat(256)]}),
        json!({"skip-cert-verify":null}),
        json!({"fingerprint":"ab"}),
        json!({"fingerprint":null}),
        json!({"dialer-proxy":null}),
        json!({"dialer-proxy":"missing"}),
        json!({"dialer-proxy":"edge"}),
        json!({"ws-opts":{}}),
        json!({"grpc-opts":{}}),
        json!({"extra-option":true}),
    ] {
        let error =
            Config::parse_yaml(&document(extra.clone())).expect_err(&format!("accepted {extra}"));
        assert!(
            !error.to_string().contains("密码"),
            "credential in parser diagnostic"
        );
    }
}
