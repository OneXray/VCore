use vcore::config::Config;

#[test]
fn feature_skeletons_do_not_open_unimplemented_yaml_or_measurement_protocols() {
    // Keep the stable FOUNDATIONS assertion ID as a regression for the retired protocol.
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "FOUNDATIONS-SCHEMA",
        "feature_skeletons_do_not_open_unimplemented_yaml_or_measurement_protocols",
    );
    let yaml = "proxies:\n  - name: node\n    type: wireguard\n    server: example.com\n    port: 443\nrules:\n  - MATCH,node\n";
    assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
    assert_eq!(vcore::INVOKE_API_VERSION, 5);
    assert_eq!(vcore::CONFIG_VERSION, 32);
    assert!(vcore::BUILD_IDENTITY.ends_with("invokeApiVersion=5;configVersion=32"));
}

#[test]
fn selected_fingerprints_follow_protocol_feature_admission() {
    for (protocol, authentication, enabled) in [
        (
            "anytls",
            "password: fixture",
            cfg!(feature = "outbound-anytls"),
        ),
        (
            "trojan",
            "password: fixture",
            cfg!(feature = "outbound-trojan"),
        ),
        (
            "vmess",
            "uuid: 00000000-0000-4000-8000-000000000001, tls: true",
            cfg!(feature = "outbound-vmess"),
        ),
        (
            "vless",
            "uuid: 00000000-0000-4000-8000-000000000001, tls: true",
            cfg!(feature = "outbound-vless"),
        ),
    ] {
        for name in [
            "none",
            "chrome",
            "chrome120",
            "firefox",
            "firefox120",
            "safari",
            "safari16",
        ] {
            let yaml = format!(
                "mixed-port: 1080\nproxies: [{{name: node, type: {protocol}, server: localhost, port: 443, {authentication}, client-fingerprint: {name}}}]\nrules: ['MATCH,node']\n"
            );
            assert_eq!(
                Config::parse_yaml(yaml.as_bytes()).is_ok(),
                // Legacy AnyTLS without a profile defers protocol admission to
                // graph preparation. Named profiles require their backend here.
                if protocol == "anytls" {
                    name == "none" || cfg!(feature = "tls-fingerprint")
                } else {
                    enabled
                },
                "{protocol}/{name}"
            );
        }
    }
}

#[test]
fn vless_yaml_follows_its_own_feature() {
    let yaml=b"mixed-port: 1080\nproxies: [{name: node, type: vless, server: localhost, port: 443, uuid: 07070707-0707-0707-0707-070707070707}]\nrules: ['MATCH,node']\n";
    assert_eq!(
        Config::parse_yaml(yaml).is_ok(),
        cfg!(feature = "outbound-vless")
    );
}

#[test]
fn vmess_yaml_follows_its_own_feature() {
    let yaml=b"mixed-port: 1080\nproxies: [{name: node, type: vmess, server: localhost, port: 443, uuid: 07070707-0707-0707-0707-070707070707}]\nrules: ['MATCH,node']\n";
    assert_eq!(
        Config::parse_yaml(yaml).is_ok(),
        cfg!(feature = "outbound-vmess")
    );
}

#[test]
fn trojan_yaml_follows_its_own_feature() {
    let yaml = b"mixed-port: 1080\nproxies: [{name: node, type: trojan, server: localhost, port: 443, password: fixture}]\nrules: ['MATCH,node']\n";
    assert_eq!(
        Config::parse_yaml(yaml).is_ok(),
        cfg!(feature = "outbound-trojan")
    );
}

#[test]
fn future_fields_and_over_limit_documents_remain_rejected() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "FOUNDATIONS-SCHEMA",
        "future_fields_and_over_limit_documents_remain_rejected",
    );
    assert!(Config::parse_yaml(&vec![b'x'; vcore::config::MAX_CONFIG_BYTES + 1]).is_err());
    assert!(Config::parse_yaml(b"listeners: []\n").is_err());
    assert!(Config::parse_yaml(b"proxies:\n  - name: s\n    type: socks4\n    server: example.com\n    port: 1080\nrules: [MATCH,s]\n").is_err());
}
