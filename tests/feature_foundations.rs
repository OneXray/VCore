use vcore::config::Config;

#[test]
fn feature_skeletons_do_not_open_unimplemented_yaml_or_measurement_protocols() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "N1-SCHEMA",
        "feature_skeletons_do_not_open_unimplemented_yaml_or_measurement_protocols",
    );
    for protocol in ["vmess", "hysteria2", "wireguard"] {
        let yaml = format!(
            "proxies:\n  - name: node\n    type: {protocol}\n    server: example.com\n    port: 443\nrules:\n  - MATCH,node\n"
        );
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
    }
    assert_eq!(vcore::INVOKE_API_VERSION, 5);
    assert_eq!(vcore::CONFIG_VERSION, 15);
    assert!(vcore::BUILD_IDENTITY.ends_with("invokeApiVersion=5;configVersion=15"));
}

#[test]
fn trojan_yaml_follows_its_own_feature() {
    let yaml = b"socks-port: 1080\nproxies: [{name: node, type: trojan, server: localhost, port: 443, password: fixture}]\nrules: ['MATCH,node']\n";
    assert_eq!(
        Config::parse_yaml(yaml).is_ok(),
        cfg!(feature = "outbound-trojan")
    );
}

#[test]
fn future_fields_and_over_limit_documents_remain_rejected() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "N1-SCHEMA",
        "future_fields_and_over_limit_documents_remain_rejected",
    );
    assert!(Config::parse_yaml(&vec![b'x'; vcore::config::MAX_CONFIG_BYTES + 1]).is_err());
    assert!(Config::parse_yaml(b"listeners: []\n").is_err());
    assert!(Config::parse_yaml(b"proxies:\n  - name: s\n    type: socks4\n    server: example.com\n    port: 1080\nrules: [MATCH,s]\n").is_err());
}
