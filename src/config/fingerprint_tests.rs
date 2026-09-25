use super::*;

fn yaml(protocol: &str, fields: &str) -> String {
    let auth = match protocol {
        "anytls" | "trojan" => "password: fixture",
        "vmess" => {
            "uuid: 00000000-0000-4000-8000-000000000001\n    alterId: 0\n    cipher: auto\n    tls: true"
        }
        "vless" => "uuid: 00000000-0000-4000-8000-000000000001\n    tls: true",
        _ => unreachable!(),
    };
    format!("port: 1080\nrules: [MATCH,p]\nproxies:\n  - name: p\n    type: {protocol}\n    server: example.com\n    port: 443\n    {auth}\n    {fields}\n").replace("rules: [MATCH,p]", "rules: ['MATCH,p']")
}

fn profile(config: &Config) -> Option<ClientFingerprint> {
    match &config.proxies[0].protocol {
        ProxyProtocol::AnyTls(p) => p.tls.client_fingerprint,
        ProxyProtocol::Trojan(p) => p.tls.client_fingerprint,
        ProxyProtocol::Vmess(p) => p.tls.as_ref().unwrap().client_fingerprint,
        ProxyProtocol::Vless(p) => match &p.security {
            SecurityConfig::Tls(tls) => tls.client_fingerprint,
            SecurityConfig::Reality(reality) => reality.client_fingerprint,
            _ => panic!("expected TLS"),
        },
        _ => unreachable!(),
    }
}

#[test]
fn named_fingerprint_is_strict_and_independent_of_certificate_pins() {
    for protocol in ["anytls", "trojan", "vmess", "vless"] {
        for (value, expected) in [
            ("chrome120", Some(ClientFingerprint::Chrome120)),
            ("\"\"", None),
        ] {
            let config = Config::parse_yaml(
                yaml(
                    protocol,
                    &format!(
                        "client-fingerprint: {value}\n    fingerprint: {}",
                        "aa".repeat(32)
                    ),
                )
                .as_bytes(),
            )
            .unwrap();
            assert_eq!(profile(&config), expected);
        }
        assert_eq!(
            profile(&Config::parse_yaml(yaml(protocol, "").as_bytes()).unwrap()),
            None
        );
        for value in [
            "chrome",
            "firefox",
            "Chrome120",
            "null",
            "[]",
            "true",
            "secret-unknown-profile",
        ] {
            let error = Config::parse_yaml(
                yaml(protocol, &format!("client-fingerprint: {value}")).as_bytes(),
            )
            .unwrap_err();
            assert!(!error.to_string().contains("secret-unknown-profile"));
        }
    }
    for protocol in ["vless", "vmess"] {
        assert!(
            Config::parse_yaml(
                yaml(protocol, "client-fingerprint: chrome120")
                    .replace("tls: true", "tls: false")
                    .as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn download_fingerprint_inherits_and_can_be_cleared_independently() {
    let base = yaml(
        "vless",
        "network: xhttp\n    client-fingerprint: chrome120\n    xhttp-opts:\n      path: /fixture\n      mode: stream-up\n      download-settings:\n        server: download.example.com",
    );
    for (extra, expected) in [
        ("", Some(ClientFingerprint::Chrome120)),
        ("\n        client-fingerprint: \"\"", None),
    ] {
        let text = format!("{}{extra}\n", base.trim_end());
        let config = Config::parse_yaml(text.as_bytes()).unwrap();
        assert_eq!(profile(&config), Some(ClientFingerprint::Chrome120));
        let ProxyProtocol::Vless(vless) = &config.proxies[0].protocol else {
            unreachable!()
        };
        let VlessTransport::Xhttp(xhttp) = &vless.transport else {
            unreachable!()
        };
        let SecurityConfig::Tls(tls) = &xhttp.download.as_ref().unwrap().security else {
            unreachable!()
        };
        assert_eq!(tls.client_fingerprint, expected);
    }
    assert!(
        Config::parse_yaml(
            yaml(
                "vless",
                "network: xhttp\n    alpn: [h3]\n    client-fingerprint: chrome120"
            )
            .as_bytes()
        )
        .is_err()
    );
    assert!(Config::parse_yaml(format!("{}        alpn: [h3]\n", base).as_bytes()).is_err());
    assert!(
        Config::parse_yaml(
            format!(
                "{}        alpn: [h3]\n        client-fingerprint: \"\"\n",
                base
            )
            .as_bytes()
        )
        .is_ok()
    );
    assert!(Config::parse_yaml(format!("{}        tls: false\n", base).as_bytes()).is_err());
}

#[test]
fn reality_accepts_named_profile_without_admitting_certificate_policy() {
    let fields = format!(
        "client-fingerprint: chrome120\n    reality-opts:\n      public-key: {}",
        URL_SAFE_NO_PAD.encode([7; 32])
    );
    let config = Config::parse_yaml(yaml("vless", &fields).as_bytes()).unwrap();
    assert_eq!(profile(&config), Some(ClientFingerprint::Chrome120));
    assert!(
        Config::parse_yaml(
            yaml("vless", &format!("skip-cert-verify: true\n    {fields}")).as_bytes()
        )
        .is_err()
    );
}
