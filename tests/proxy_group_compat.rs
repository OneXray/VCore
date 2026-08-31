use vcore::config::{
    Config, DnsRoute, ProxyGroupId, ProxyGroupMemberTarget, RouteTargetId, RuleAction,
};

const COMMON_PREFIX: &str = r#"
port: 1080
authentication: [user:password]
proxies:
  - name: node-a
    type: socks5
    server: 192.0.2.1
    port: 1080
    udp: true
  - name: node-b
    type: socks5
    server: 192.0.2.2
    port: 1080
    udp: true
"#;

#[test]
fn accepts_the_mihomo_select_common_subset_without_flattening() {
    let yaml = format!(
        r#"{COMMON_PREFIX}
proxy-groups:
  - name: backup
    type: select
    proxies: [node-b, DIRECT]
  - name: primary
    type: select
    proxies: [node-a, backup, REJECT, node-a]
    default-selected: backup
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#primary"]
rules:
  - DOMAIN-SUFFIX,example.com,backup
  - MATCH,primary
"#
    );

    let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
    let backup = ProxyGroupId::new(0).unwrap();
    let primary = ProxyGroupId::new(1).unwrap();

    assert_eq!(config.proxy_groups[1].initial_member, 1);
    assert_eq!(
        config.proxy_groups[1]
            .members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        ["node-a", "backup", "REJECT", "node-a"]
    );
    assert_eq!(
        config.proxy_groups[1].members[1].target,
        ProxyGroupMemberTarget::Route(RouteTargetId::Group(backup))
    );
    assert_eq!(config.default_route_target, RouteTargetId::Group(primary));
    assert_eq!(
        config.rules[0].action,
        RuleAction::Route(RouteTargetId::Group(backup))
    );
    assert_eq!(
        config.dns.nameservers[0].route,
        DnsRoute::Route(RouteTargetId::Group(primary))
    );
}

#[test]
fn keeps_vcore_stricter_than_mihomo_at_the_documented_boundaries() {
    for groups in [
        r#"
proxy-groups:
  - name: primary
    type: select
    proxies: [node-a]
    default-selected: missing
"#,
        r#"
proxy-groups:
  - name: primary
    type: select
    proxies: [node-a]
    url: https://example.com/generate_204
"#,
        r#"
proxy-groups:
  - name: primary
    type: url-test
    proxies: [node-a]
"#,
    ] {
        let yaml = format!("{COMMON_PREFIX}{groups}rules:\n  - MATCH,primary\n");
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
    }
}

#[test]
fn keeps_dialer_proxy_concrete_node_only() {
    let yaml = format!(
        r#"{COMMON_PREFIX}
proxy-groups:
  - name: primary
    type: select
    proxies: [node-a, node-b]
rules:
  - MATCH,primary
"#
    )
    .replacen(
        "    server: 192.0.2.1\n",
        "    server: 192.0.2.1\n    dialer-proxy: primary\n",
        1,
    );

    let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("concrete proxy"));
}
