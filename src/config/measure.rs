use serde::Deserialize;
use serde_yaml_ng::Value as YamlValue;

use crate::{Result, VCoreError};

use super::{
    MAX_CONFIG_BYTES, ProxyConfig, ProxyId, RawOutbound, normalize_proxy_graph,
    reject_yaml_anchors_and_aliases, validate_json_compatible_yaml,
};

/// Strict node-only configuration accepted by the built-in latency runner.
///
/// A measurement never owns an inbound, routing rules, DNS, sniffer state, or
/// GeoData. Keeping a separate deserializer makes those fields unknown rather
/// than silently ignoring runtime-only behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeasureConfig {
    pub(crate) proxies: Vec<ProxyConfig>,
    pub(crate) default_proxy: ProxyId,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMeasureConfig {
    proxies: Vec<RawOutbound>,
}

impl MeasureConfig {
    pub(crate) fn parse_yaml(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(VCoreError::InvalidConfig(format!(
                "configuration exceeds the {MAX_CONFIG_BYTES}-byte limit"
            )));
        }
        let input = std::str::from_utf8(input)
            .map_err(|_| VCoreError::InvalidConfig("configuration is not UTF-8".to_owned()))?;

        reject_yaml_anchors_and_aliases(input)?;
        let yaml: YamlValue = serde_yaml_ng::from_str(input)
            .map_err(|error| VCoreError::InvalidConfig(error.to_string()))?;
        validate_json_compatible_yaml(&yaml)?;
        let raw: RawMeasureConfig = serde_yaml_ng::from_value(yaml)
            .map_err(|error| VCoreError::InvalidConfig(error.to_string()))?;
        raw.normalize()
    }
}

impl RawMeasureConfig {
    fn normalize(self) -> Result<MeasureConfig> {
        let (proxies, _) = normalize_proxy_graph(self.proxies)?;
        let mut referenced_as_parent = vec![false; proxies.len()];
        for proxy in &proxies {
            if let Some(parent) = proxy.dialer_proxy {
                referenced_as_parent[parent.index()] = true;
            }
        }
        let mut heads = referenced_as_parent
            .iter()
            .enumerate()
            .filter_map(|(index, referenced)| (!referenced).then_some(ProxyId::from_index(index)));
        let default_proxy = heads.next().ok_or_else(|| {
            VCoreError::InvalidConfig(
                "measurement proxies must form one chain with exactly one head".to_owned(),
            )
        })?;
        if heads.next().is_some() {
            return Err(VCoreError::InvalidConfig(
                "measurement proxies must form one chain with exactly one head".to_owned(),
            ));
        }

        let mut visited = vec![false; proxies.len()];
        let mut current = Some(default_proxy);
        let mut reachable = 0_usize;
        while let Some(proxy_id) = current {
            if visited[proxy_id.index()] {
                break;
            }
            visited[proxy_id.index()] = true;
            reachable += 1;
            current = proxies[proxy_id.index()].dialer_proxy;
        }
        if reachable != proxies.len() {
            return Err(VCoreError::InvalidConfig(
                "measurement proxies must form one chain with exactly one head".to_owned(),
            ));
        }

        Ok(MeasureConfig {
            proxies,
            default_proxy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = r#"
proxies:
  - name: proxy
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
"#;

    fn socks_chain(count: usize) -> String {
        assert!(count > 0);
        let mut yaml = "proxies:\n".to_owned();
        for index in 0..count {
            yaml.push_str(&format!("  - name: node-{index}\n    type: socks5\n"));
            if index > 0 {
                yaml.push_str(&format!("    dialer-proxy: node-{}\n", index - 1));
            }
            yaml.push_str(&format!(
                "    server: node-{index}.example.com\n    port: 1080\n    udp: true\n"
            ));
        }
        yaml
    }

    #[test]
    fn accepts_only_the_node_graph_subset() {
        let config = MeasureConfig::parse_yaml(NODE.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.default_proxy.index(), 0);

        for extra in [
            "port: 18080",
            "authentication: [measure:secret]",
            "tun: { enable: false }",
            "sniffer: { enable: false }",
            "dns: { enable: false }",
            "rules: [MATCH,PROXY]",
            "geo-auto-update: false",
            "configVersion: 9",
            "default-proxy: proxy",
            "proxy-groups: []",
        ] {
            let yaml = NODE.replacen("proxies:", &format!("{extra}\nproxies:"), 1);
            assert!(
                MeasureConfig::parse_yaml(yaml.as_bytes()).is_err(),
                "{extra} must be rejected"
            );
        }
    }

    #[test]
    fn reuses_proxy_graph_validation() {
        let chain = NODE.replace(
            "  - name: proxy\n",
            "  - name: hop\n    type: socks5\n    server: 127.0.0.1\n    port: 1081\n    udp: true\n  - name: exit\n    dialer-proxy: hop\n",
        );
        let config = MeasureConfig::parse_yaml(chain.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(config.default_proxy.index(), 1);

        let unknown = NODE.replace(
            "    server: 127.0.0.1\n",
            "    dialer-proxy: missing\n    server: 127.0.0.1\n",
        );
        assert!(MeasureConfig::parse_yaml(unknown.as_bytes()).is_err());

        let independent = NODE.replace(
            "proxies:\n",
            "proxies:\n  - name: unused\n    type: socks5\n    server: 127.0.0.1\n    port: 1081\n",
        );
        assert!(MeasureConfig::parse_yaml(independent.as_bytes()).is_err());
    }

    #[test]
    fn accepts_a_long_chain_beyond_u8_proxy_indices() {
        let config = MeasureConfig::parse_yaml(socks_chain(300).as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 300);
        assert_eq!(config.default_proxy.index(), 299);
        assert_eq!(
            config.proxies[299]
                .dialer_proxy
                .expect("last node uses the preceding hop")
                .index(),
            298
        );
    }

    #[test]
    fn rejects_removed_selectors_and_non_json_yaml() {
        assert!(
            MeasureConfig::parse_yaml(
                NODE.replacen("proxies:", "configVersion: 9\nproxies:", 1)
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            MeasureConfig::parse_yaml(NODE.replace("name: proxy", "name: &tag proxy").as_bytes())
                .is_err()
        );
    }

    #[test]
    fn preserves_mihomo_udp_capability() {
        let enabled = MeasureConfig::parse_yaml(NODE.as_bytes()).unwrap();
        assert!(enabled.proxies[0].udp);

        let disabled =
            MeasureConfig::parse_yaml(NODE.replace("    udp: true\n", "").as_bytes()).unwrap();
        assert!(!disabled.proxies[0].udp);
    }
}
