use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

const MAX_EXCLUDED_CIDRS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WindowsVpnPolicy {
    always_on: bool,
    allow_local_network: bool,
    #[serde(deserialize_with = "deserialize_excluded_cidrs")]
    excluded_cidrs: Vec<WindowsVpnCidr>,
}

impl WindowsVpnPolicy {
    pub(crate) fn always_on(&self) -> bool {
        self.always_on
    }

    pub(crate) fn allow_local_network(&self) -> bool {
        self.allow_local_network
    }

    pub(crate) fn excluded_cidrs(&self) -> &[WindowsVpnCidr] {
        &self.excluded_cidrs
    }

    pub(crate) fn validate_for(
        &self,
        ipv6: bool,
        dns_ipv4: Ipv4Addr,
        dns_ipv6: Ipv6Addr,
    ) -> Result<(), &'static str> {
        if self.excluded_cidrs.iter().any(|cidr| {
            (!ipv6 && cidr.network.is_ipv6())
                || cidr.contains(IpAddr::V4(dns_ipv4))
                || cidr.contains(IpAddr::V6(dns_ipv6))
        }) {
            return Err("Windows VPN exclusion conflicts with network settings");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WindowsVpnCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl WindowsVpnCidr {
    pub(crate) fn network(&self) -> IpAddr {
        self.network
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX << (32 - u32::from(self.prefix_len));
                u32::from(address) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX << (128 - u32::from(self.prefix_len));
                u128::from(address) & mask == u128::from(network)
            }
            _ => false,
        }
    }
}

impl FromStr for WindowsVpnCidr {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .filter(|(_, prefix)| !prefix.contains('/'))
            .ok_or("invalid Windows VPN exclusion CIDR")?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "invalid Windows VPN exclusion CIDR")?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|_| "invalid Windows VPN exclusion CIDR")?;
        let network = match address {
            IpAddr::V4(address) if (1..=32).contains(&prefix_len) => {
                let mask = u32::MAX << (32 - u32::from(prefix_len));
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) if (1..=128).contains(&prefix_len) => {
                let mask = u128::MAX << (128 - u32::from(prefix_len));
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
            _ => return Err("invalid Windows VPN exclusion CIDR"),
        };
        if address != network {
            return Err("invalid Windows VPN exclusion CIDR");
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl fmt::Display for WindowsVpnCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

impl Serialize for WindowsVpnCidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for WindowsVpnCidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

fn deserialize_excluded_cidrs<'de, D>(deserializer: D) -> Result<Vec<WindowsVpnCidr>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut cidrs = Vec::<WindowsVpnCidr>::deserialize(deserializer)?;
    cidrs.sort_unstable();
    if cidrs.len() > MAX_EXCLUDED_CIDRS || cidrs.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(D::Error::custom("invalid Windows VPN exclusion CIDRs"));
    }
    Ok(cidrs)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn policy_rejects_unsafe_excluded_cidrs() {
        let policy = |excluded_cidrs| {
            serde_json::from_value::<WindowsVpnPolicy>(json!({
                "alwaysOn": false,
                "allowLocalNetwork": true,
                "excludedCidrs": excluded_cidrs
            }))
        };

        for invalid in [
            json!(["192.0.2.0/24", "192.0.2.0/24"]),
            json!(["192.0.2.1/24"]),
            json!(["0.0.0.0/0"]),
            json!(["2001:db8::/129"]),
        ] {
            assert!(policy(invalid).is_err());
        }
        assert!(
            policy(json!(
                (0..65)
                    .map(|index| format!("192.0.2.{index}/32"))
                    .collect::<Vec<_>>()
            ))
            .is_err()
        );
    }

    #[test]
    fn policy_canonicalizes_excluded_cidrs() {
        let policy: WindowsVpnPolicy = serde_json::from_value(json!({
            "alwaysOn": true,
            "allowLocalNetwork": false,
            "excludedCidrs": ["2001:0DB8:0:0::/64", "192.0.2.0/24"]
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(policy).unwrap(),
            json!({
                "alwaysOn": true,
                "allowLocalNetwork": false,
                "excludedCidrs": ["192.0.2.0/24", "2001:db8::/64"]
            })
        );
    }
}
