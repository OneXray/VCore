use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use windows::{
    Win32::Foundation::E_FAIL,
    core::{Error, Result},
};

use super::{policy::WindowsVpnPolicy, snapshot::SessionReference};

const PROFILE_CONFIGURATION_VERSION: u32 = 4;
const MAX_PROFILE_CONFIGURATION_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WindowsNetworkSettings {
    ipv4_address: Ipv4Addr,
    ipv6_address: Ipv6Addr,
    dns_ipv4_address: Ipv4Addr,
    dns_ipv6_address: Ipv6Addr,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawWindowsNetworkSettings {
    ipv4_address: Ipv4Addr,
    ipv6_address: Ipv6Addr,
    dns_ipv4_address: Ipv4Addr,
    dns_ipv6_address: Ipv6Addr,
}

impl<'de> Deserialize<'de> for WindowsNetworkSettings {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawWindowsNetworkSettings::deserialize(deserializer)?;
        let settings = Self {
            ipv4_address: raw.ipv4_address,
            ipv6_address: raw.ipv6_address,
            dns_ipv4_address: raw.dns_ipv4_address,
            dns_ipv6_address: raw.dns_ipv6_address,
        };
        settings.validate().map_err(D::Error::custom)?;
        Ok(settings)
    }
}

impl WindowsNetworkSettings {
    pub(crate) fn ipv4_address(&self) -> Ipv4Addr {
        self.ipv4_address
    }

    pub(crate) fn ipv6_address(&self) -> Ipv6Addr {
        self.ipv6_address
    }

    pub(crate) fn dns_ipv4_address(&self) -> Ipv4Addr {
        self.dns_ipv4_address
    }

    pub(crate) fn dns_ipv6_address(&self) -> Ipv6Addr {
        self.dns_ipv6_address
    }

    fn validate(&self) -> std::result::Result<(), &'static str> {
        if invalid_ipv4(self.ipv4_address)
            || invalid_ipv4(self.dns_ipv4_address)
            || invalid_ipv6(self.ipv6_address)
            || invalid_ipv6(self.dns_ipv6_address)
            || self.ipv4_address == self.dns_ipv4_address
            || self.ipv6_address == self.dns_ipv6_address
        {
            return Err("invalid Windows VPN network settings");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WindowsProfileConfiguration {
    version: u32,
    snapshot_token: String,
    ipv6: bool,
    network_settings: WindowsNetworkSettings,
    policy: WindowsVpnPolicy,
}

impl WindowsProfileConfiguration {
    pub(crate) fn new(
        snapshot: &SessionReference,
        ipv6: bool,
        network_settings: WindowsNetworkSettings,
        policy: WindowsVpnPolicy,
    ) -> Self {
        Self {
            version: PROFILE_CONFIGURATION_VERSION,
            snapshot_token: snapshot.token(),
            ipv6,
            network_settings,
            policy,
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.len() > MAX_PROFILE_CONFIGURATION_BYTES {
            return Err(invalid_profile_configuration());
        }
        let configuration: Self =
            serde_json::from_str(value).map_err(|_| invalid_profile_configuration())?;
        if configuration.version != PROFILE_CONFIGURATION_VERSION
            || SessionReference::parse(&configuration.snapshot_token).is_err()
            || configuration
                .policy
                .validate_for(
                    configuration.ipv6,
                    configuration.network_settings.dns_ipv4_address,
                    configuration.network_settings.dns_ipv6_address,
                )
                .is_err()
        {
            return Err(invalid_profile_configuration());
        }
        Ok(configuration)
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| invalid_profile_configuration())
    }

    pub(crate) fn snapshot_token(&self) -> &str {
        &self.snapshot_token
    }

    pub(crate) fn session_reference(&self) -> Result<SessionReference> {
        SessionReference::parse(&self.snapshot_token)
    }

    pub(crate) fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    pub(crate) fn network_settings(&self) -> &WindowsNetworkSettings {
        &self.network_settings
    }

    pub(crate) fn policy(&self) -> &WindowsVpnPolicy {
        &self.policy
    }
}

fn invalid_ipv4(address: Ipv4Addr) -> bool {
    address.is_unspecified()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
}

fn invalid_ipv6(address: Ipv6Addr) -> bool {
    address.is_unspecified()
        || address.is_loopback()
        || address.is_unicast_link_local()
        || address.is_multicast()
}

fn invalid_profile_configuration() -> Error {
    Error::new(E_FAIL, "invalid Windows VPN profile configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_json() -> String {
        let digest = "0123456789abcdef".repeat(4);
        format!(
            r#"{{"version":4,"snapshotToken":"vcore-session-v2:{digest}","ipv6":true,"networkSettings":{{"ipv4Address":"192.168.8.1","ipv6Address":"fd00:8::2","dnsIpv4Address":"223.5.5.5","dnsIpv6Address":"2400:3200::1"}},"policy":{{"alwaysOn":false,"allowLocalNetwork":true,"excludedCidrs":[]}}}}"#
        )
    }

    #[test]
    fn profile_configuration_round_trips_external_network_settings() {
        let json = valid_json();
        let configuration = WindowsProfileConfiguration::parse(&json).unwrap();

        assert_eq!(
            configuration.snapshot_token(),
            format!("vcore-session-v2:{}", "0123456789abcdef".repeat(4))
        );
        assert!(configuration.ipv6_enabled());
        assert_eq!(
            configuration.network_settings().ipv4_address().to_string(),
            "192.168.8.1"
        );
        assert_eq!(
            configuration.network_settings().ipv6_address().to_string(),
            "fd00:8::2"
        );
        assert_eq!(
            configuration
                .network_settings()
                .dns_ipv4_address()
                .to_string(),
            "223.5.5.5"
        );
        assert_eq!(
            configuration
                .network_settings()
                .dns_ipv6_address()
                .to_string(),
            "2400:3200::1"
        );
        assert!(!configuration.policy().always_on());
        assert!(configuration.policy().allow_local_network());
        assert!(configuration.policy().excluded_cidrs().is_empty());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&configuration.to_json().unwrap()).unwrap(),
            serde_json::from_str::<serde_json::Value>(&json).unwrap()
        );
    }

    #[test]
    fn profile_configuration_rejects_unknown_or_unsafe_network_settings() {
        let valid = valid_json();
        for invalid in [
            valid.replace(r#""version":4"#, r#""version":3"#),
            valid.replace(r#","ipv6":true"#, ""),
            valid.replace(r#""ipv6":true"#, r#""ipv6":"true""#),
            valid.replace(r#""snapshotToken""#, r#""unknown":true,"snapshotToken""#),
            valid.replace(
                r#""ipv4Address":"192.168.8.1""#,
                r#""ipv4Address":"0.0.0.0""#,
            ),
            valid.replace(
                r#""dnsIpv4Address":"223.5.5.5""#,
                r#""dnsIpv4Address":"192.168.8.1""#,
            ),
            valid.replace(r#""ipv6Address":"fd00:8::2""#, r#""ipv6Address":"ff02::1""#),
            valid.replace(
                r#""dnsIpv6Address":"2400:3200::1""#,
                r#""dnsIpv6Address":"fd00:8::2""#,
            ),
        ] {
            assert!(WindowsProfileConfiguration::parse(&invalid).is_err());
        }
        assert!(
            WindowsProfileConfiguration::parse(&"x".repeat(MAX_PROFILE_CONFIGURATION_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn profile_configuration_rejects_policy_conflicts() {
        let json = valid_json();
        assert!(
            WindowsProfileConfiguration::parse(&json.replace(
                r#""excludedCidrs":[]"#,
                r#""excludedCidrs":["223.5.5.5/32"]"#
            ))
            .is_err()
        );
        assert!(
            WindowsProfileConfiguration::parse(
                &json.replace(r#""ipv6":true"#, r#""ipv6":false"#).replace(
                    r#""excludedCidrs":[]"#,
                    r#""excludedCidrs":["2001:db8::/64"]"#,
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn profile_configuration_round_trips_disabled_ipv6() {
        let json = valid_json().replace(r#""ipv6":true"#, r#""ipv6":false"#);
        let configuration = WindowsProfileConfiguration::parse(&json).unwrap();

        assert!(!configuration.ipv6_enabled());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&configuration.to_json().unwrap()).unwrap(),
            serde_json::from_str::<serde_json::Value>(&json).unwrap()
        );
        assert!(
            WindowsProfileConfiguration::parse(
                &json.replace(r#""ipv6Address":"fd00:8::2""#, r#""ipv6Address":"::""#)
            )
            .is_err()
        );
    }
}
