use serde::Deserialize;

use super::{
    AnyTlsCertificatePolicy, ProxyProtocol, deserialize_present_option, invalid, validate_host,
    validate_port,
};
use crate::Result;

#[derive(Clone, PartialEq, Eq)]
pub struct TrojanOutboundConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub server_name: String,
    pub tls: AnyTlsCertificatePolicy,
}

impl std::fmt::Debug for TrojanOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanOutboundConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTrojan {
    name: String,
    server: String,
    port: u16,
    password: String,
    #[serde(default)]
    udp: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    network: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sni: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(
        rename = "dialer-proxy",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    dialer_proxy: Option<String>,
}

impl std::fmt::Debug for RawTrojan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTrojan").finish_non_exhaustive()
    }
}

impl RawTrojan {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-trojan") {
            return invalid("Trojan outbound support is disabled at build time");
        }
        validate_host(&self.server, "Trojan server")?;
        validate_port(self.port, "Trojan")?;
        if self.password.is_empty() {
            return invalid("Trojan password must not be empty");
        }
        if self.network.as_deref().unwrap_or("tcp") != "tcp" {
            return invalid("Trojan network must be tcp");
        }
        let server_name = self.sni.unwrap_or_else(|| self.server.clone());
        validate_host(&server_name, "Trojan sni")?;
        let alpn: Vec<Vec<u8>> = self
            .alpn
            .unwrap_or_default()
            .into_iter()
            .map(String::into_bytes)
            .collect();
        if alpn
            .iter()
            .any(|value| value.is_empty() || value.len() > 255)
            || alpn.iter().map(|value| value.len() + 1).sum::<usize>() > 65_533
        {
            return invalid("invalid Trojan ALPN list");
        }
        let fingerprint = self
            .fingerprint
            .map(|value| {
                let hex: Vec<u8> = value.trim().bytes().filter(|byte| *byte != b':').collect();
                if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
                    return invalid("Trojan fingerprint must be a SHA-256 certificate digest");
                }
                let mut pin = [0; 32];
                for (byte, pair) in pin.iter_mut().zip(hex.as_chunks::<2>().0) {
                    *byte = ((pair[0] as char).to_digit(16).unwrap() * 16
                        + (pair[1] as char).to_digit(16).unwrap())
                        as u8;
                }
                Ok(pin)
            })
            .transpose()?;
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Trojan(TrojanOutboundConfig {
                address: self.server,
                port: self.port,
                password: self.password,
                server_name,
                tls: AnyTlsCertificatePolicy {
                    alpn,
                    skip_cert_verify: self.skip_cert_verify,
                    fingerprint,
                },
            }),
        ))
    }
}
