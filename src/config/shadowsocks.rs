use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

use super::{invalid, validate_host, validate_port};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl ShadowsocksCipher {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub const fn key_len(self) -> usize {
        if matches!(self, Self::Aes128Gcm) {
            16
        } else {
            32
        }
    }

    pub const fn supports_eih(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes256Gcm)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ShadowsocksOutboundConfig {
    pub address: String,
    pub port: u16,
    pub cipher: ShadowsocksCipher,
    pub password: String,
}

impl std::fmt::Debug for ShadowsocksOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksOutboundConfig")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl ShadowsocksOutboundConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_host(&self.address, "Shadowsocks server")?;
        validate_port(self.port, "Shadowsocks")?;
        if !self.cipher.supports_eih() && self.password.contains(':') {
            return invalid("Shadowsocks identity chains require an AES 2022 cipher");
        }
        const ENGINE: GeneralPurpose = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        for key in self.password.split(':') {
            if key.is_empty() || key.len() > 44 {
                return invalid("Shadowsocks password contains an invalid PSK");
            }
            if !matches!(ENGINE.decode(key), Ok(decoded) if decoded.len() == self.cipher.key_len())
            {
                return invalid(
                    "Shadowsocks PSK must be valid Base64 with the cipher's key length",
                );
            }
        }
        Ok(())
    }
}

pub(super) fn normalize(
    address: String,
    port: u16,
    cipher: String,
    password: String,
) -> Result<ShadowsocksOutboundConfig> {
    let cipher = match cipher.as_str() {
        "2022-blake3-aes-128-gcm" => ShadowsocksCipher::Aes128Gcm,
        "2022-blake3-aes-256-gcm" => ShadowsocksCipher::Aes256Gcm,
        "2022-blake3-chacha20-poly1305" => ShadowsocksCipher::Chacha20Poly1305,
        _ => return invalid("Shadowsocks cipher must be one of the three supported 2022 methods"),
    };
    let config = ShadowsocksOutboundConfig {
        address,
        port,
        cipher,
        password,
    };
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ProxyProtocol};
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn ss_schema_validates_three_methods_and_preserves_eih_order() {
        for cipher in [
            ShadowsocksCipher::Aes128Gcm,
            ShadowsocksCipher::Aes256Gcm,
            ShadowsocksCipher::Chacha20Poly1305,
        ] {
            let key = STANDARD.encode(vec![7; cipher.key_len()]);
            for password in [key.clone(), key.trim_end_matches('=').to_owned()] {
                let yaml = format!(
                    "port: 1080\nproxies: [{{name: ss, type: ss, server: fixture.invalid, port: 443, cipher: {}, password: '{password}', udp: true}}]\nrules: ['MATCH,ss']",
                    cipher.as_str()
                );
                let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
                let ProxyProtocol::Shadowsocks(ss) = &config.proxies[0].protocol else {
                    panic!("wrong protocol")
                };
                assert_eq!(ss.password, password);
                assert!(!format!("{ss:?}").contains(&password));
                assert!(!format!("{ss:?}").contains("fixture.invalid"));
                for field in [
                    "plugin: obfs",
                    "tls: true",
                    "sni: fixture.invalid",
                    "username: secret",
                    "alpn: [h2]",
                ] {
                    let invalid = yaml.replace("udp: true", &format!("udp: true, {field}"));
                    assert!(Config::parse_yaml(invalid.as_bytes()).is_err());
                }
            }
            let chain = format!("{}:{key}", STANDARD.encode(vec![9; cipher.key_len()]));
            let result = normalize(
                "fixture.invalid".into(),
                443,
                cipher.as_str().into(),
                chain.clone(),
            );
            assert_eq!(result.is_ok(), cipher.supports_eih());
            if let Ok(config) = result {
                assert_eq!(config.password, chain);
            }
            for bad in [
                String::new(),
                ":".into(),
                format!("{key}:"),
                format!(" {key}"),
                STANDARD.encode([1; 17]),
                "PRIVATE-BAD-KEY".into(),
            ] {
                let error = normalize(
                    "fixture.invalid".into(),
                    443,
                    cipher.as_str().into(),
                    bad.clone(),
                )
                .unwrap_err();
                assert!(!error.to_string().contains("PRIVATE-BAD-KEY"));
            }
        }
        for cipher in [
            "aes-128-gcm",
            "none",
            "2022-blake3-chacha12-poly1305",
            "2022-blake3-chacha8-poly1305",
            "2022-blake3-chacha20-ietf-poly1305",
        ] {
            assert!(
                normalize(
                    "fixture.invalid".into(),
                    443,
                    cipher.into(),
                    STANDARD.encode([7; 32])
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ss_chacha8_is_rejected_by_runtime_and_measurement_config() {
        let node = format!(
            "{{name: ss, type: ss, server: fixture.invalid, port: 443, cipher: 2022-blake3-chacha8-poly1305, password: '{}' }}",
            STANDARD.encode([7; 32])
        );
        let runtime = format!("port: 1080\nproxies: [{node}]\nrules: ['MATCH,ss']");
        assert!(Config::parse_yaml(runtime.as_bytes()).is_err());
        #[cfg(feature = "ffi")]
        assert!(
            crate::config::MeasureConfig::parse_yaml(format!("proxies: [{node}]").as_bytes())
                .is_err()
        );
    }
}
