use std::io;

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// One client-proxy credential shared by the HTTP and SOCKS5 frontends.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    username: String,
    password: String,
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCredentials")
            .finish_non_exhaustive()
    }
}

impl ProxyCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> io::Result<Self> {
        let username = username.into();
        let password = password.into();
        for (kind, value) in [("user", &username), ("password", &password)] {
            if !(1..=255).contains(&value.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("authentication {kind} must contain between 1 and 255 UTF-8 bytes"),
                ));
            }
        }
        if username.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authentication user must not contain `:`",
            ));
        }
        Ok(Self { username, password })
    }

    #[must_use]
    pub fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        // Always compare both fixed-size credential slots; never expose the
        // matching prefix or short-circuit after a successful username check.
        let mut difference = username.len() ^ self.username.len();
        difference |= password.len() ^ self.password.len();
        for index in 0..255 {
            difference |= usize::from(
                username.get(index).copied().unwrap_or(0)
                    ^ self.username.as_bytes().get(index).copied().unwrap_or(0),
            );
            difference |= usize::from(
                password.get(index).copied().unwrap_or(0)
                    ^ self.password.as_bytes().get(index).copied().unwrap_or(0),
            );
        }
        difference == 0
    }

    #[must_use]
    pub fn authorization_header_value(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.username, self.password))
        )
    }

    pub(crate) fn verifies(&self, headers: &[(String, String)]) -> bool {
        let mut values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, value)| value.as_str());
        let (Some(value), None) = (values.next(), values.next()) else {
            return false;
        };
        let mut parts = value.split_ascii_whitespace();
        let (Some(scheme), Some(encoded), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") || encoded.len() > 684 {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return false;
        };
        let Some(separator) = decoded.iter().position(|&byte| byte == b':') else {
            return false;
        };
        self.matches(&decoded[..separator], &decoded[separator + 1..])
    }
}

/// A fixed client-oriented listener policy, not an arbitrary address list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyAccess {
    pub allow_lan: bool,
    pub ipv6: bool,
}
