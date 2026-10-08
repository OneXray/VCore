//! Static ECH configuration admission shared by both TLS backends. In
//! particular, BoringSSL otherwise silently skips unsupported configurations.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub struct StaticEchConfig(Vec<u8>);

impl std::fmt::Debug for StaticEchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticEchConfig").finish_non_exhaustive()
    }
}

impl StaticEchConfig {
    /// Keeps the first mutually supported config's exact wire encoding. No
    /// backend can skip an earlier unsupported entry and expose the inner SNI.
    pub fn from_config_list(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65_537 {
            return invalid("ECH config list exceeds the wire bound");
        }
        let mut reader = Reader(bytes);
        let list = reader.vector16()?;
        reader.end()?;
        let mut configs = Reader(list);
        let mut selected = None;
        while !configs.0.is_empty() {
            let start = configs.0;
            let version = configs.u16()?;
            let contents = configs.vector16()?;
            if version == 0xfe0d && supported(contents)? && selected.is_none() {
                selected = Some(&start[..4 + contents.len()]);
            }
        }
        let selected = selected.ok_or_else(|| {
            VoleError::InvalidConfig("ECH has no compatible configuration".into())
        })?;
        let mut wire = (selected.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(selected);
        Ok(Self(wire))
    }

    #[cfg(feature = "tls-fingerprint")]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn supported(bytes: &[u8]) -> Result<bool> {
    let mut r = Reader(bytes);
    r.take(1)?; // config_id
    let kem = r.u16()?;
    let key = r.vector16()?;
    let suites = r.vector16()?;
    if suites.is_empty() || !suites.len().is_multiple_of(4) {
        return invalid("invalid ECH cipher suites");
    }
    let compatible_suite = suites.as_chunks::<4>().0.iter().any(|suite| {
        suite[..2] == [0, 1] && matches!(u16::from_be_bytes([suite[2], suite[3]]), 1..=3)
    });
    r.take(1)?; // maximum_name_length
    let name_len = usize::from(r.take(1)?[0]);
    let name = r.take(name_len)?;
    let mut extensions = Reader(r.vector16()?);
    r.end()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut compatible_extensions = true;
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        extensions.vector16()?;
        compatible_extensions &= kind & 0x8000 == 0 && seen.insert(kind);
    }
    Ok(kem == 0x0020
        && key.len() == 32
        && compatible_suite
        && compatible_extensions
        && valid_public_name(name))
}

fn valid_public_name(name: &[u8]) -> bool {
    // Match the stricter fixed BoringSSL LDH/IP-lookalike admission rules.
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if name.split(|b| *b == b'.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    }) {
        return false;
    }
    let last = name.rsplit(|b| *b == b'.').next().unwrap_or_default();
    !last.iter().all(u8::is_ascii_digit)
        && !(last.len() >= 2
            && last[0] == b'0'
            && matches!(last[1], b'x' | b'X')
            && last[2..].iter().all(u8::is_ascii_hexdigit))
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let Some((head, tail)) = self.0.split_at_checked(n) else {
            return invalid("invalid ECH config list");
        };
        self.0 = tail;
        Ok(head)
    }
    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn vector16(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
    fn end(self) -> Result<()> {
        if !self.0.is_empty() {
            return invalid("invalid ECH config list");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawEch {
    #[serde(default)]
    enable: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    config: Option<String>,
}

impl std::fmt::Debug for RawEch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEch").finish_non_exhaustive()
    }
}

impl RawEch {
    pub(super) fn normalize(self) -> Result<Option<StaticEchConfig>> {
        if !self.enable {
            if self.config.as_ref().is_some_and(|value| !value.is_empty()) {
                return invalid("ECH config requires enable=true");
            }
            return Ok(None);
        }
        let encoded = self.config.ok_or_else(|| {
            VoleError::InvalidConfig("static ECH requires an explicit config".into())
        })?;
        if encoded.len() > 87_384 {
            return invalid("ECH config exceeds the wire bound");
        }
        let wire = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| VoleError::InvalidConfig("invalid ECH Base64 config".into()))?;
        StaticEchConfig::from_config_list(&wire).map(Some)
    }
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<RawEch>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_present_map(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid static ECH options"))
}
