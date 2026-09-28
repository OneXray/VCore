use super::{crypto, invalid_config};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use boring::mlkem::{Algorithm, MlKemPublicKey};
use std::{io, time::Duration};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Appearance {
    Native,
    XorPublic,
    Random,
}

pub(super) struct Settings {
    pub keys: Vec<Vec<u8>>,
    pub appearance: Appearance,
    pub resume: bool,
    padding: Vec<[u32; 3]>,
}

impl Settings {
    pub(super) fn parse(value: &str) -> io::Result<Self> {
        if value.len() > 65_536 {
            return Err(invalid_config());
        }
        let mut parts = value.split('.');
        if parts.next() != Some("mlkem768x25519plus") {
            return Err(invalid_config());
        }
        let appearance = match parts.next() {
            Some("native") => Appearance::Native,
            Some("xorpub") => Appearance::XorPublic,
            Some("random") => Appearance::Random,
            _ => return Err(invalid_config()),
        };
        let resume = match parts.next() {
            Some("1rtt") => false,
            Some("0rtt") => true,
            _ => return Err(invalid_config()),
        };
        let (mut keys, mut padding) = (Vec::new(), Vec::new());
        let mut max_padding = 0u64;
        for part in parts {
            if part.len() >= 20 {
                if keys.len() == 16 {
                    return Err(invalid_config());
                }
                let key = URL_SAFE_NO_PAD.decode(part).map_err(|_| invalid_config())?;
                match key.len() {
                    32 => {
                        crypto::x_public(&key).map_err(|_| invalid_config())?;
                    }
                    1184 => {
                        MlKemPublicKey::from_slice(Algorithm::MlKem768, &key)
                            .map_err(|_| invalid_config())?;
                    }
                    _ => return Err(invalid_config()),
                }
                keys.push(key);
            } else {
                if padding.len() == 128 {
                    return Err(invalid_config());
                }
                let numbers = part
                    .split('-')
                    .map(str::parse::<u32>)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| invalid_config())?;
                let row: [u32; 3] = numbers.try_into().map_err(|_| invalid_config())?;
                if padding.is_empty() && (row[0] < 100 || row[1] < 35 || row[2] < 35) {
                    return Err(invalid_config());
                }
                if padding.len() % 2 == 0 {
                    max_padding += u64::from(row[1].max(row[2]));
                    if max_padding > 65_553 {
                        return Err(invalid_config());
                    }
                }
                padding.push(row);
            }
        }
        if keys.is_empty() {
            return Err(invalid_config());
        }
        if padding.is_empty() {
            padding = vec![[100, 111, 1111], [75, 0, 111], [50, 0, 3333]];
        }
        Ok(Self {
            keys,
            appearance,
            resume,
            padding,
        })
    }

    pub(super) fn padding(&self) -> (Vec<usize>, Vec<Duration>) {
        let mut lengths = Vec::new();
        let mut gaps = Vec::new();
        for (index, [probability, left, right]) in self.padding.iter().copied().enumerate() {
            // Match Mihomo's inclusive probability comparison and exclusive
            // upper range, including reversed/equal endpoints.
            let value = if probability >= rand::random_range(0..100) {
                if left == right {
                    left
                } else {
                    rand::random_range(left.min(right)..left.max(right))
                }
            } else {
                0
            };
            if index % 2 == 0 {
                lengths.push(value as usize);
            } else {
                gaps.push(Duration::from_millis(u64::from(value)));
            }
        }
        (lengths, gaps)
    }
}
