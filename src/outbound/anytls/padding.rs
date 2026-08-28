use std::{collections::BTreeMap, io};

use bytes::{Bytes, BytesMut};
use md5::{Digest as _, Md5};
use rand::Rng as _;
use tokio::io::{AsyncWrite, AsyncWriteExt as _};

use super::frame::{Command, Frame, HEADER_LENGTH, MAX_FRAME_PAYLOAD};

pub(crate) const DEFAULT_PADDING_SCHEME: &str = "stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

const MAX_STOP: u32 = 256;
const MAX_ITEMS_PER_PACKET: usize = 32;
const MAX_LOGICAL_PADDING_BYTES: usize = MAX_FRAME_PAYLOAD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaddingItem {
    Range { minimum: u16, maximum: u16 },
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaddingScheme {
    md5: [u8; 16],
    stop: u32,
    packets: BTreeMap<u32, Box<[PaddingItem]>>,
}

impl PaddingScheme {
    pub(crate) fn default_scheme() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME.as_bytes())
            .expect("the built-in AnyTLS padding scheme is valid")
    }

    pub(crate) fn parse(raw: &[u8]) -> io::Result<Self> {
        if raw.is_empty() || raw.len() > MAX_FRAME_PAYLOAD {
            return Err(invalid_scheme("padding scheme has an invalid size"));
        }
        let text =
            std::str::from_utf8(raw).map_err(|_| invalid_scheme("padding scheme is not UTF-8"))?;
        let mut stop = None;
        let mut packets = BTreeMap::new();
        for line in text.lines() {
            if line.is_empty() {
                return Err(invalid_scheme("padding scheme contains an empty line"));
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid_scheme("padding scheme line has no equals sign"))?;
            if key == "stop" {
                if stop.is_some() {
                    return Err(invalid_scheme("padding scheme repeats stop"));
                }
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| invalid_scheme("padding stop is not an integer"))?;
                if parsed == 0 || parsed > MAX_STOP {
                    return Err(invalid_scheme(
                        "padding stop is outside the supported range",
                    ));
                }
                stop = Some(parsed);
                continue;
            }

            let packet = key
                .parse::<u32>()
                .map_err(|_| invalid_scheme("padding packet key is not an integer"))?;
            if packets.contains_key(&packet) {
                return Err(invalid_scheme("padding scheme repeats a packet key"));
            }
            let mut items = Vec::new();
            for token in value.split(',') {
                if items.len() == MAX_ITEMS_PER_PACKET {
                    return Err(invalid_scheme("padding packet has too many items"));
                }
                if token == "c" {
                    items.push(PaddingItem::Check);
                    continue;
                }
                let (minimum, maximum) = token
                    .split_once('-')
                    .ok_or_else(|| invalid_scheme("padding range has an invalid form"))?;
                let mut minimum = minimum
                    .parse::<u16>()
                    .map_err(|_| invalid_scheme("padding range minimum is invalid"))?;
                let mut maximum = maximum
                    .parse::<u16>()
                    .map_err(|_| invalid_scheme("padding range maximum is invalid"))?;
                if minimum == 0 || maximum == 0 {
                    return Err(invalid_scheme("padding range must be positive"));
                }
                if minimum > maximum {
                    std::mem::swap(&mut minimum, &mut maximum);
                }
                items.push(PaddingItem::Range { minimum, maximum });
            }
            if items.is_empty() {
                return Err(invalid_scheme("padding packet has no items"));
            }
            packets.insert(packet, items.into_boxed_slice());
        }
        let stop = stop.ok_or_else(|| invalid_scheme("padding scheme omits stop"))?;
        if packets.keys().any(|packet| *packet >= stop) {
            return Err(invalid_scheme("padding packet key is not below stop"));
        }
        let packet_zero = packets
            .get(&0)
            .ok_or_else(|| invalid_scheme("padding scheme omits packet zero"))?;
        if !matches!(packet_zero.as_ref(), [PaddingItem::Range { .. }]) {
            return Err(invalid_scheme(
                "padding packet zero must contain exactly one range",
            ));
        }
        for items in packets.values() {
            let maximum_total = items.iter().try_fold(0_usize, |total, item| match item {
                PaddingItem::Check => Some(total),
                PaddingItem::Range { maximum, .. } => total.checked_add(usize::from(*maximum)),
            });
            if maximum_total.is_none_or(|total| total > MAX_LOGICAL_PADDING_BYTES) {
                return Err(invalid_scheme(
                    "padding packet can generate too much plaintext",
                ));
            }
        }
        Ok(Self {
            md5: Md5::digest(raw).into(),
            stop,
            packets,
        })
    }

    pub(crate) fn md5_hex(&self) -> String {
        let mut output = String::with_capacity(32);
        for byte in self.md5 {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    pub(crate) fn authentication_padding_length(&self) -> u16 {
        let items = self
            .packets
            .get(&0)
            .expect("validated padding scheme has packet zero");
        let PaddingItem::Range { minimum, maximum } = items[0] else {
            unreachable!("validated packet zero is one range")
        };
        random_in_half_open_range(minimum, maximum)
    }

    fn generated_items(&self, packet: u32) -> Option<Vec<GeneratedItem>> {
        if packet >= self.stop {
            return None;
        }
        let items = self.packets.get(&packet)?;
        Some(
            items
                .iter()
                .map(|item| match *item {
                    PaddingItem::Check => GeneratedItem::Check,
                    PaddingItem::Range { minimum, maximum } => GeneratedItem::Size(usize::from(
                        random_in_half_open_range(minimum, maximum),
                    )),
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeneratedItem {
    Size(usize),
    Check,
}

fn random_in_half_open_range(minimum: u16, maximum: u16) -> u16 {
    if minimum == maximum {
        minimum
    } else {
        rand::rng().random_range(minimum..maximum)
    }
}

pub(crate) async fn write_packet<W>(
    writer: &mut W,
    scheme: &PaddingScheme,
    packet: u32,
    payload: &Bytes,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let Some(items) = scheme.generated_items(packet) else {
        writer.write_all(payload).await?;
        writer.flush().await?;
        return Ok(());
    };

    let mut offset = 0_usize;
    for item in items {
        match item {
            GeneratedItem::Check if offset == payload.len() => break,
            GeneratedItem::Check => continue,
            GeneratedItem::Size(target) => {
                let remaining = &payload[offset..];
                if remaining.len() > target {
                    writer.write_all(&remaining[..target]).await?;
                    writer.flush().await?;
                    offset += target;
                    continue;
                }

                if remaining.is_empty() {
                    let waste =
                        Frame::with_payload(Command::Waste, 0, Bytes::from(vec![0_u8; target]))?;
                    let mut record = BytesMut::with_capacity(HEADER_LENGTH + target);
                    waste.encode_into(&mut record)?;
                    writer.write_all(&record).await?;
                    writer.flush().await?;
                    continue;
                }

                let mut record = BytesMut::with_capacity(target);
                record.extend_from_slice(remaining);
                offset = payload.len();
                let available = target.saturating_sub(record.len());
                if available >= HEADER_LENGTH {
                    let waste_length = available - HEADER_LENGTH;
                    let waste = Frame::with_payload(
                        Command::Waste,
                        0,
                        Bytes::from(vec![0_u8; waste_length]),
                    )?;
                    waste.encode_into(&mut record)?;
                }
                writer.write_all(&record).await?;
                writer.flush().await?;
            }
        }
    }
    if offset < payload.len() {
        writer.write_all(&payload[offset..]).await?;
        writer.flush().await?;
    }
    Ok(())
}

fn invalid_scheme(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt as _;

    use super::*;

    #[test]
    fn md5_matches_rfc_vectors() {
        assert_eq!(
            PaddingScheme::parse(b"stop=1\n0=30-30").unwrap().md5_hex(),
            "4caf70510662fcb25a851bc47113784c"
        );
        assert_eq!(
            <[u8; 16]>::from(Md5::digest(b"")),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn default_scheme_has_stable_wire_identity() {
        let scheme = PaddingScheme::default_scheme();
        assert_eq!(scheme.authentication_padding_length(), 30);
        assert_eq!(scheme.md5_hex(), "75cff2ad89aadf5e257059ee571ebe11");
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_schemes() {
        for invalid in [
            "",
            "0=30-30",
            "stop=0\n0=30-30",
            "stop=257\n0=30-30",
            "stop=1\n0=c",
            "stop=1\n1=30-30",
            "stop=1\n0=30-30\n0=31-31",
            "stop=1\n0=0-1",
        ] {
            assert!(
                PaddingScheme::parse(invalid.as_bytes()).is_err(),
                "{invalid}"
            );
        }
    }

    #[tokio::test]
    async fn packet_strategy_preserves_payload_and_adds_waste() {
        let scheme = PaddingScheme::parse(b"stop=2\n0=30-30\n1=20-20").unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let payload = Bytes::from_static(b"abc");
        let sending =
            tokio::spawn(async move { write_packet(&mut writer, &scheme, 1, &payload).await });
        let mut record = [0_u8; 20];
        reader.read_exact(&mut record).await.unwrap();
        sending.await.unwrap().unwrap();
        assert_eq!(&record[..3], b"abc");
        assert_eq!(record[3], Command::Waste.wire_value());
        assert_eq!(&record[4..8], &[0, 0, 0, 0]);
        assert_eq!(u16::from_be_bytes([record[8], record[9]]), 10);
        assert!(record[10..].iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn all_padding_item_uses_the_range_as_waste_payload_length() {
        let scheme = PaddingScheme::parse(b"stop=2\n0=30-30\n1=3-3,5-5").unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let payload = Bytes::from_static(b"abc");
        let sending =
            tokio::spawn(async move { write_packet(&mut writer, &scheme, 1, &payload).await });
        let mut record = [0_u8; 3 + HEADER_LENGTH + 5];
        reader.read_exact(&mut record).await.unwrap();
        sending.await.unwrap().unwrap();
        assert_eq!(&record[..3], b"abc");
        assert_eq!(record[3], Command::Waste.wire_value());
        assert_eq!(u16::from_be_bytes([record[8], record[9]]), 5);
        assert!(record[10..].iter().all(|byte| *byte == 0));
    }
}
