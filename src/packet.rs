use crate::{Result, VCoreError};

const UTUN_HEADER_LEN: usize = 4;
const DARWIN_AF_INET: u32 = 2;
const DARWIN_AF_INET6: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    fn from_packet(packet: &[u8]) -> Result<Self> {
        let first = *packet
            .first()
            .ok_or(VCoreError::InvalidPacket("empty IP packet"))?;
        match first >> 4 {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            _ => Err(VCoreError::InvalidPacket("unsupported IP version")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunFraming {
    RawIp,
    Utun,
}

impl TunFraming {
    pub fn decode(self, frame: &[u8]) -> Result<(IpVersion, &[u8])> {
        match self {
            Self::RawIp => Ok((IpVersion::from_packet(frame)?, frame)),
            Self::Utun => {
                if frame.len() <= UTUN_HEADER_LEN {
                    return Err(VCoreError::InvalidPacket("truncated utun frame"));
                }
                let family_bytes: [u8; UTUN_HEADER_LEN] = frame[..UTUN_HEADER_LEN]
                    .try_into()
                    .map_err(|_| VCoreError::InvalidPacket("truncated utun frame"))?;
                let family = u32::from_be_bytes(family_bytes);
                let packet = &frame[UTUN_HEADER_LEN..];
                let version = match family {
                    DARWIN_AF_INET => IpVersion::V4,
                    DARWIN_AF_INET6 => IpVersion::V6,
                    _ => return Err(VCoreError::InvalidPacket("unknown utun address family")),
                };
                if IpVersion::from_packet(packet)? != version {
                    return Err(VCoreError::InvalidPacket(
                        "utun address family does not match IP packet",
                    ));
                }
                Ok((version, packet))
            }
        }
    }

    pub fn encode(self, packet: &[u8], output: &mut Vec<u8>) -> Result<IpVersion> {
        let version = IpVersion::from_packet(packet)?;
        output.clear();
        if self == Self::Utun {
            let family = match version {
                IpVersion::V4 => DARWIN_AF_INET,
                IpVersion::V6 => DARWIN_AF_INET6,
            };
            output.extend_from_slice(&family.to_be_bytes());
        }
        output.extend_from_slice(packet);
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    const IPV6: [u8; 40] = [
        0x60, 0, 0, 0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    #[test]
    fn raw_ip_round_trips_both_families() {
        for packet in [&IPV4[..], &IPV6[..]] {
            let mut frame = Vec::new();
            TunFraming::RawIp.encode(packet, &mut frame).unwrap();
            let (_, decoded) = TunFraming::RawIp.decode(&frame).unwrap();
            assert_eq!(decoded, packet);
        }
    }

    #[test]
    fn utun_round_trips_both_families() {
        for packet in [&IPV4[..], &IPV6[..]] {
            let mut frame = Vec::new();
            TunFraming::Utun.encode(packet, &mut frame).unwrap();
            let (_, decoded) = TunFraming::Utun.decode(&frame).unwrap();
            assert_eq!(decoded, packet);
        }
    }

    #[test]
    fn utun_rejects_family_mismatch() {
        let mut frame = DARWIN_AF_INET6.to_be_bytes().to_vec();
        frame.extend_from_slice(&IPV4);
        assert!(TunFraming::Utun.decode(&frame).is_err());
    }
}
