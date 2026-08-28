//! SOCKS5 wire helpers used by outbound implementations.

use std::{fmt, io, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::session::Destination;

pub const VERSION: u8 = 0x05;
pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
pub const ADDRESS_IPV4: u8 = 0x01;
pub const ADDRESS_DOMAIN: u8 = 0x03;
pub const ADDRESS_IPV6: u8 = 0x04;

/// RSV, FRAG, ATYP, one maximum-length domain, and the destination port.
pub const MAX_UDP_HEADER_SIZE: u16 = 2 + 1 + 1 + 1 + u8::MAX as u16 + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5CodecError {
    Truncated,
    NonZeroReserved,
    Fragmented,
    UnsupportedAddress,
    InvalidDomain,
    ZeroPort,
    Oversize,
}

impl fmt::Display for Socks5CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated SOCKS5 datagram",
            Self::NonZeroReserved => "non-zero SOCKS5 reserved field",
            Self::Fragmented => "fragmented SOCKS5 datagram",
            Self::UnsupportedAddress => "unsupported SOCKS5 address type",
            Self::InvalidDomain => "invalid SOCKS5 domain",
            Self::ZeroPort => "SOCKS5 destination port is zero",
            Self::Oversize => "SOCKS5 datagram exceeds its limit",
        })
    }
}

impl std::error::Error for Socks5CodecError {}

pub async fn read_destination<R>(reader: &mut R, allow_zero_port: bool) -> io::Result<Destination>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let address_type = reader.read_u8().await?;
    let destination = match address_type {
        ADDRESS_IPV4 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            let port = reader.read_u16().await?;
            Destination::Ip(SocketAddr::from((octets, port)))
        }
        ADDRESS_IPV6 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            let port = reader.read_u16().await?;
            Destination::Ip(SocketAddr::from((octets, port)))
        }
        ADDRESS_DOMAIN => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty SOCKS5 domain",
                ));
            }
            let mut domain = vec![0_u8; length];
            reader.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 domain is not UTF-8")
            })?;
            let port = reader.read_u16().await?;
            if port == 0 && allow_zero_port {
                Destination::Domain { host: domain, port }
            } else {
                Destination::domain(domain, port)?
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported SOCKS5 address type",
            ));
        }
    };
    if destination.port() == 0 && !allow_zero_port {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 destination port is zero",
        ));
    }
    Ok(destination)
}

pub fn decode_udp_packet(
    packet: &[u8],
    max_size: usize,
) -> Result<(Destination, &[u8]), Socks5CodecError> {
    if packet.len() > max_size {
        return Err(Socks5CodecError::Oversize);
    }
    if packet.len() < 4 {
        return Err(Socks5CodecError::Truncated);
    }
    if packet[..2] != [0, 0] {
        return Err(Socks5CodecError::NonZeroReserved);
    }
    if packet[2] != 0 {
        return Err(Socks5CodecError::Fragmented);
    }
    let (destination, consumed) = decode_address(&packet[3..])?;
    Ok((destination, &packet[3 + consumed..]))
}

pub fn encode_udp_packet(
    remote: &Destination,
    payload: &[u8],
    max_size: usize,
) -> Result<Vec<u8>, Socks5CodecError> {
    let packet_size = 3_usize
        .checked_add(encoded_address_size(remote)?)
        .and_then(|size| size.checked_add(payload.len()))
        .ok_or(Socks5CodecError::Oversize)?;
    if packet_size > max_size {
        return Err(Socks5CodecError::Oversize);
    }
    let mut packet = Vec::with_capacity(packet_size);
    packet.extend_from_slice(&[0, 0, 0]);
    encode_address(remote, &mut packet).map_err(|_| Socks5CodecError::UnsupportedAddress)?;
    packet.extend_from_slice(payload);
    debug_assert_eq!(packet.len(), packet_size);
    Ok(packet)
}

fn encoded_address_size(destination: &Destination) -> Result<usize, Socks5CodecError> {
    match destination {
        Destination::Ip(SocketAddr::V4(_)) => Ok(1 + 4 + 2),
        Destination::Ip(SocketAddr::V6(_)) => Ok(1 + 16 + 2),
        Destination::Domain { host, .. } if (1..=usize::from(u8::MAX)).contains(&host.len()) => {
            Ok(1 + 1 + host.len() + 2)
        }
        Destination::Domain { .. } => Err(Socks5CodecError::UnsupportedAddress),
    }
}

pub fn encode_address(destination: &Destination, output: &mut Vec<u8>) -> io::Result<()> {
    match destination {
        Destination::Ip(SocketAddr::V4(address)) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&address.ip().octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
        Destination::Ip(SocketAddr::V6(address)) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&address.ip().octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
        Destination::Domain { host, port } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 domain is too long")
            })?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty SOCKS5 domain",
                ));
            }
            output.extend_from_slice(&[ADDRESS_DOMAIN, length]);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn decode_address(packet: &[u8]) -> Result<(Destination, usize), Socks5CodecError> {
    let address_type = *packet.first().ok_or(Socks5CodecError::Truncated)?;
    match address_type {
        ADDRESS_IPV4 => {
            if packet.len() < 7 {
                return Err(Socks5CodecError::Truncated);
            }
            let port = u16::from_be_bytes([packet[5], packet[6]]);
            if port == 0 {
                return Err(Socks5CodecError::ZeroPort);
            }
            Ok((
                Destination::Ip(SocketAddr::from((
                    [packet[1], packet[2], packet[3], packet[4]],
                    port,
                ))),
                7,
            ))
        }
        ADDRESS_IPV6 => {
            if packet.len() < 19 {
                return Err(Socks5CodecError::Truncated);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[1..17]);
            let port = u16::from_be_bytes([packet[17], packet[18]]);
            if port == 0 {
                return Err(Socks5CodecError::ZeroPort);
            }
            Ok((Destination::Ip(SocketAddr::from((octets, port))), 19))
        }
        ADDRESS_DOMAIN => {
            let length = *packet.get(1).ok_or(Socks5CodecError::Truncated)? as usize;
            if length == 0 || packet.len() < length + 4 {
                return Err(if length == 0 {
                    Socks5CodecError::InvalidDomain
                } else {
                    Socks5CodecError::Truncated
                });
            }
            let domain = std::str::from_utf8(&packet[2..2 + length])
                .map_err(|_| Socks5CodecError::InvalidDomain)?;
            let port = u16::from_be_bytes([packet[2 + length], packet[3 + length]]);
            if port == 0 {
                return Err(Socks5CodecError::ZeroPort);
            }
            Ok((
                Destination::Domain {
                    host: domain.to_owned(),
                    port,
                },
                length + 4,
            ))
        }
        _ => Err(Socks5CodecError::UnsupportedAddress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_codec_round_trips_every_address_type() {
        let destinations = [
            Destination::from("127.0.0.1:53".parse::<SocketAddr>().unwrap()),
            Destination::from("[::1]:53".parse::<SocketAddr>().unwrap()),
            Destination::domain("example.com", 53).unwrap(),
        ];
        for destination in destinations {
            let encoded = encode_udp_packet(&destination, b"payload", 65_535).unwrap();
            let (decoded, payload) = decode_udp_packet(&encoded, 65_535).unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(payload, b"payload");
        }
    }

    #[test]
    fn udp_codec_rejects_reserved_fragments_and_truncation() {
        assert_eq!(
            decode_udp_packet(&[1, 0, 0, 1], 65_535).unwrap_err(),
            Socks5CodecError::NonZeroReserved
        );
        assert_eq!(
            decode_udp_packet(&[0, 0, 1, 1], 65_535).unwrap_err(),
            Socks5CodecError::Fragmented
        );
        assert_eq!(
            decode_udp_packet(&[0, 0, 0, 1], 65_535).unwrap_err(),
            Socks5CodecError::Truncated
        );
    }

    #[test]
    fn udp_codec_enforces_the_total_size_limit() {
        let destination = Destination::domain("example.com", 53).unwrap();
        assert_eq!(
            encode_udp_packet(&destination, &[0; 64], 16).unwrap_err(),
            Socks5CodecError::Oversize
        );
    }

    #[test]
    fn maximum_udp_header_constant_covers_a_domain_destination() {
        let destination = Destination::domain("a".repeat(255), 53).unwrap();
        let encoded = encode_udp_packet(&destination, &[], u16::MAX as usize).unwrap();
        assert_eq!(encoded.len(), usize::from(MAX_UDP_HEADER_SIZE));
    }
}
