//! Shared port-first address encoding used by VLESS, VMess and XUDP.
//! Address kinds are IPv4=1, domain=2, IPv6=3; SOCKS uses a different layout.
use crate::session::Destination;
use bytes::{BufMut as _, BytesMut};
use std::io;

pub fn encode_port_first(destination: &Destination, output: &mut BytesMut) -> io::Result<()> {
    output.put_u16(destination.port());
    match destination {
        Destination::Ip(address) if address.is_ipv4() => {
            output.put_u8(1);
            let std::net::IpAddr::V4(ip) = address.ip() else {
                unreachable!("is_ipv4 checked")
            };
            output.extend_from_slice(&ip.octets());
        }
        Destination::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "proxy domain is too long")
            })?;
            output.put_u8(2);
            output.put_u8(length);
            output.extend_from_slice(host.as_bytes());
        }
        Destination::Ip(address) => {
            output.put_u8(3);
            let std::net::IpAddr::V6(ip) = address.ip() else {
                unreachable!("non-IPv4 address is IPv6")
            };
            output.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

pub fn decode_port_first(input: &[u8]) -> io::Result<(Destination, usize)> {
    if input.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated XUDP destination",
        ));
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy destination port is zero",
        ));
    }
    match input[2] {
        1 => {
            let octets: [u8; 4] = input
                .get(3..7)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated IPv4 destination")
                })?
                .try_into()
                .expect("slice length checked");
            Ok((
                Destination::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(octets.into()),
                    port,
                )),
                7,
            ))
        }
        2 => {
            let length = usize::from(*input.get(3).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated domain destination")
            })?);
            let host = input.get(4..4 + length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated domain destination")
            })?;
            let host = std::str::from_utf8(host)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 domain"))?;
            Ok((Destination::domain(host, port)?, 4 + length))
        }
        3 => {
            let octets: [u8; 16] = input
                .get(3..19)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated IPv6 destination")
                })?
                .try_into()
                .expect("slice length checked");
            Ok((
                Destination::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(octets.into()),
                    port,
                )),
                19,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown XUDP address type",
        )),
    }
}
