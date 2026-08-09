use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, UdpPacket};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::Packet;

/// One UDP datagram with the original IP endpoints retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDatagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Bytes,
}

impl UdpDatagram {
    #[must_use]
    pub fn new(source: SocketAddr, destination: SocketAddr, payload: impl Into<Bytes>) -> Self {
        Self {
            source,
            destination,
            payload: payload.into(),
        }
    }
}

/// Async, datagram-preserving UDP API.
pub struct UdpSocket {
    pub(crate) receiver: mpsc::Receiver<UdpDatagram>,
    pub(crate) raw_outbound: mpsc::Sender<Packet>,
    pub(crate) cancellation: CancellationToken,
    pub(crate) mtu: usize,
}

impl UdpSocket {
    /// Receives a datagram from the TUN side. Returns `None` after stop begins.
    pub async fn recv(&mut self) -> Option<UdpDatagram> {
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => None,
            datagram = self.receiver.recv() => datagram,
        }
    }

    /// Writes one datagram back to the TUN side with bounded backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::AddressFamilyMismatch`] for mixed IP families,
    /// [`UdpError::MtuExceeded`] for oversized datagrams, or
    /// [`UdpError::Stopped`] after shutdown begins.
    pub async fn send(&self, datagram: UdpDatagram) -> Result<(), UdpError> {
        let packet = build_udp_packet(&datagram, self.mtu)?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(UdpError::Stopped),
            result = self.raw_outbound.send(packet) => {
                result.map_err(|_| UdpError::Stopped)
            }
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UdpError {
    #[error("UDP source and destination address families differ")]
    AddressFamilyMismatch,
    #[error("UDP datagram produces a {packet_size}-byte IP packet exceeding MTU {mtu}")]
    MtuExceeded { packet_size: usize, mtu: usize },
    #[error("netstack is stopping or stopped")]
    Stopped,
}

pub(crate) fn parse_udp_packet(packet: &Packet) -> Option<UdpDatagram> {
    match IpVersion::of_packet(packet.data()).ok()? {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(packet.data()).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(UdpDatagram::new(
                SocketAddr::new(IpAddr::from(ip.src_addr()), udp.src_port()),
                SocketAddr::new(IpAddr::from(ip.dst_addr()), udp.dst_port()),
                Bytes::copy_from_slice(udp.payload()),
            ))
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(packet.data()).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(UdpDatagram::new(
                SocketAddr::new(IpAddr::from(ip.src_addr()), udp.src_port()),
                SocketAddr::new(IpAddr::from(ip.dst_addr()), udp.dst_port()),
                Bytes::copy_from_slice(udp.payload()),
            ))
        }
    }
}

pub(crate) fn build_udp_packet(datagram: &UdpDatagram, mtu: usize) -> Result<Packet, UdpError> {
    match (datagram.source, datagram.destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => build_udp_v4(
            *source.ip(),
            source.port(),
            *destination.ip(),
            destination.port(),
            &datagram.payload,
            mtu,
        ),
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => build_udp_v6(
            *source.ip(),
            source.port(),
            *destination.ip(),
            destination.port(),
            &datagram.payload,
            mtu,
        ),
        _ => Err(UdpError::AddressFamilyMismatch),
    }
}

fn build_udp_v4(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
    mtu: usize,
) -> Result<Packet, UdpError> {
    let packet_size = 20 + 8 + payload.len();
    check_packet_size(packet_size, mtu)?;
    let udp_len =
        u16::try_from(8 + payload.len()).map_err(|_| UdpError::MtuExceeded { packet_size, mtu })?;
    let total_len =
        u16::try_from(packet_size).map_err(|_| UdpError::MtuExceeded { packet_size, mtu })?;

    let mut packet = vec![0_u8; packet_size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    write_udp_header(
        &mut packet[20..],
        source_port,
        destination_port,
        udp_len,
        payload,
    );
    let checksum = udp_checksum_v4(source, destination, &packet[20..]);
    packet[26..28].copy_from_slice(&nonzero_checksum(checksum).to_be_bytes());
    Ok(Packet::new(packet))
}

fn build_udp_v6(
    source: Ipv6Addr,
    source_port: u16,
    destination: Ipv6Addr,
    destination_port: u16,
    payload: &[u8],
    mtu: usize,
) -> Result<Packet, UdpError> {
    let packet_size = 40 + 8 + payload.len();
    check_packet_size(packet_size, mtu)?;
    let udp_len =
        u16::try_from(8 + payload.len()).map_err(|_| UdpError::MtuExceeded { packet_size, mtu })?;

    let mut packet = vec![0_u8; packet_size];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&udp_len.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    write_udp_header(
        &mut packet[40..],
        source_port,
        destination_port,
        udp_len,
        payload,
    );
    let checksum = udp_checksum_v6(source, destination, &packet[40..]);
    packet[46..48].copy_from_slice(&nonzero_checksum(checksum).to_be_bytes());
    Ok(Packet::new(packet))
}

fn check_packet_size(packet_size: usize, mtu: usize) -> Result<(), UdpError> {
    if packet_size > mtu || packet_size > usize::from(u16::MAX) {
        Err(UdpError::MtuExceeded { packet_size, mtu })
    } else {
        Ok(())
    }
}

fn write_udp_header(
    udp: &mut [u8],
    source_port: u16,
    destination_port: u16,
    udp_len: u16,
    payload: &[u8],
) {
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[8..].copy_from_slice(payload);
}

fn udp_checksum_v4(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_checksum_bytes(&mut sum, &source.octets());
    add_checksum_bytes(&mut sum, &destination.octets());
    sum += 17;
    sum += u32::try_from(udp.len()).unwrap_or(u32::MAX);
    add_checksum_bytes(&mut sum, udp);
    fold_checksum(sum)
}

fn udp_checksum_v6(source: Ipv6Addr, destination: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_checksum_bytes(&mut sum, &source.octets());
    add_checksum_bytes(&mut sum, &destination.octets());
    let length = u32::try_from(udp.len()).unwrap_or(u32::MAX);
    sum += length >> 16;
    sum += length & 0xffff;
    sum += 17;
    add_checksum_bytes(&mut sum, udp);
    fold_checksum(sum)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_checksum_bytes(&mut sum, bytes);
    fold_checksum(sum)
}

fn add_checksum_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        *sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        *sum += u32::from(*byte) << 8;
    }
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits in u16")
}

const fn nonzero_checksum(checksum: u16) -> u16 {
    if checksum == 0 { u16::MAX } else { checksum }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_both_ip_families() {
        for datagram in [
            UdpDatagram::new(
                "192.0.2.1:53".parse().unwrap(),
                "198.51.100.2:4000".parse().unwrap(),
                &b"v4"[..],
            ),
            UdpDatagram::new(
                "[2001:db8::1]:53".parse().unwrap(),
                "[2001:db8::2]:4000".parse().unwrap(),
                &b"v6"[..],
            ),
        ] {
            let packet = build_udp_packet(&datagram, 1_500).unwrap();
            assert_eq!(parse_udp_packet(&packet), Some(datagram));
        }
    }
}
