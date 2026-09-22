use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv6Packet, UdpPacket, UdpRepr},
};
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
    if datagram.source.is_ipv4() != datagram.destination.is_ipv4() {
        return Err(UdpError::AddressFamilyMismatch);
    }

    let source = datagram.source.ip().into();
    let destination = datagram.destination.ip().into();
    let udp = UdpRepr {
        src_port: datagram.source.port(),
        dst_port: datagram.destination.port(),
    };
    let ip = IpRepr::new(
        source,
        destination,
        IpProtocol::Udp,
        udp.header_len() + datagram.payload.len(),
        64,
    );
    let packet_size = ip.buffer_len();
    if packet_size > mtu || packet_size > usize::from(u16::MAX) {
        return Err(UdpError::MtuExceeded { packet_size, mtu });
    }

    let checksum = ChecksumCapabilities::default();
    let mut bytes = vec![0_u8; packet_size];
    ip.emit(&mut bytes[..], &checksum);
    udp.emit(
        &mut UdpPacket::new_unchecked(&mut bytes[ip.header_len()..]),
        &source,
        &destination,
        datagram.payload.len(),
        |payload| payload.copy_from_slice(&datagram.payload),
        &checksum,
    );
    Ok(Packet::new(bytes))
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
            let source = datagram.source.ip().into();
            let destination = datagram.destination.ip().into();
            let checksum_valid = match IpVersion::of_packet(packet.data()).unwrap() {
                IpVersion::Ipv4 => {
                    let ip = Ipv4Packet::new_checked(packet.data()).unwrap();
                    assert!(ip.verify_checksum());
                    UdpPacket::new_checked(ip.payload())
                        .unwrap()
                        .verify_checksum(&source, &destination)
                }
                IpVersion::Ipv6 => {
                    let ip = Ipv6Packet::new_checked(packet.data()).unwrap();
                    UdpPacket::new_checked(ip.payload())
                        .unwrap()
                        .verify_checksum(&source, &destination)
                }
            };
            assert!(checksum_valid);
            assert_eq!(parse_udp_packet(&packet), Some(datagram));
        }
    }

    #[test]
    fn rejects_mixed_families_and_packets_over_mtu() {
        let mixed = UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
            &b"mixed"[..],
        );
        assert_eq!(
            build_udp_packet(&mixed, 1_500),
            Err(UdpError::AddressFamilyMismatch)
        );

        let oversized = UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "198.51.100.2:4000".parse().unwrap(),
            vec![0_u8; 1_473],
        );
        assert_eq!(
            build_udp_packet(&oversized, 1_500),
            Err(UdpError::MtuExceeded {
                packet_size: 1_501,
                mtu: 1_500,
            })
        );
    }
}
