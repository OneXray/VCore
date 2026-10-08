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

/// Borrowed endpoints and payload of a checked IPv4 or IPv6 UDP packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPacketView<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: &'a [u8],
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

/// A send-only handle sharing the socket's existing bounded TUN output queue.
#[derive(Clone)]
pub struct UdpSender {
    raw_outbound: mpsc::Sender<Packet>,
    cancellation: CancellationToken,
    mtu: usize,
}

impl UdpSocket {
    /// Returns a send-only handle without adding a queue or receiving ownership.
    #[must_use]
    pub fn sender(&self) -> UdpSender {
        UdpSender {
            raw_outbound: self.raw_outbound.clone(),
            cancellation: self.cancellation.clone(),
            mtu: self.mtu,
        }
    }

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
        send_udp_datagram(&self.raw_outbound, &self.cancellation, self.mtu, datagram).await
    }
}

impl UdpSender {
    /// Writes one datagram back to the TUN side with bounded backpressure.
    ///
    /// # Errors
    ///
    /// Returns the same address-family, MTU, and stop errors as [`UdpSocket::send`].
    pub async fn send(&self, datagram: UdpDatagram) -> Result<(), UdpError> {
        send_udp_datagram(&self.raw_outbound, &self.cancellation, self.mtu, datagram).await
    }
}

async fn send_udp_datagram(
    raw_outbound: &mpsc::Sender<Packet>,
    cancellation: &CancellationToken,
    mtu: usize,
    datagram: UdpDatagram,
) -> Result<(), UdpError> {
    let packet = build_udp_packet(&datagram, mtu)?;
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(UdpError::Stopped),
        result = raw_outbound.send(packet) => {
            result.map_err(|_| UdpError::Stopped)
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
    let view = parse_udp_packet_view(packet.data())?;
    Some(UdpDatagram::new(
        view.source,
        view.destination,
        Bytes::copy_from_slice(view.payload),
    ))
}

/// Parses a UDP packet without copying its payload.
///
/// Retains the netstack's checked-header policy: direct UDP next headers only,
/// without additional checksum or fragmentation validation.
#[must_use]
pub fn parse_udp_packet_view(bytes: &[u8]) -> Option<UdpPacketView<'_>> {
    if bytes.is_empty() {
        return None;
    }
    match IpVersion::of_packet(bytes).ok()? {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(bytes).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(UdpPacketView {
                source: SocketAddr::new(IpAddr::from(ip.src_addr()), udp.src_port()),
                destination: SocketAddr::new(IpAddr::from(ip.dst_addr()), udp.dst_port()),
                payload: udp.payload(),
            })
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(bytes).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(UdpPacketView {
                source: SocketAddr::new(IpAddr::from(ip.src_addr()), udp.src_port()),
                destination: SocketAddr::new(IpAddr::from(ip.dst_addr()), udp.dst_port()),
                payload: udp.payload(),
            })
        }
    }
}

pub(crate) fn build_udp_packet(datagram: &UdpDatagram, mtu: usize) -> Result<Packet, UdpError> {
    let mut bytes = Vec::new();
    encode_udp_packet_into(datagram, mtu, &mut bytes)?;
    Ok(Packet::new(bytes))
}

/// Encodes one checksummed IP/UDP packet, reusing the caller's allocation.
///
/// # Errors
///
/// Returns [`UdpError::AddressFamilyMismatch`] or [`UdpError::MtuExceeded`]
/// without changing `frame`. This pure codec is independent of stack shutdown.
pub fn encode_udp_packet_into(
    datagram: &UdpDatagram,
    mtu: usize,
    frame: &mut Vec<u8>,
) -> Result<(), UdpError> {
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
    frame.clear();
    frame.resize(packet_size, 0);
    ip.emit(&mut frame[..], &checksum);
    udp.emit(
        &mut UdpPacket::new_unchecked(&mut frame[ip.header_len()..]),
        &source,
        &destination,
        datagram.payload.len(),
        |payload| payload.copy_from_slice(&datagram.payload),
        &checksum,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use super::*;

    fn socket_fixture() -> (UdpSocket, mpsc::Sender<UdpDatagram>, mpsc::Receiver<Packet>) {
        let (inbound, receiver) = mpsc::channel(1);
        let (raw_outbound, output) = mpsc::channel(1);
        (
            UdpSocket {
                receiver,
                raw_outbound,
                cancellation: CancellationToken::new(),
                mtu: 1_500,
            },
            inbound,
            output,
        )
    }

    fn valid_datagram() -> UdpDatagram {
        UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "198.51.100.2:4000".parse().unwrap(),
            &b"payload"[..],
        )
    }

    #[test]
    fn configured_jumbo_mtu_preserves_full_udp_packets_for_both_families() {
        for (source, destination, overhead) in [
            ("192.0.2.1:4000", "198.51.100.2:443", 28),
            ("[2001:db8::1]:4000", "[2001:db8::2]:443", 48),
        ] {
            let datagram = UdpDatagram::new(
                source.parse().unwrap(),
                destination.parse().unwrap(),
                vec![0x5a; 9000 - overhead],
            );
            let mut frame = Vec::new();
            encode_udp_packet_into(&datagram, 9000, &mut frame).unwrap();
            assert_eq!(frame.len(), 9000);
            let parsed = parse_udp_packet_view(&frame).unwrap();
            assert_eq!(parsed.source, datagram.source);
            assert_eq!(parsed.destination, datagram.destination);
            assert_eq!(parsed.payload, datagram.payload.as_ref());
            assert!(matches!(
                encode_udp_packet_into(&datagram, 8999, &mut frame),
                Err(UdpError::MtuExceeded { .. })
            ));
        }
    }

    #[tokio::test]
    async fn sender_backpressure_does_not_block_socket_receive() {
        let (mut socket, inbound, mut output) = socket_fixture();
        let sender = socket.sender();
        let datagram = valid_datagram();
        socket.send(datagram.clone()).await.unwrap();

        let mut blocked_send = Box::pin(sender.send(datagram.clone()));
        assert!(futures_util::poll!(&mut blocked_send).is_pending());

        inbound.try_send(datagram.clone()).unwrap();
        assert_eq!(
            futures_util::poll!(Box::pin(socket.recv())),
            Poll::Ready(Some(datagram.clone()))
        );
        assert!(futures_util::poll!(&mut blocked_send).is_pending());

        assert_eq!(
            parse_udp_packet(&output.try_recv().unwrap()),
            Some(datagram.clone())
        );
        assert_eq!(futures_util::poll!(&mut blocked_send), Poll::Ready(Ok(())));
        assert_eq!(
            parse_udp_packet(&output.try_recv().unwrap()),
            Some(datagram)
        );
    }

    #[tokio::test]
    async fn stop_unblocks_pending_sender_and_socket_receive() {
        let (mut socket, _inbound, _output) = socket_fixture();
        let sender = socket.sender();
        let cancellation = socket.cancellation.clone();
        let datagram = valid_datagram();
        socket.send(datagram.clone()).await.unwrap();

        let mut blocked_send = Box::pin(sender.send(datagram));
        let mut blocked_receive = Box::pin(socket.recv());
        assert!(futures_util::poll!(&mut blocked_send).is_pending());
        assert!(futures_util::poll!(&mut blocked_receive).is_pending());

        cancellation.cancel();
        assert_eq!(
            futures_util::poll!(&mut blocked_send),
            Poll::Ready(Err(UdpError::Stopped))
        );
        assert_eq!(futures_util::poll!(&mut blocked_receive), Poll::Ready(None));
    }

    #[tokio::test]
    async fn sender_preserves_socket_validation_and_stop_errors() {
        let (socket, _inbound, output) = socket_fixture();
        let sender = socket.sender();
        let mixed = UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
            &b"mixed"[..],
        );
        let oversized = UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "198.51.100.2:4000".parse().unwrap(),
            vec![0_u8; 1_473],
        );

        for stopped in [false, true] {
            if stopped {
                socket.cancellation.cancel();
            }
            assert_eq!(
                sender.send(mixed.clone()).await,
                Err(UdpError::AddressFamilyMismatch)
            );
            assert_eq!(
                socket.send(mixed.clone()).await,
                Err(UdpError::AddressFamilyMismatch)
            );
            assert_eq!(
                sender.send(oversized.clone()).await,
                Err(UdpError::MtuExceeded {
                    packet_size: 1_501,
                    mtu: 1_500,
                })
            );
            assert_eq!(
                socket.send(oversized.clone()).await,
                Err(UdpError::MtuExceeded {
                    packet_size: 1_501,
                    mtu: 1_500,
                })
            );
        }
        assert_eq!(sender.send(valid_datagram()).await, Err(UdpError::Stopped));
        assert_eq!(socket.send(valid_datagram()).await, Err(UdpError::Stopped));

        let (socket, _inbound, output_on_close) = socket_fixture();
        let sender = socket.sender();
        drop(output_on_close);
        assert_eq!(sender.send(valid_datagram()).await, Err(UdpError::Stopped));
        assert_eq!(socket.send(valid_datagram()).await, Err(UdpError::Stopped));
        drop(output);
    }

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

    #[test]
    fn borrowed_codec_reuses_frames_and_retains_payload_storage() {
        let mut frame = Vec::with_capacity(1_500);
        let storage = frame.as_ptr();
        for datagram in [
            valid_datagram(),
            UdpDatagram::new(
                "[2001:db8::1]:53".parse().unwrap(),
                "[2001:db8::2]:4000".parse().unwrap(),
                b"ipv6-payload".as_slice(),
            ),
        ] {
            encode_udp_packet_into(&datagram, 1_500, &mut frame).unwrap();
            assert_eq!(frame.as_ptr(), storage);
            let view = parse_udp_packet_view(&frame).unwrap();
            assert_eq!(view.source, datagram.source);
            assert_eq!(view.destination, datagram.destination);
            assert_eq!(view.payload, datagram.payload.as_ref());
            let payload_offset = frame.len() - datagram.payload.len();
            assert_eq!(view.payload.as_ptr(), frame[payload_offset..].as_ptr());
            assert_eq!(frame, build_udp_packet(&datagram, 1_500).unwrap().data());
        }
    }

    #[test]
    fn codec_validation_errors_leave_the_reusable_frame_unchanged() {
        let mut frame = b"previous-packet".to_vec();
        let old = frame.clone();
        let mixed = UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
            b"mixed".as_slice(),
        );
        assert_eq!(
            encode_udp_packet_into(&mixed, 1_500, &mut frame),
            Err(UdpError::AddressFamilyMismatch)
        );
        assert_eq!(frame, old);

        let oversized = UdpDatagram::new(
            "192.0.2.1:53".parse().unwrap(),
            "198.51.100.2:4000".parse().unwrap(),
            vec![0; 1_473],
        );
        assert_eq!(
            encode_udp_packet_into(&oversized, 1_500, &mut frame),
            Err(UdpError::MtuExceeded {
                packet_size: 1_501,
                mtu: 1_500,
            })
        );
        assert_eq!(frame, old);
    }

    #[test]
    fn borrowed_parser_keeps_the_existing_checked_header_policy() {
        assert!(parse_udp_packet_view(&[]).is_none());
        let mut packet = build_udp_packet(&valid_datagram(), 1_500)
            .unwrap()
            .data()
            .to_vec();
        assert!(parse_udp_packet_view(&packet[..27]).is_none());

        // This refactor does not add IP/UDP checksum or fragment rejection.
        packet[6] = 0x20;
        packet[10] ^= 1;
        packet[26] ^= 1;
        packet.push(0xaa);
        let view = parse_udp_packet_view(&packet).unwrap();
        assert_eq!(view.payload, valid_datagram().payload.as_ref());
        assert_eq!(view.source, valid_datagram().source);
    }
}
