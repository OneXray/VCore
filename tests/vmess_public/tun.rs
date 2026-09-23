//! Host-fd/netstack interop only: no real interface, route or system proxy.
use super::*;
use std::os::unix::net::UnixDatagram;

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn packet(
    target: SocketAddr,
    protocol: u8,
    seq_ack_flags: (u32, u32, u8),
    payload: &[u8],
) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 fixture");
    };
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let mut segment = vec![0; if protocol == 6 { 20 } else { 8 }];
    segment[..2].copy_from_slice(&12000_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&target.port().to_be_bytes());
    if protocol == 6 {
        segment[4..8].copy_from_slice(&seq_ack_flags.0.to_be_bytes());
        segment[8..12].copy_from_slice(&seq_ack_flags.1.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = seq_ack_flags.2;
        segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    } else {
        segment[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    segment.extend_from_slice(payload);
    let mut pseudo = source.octets().to_vec();
    pseudo.extend_from_slice(&target.ip().octets());
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let offset = if protocol == 6 { 16 } else { 6 };
    let value = checksum(&pseudo);
    segment[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + segment.len()) as u16).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&source.octets());
    ip[16..20].copy_from_slice(&target.ip().octets());
    let value = checksum(&ip);
    ip[10..12].copy_from_slice(&value.to_be_bytes());
    ip.extend_from_slice(&segment);
    let mut framed = 2_u32.to_be_bytes().to_vec(); // Darwin AF_INET PI header.
    framed.extend_from_slice(&ip);
    framed
}

pub(crate) fn receive(peer: &UnixDatagram, protocol: u8) -> Vec<u8> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "TUN packet deadline");
        let mut bytes = [0; 1504];
        let size = peer.recv(&mut bytes).unwrap();
        assert!(size >= 24);
        assert_eq!(&bytes[..4], 2_u32.to_be_bytes());
        let ip = &bytes[4..size];
        assert_eq!(checksum(&ip[..20]), 0);
        if ip[9] == protocol {
            return ip.to_vec();
        }
    }
}
