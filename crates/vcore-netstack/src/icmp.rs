use std::net::Ipv4Addr;

use smoltcp::wire::{Ipv4Packet, Ipv6Packet};

use crate::Packet;

const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_ICMPV6: u8 = 58;

/// Policy applied before smoltcp validates and optionally answers the packet.
pub(crate) enum IcmpIngress {
    /// The base IP header does not identify ICMP/ICMPv6. Normal dispatch may continue.
    NotIcmp,
    /// The packet violates `VCore`'s strict raw-IP or address policy.
    Dropped,
    /// Let smoltcp parse the message and generate an echo reply when appropriate.
    Smoltcp,
}

pub(crate) fn classify(packet: &Packet) -> IcmpIngress {
    let bytes = packet.data();
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) if bytes.get(9) == Some(&IP_PROTOCOL_ICMP) => classify_ipv4(bytes),
        Some(6) if bytes.get(6) == Some(&IP_PROTOCOL_ICMPV6) => classify_ipv6(bytes),
        _ => IcmpIngress::NotIcmp,
    }
}

fn classify_ipv4(bytes: &[u8]) -> IcmpIngress {
    let Ok(packet) = Ipv4Packet::new_checked(bytes) else {
        return IcmpIngress::Dropped;
    };
    let source = packet.src_addr();
    let destination = packet.dst_addr();
    if usize::from(packet.total_len()) != bytes.len()
        || source.is_unspecified()
        || source.is_multicast()
        || source == Ipv4Addr::BROADCAST
        || destination.is_unspecified()
        || destination.is_multicast()
        || destination == Ipv4Addr::BROADCAST
    {
        IcmpIngress::Dropped
    } else {
        IcmpIngress::Smoltcp
    }
}

fn classify_ipv6(bytes: &[u8]) -> IcmpIngress {
    let Ok(packet) = Ipv6Packet::new_checked(bytes) else {
        return IcmpIngress::Dropped;
    };
    let source = packet.src_addr();
    let destination = packet.dst_addr();
    if packet.total_len() != bytes.len()
        || source.is_unspecified()
        || source.is_multicast()
        || destination.is_unspecified()
        || destination.is_multicast()
    {
        IcmpIngress::Dropped
    } else {
        IcmpIngress::Smoltcp
    }
}
