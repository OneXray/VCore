use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Packet;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const ICMP_HEADER_LEN: usize = 8;
const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_ICMPV6: u8 = 58;
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ECHO_CODE: u8 = 0;
const REPLY_HOP_LIMIT: u8 = 64;
const IPV4_MORE_FRAGMENTS_OR_OFFSET: u16 = 0x3fff;

/// Result of inspecting one raw IP packet for local echo handling.
pub(crate) enum EchoReply {
    /// The base IP header does not identify ICMP/ICMPv6. Normal dispatch may continue.
    NotIcmp,
    /// The packet is ICMP but is not a valid, supported echo request.
    Dropped,
    /// A fully checksummed raw IP reply ready for the bounded TUN egress queue.
    Reply(Packet),
}

/// Builds one minimal local echo reply without retaining any per-flow state.
///
/// A successful call allocates exactly one reply buffer. Invalid and unsupported
/// packets allocate nothing.
pub(crate) fn build_echo_reply(packet: &Packet, mtu: usize) -> EchoReply {
    let bytes = packet.data();
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return EchoReply::NotIcmp;
    };
    match version {
        4 if bytes.get(9) == Some(&IP_PROTOCOL_ICMP) => build_ipv4_reply(bytes, mtu),
        6 if bytes.get(6) == Some(&IP_PROTOCOL_ICMPV6) => build_ipv6_reply(bytes, mtu),
        _ => EchoReply::NotIcmp,
    }
}

fn build_ipv4_reply(packet: &[u8], mtu: usize) -> EchoReply {
    if packet.len() < IPV4_HEADER_LEN {
        return EchoReply::Dropped;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let declared_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN
        || header_len > packet.len()
        || declared_len != packet.len()
        || declared_len < header_len + ICMP_HEADER_LEN
        || !checksum_valid(&packet[..header_len])
    {
        return EchoReply::Dropped;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & IPV4_MORE_FRAGMENTS_OR_OFFSET != 0 {
        return EchoReply::Dropped;
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if source.is_unspecified() || destination.is_multicast() || destination == Ipv4Addr::BROADCAST {
        return EchoReply::Dropped;
    }

    let message = &packet[header_len..declared_len];
    if message[0] != ICMPV4_ECHO_REQUEST || message[1] != ECHO_CODE || !checksum_valid(message) {
        return EchoReply::Dropped;
    }

    let reply_len = IPV4_HEADER_LEN + message.len();
    if reply_len > mtu || reply_len > usize::from(u16::MAX) {
        return EchoReply::Dropped;
    }

    let mut reply = vec![0_u8; reply_len];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(
        &u16::try_from(reply_len)
            .expect("validated IPv4 reply length")
            .to_be_bytes(),
    );
    reply[8] = REPLY_HOP_LIMIT;
    reply[9] = IP_PROTOCOL_ICMP;
    reply[12..16].copy_from_slice(&destination.octets());
    reply[16..20].copy_from_slice(&source.octets());
    reply[IPV4_HEADER_LEN..].copy_from_slice(message);
    reply[IPV4_HEADER_LEN] = ICMPV4_ECHO_REPLY;
    reply[IPV4_HEADER_LEN + 2..IPV4_HEADER_LEN + 4].fill(0);
    let icmp_checksum = checksum(&reply[IPV4_HEADER_LEN..]);
    reply[IPV4_HEADER_LEN + 2..IPV4_HEADER_LEN + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_checksum = checksum(&reply[..IPV4_HEADER_LEN]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    EchoReply::Reply(Packet::new(reply))
}

fn build_ipv6_reply(packet: &[u8], mtu: usize) -> EchoReply {
    if packet.len() < IPV6_HEADER_LEN {
        return EchoReply::Dropped;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if IPV6_HEADER_LEN + payload_len != packet.len() || payload_len < ICMP_HEADER_LEN {
        return EchoReply::Dropped;
    }

    let source = ipv6_address(&packet[8..24]);
    let destination = ipv6_address(&packet[24..40]);
    if source.is_unspecified() || destination.is_multicast() {
        return EchoReply::Dropped;
    }

    let message = &packet[IPV6_HEADER_LEN..];
    if message[0] != ICMPV6_ECHO_REQUEST
        || message[1] != ECHO_CODE
        || !icmpv6_checksum_valid(source, destination, message)
    {
        return EchoReply::Dropped;
    }
    if packet.len() > mtu {
        return EchoReply::Dropped;
    }

    let mut reply = vec![0_u8; packet.len()];
    reply[0] = 0x60;
    reply[4..6].copy_from_slice(
        &u16::try_from(message.len())
            .expect("validated IPv6 payload length")
            .to_be_bytes(),
    );
    reply[6] = IP_PROTOCOL_ICMPV6;
    reply[7] = REPLY_HOP_LIMIT;
    reply[8..24].copy_from_slice(&destination.octets());
    reply[24..40].copy_from_slice(&source.octets());
    reply[IPV6_HEADER_LEN..].copy_from_slice(message);
    reply[IPV6_HEADER_LEN] = ICMPV6_ECHO_REPLY;
    reply[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].fill(0);
    let icmp_checksum = icmpv6_checksum(destination, source, &reply[IPV6_HEADER_LEN..]);
    reply[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    EchoReply::Reply(Packet::new(reply))
}

fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let octets: [u8; 16] = bytes.try_into().expect("fixed IPv6 address slice");
    Ipv6Addr::from(octets)
}

fn checksum(bytes: &[u8]) -> u16 {
    !fold(sum_bytes(0, bytes))
}

fn checksum_valid(bytes: &[u8]) -> bool {
    fold(sum_bytes(0, bytes)) == u16::MAX
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
    !fold(icmpv6_sum(source, destination, message))
}

fn icmpv6_checksum_valid(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> bool {
    fold(icmpv6_sum(source, destination, message)) == u16::MAX
}

fn icmpv6_sum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u32 {
    let mut sum = sum_bytes(0, &source.octets());
    sum = sum_bytes(sum, &destination.octets());
    sum = sum_bytes(
        sum,
        &u32::try_from(message.len())
            .expect("ICMPv6 payload length fits in u32")
            .to_be_bytes(),
    );
    sum = sum_bytes(sum, &[0, 0, 0, IP_PROTOCOL_ICMPV6]);
    sum_bytes(sum, message)
}

fn sum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(*byte) << 8);
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).expect("folded checksum fits in u16")
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const V4_DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    const V6_SOURCE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10);
    const V6_DESTINATION: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 20);

    #[test]
    fn ipv4_reply_removes_options_and_preserves_echo_body() {
        let request = ipv4_request(
            V4_SOURCE,
            V4_DESTINATION,
            &[0xaa, 0xbb, 0xcc],
            &[1, 1, 0, 0],
        );
        let EchoReply::Reply(reply) = build_echo_reply(&request, 1_500) else {
            panic!("valid ICMPv4 request was dropped");
        };
        let bytes = reply.data();
        assert_eq!(bytes.len(), IPV4_HEADER_LEN + ICMP_HEADER_LEN + 3);
        assert_eq!(bytes[0], 0x45);
        assert_eq!(bytes[8], REPLY_HOP_LIMIT);
        assert_eq!(bytes[9], IP_PROTOCOL_ICMP);
        assert_eq!(&bytes[12..16], &V4_DESTINATION.octets());
        assert_eq!(&bytes[16..20], &V4_SOURCE.octets());
        assert!(checksum_valid(&bytes[..IPV4_HEADER_LEN]));
        assert_eq!(bytes[IPV4_HEADER_LEN], ICMPV4_ECHO_REPLY);
        assert_eq!(
            &bytes[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 8],
            &[0x12, 0x34, 0x56, 0x78]
        );
        assert_eq!(&bytes[IPV4_HEADER_LEN + 8..], &[0xaa, 0xbb, 0xcc]);
        assert!(checksum_valid(&bytes[IPV4_HEADER_LEN..]));
    }

    #[test]
    fn ipv6_reply_preserves_odd_echo_body_and_rechecks_pseudo_header() {
        let request = ipv6_request(V6_SOURCE, V6_DESTINATION, &[0xaa, 0xbb, 0xcc]);
        let EchoReply::Reply(reply) = build_echo_reply(&request, 1_500) else {
            panic!("valid ICMPv6 request was dropped");
        };
        let bytes = reply.data();
        assert_eq!(bytes.len(), IPV6_HEADER_LEN + ICMP_HEADER_LEN + 3);
        assert_eq!(bytes[0], 0x60);
        assert_eq!(bytes[6], IP_PROTOCOL_ICMPV6);
        assert_eq!(bytes[7], REPLY_HOP_LIMIT);
        assert_eq!(&bytes[8..24], &V6_DESTINATION.octets());
        assert_eq!(&bytes[24..40], &V6_SOURCE.octets());
        assert_eq!(bytes[IPV6_HEADER_LEN], ICMPV6_ECHO_REPLY);
        assert_eq!(
            &bytes[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 8],
            &[0x12, 0x34, 0x56, 0x78]
        );
        assert_eq!(&bytes[IPV6_HEADER_LEN + 8..], &[0xaa, 0xbb, 0xcc]);
        assert!(icmpv6_checksum_valid(
            V6_DESTINATION,
            V6_SOURCE,
            &bytes[IPV6_HEADER_LEN..]
        ));
    }

    #[test]
    fn mtu_boundary_is_accepted_for_both_families() {
        let ipv4 = ipv4_request(V4_SOURCE, V4_DESTINATION, &vec![0x5a; 1_472], &[]);
        let EchoReply::Reply(ipv4_reply) = build_echo_reply(&ipv4, 1_500) else {
            panic!("MTU-sized ICMPv4 request was dropped");
        };
        assert_eq!(ipv4_reply.len(), 1_500);

        let ipv6 = ipv6_request(V6_SOURCE, V6_DESTINATION, &vec![0xa5; 1_452]);
        let EchoReply::Reply(ipv6_reply) = build_echo_reply(&ipv6, 1_500) else {
            panic!("MTU-sized ICMPv6 request was dropped");
        };
        assert_eq!(ipv6_reply.len(), 1_500);
    }

    #[test]
    fn ipv4_rejects_invalid_checksum_non_echo_fragments_and_addresses() {
        let valid = ipv4_request(V4_SOURCE, V4_DESTINATION, b"payload", &[]);

        let mut bad_ip_checksum = valid.data().to_vec();
        bad_ip_checksum[10] ^= 1;
        assert_dropped(&Packet::new(bad_ip_checksum));

        let mut bad_icmp_checksum = valid.data().to_vec();
        bad_icmp_checksum[IPV4_HEADER_LEN + 2] ^= 1;
        assert_dropped(&Packet::new(bad_icmp_checksum));

        let mut non_echo = valid.data().to_vec();
        non_echo[IPV4_HEADER_LEN] = 3;
        rewrite_checksum(&mut non_echo[IPV4_HEADER_LEN..], 2);
        assert_dropped(&Packet::new(non_echo));

        for fragment in [0x2000_u16, 0x0001] {
            let mut fragmented = valid.data().to_vec();
            fragmented[6..8].copy_from_slice(&fragment.to_be_bytes());
            rewrite_checksum(&mut fragmented[..IPV4_HEADER_LEN], 10);
            assert_dropped(&Packet::new(fragmented));
        }

        assert_dropped(&ipv4_request(
            Ipv4Addr::UNSPECIFIED,
            V4_DESTINATION,
            b"x",
            &[],
        ));
        assert_dropped(&ipv4_request(V4_SOURCE, Ipv4Addr::BROADCAST, b"x", &[]));
        assert_dropped(&ipv4_request(
            V4_SOURCE,
            Ipv4Addr::new(224, 0, 0, 1),
            b"x",
            &[],
        ));
    }

    #[test]
    fn ipv6_rejects_invalid_checksum_addresses_and_extension_headers() {
        let valid = ipv6_request(V6_SOURCE, V6_DESTINATION, b"payload");
        let mut bad_checksum = valid.data().to_vec();
        bad_checksum[IPV6_HEADER_LEN + 2] ^= 1;
        assert_dropped(&Packet::new(bad_checksum));

        assert_dropped(&ipv6_request(Ipv6Addr::UNSPECIFIED, V6_DESTINATION, b"x"));
        assert_dropped(&ipv6_request(
            V6_SOURCE,
            "ff02::1".parse().expect("multicast fixture"),
            b"x",
        ));

        for next_header in [0_u8, 44] {
            let mut extension = valid.data().to_vec();
            extension[6] = next_header;
            assert!(matches!(
                build_echo_reply(&Packet::new(extension), 1_500),
                EchoReply::NotIcmp
            ));
        }
    }

    #[test]
    fn declared_lengths_and_codes_fail_closed() {
        let valid_v4 = ipv4_request(V4_SOURCE, V4_DESTINATION, b"payload", &[]);
        let mut truncated_v4 = valid_v4.data().to_vec();
        truncated_v4.pop();
        assert_dropped(&Packet::new(truncated_v4));

        let mut bad_v4_code = valid_v4.data().to_vec();
        bad_v4_code[IPV4_HEADER_LEN + 1] = 1;
        rewrite_checksum(&mut bad_v4_code[IPV4_HEADER_LEN..], 2);
        assert_dropped(&Packet::new(bad_v4_code));

        let valid_v6 = ipv6_request(V6_SOURCE, V6_DESTINATION, b"payload");
        let mut truncated_v6 = valid_v6.data().to_vec();
        truncated_v6.pop();
        assert_dropped(&Packet::new(truncated_v6));

        let mut bad_v6_code = valid_v6.data().to_vec();
        bad_v6_code[IPV6_HEADER_LEN + 1] = 1;
        bad_v6_code[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].fill(0);
        let checksum = icmpv6_checksum(V6_SOURCE, V6_DESTINATION, &bad_v6_code[IPV6_HEADER_LEN..]);
        bad_v6_code[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4]
            .copy_from_slice(&checksum.to_be_bytes());
        assert_dropped(&Packet::new(bad_v6_code));
    }

    fn assert_dropped(packet: &Packet) {
        assert!(matches!(
            build_echo_reply(packet, 1_500),
            EchoReply::Dropped
        ));
    }

    fn ipv4_request(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload: &[u8],
        options: &[u8],
    ) -> Packet {
        assert!(options.len().is_multiple_of(4));
        let header_len = IPV4_HEADER_LEN + options.len();
        let mut message = vec![0_u8; ICMP_HEADER_LEN + payload.len()];
        message[0] = ICMPV4_ECHO_REQUEST;
        message[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        message[8..].copy_from_slice(payload);
        rewrite_checksum(&mut message, 2);

        let mut packet = vec![0_u8; header_len + message.len()];
        let packet_len = u16::try_from(packet.len()).expect("IPv4 fixture length");
        packet[0] = 0x40 | u8::try_from(header_len / 4).expect("IPv4 IHL fixture");
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 32;
        packet[9] = IP_PROTOCOL_ICMP;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[IPV4_HEADER_LEN..header_len].copy_from_slice(options);
        packet[header_len..].copy_from_slice(&message);
        rewrite_checksum(&mut packet[..header_len], 10);
        Packet::new(packet)
    }

    fn ipv6_request(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Packet {
        let mut message = vec![0_u8; ICMP_HEADER_LEN + payload.len()];
        message[0] = ICMPV6_ECHO_REQUEST;
        message[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        message[8..].copy_from_slice(payload);
        let checksum = icmpv6_checksum(source, destination, &message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut packet = vec![0_u8; IPV6_HEADER_LEN + message.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(
            &u16::try_from(message.len())
                .expect("IPv6 fixture payload length")
                .to_be_bytes(),
        );
        packet[6] = IP_PROTOCOL_ICMPV6;
        packet[7] = 32;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[IPV6_HEADER_LEN..].copy_from_slice(&message);
        Packet::new(packet)
    }

    fn rewrite_checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset..offset + 2].fill(0);
        let value = checksum(bytes);
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }
}
