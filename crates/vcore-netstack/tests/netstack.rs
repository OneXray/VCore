use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use vcore_netstack::{NetStack, NetStackConfig, NetStackError, Packet, UdpDatagram};

const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn synthetic_tun_supports_ipv4_and_ipv6_tcp_and_udp() {
    let stack = NetStack::start(NetStackConfig::default()).unwrap();
    let mut parts = stack.into_parts();

    for flow in [Flow::v4(12_000), Flow::v6(12_001)] {
        parts
            .packet_sink
            .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let reply = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&reply, &flow));
        let stream = tokio::time::timeout(WAIT, parts.tcp_listener.accept())
            .await
            .expect("TCP accept timed out")
            .expect("TCP listener stopped");
        assert_eq!(stream.source_addr(), flow.source);
        assert_eq!(stream.destination_addr(), flow.destination);
    }

    for flow in [Flow::v4(13_000), Flow::v6(13_001)] {
        let payload = Bytes::from_static(b"synthetic-tun-udp");
        parts
            .packet_sink
            .send(build_udp(&flow, &payload))
            .await
            .unwrap();
        let datagram = tokio::time::timeout(WAIT, parts.udp_socket.recv())
            .await
            .expect("UDP receive timed out")
            .expect("UDP socket stopped");
        assert_eq!(datagram.source, flow.source);
        assert_eq!(datagram.destination, flow.destination);
        assert_eq!(datagram.payload, payload);

        let response = UdpDatagram::new(flow.destination, flow.source, b"reply".as_slice());
        parts.udp_socket.send(response.clone()).await.unwrap();
        let raw_response = timeout_packet(&mut parts.packet_stream).await;
        assert_udp_packet(&raw_response, &response);
    }

    parts.control.stop().await;
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn tcp_write_applies_backpressure_and_stop_unblocks_it() {
    let config = NetStackConfig {
        packet_queue: 1,
        tcp_accept_queue: 1,
        udp_queue: 1,
        tcp_buffer_per_direction: 8 * 1024,
        max_poll_interval: Duration::from_millis(5),
        ..NetStackConfig::default()
    };
    let stack = NetStack::start(config).unwrap();
    let mut parts = stack.into_parts();
    let flow = Flow::v4(14_000);
    parts
        .packet_sink
        .send(build_tcp(&flow, 10, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    let syn_ack = timeout_packet(&mut parts.packet_stream).await;
    let server_sequence = tcp_sequence(&syn_ack);
    let mut stream = parts.tcp_listener.accept().await.unwrap();
    parts
        .packet_sink
        .send(build_tcp(
            &flow,
            11,
            server_sequence.wrapping_add(1),
            TcpFlags::ACK,
            &[],
        ))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    let payload = vec![0x5a; 128 * 1024];
    let mut write = Box::pin(stream.write_all(&payload));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut write)
            .await
            .is_err(),
        "write unexpectedly bypassed bounded TCP buffers"
    );

    parts.control.stop().await;
    let write_result = tokio::time::timeout(WAIT, write)
        .await
        .expect("blocked TCP write was not woken by stop");
    assert!(write_result.is_err());
    assert!(stream.is_stopped());
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn half_open_flows_are_not_count_limited_and_udp_queue_remains_bounded() {
    const FLOW_COUNT: usize = 40;

    let config = NetStackConfig {
        packet_queue: 4,
        tcp_accept_queue: 1,
        udp_queue: 1,
        max_poll_interval: Duration::from_millis(5),
        ..NetStackConfig::default()
    };
    let stack = NetStack::start(config).unwrap();
    let mut parts = stack.into_parts();

    let mut half_open_streams = Vec::with_capacity(FLOW_COUNT);
    for index in 0..FLOW_COUNT {
        let flow = Flow::v4(15_000 + u16::try_from(index).unwrap());
        parts
            .packet_sink
            .send(build_tcp(&flow, 1, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&syn_ack, &flow));
        half_open_streams.push(
            tokio::time::timeout(WAIT, parts.tcp_listener.accept())
                .await
                .expect("TCP accept timed out")
                .expect("TCP listener stopped"),
        );
    }

    let tcp_snapshot = parts.stats.snapshot();
    assert_eq!(tcp_snapshot.active_tcp, FLOW_COUNT);
    assert_eq!(tcp_snapshot.active_tcp_peak, FLOW_COUNT);
    assert_eq!(tcp_snapshot.half_open_tcp, FLOW_COUNT);
    assert_eq!(tcp_snapshot.half_open_tcp_peak, FLOW_COUNT);
    assert_eq!(tcp_snapshot.rejected_tcp, 0);

    for port in 16_000..16_003 {
        let flow = Flow::v4(port);
        parts
            .packet_sink
            .send(build_udp(&flow, b"queued"))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(parts.stats.snapshot().dropped_udp >= 2);
    assert!(parts.udp_socket.recv().await.is_some());

    parts.control.stop().await;
    let stopped_snapshot = parts.stats.snapshot();
    assert_eq!(stopped_snapshot.active_tcp, 0);
    assert_eq!(stopped_snapshot.active_tcp_peak, FLOW_COUNT);
    assert_eq!(stopped_snapshot.half_open_tcp, 0);
    assert_eq!(stopped_snapshot.half_open_tcp_peak, FLOW_COUNT);
}

#[tokio::test]
async fn stop_is_a_completion_barrier_for_all_async_endpoints() {
    let stack = NetStack::start(NetStackConfig::default()).unwrap();
    let mut parts = stack.into_parts();
    parts.control.stop().await;

    assert!(parts.control.is_stopped());
    assert!(parts.packet_stream.recv().await.is_none());
    assert!(parts.tcp_listener.accept().await.is_none());
    assert!(parts.udp_socket.recv().await.is_none());
    assert!(matches!(
        parts.packet_sink.send(Packet::new(vec![0x45; 20])).await,
        Err(NetStackError::Stopped)
    ));
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[test]
fn dropping_the_tokio_runtime_still_completes_driver_shutdown() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let parts = runtime.block_on(async {
        NetStack::start(NetStackConfig::default())
            .unwrap()
            .into_parts()
    });
    assert!(!parts.control.is_stopped());

    drop(runtime);

    assert!(parts.control.is_stopped());
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn fake_icmp_echo_is_explicitly_gated_and_answers_both_families() {
    let default_stack = NetStack::start(NetStackConfig::default()).unwrap();
    let mut default_parts = default_stack.into_parts();
    default_parts
        .packet_sink
        .send(build_icmpv4_echo(b"default"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            default_parts.packet_stream.recv()
        )
        .await
        .is_err(),
        "default netstack unexpectedly answered ICMP"
    );
    assert_eq!(default_parts.stats.snapshot().icmp_replied, 0);
    default_parts.control.stop().await;

    let stack = NetStack::start(NetStackConfig {
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let mut parts = stack.into_parts();
    for (request, reply_type) in [
        (build_icmpv4_echo(b"odd"), 0_u8),
        (build_icmpv6_echo(b"odd"), 129_u8),
    ] {
        let request_version = request.data()[0] >> 4;
        parts.packet_sink.send(request).await.unwrap();
        let reply = timeout_packet(&mut parts.packet_stream).await;
        assert_eq!(reply.data()[0] >> 4, request_version);
        let offset = ip_header_len(reply.data());
        assert_eq!(reply.data()[offset], reply_type);
        assert_eq!(reply.data()[offset + 1], 0);
        assert_eq!(
            &reply.data()[offset + 4..],
            &[0x12, 0x34, 0x56, 0x78, b'o', b'd', b'd']
        );
    }
    let snapshot = parts.stats.snapshot();
    assert_eq!(snapshot.icmp_replied, 2);
    assert_eq!(snapshot.icmp_dropped, 0);
    parts.control.stop().await;
}

#[tokio::test]
async fn full_raw_egress_drops_only_the_current_icmp_reply() {
    let stack = NetStack::start(NetStackConfig {
        packet_queue: 1,
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let mut parts = stack.into_parts();

    parts
        .packet_sink
        .send(build_icmpv4_echo(b"first"))
        .await
        .unwrap();
    parts
        .packet_sink
        .send(build_icmpv4_echo(b"second"))
        .await
        .unwrap();

    for _ in 0..50 {
        let snapshot = parts.stats.snapshot();
        if snapshot.icmp_replied + snapshot.icmp_dropped == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let snapshot = parts.stats.snapshot();
    assert_eq!(snapshot.icmp_replied, 1);
    assert_eq!(snapshot.icmp_dropped, 1);

    let reply = timeout_packet(&mut parts.packet_stream).await;
    let offset = ip_header_len(reply.data());
    assert_eq!(&reply.data()[offset + 8..], b"first");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), parts.packet_stream.recv())
            .await
            .is_err(),
        "queue-full reply was retained outside the bounded raw egress queue"
    );

    assert!(!parts.control.is_stopped());
    parts.control.stop().await;
    assert!(parts.control.is_stopped());
}

#[derive(Clone, Copy)]
struct Flow {
    source: SocketAddr,
    destination: SocketAddr,
}

impl Flow {
    fn v4(source_port: u16) -> Self {
        Self {
            source: SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), source_port),
            destination: SocketAddr::new(Ipv4Addr::new(198, 51, 100, 20).into(), 443),
        }
    }

    fn v6(source_port: u16) -> Self {
        Self {
            source: SocketAddr::new("2001:db8:1::10".parse().unwrap(), source_port),
            destination: SocketAddr::new("2001:db8:2::20".parse().unwrap(), 443),
        }
    }
}

#[derive(Clone, Copy)]
struct TcpFlags;

impl TcpFlags {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
}

async fn timeout_packet(stream: &mut vcore_netstack::PacketStream) -> Packet {
    tokio::time::timeout(WAIT, stream.recv())
        .await
        .expect("raw output timed out")
        .expect("raw output closed")
}

fn build_tcp(flow: &Flow, sequence: u32, ack: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut transport = vec![0_u8; 20 + payload.len()];
    transport[..2].copy_from_slice(&flow.source.port().to_be_bytes());
    transport[2..4].copy_from_slice(&flow.destination.port().to_be_bytes());
    transport[4..8].copy_from_slice(&sequence.to_be_bytes());
    transport[8..12].copy_from_slice(&ack.to_be_bytes());
    transport[12] = 5 << 4;
    transport[13] = flags;
    transport[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    transport[20..].copy_from_slice(payload);

    match (flow.source, flow.destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let checksum = transport_checksum_v4(*source.ip(), *destination.ip(), 6, &transport);
            transport[16..18].copy_from_slice(&checksum.to_be_bytes());
            build_ipv4(*source.ip(), *destination.ip(), 6, &transport)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            let checksum = transport_checksum_v6(*source.ip(), *destination.ip(), 6, &transport);
            transport[16..18].copy_from_slice(&checksum.to_be_bytes());
            build_ipv6(*source.ip(), *destination.ip(), 6, &transport)
        }
        _ => unreachable!(),
    }
}

fn build_udp(flow: &Flow, payload: &[u8]) -> Packet {
    let mut transport = vec![0_u8; 8 + payload.len()];
    let transport_len = u16::try_from(transport.len()).unwrap();
    transport[..2].copy_from_slice(&flow.source.port().to_be_bytes());
    transport[2..4].copy_from_slice(&flow.destination.port().to_be_bytes());
    transport[4..6].copy_from_slice(&transport_len.to_be_bytes());
    transport[8..].copy_from_slice(payload);

    match (flow.source, flow.destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let checksum = transport_checksum_v4(*source.ip(), *destination.ip(), 17, &transport);
            transport[6..8].copy_from_slice(&checksum.to_be_bytes());
            build_ipv4(*source.ip(), *destination.ip(), 17, &transport)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            let checksum = transport_checksum_v6(*source.ip(), *destination.ip(), 17, &transport);
            transport[6..8].copy_from_slice(&checksum.to_be_bytes());
            build_ipv6(*source.ip(), *destination.ip(), 17, &transport)
        }
        _ => unreachable!(),
    }
}

fn build_icmpv4_echo(payload: &[u8]) -> Packet {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 20);
    let mut message = vec![0_u8; 8 + payload.len()];
    message[0] = 8;
    message[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    message[8..].copy_from_slice(payload);
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    build_ipv4(source, destination, 1, &message)
}

fn build_icmpv6_echo(payload: &[u8]) -> Packet {
    let source: Ipv6Addr = "2001:db8:1::10".parse().unwrap();
    let destination: Ipv6Addr = "2001:db8:2::20".parse().unwrap();
    let mut message = vec![0_u8; 8 + payload.len()];
    message[0] = 128;
    message[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    message[8..].copy_from_slice(payload);
    let checksum = transport_checksum_v6(source, destination, 58, &message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    build_ipv6(source, destination, 58, &message)
}

fn build_ipv4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, transport: &[u8]) -> Packet {
    let mut packet = vec![0_u8; 20 + transport.len()];
    packet[0] = 0x45;
    let packet_len = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(transport);
    Packet::new(packet)
}

fn build_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    transport: &[u8],
) -> Packet {
    let mut packet = vec![0_u8; 40 + transport.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(transport.len()).unwrap().to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..].copy_from_slice(transport);
    Packet::new(packet)
}

fn is_syn_ack(packet: &Packet, flow: &Flow) -> bool {
    let offset = ip_header_len(packet.data());
    packet.data().get(offset + 13).copied() == Some(TcpFlags::SYN | TcpFlags::ACK)
        && u16::from_be_bytes(packet.data()[offset..offset + 2].try_into().unwrap())
            == flow.destination.port()
        && u16::from_be_bytes(packet.data()[offset + 2..offset + 4].try_into().unwrap())
            == flow.source.port()
}

fn tcp_sequence(packet: &Packet) -> u32 {
    let offset = ip_header_len(packet.data());
    u32::from_be_bytes(packet.data()[offset + 4..offset + 8].try_into().unwrap())
}

fn assert_udp_packet(packet: &Packet, expected: &UdpDatagram) {
    let offset = ip_header_len(packet.data());
    assert_eq!(
        u16::from_be_bytes(packet.data()[offset..offset + 2].try_into().unwrap()),
        expected.source.port()
    );
    assert_eq!(
        u16::from_be_bytes(packet.data()[offset + 2..offset + 4].try_into().unwrap()),
        expected.destination.port()
    );
    assert_eq!(&packet.data()[offset + 8..], expected.payload.as_ref());
}

fn ip_header_len(packet: &[u8]) -> usize {
    match packet[0] >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        6 => 40,
        _ => panic!("unexpected IP version"),
    }
}

fn transport_checksum_v4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    transport: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, &source.octets());
    add_bytes(&mut sum, &destination.octets());
    sum += u32::from(protocol);
    sum += u32::try_from(transport.len()).unwrap();
    add_bytes(&mut sum, transport);
    fold(sum)
}

fn transport_checksum_v6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    transport: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, &source.octets());
    add_bytes(&mut sum, &destination.octets());
    let length = u32::try_from(transport.len()).unwrap();
    sum += length >> 16;
    sum += length & 0xffff;
    sum += u32::from(next_header);
    add_bytes(&mut sum, transport);
    fold(sum)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, bytes);
    fold(sum)
}

fn add_bytes(sum: &mut u32, bytes: &[u8]) {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        *sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(byte) = remainder.first() {
        *sum += u32::from(*byte) << 8;
    }
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !u16::try_from(sum).expect("folded checksum fits in u16");
    if checksum == 0 { u16::MAX } else { checksum }
}
