#![cfg(all(
    feature = "stream-transport",
    feature = "quic-transport",
    feature = "outbound-vless"
))]
use std::collections::BTreeMap;

#[test]
fn registry_matches_live_production_constants_and_has_owned_boundary_cases() {
    #[cfg(feature = "interop-test")]
    let mut _case = vcore::resources::case_events::Case::new(
        "N1-LIMITS",
        "registry_matches_live_production_constants_and_has_owned_boundary_cases",
    );
    use vcore::{ResourceLimits, dispatch, transport};
    let defaults = ResourceLimits::default();
    let expected = BTreeMap::from([
        ("config-bytes", vcore::config::MAX_CONFIG_BYTES),
        (
            "establish-timeout",
            vcore::outbound::DEFAULT_ESTABLISH_TIMEOUT.as_millis() as usize,
        ),
        ("tls-buffer", defaults.tls_buffer_limit),
        (
            "tls-close",
            vcore::security::CLOSE_NOTIFY_TIMEOUT.as_millis() as usize,
        ),
        (
            "tls-resumption",
            vcore::security::TLS_RESUMPTION_SESSION_BUDGET,
        ),
        ("stream-chunk", transport::STREAM_CHUNK_BYTES),
        ("stream-buffer", transport::STREAM_BUFFER_BYTES),
        ("http-head", transport::HTTP_HEAD_BYTES),
        ("http-headers", transport::HTTP_HEADER_COUNT),
        ("ws-early-data", transport::MAX_EARLY_DATA_BYTES),
        ("xudp-metadata", vcore::xudp::MAX_METADATA_LENGTH),
        ("io-poll", vcore::limits::IO_POLL_BUDGET),
        ("quic-queue", transport::quic::QUEUE_LIMIT),
        (
            "quic-close",
            transport::quic::CLOSE_TIMEOUT.as_millis() as usize,
        ),
        (
            "quic-minimum",
            usize::from(dispatch::QUIC_MIN_PAYLOAD_BYTES),
        ),
        (
            "wireguard-minimum",
            usize::from(dispatch::WIREGUARD_MIN_INNER_MTU),
        ),
        (
            "wireguard-overhead",
            usize::from(dispatch::WIREGUARD_TRANSPORT_OVERHEAD),
        ),
        (
            "resolution-depth",
            vcore::dns::resolution::MAX_RESOLUTION_DEPTH,
        ),
        ("packet-queue", defaults.packet_queue_capacity),
        ("event-queue", defaults.event_queue_capacity),
        ("udp-payload", defaults.max_datagram_size),
        ("tun-packet", defaults.tun_max_datagram_size),
        ("tcp-buffer", defaults.tcp_buffer_per_direction),
        ("dns-cache", defaults.dns_address_cache_entries),
        ("dns-hints", defaults.dns_redir_host_entries),
        ("tun-dns-ingress", defaults.tun_dns_ingress_queue_capacity),
        ("tun-dns-response", defaults.tun_dns_response_queue_capacity),
        ("xhttp-send", defaults.xhttp_send_buffer_size),
        ("xhttp-upload", defaults.xhttp_upload_chunk_size),
    ]);
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("protocols/limits.json")).unwrap();
    let rows = registry["limits"].as_array().unwrap();
    assert_eq!(rows.len(), expected.len());
    let mut actual = BTreeMap::new();
    for row in rows {
        let id = row["id"].as_str().unwrap();
        assert!(
            actual
                .insert(id, row["value"].as_u64().unwrap() as usize)
                .is_none()
        );
        for key in ["unit", "owner", "saturation", "cancellation"] {
            assert!(!row[key].as_str().unwrap().is_empty());
        }
        assert!(!row["boundary_cases"].as_array().unwrap().is_empty());
    }
    assert_eq!(actual, expected);
}
