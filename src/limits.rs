use crate::{Result, VCoreError};

/// Historical iOS TUN footprint target retained for best-effort telemetry.
///
/// Crossing this value never changes a runtime lifecycle result.
pub const IOS_TUN_PEAK_OBSERVATION_TARGET_BYTES: u64 = 45 * 1024 * 1024;

/// Historical iOS TUN start-footprint target retained for best-effort
/// telemetry. Crossing this value never prevents the runtime from starting.
pub const IOS_TUN_START_OBSERVATION_TARGET_BYTES: u64 = 35 * 1024 * 1024;

/// Fixed stack used by each bootstrap resolver worker.
pub(crate) const DNS_WORKER_STACK_BYTES: usize = 512 * 1024;
/// Process-wide ceiling for lazily created bootstrap resolver workers.
pub(crate) const MAX_DNS_WORKERS: usize = 4;

/// Retained-memory, queue and per-object safety boundaries.
///
/// These values deliberately do not cap concurrent TCP sessions, UDP
/// associations, half-open TCP flows, outbound handshakes or DNS queries.
/// Runtime concurrency follows actual workload; bounded queues, per-flow
/// buffers, caches and operation timeouts keep individual retained objects
/// controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub packet_queue_capacity: usize,
    pub event_queue_capacity: usize,
    /// Maximum datagram accepted by local SOCKS5/mixed inbounds.
    pub max_datagram_size: usize,
    /// Maximum raw IP packet accepted by a TUN netstack.
    pub tun_max_datagram_size: usize,
    pub tcp_buffer_per_direction: usize,
    /// Retained A/AAAA cache entries. A and AAAA share this one capacity.
    pub dns_address_cache_entries: usize,
    /// Retained address-to-domain hints used by redir-host routing.
    pub dns_redir_host_entries: usize,
    /// Netstack UDP ingress capacity while DNS hijacking is enabled.
    pub tun_dns_ingress_queue_capacity: usize,
    /// Reserved TUN DNS response capacity. The isolated response path consumes
    /// this value once that path is enabled.
    pub tun_dns_response_queue_capacity: usize,
    pub tls_buffer_limit: usize,
    pub xhttp_send_buffer_size: usize,
    pub xhttp_upload_chunk_size: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            packet_queue_capacity: 256,
            event_queue_capacity: 128,
            max_datagram_size: 65_535,
            tun_max_datagram_size: 1_500,
            tcp_buffer_per_direction: 32 * 1024,
            dns_address_cache_entries: 256,
            dns_redir_host_entries: 256,
            tun_dns_ingress_queue_capacity: 128,
            tun_dns_response_queue_capacity: 128,
            tls_buffer_limit: 64 * 1024,
            xhttp_send_buffer_size: 64 * 1024,
            xhttp_upload_chunk_size: 64 * 1024,
        }
    }
}

impl ResourceLimits {
    /// Workload profile used by every runtime containing a TUN inbound.
    #[must_use]
    pub const fn tun() -> Self {
        Self {
            packet_queue_capacity: 256,
            event_queue_capacity: 128,
            max_datagram_size: 65_535,
            tun_max_datagram_size: 1_500,
            tcp_buffer_per_direction: 32 * 1024,
            dns_address_cache_entries: 256,
            dns_redir_host_entries: 256,
            tun_dns_ingress_queue_capacity: 128,
            tun_dns_response_queue_capacity: 128,
            tls_buffer_limit: 64 * 1024,
            xhttp_send_buffer_size: 64 * 1024,
            xhttp_upload_chunk_size: 64 * 1024,
        }
    }

    #[must_use]
    #[cfg_attr(not(feature = "ffi"), allow(dead_code))]
    pub(crate) fn for_runtime(has_tun: bool) -> Self {
        if has_tun {
            Self::tun()
        } else {
            Self::default()
        }
    }

    pub fn validate(self) -> Result<Self> {
        for (name, value) in [
            ("packet_queue_capacity", self.packet_queue_capacity),
            ("event_queue_capacity", self.event_queue_capacity),
            ("max_datagram_size", self.max_datagram_size),
            ("tun_max_datagram_size", self.tun_max_datagram_size),
            ("tcp_buffer_per_direction", self.tcp_buffer_per_direction),
            ("dns_address_cache_entries", self.dns_address_cache_entries),
            ("dns_redir_host_entries", self.dns_redir_host_entries),
            (
                "tun_dns_ingress_queue_capacity",
                self.tun_dns_ingress_queue_capacity,
            ),
            (
                "tun_dns_response_queue_capacity",
                self.tun_dns_response_queue_capacity,
            ),
            ("tls_buffer_limit", self.tls_buffer_limit),
            ("xhttp_send_buffer_size", self.xhttp_send_buffer_size),
            ("xhttp_upload_chunk_size", self.xhttp_upload_chunk_size),
        ] {
            if value == 0 {
                return Err(VCoreError::ResourceLimit {
                    resource: name,
                    limit: value,
                });
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_sized_limits_are_rejected() {
        let invalid = [
            ResourceLimits {
                packet_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_max_datagram_size: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tcp_buffer_per_direction: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                dns_address_cache_entries: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                dns_redir_host_entries: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_dns_ingress_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_dns_response_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tls_buffer_limit: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                xhttp_send_buffer_size: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                xhttp_upload_chunk_size: 0,
                ..ResourceLimits::default()
            },
        ];
        assert!(invalid.into_iter().all(|limits| limits.validate().is_err()));
    }

    #[test]
    fn tun_profile_keeps_only_queue_cache_and_per_object_boundaries() {
        let limits = ResourceLimits::tun().validate().unwrap();
        assert_eq!(limits.packet_queue_capacity, 256);
        assert_eq!(limits.event_queue_capacity, 128);
        assert_eq!(limits.max_datagram_size, 65_535);
        assert_eq!(limits.tun_max_datagram_size, 1_500);
        assert_eq!(limits.tcp_buffer_per_direction, 32 * 1024);
        assert_eq!(limits.dns_address_cache_entries, 256);
        assert_eq!(limits.dns_redir_host_entries, 256);
        assert_eq!(limits.tun_dns_ingress_queue_capacity, 128);
        assert_eq!(limits.tun_dns_response_queue_capacity, 128);
        assert_eq!(limits.tls_buffer_limit, 64 * 1024);
        assert_eq!(limits.xhttp_send_buffer_size, 64 * 1024);
        assert_eq!(limits.xhttp_upload_chunk_size, 64 * 1024);
    }

    #[test]
    fn generic_profile_keeps_the_existing_buffer_defaults() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_datagram_size, 65_535);
        assert_eq!(limits.tun_max_datagram_size, 1_500);
        assert_eq!(limits.tcp_buffer_per_direction, 32 * 1024);
        assert_eq!(limits.tls_buffer_limit, 64 * 1024);
        assert_eq!(limits.xhttp_send_buffer_size, 64 * 1024);
        assert_eq!(limits.xhttp_upload_chunk_size, 64 * 1024);
    }

    #[test]
    fn runtime_selection_depends_only_on_tun_workload() {
        assert_eq!(ResourceLimits::for_runtime(true), ResourceLimits::tun());
        assert_eq!(
            ResourceLimits::for_runtime(false),
            ResourceLimits::default()
        );
    }
}
