use std::time::Duration;

use thiserror::Error;

/// Finite buffering and timing configuration for one netstack instance.
///
/// Queue counts are hard limits. `tcp_buffer_per_direction` includes both the
/// smoltcp socket buffer and the application-facing queue for one flow in that
/// direction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetStackConfig {
    /// Maximum raw IP packet size and the IP-medium MTU advertised to smoltcp.
    pub mtu: usize,
    /// Raw packet count in each TUN direction.
    pub packet_queue: usize,
    /// Accepted TCP streams waiting for the dispatcher.
    pub tcp_accept_queue: usize,
    /// UDP datagrams waiting for the dispatcher.
    pub udp_queue: usize,
    /// Total bytes reserved for one TCP direction across smoltcp and app sides.
    pub tcp_buffer_per_direction: usize,
    /// Inactive TCP socket timeout enforced by smoltcp.
    pub tcp_idle_timeout: Duration,
    /// Maximum delay before the driver polls sockets again.
    pub max_poll_interval: Duration,
    /// Locally answer ICMPv4/ICMPv6 echo requests received from TUN.
    ///
    /// This is disabled by default for generic netstack users. The `VCore` TUN
    /// runtime enables it explicitly.
    pub fake_icmp_echo: bool,
}

impl Default for NetStackConfig {
    fn default() -> Self {
        Self {
            mtu: 1_500,
            packet_queue: 64,
            tcp_accept_queue: 32,
            udp_queue: 128,
            tcp_buffer_per_direction: 32 * 1024,
            tcp_idle_timeout: Duration::from_mins(2),
            max_poll_interval: Duration::from_millis(100),
            fake_icmp_echo: false,
        }
    }
}

impl NetStackConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !(1_280..=65_535).contains(&self.mtu) {
            return Err(ConfigError::Mtu(self.mtu));
        }
        for (name, value) in [
            ("packet_queue", self.packet_queue),
            ("tcp_accept_queue", self.tcp_accept_queue),
            ("udp_queue", self.udp_queue),
        ] {
            if value == 0 {
                return Err(ConfigError::ZeroLimit(name));
            }
        }
        if self.tcp_buffer_per_direction < 4 * 1024
            || !self.tcp_buffer_per_direction.is_multiple_of(2)
        {
            return Err(ConfigError::TcpBuffer(self.tcp_buffer_per_direction));
        }
        if self.tcp_idle_timeout.is_zero() {
            return Err(ConfigError::ZeroDuration("tcp_idle_timeout"));
        }
        if self.max_poll_interval.is_zero() {
            return Err(ConfigError::ZeroDuration("max_poll_interval"));
        }
        Ok(())
    }

    pub(crate) const fn layer_buffer_size(&self) -> usize {
        self.tcp_buffer_per_direction / 2
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("MTU must be between 1280 and 65535 bytes, got {0}")]
    Mtu(usize),
    #[error("resource limit `{0}` must be greater than zero")]
    ZeroLimit(&'static str),
    #[error("duration `{0}` must be greater than zero")]
    ZeroDuration(&'static str),
    #[error("tcp_buffer_per_direction must be even and at least 4096 bytes, got {0}")]
    TcpBuffer(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_keep_queues_and_per_flow_buffers_bounded() {
        let config = NetStackConfig::default();
        assert_eq!(config.packet_queue, 64);
        assert_eq!(config.tcp_accept_queue, 32);
        assert_eq!(config.udp_queue, 128);
        assert_eq!(config.tcp_buffer_per_direction, 32 * 1024);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_zero_queue_capacity() {
        let config = NetStackConfig {
            udp_queue: 0,
            ..NetStackConfig::default()
        };
        assert_eq!(config.validate(), Err(ConfigError::ZeroLimit("udp_queue")));
    }
}
