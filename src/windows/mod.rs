pub(crate) mod host;
pub(crate) mod log;
pub(crate) mod managed_processes;
pub(crate) mod packet_channel;
pub(crate) mod policy;
pub(crate) mod profile;
#[doc(hidden)]
pub mod session;
pub(crate) mod snapshot;
pub(crate) mod vpn;

/// WinRT transports cannot declare a larger interface MTU. Require callers to
/// choose a supported YAML value; never replace the normalized core default.
pub(crate) fn packet_channel_mtu(config: &crate::config::Config) -> std::io::Result<u16> {
    crate::platform::validate_packet_channel_mtu(config.tun.mtu)?;
    Ok(config.tun.mtu)
}
