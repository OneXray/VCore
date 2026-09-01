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

// StartWithMainTransport requires an interface MTU no greater than 1400.
pub(crate) const WINDOWS_VPN_MTU: usize = 1400;
