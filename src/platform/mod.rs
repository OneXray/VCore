#[cfg(all(
    feature = "ffi",
    any(target_os = "ios", target_os = "tvos", target_os = "macos")
))]
pub(crate) mod apple_logging;
#[cfg(all(target_os = "linux", feature = "tun"))]
mod linux_tun;
#[cfg(all(
    feature = "ffi",
    any(target_os = "ios", target_os = "tvos", target_os = "macos")
))]
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) mod process_memory;
#[cfg(all(unix, feature = "tun"))]
mod rust_tun_io;
#[cfg(all(unix, feature = "tun"))]
mod tun_fd;
#[cfg(all(feature = "tun", any(windows, test)))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_tun_io;

/// Ready packets processed per turn; never wait to fill this batch.
#[cfg(feature = "tun")]
pub(crate) const TUN_PACKET_BATCH_SIZE: usize = 8;

#[cfg(all(unix, feature = "tun"))]
pub use rust_tun_io::RustTunIo as TunIo;
#[cfg(all(unix, feature = "tun"))]
pub use tun_fd::TunFd;
#[cfg(all(windows, feature = "tun"))]
pub(crate) use windows_tun_io::{WindowsPacketAdapter, WindowsPacketStats, WindowsTunIo as TunIo};
