#[cfg(all(feature = "ffi", any(target_os = "ios", target_os = "macos")))]
pub(crate) mod apple_logging;
#[cfg(all(feature = "ffi", any(target_os = "ios", target_os = "macos")))]
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) mod process_memory;
#[cfg(all(unix, feature = "tun"))]
mod rust_tun_io;
#[cfg(all(unix, feature = "tun"))]
mod tun_fd;

#[cfg(all(unix, feature = "tun"))]
pub use rust_tun_io::RustTunIo as TunIo;
#[cfg(all(unix, feature = "tun"))]
pub use tun_fd::TunFd;
