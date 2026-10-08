//! SOCKS5 client-proxy frontend. UDP authorization belongs to its TCP control.

mod association;
mod handshake;
mod server;

pub use server::Socks5Server;
#[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
pub(crate) use server::{Socks5Handler, UDP_CLEANUP_INTERVAL};

#[cfg(test)]
mod tests;
