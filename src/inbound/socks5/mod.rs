//! SOCKS5 client-proxy frontend. UDP authorization belongs to its TCP control.

mod association;
mod handshake;
mod server;

pub use server::Socks5Server;

#[cfg(test)]
mod tests;
