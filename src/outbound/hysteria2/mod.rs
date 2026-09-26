//! Hysteria2 over the shared, protected QUIC transport.
mod bandwidth;
mod datagram;
mod outbound;
mod paths;
mod salamander;
mod socket;
mod stream;
mod wire;
pub use outbound::Hysteria2Outbound;
