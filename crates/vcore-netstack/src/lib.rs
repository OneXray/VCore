//! Bounded userspace raw-IP netstack used by `VCore`.
//!
//! The crate intentionally has no TUN file-descriptor dependency. Platform
//! code feeds raw IP packets through [`PacketSink`] and drains generated raw IP
//! packets from [`PacketStream`]. TCP and UDP are exposed separately to the
//! outbound dispatcher.

mod config;
mod device;
mod icmp;
mod packet;
mod stack;
mod tcp;
mod udp;

pub use config::{ConfigError, NetStackConfig};
pub use packet::Packet;
pub use stack::{
    NetStack, NetStackControl, NetStackError, NetStackParts, NetStackStats, PacketSink,
    PacketStream, ResourceSnapshot,
};
pub use tcp::{TcpListener, TcpStream};
pub use udp::{UdpDatagram, UdpError, UdpSocket};
