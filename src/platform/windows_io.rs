#[cfg(feature = "windows-uwp")]
use std::io;

use crate::{IpVersion, Result};

#[cfg(feature = "windows-uwp")]
use super::windows_tun_io::{WindowsPacketAdapter, WindowsTunIo, validate_packet_channel_mtu};
#[cfg(feature = "windows-wintun")]
use super::windows_wintun_io::WindowsWintunIo;

#[derive(Debug)]
pub(crate) enum TunIo {
    #[cfg(feature = "windows-uwp")]
    PacketChannel(WindowsTunIo),
    #[cfg(feature = "windows-wintun")]
    Wintun(WindowsWintunIo),
}

impl TunIo {
    #[cfg(feature = "windows-uwp")]
    pub(crate) fn new(
        capacity: usize,
        mtu: u16,
        wake: impl Fn() -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<(Self, WindowsPacketAdapter)> {
        validate_packet_channel_mtu(mtu)?;
        let (io, adapter) = WindowsTunIo::new(capacity, mtu, wake)?;
        Ok((Self::PacketChannel(io), adapter))
    }

    #[cfg(feature = "windows-wintun")]
    pub(crate) fn from_wintun(io: WindowsWintunIo) -> Self {
        Self::Wintun(io)
    }

    pub(crate) async fn read_packets(
        &self,
        packets: &mut [Vec<u8>],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "windows-uwp")]
            Self::PacketChannel(io) => io.read_packets(packets, outcomes).await,
            #[cfg(feature = "windows-wintun")]
            Self::Wintun(io) => io.read_packets(packets, outcomes).await,
        }
    }

    #[cfg(feature = "windows-uwp")]
    pub(crate) async fn read_packet_batch(
        &self,
        packets: &mut Vec<Vec<u8>>,
        max_packets: usize,
    ) -> Result<()> {
        match self {
            Self::PacketChannel(io) => io.read_packet_batch(packets, max_packets).await,
        }
    }

    pub(crate) async fn write_packets(
        &self,
        packets: &[&[u8]],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "windows-uwp")]
            Self::PacketChannel(io) => io.write_packets(packets, outcomes).await,
            #[cfg(feature = "windows-wintun")]
            Self::Wintun(io) => io.write_packets(packets, outcomes).await,
        }
    }

    #[cfg(feature = "windows-uwp")]
    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<IpVersion> {
        match self {
            Self::PacketChannel(io) => io.write_packet(packet).await,
        }
    }
}
