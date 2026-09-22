use std::{fmt, io, os::fd::IntoRawFd};

use tokio::io::unix::AsyncFd;

use crate::{IpVersion, Result, TunFraming, VCoreError};

use super::TunFd;

// The current config protocol accepts only MTU 1500. Keeping the slice passed
// to rust-tun at exactly that size is also important on Apple: its PI adapter
// uses a fixed 1504-byte stack buffer at this size, but allocates a temporary
// Vec for larger reads and writes.
const TUN_MTU: usize = 1_500;

/// Non-blocking raw-IP packet I/O backed by rust-tun.
///
/// VCore validates and duplicates the borrowed host descriptor before this
/// type is constructed. The duplicate is then owned and closed by rust-tun.
/// We deliberately wrap the synchronous rust-tun device in Tokio's `AsyncFd`
/// instead of using rust-tun's `AsyncDevice`: the latter calls `F_SETFL`, while
/// a duplicated descriptor shares file-status flags with the host descriptor.
pub struct RustTunIo {
    device: AsyncFd<rust_tun::Device>,
    framing: TunFraming,
}

impl fmt::Debug for RustTunIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustTunIo")
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

impl RustTunIo {
    pub fn new(fd: TunFd, framing: TunFraming) -> Result<Self> {
        let mut configuration = rust_tun::Configuration::default();
        configuration
            .raw_fd(fd.into_raw_fd())
            .close_fd_on_drop(true)
            .mtu(TUN_MTU as u16);
        configure_platform_framing(&mut configuration, framing);

        let device = rust_tun::create(&configuration)
            .map_err(|error| io::Error::other(format!("rust-tun create failed: {error}")))?;
        Ok(Self {
            device: AsyncFd::new(device)?,
            framing,
        })
    }

    #[must_use]
    pub const fn framing(&self) -> TunFraming {
        self.framing
    }

    /// Reads exactly one packet. rust-tun removes the Apple PI header and
    /// exposes raw IP on every supported fd platform.
    pub async fn read_packet(&self, packet: &mut Vec<u8>) -> Result<IpVersion> {
        packet.clear();
        packet.resize(TUN_MTU, 0);
        let size = loop {
            let mut ready = self.device.readable().await?;
            match ready.try_io(|inner| inner.get_ref().recv(packet)) {
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };
        if size == 0 {
            return Err(VCoreError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN closed",
            )));
        }
        packet.truncate(size);
        let (version, _) = TunFraming::RawIp.decode(packet)?;
        Ok(version)
    }

    /// Writes one complete packet. Partial writes are rejected because retrying
    /// a suffix would create a second malformed TUN packet.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<IpVersion> {
        if packet.len() > TUN_MTU {
            return Err(VCoreError::InvalidPacket(
                "TUN packet exceeds configured MTU",
            ));
        }
        let (version, _) = TunFraming::RawIp.decode(packet)?;
        let written = loop {
            let mut ready = self.device.writable().await?;
            match ready.try_io(|inner| inner.get_ref().send(packet)) {
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };
        if written != packet.len() {
            return Err(VCoreError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial TUN packet write",
            )));
        }
        Ok(version)
    }
}

#[cfg(target_vendor = "apple")]
fn configure_platform_framing(configuration: &mut rust_tun::Configuration, framing: TunFraming) {
    configuration.platform_config(|platform| {
        platform.packet_information(framing == TunFraming::Utun);
        #[cfg(target_os = "macos")]
        platform.enable_routing(false);
    });
}

#[cfg(not(target_vendor = "apple"))]
fn configure_platform_framing(_configuration: &mut rust_tun::Configuration, _framing: TunFraming) {}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::net::{UnixDatagram, UnixStream},
        },
    };

    use super::*;

    const IPV4: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    const IPV6: [u8; 40] = [
        0x60, 0, 0, 0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    #[tokio::test]
    async fn raw_ip_read_reuses_caller_buffer_for_ipv4_and_ipv6() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let io = RustTunIo::new(fd, TunFraming::RawIp).unwrap();

        let mut packet = Vec::with_capacity(1500);
        for (expected, version) in [(&IPV4[..], IpVersion::V4), (&IPV6[..], IpVersion::V6)] {
            peer.send(expected).unwrap();
            assert_eq!(io.read_packet(&mut packet).await.unwrap(), version);
            assert_eq!(packet, expected);
            assert_eq!(packet.capacity(), TUN_MTU);
        }
    }

    #[tokio::test]
    async fn rust_tun_drop_closes_only_duplicate_and_preserves_host_flags() {
        let (mut host, mut peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        // SAFETY: host remains open for both flag reads.
        let before = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let io = RustTunIo::new(fd, TunFraming::RawIp).unwrap();
        drop(io);
        // SAFETY: rust-tun owns only the duplicate; host remains open.
        let after = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(after, before);

        host.write_all(b"ok").unwrap();
        let mut bytes = [0; 2];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
    }

    #[tokio::test]
    async fn raw_ip_rejects_invalid_version_and_oversized_write() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let io = RustTunIo::new(fd, TunFraming::RawIp).unwrap();

        peer.send(&[0x70]).unwrap();
        assert!(matches!(
            io.read_packet(&mut Vec::new()).await,
            Err(VCoreError::InvalidPacket("unsupported IP version"))
        ));
        assert!(matches!(
            io.write_packet(&vec![0x45; TUN_MTU + 1]).await,
            Err(VCoreError::InvalidPacket(
                "TUN packet exceeds configured MTU"
            ))
        ));
    }

    #[tokio::test]
    async fn zero_length_read_is_tun_eof() {
        let (host, peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let io = RustTunIo::new(fd, TunFraming::RawIp).unwrap();
        drop(peer);

        let error = io.read_packet(&mut Vec::new()).await.unwrap_err();
        assert!(matches!(
            error,
            VCoreError::Io(ref error) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn utun_write_adds_darwin_family_header_for_ipv4_and_ipv6() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let io = RustTunIo::new(fd, TunFraming::Utun).unwrap();

        for (packet, family, version) in [
            (&IPV4[..], 2_u32, IpVersion::V4),
            (&IPV6[..], 30_u32, IpVersion::V6),
        ] {
            assert_eq!(io.write_packet(packet).await.unwrap(), version);
            let mut received = [0_u8; 64];
            let size = peer.recv(&mut received).unwrap();
            assert_eq!(&received[..4], &family.to_be_bytes());
            assert_eq!(&received[4..size], packet);
        }
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn utun_read_strips_darwin_family_header_for_ipv4_and_ipv6() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let io = RustTunIo::new(fd, TunFraming::Utun).unwrap();

        let mut packet = Vec::new();
        for (expected, family, version) in [
            (&IPV4[..], 2_u32, IpVersion::V4),
            (&IPV6[..], 30_u32, IpVersion::V6),
        ] {
            let mut frame = family.to_be_bytes().to_vec();
            frame.extend_from_slice(expected);
            peer.send(&frame).unwrap();
            assert_eq!(io.read_packet(&mut packet).await.unwrap(), version);
            assert_eq!(packet, expected);
        }
    }
}
