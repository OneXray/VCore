#[cfg(any(feature = "windows-uwp", test))]
use std::collections::VecDeque;
use std::{
    fmt,
    future::poll_fn,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
};

use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::{IpVersion, Result, TunFraming, VCoreError};

use super::TUN_PACKET_BATCH_SIZE;

#[cfg(any(feature = "windows-uwp", test))]
pub(super) const PACKET_CHANNEL_MAX_MTU: usize = 1_400;

#[cfg(any(feature = "windows-uwp", test))]
type Wake = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

struct Shared {
    mtu: usize,
    // Only WinRT callbacks own queued egress; Wintun writes to its native ring.
    #[cfg(any(feature = "windows-uwp", test))]
    egress: Mutex<VecDeque<Vec<u8>>>,
    #[cfg(any(feature = "windows-uwp", test))]
    capacity: usize,
    #[cfg(any(feature = "windows-uwp", test))]
    wake: Wake,
    ingress_dropped: AtomicU64,
    ingress_closed: AtomicU64,
    ingress_failure: Mutex<Option<io::Error>>,
    #[cfg(any(feature = "windows-uwp", test))]
    egress_dropped: AtomicU64,
}

pub(crate) struct WindowsTunIo {
    ingress: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    shared: Arc<Shared>,
}

impl fmt::Debug for WindowsTunIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTunIo")
            .finish_non_exhaustive()
    }
}

impl WindowsTunIo {
    pub(crate) fn new(
        capacity: usize,
        mtu: u16,
        wake: impl Fn() -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<(Self, WindowsPacketAdapter)> {
        #[cfg(not(any(feature = "windows-uwp", test)))]
        let _ = wake;
        if capacity == 0 || mtu == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Windows TUN queue capacity or MTU",
            ));
        }
        let (ingress, receiver) = mpsc::channel(capacity);
        let shared = Arc::new(Shared {
            mtu: usize::from(mtu),
            #[cfg(any(feature = "windows-uwp", test))]
            egress: Mutex::new(VecDeque::with_capacity(capacity)),
            #[cfg(any(feature = "windows-uwp", test))]
            capacity,
            #[cfg(any(feature = "windows-uwp", test))]
            wake: Arc::new(wake),
            ingress_dropped: AtomicU64::new(0),
            ingress_closed: AtomicU64::new(0),
            ingress_failure: Mutex::new(None),
            #[cfg(any(feature = "windows-uwp", test))]
            egress_dropped: AtomicU64::new(0),
        });
        Ok((
            Self {
                ingress: AsyncMutex::new(receiver),
                shared: shared.clone(),
            },
            WindowsPacketAdapter { ingress, shared },
        ))
    }

    #[cfg(test)]
    pub(crate) async fn read_packet(&self, packet: &mut Vec<u8>) -> Result<IpVersion> {
        let received = self
            .ingress
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| self.closed())?;
        let version = packet_version(&received, self.shared.mtu)?;
        *packet = received;
        Ok(version)
    }

    pub(crate) async fn read_packets(
        &self,
        packets: &mut [Vec<u8>],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        outcomes.clear();
        validate_batch_size(packets.len())?;
        let mut ingress = self.ingress.lock().await;
        packets[0] = ingress.recv().await.ok_or_else(|| self.closed())?;
        outcomes.push(packet_version(&packets[0], self.shared.mtu));
        for packet in &mut packets[1..] {
            // Return the prefix instead of parking a worker or waiting for a
            // producer when the next receive is not immediately ready.
            match poll_fn(|cx| Poll::Ready(ingress.poll_recv(cx))).await {
                Poll::Ready(Some(received)) => {
                    *packet = received;
                    outcomes.push(packet_version(packet, self.shared.mtu));
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "windows-uwp", test))]
    pub(crate) async fn read_packet_batch(
        &self,
        packets: &mut Vec<Vec<u8>>,
        max_packets: usize,
    ) -> Result<()> {
        packets.clear();
        validate_batch_size(max_packets)?;
        let mut ingress = self.ingress.lock().await;
        let first = ingress.recv().await.ok_or_else(|| self.closed())?;
        push_valid_frame(packets, first, self.shared.mtu)?;
        for _ in 1..max_packets {
            match poll_fn(|cx| Poll::Ready(ingress.poll_recv(cx))).await {
                Poll::Ready(Some(packet)) => {
                    push_valid_frame(packets, packet, self.shared.mtu)?;
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "windows-uwp", test))]
    pub(crate) async fn write_packets(
        &self,
        packets: &[&[u8]],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        outcomes.clear();
        validate_batch_size(packets.len())?;
        let wake = {
            let mut egress =
                self.shared.egress.lock().map_err(|_| {
                    VCoreError::Platform("Windows packet queue lock poisoned".into())
                })?;
            let mut wake = false;
            for packet in packets {
                let version = match packet_version(packet, self.shared.mtu) {
                    Ok(version) => version,
                    Err(error) => {
                        outcomes.push(Err(error));
                        continue;
                    }
                };
                if egress.len() == self.shared.capacity {
                    saturating_increment(&self.shared.egress_dropped);
                } else {
                    wake |= egress.is_empty();
                    egress.push_back(packet.to_vec());
                }
                outcomes.push(Ok(version));
            }
            wake
        };
        if wake {
            (self.shared.wake)()?;
        }
        Ok(())
    }

    #[cfg(any(feature = "windows-uwp", test))]
    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<IpVersion> {
        let version = packet_version(packet, self.shared.mtu)?;
        let wake = {
            let mut egress =
                self.shared.egress.lock().map_err(|_| {
                    VCoreError::Platform("Windows packet queue lock poisoned".into())
                })?;
            if egress.len() == self.shared.capacity {
                saturating_increment(&self.shared.egress_dropped);
                return Ok(version);
            }
            let wake = egress.is_empty();
            egress.push_back(packet.to_vec());
            wake
        };
        if wake {
            (self.shared.wake)()?;
        }
        Ok(version)
    }

    fn closed(&self) -> VCoreError {
        if let Some(error) = self
            .shared
            .ingress_failure
            .lock()
            .ok()
            .and_then(|mut failure| failure.take())
        {
            return VCoreError::Io(error);
        }
        closed()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg(any(feature = "windows-uwp", test))]
pub(crate) struct WindowsPacketStats {
    pub(crate) ingress_queue_dropped: u64,
    pub(crate) ingress_closed: u64,
    pub(crate) egress_queue_dropped: u64,
}

#[derive(Clone)]
pub(crate) struct WindowsPacketAdapter {
    ingress: mpsc::Sender<Vec<u8>>,
    shared: Arc<Shared>,
}

impl WindowsPacketAdapter {
    // The producer must then drop its last sender. Queued packets remain
    // readable before this terminal failure; no error occupies packet capacity.
    #[cfg(any(feature = "windows-wintun", test))]
    pub(super) fn fail_ingress(&self, error: io::Error) {
        if let Ok(mut failure) = self.shared.ingress_failure.lock()
            && failure.is_none()
        {
            *failure = Some(error);
        }
    }

    pub(crate) fn try_send(&self, packet: Vec<u8>) -> bool {
        match self.ingress.try_send(packet) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                saturating_increment(&self.shared.ingress_dropped);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                saturating_increment(&self.shared.ingress_closed);
                false
            }
        }
    }

    #[cfg(any(feature = "windows-uwp", test))]
    pub(crate) fn pop_egress(&self) -> Option<Vec<u8>> {
        self.shared.egress.lock().ok()?.pop_front()
    }

    #[cfg(any(feature = "windows-uwp", test))]
    pub(crate) fn stats(&self) -> WindowsPacketStats {
        WindowsPacketStats {
            ingress_queue_dropped: self.shared.ingress_dropped.load(Ordering::Relaxed),
            ingress_closed: self.shared.ingress_closed.load(Ordering::Relaxed),
            egress_queue_dropped: self.shared.egress_dropped.load(Ordering::Relaxed),
        }
    }
}

pub(super) fn packet_version(packet: &[u8], mtu: usize) -> Result<IpVersion> {
    if packet.len() > mtu {
        return Err(VCoreError::InvalidPacket(
            "TUN packet exceeds configured MTU",
        ));
    }
    TunFraming::RawIp.decode(packet).map(|(version, _)| version)
}

pub(super) fn validate_batch_size(size: usize) -> Result<()> {
    if !(1..=TUN_PACKET_BATCH_SIZE).contains(&size) {
        return Err(VCoreError::Platform(
            "invalid Windows TUN packet batch size".into(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "windows-uwp", test))]
fn push_valid_frame(packets: &mut Vec<Vec<u8>>, packet: Vec<u8>, mtu: usize) -> Result<()> {
    if packet.is_empty() || packet.len() > mtu {
        return Err(VCoreError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows packet frame size",
        )));
    }
    match packet_version(&packet, mtu) {
        Ok(_) => packets.push(packet),
        Err(VCoreError::InvalidPacket(_)) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(any(feature = "windows-uwp", test))]
pub(super) fn validate_packet_channel_mtu(mtu: u16) -> io::Result<()> {
    if mtu == 0 || usize::from(mtu) > PACKET_CHANNEL_MAX_MTU {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows VPN packet channel supports MTU values from 1 through 1400",
        ));
    }
    Ok(())
}

fn closed() -> VCoreError {
    VCoreError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Windows packet ingress closed",
    ))
}

fn saturating_increment(counter: &AtomicU64) {
    _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    const TEST_MTU: usize = 1_500;

    fn memory_io(
        capacity: usize,
        wake: impl Fn() -> io::Result<()> + Send + Sync + 'static,
    ) -> (WindowsTunIo, WindowsPacketAdapter) {
        WindowsTunIo::new(capacity, TEST_MTU as u16, wake).unwrap()
    }

    #[test]
    fn packet_channel_rejects_unsupported_mtu_instead_of_clamping() {
        assert!(validate_packet_channel_mtu(1400).is_ok());
        for mtu in [0, 1401, 9000] {
            assert_eq!(
                validate_packet_channel_mtu(mtu).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[tokio::test]
    async fn queue_read_and_write_enforce_the_supplied_mtu() {
        let (io, adapter) = WindowsTunIo::new(2, 40, || Ok(())).unwrap();
        assert!(adapter.try_send(IPV4.to_vec()));
        assert!(adapter.try_send(vec![0x45; 41]));
        let mut packets = vec![Vec::new(); 2];
        let mut outcomes = Vec::new();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0].is_ok());
        assert!(matches!(outcomes[1], Err(VCoreError::InvalidPacket(_))));
        assert!(matches!(
            io.write_packet(&vec![0x45; 41]).await,
            Err(VCoreError::InvalidPacket(_))
        ));
        assert!(adapter.pop_egress().is_none());
    }

    const IPV4: &[u8] = &[
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    const IPV6: &[u8] = &[
        0x60, 0, 0, 0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    #[tokio::test]
    async fn ingress_batch_waits_for_one_then_drains_only_ready_packets() {
        let (io, adapter) = memory_io(3, || Ok(()));
        assert!(adapter.try_send(IPV4.to_vec()));
        assert!(adapter.try_send(IPV6.to_vec()));
        assert!(adapter.try_send(IPV4.to_vec()));

        let mut packets = Vec::new();
        io.read_packet_batch(&mut packets, 2).await.unwrap();
        assert_eq!(packets, [IPV4, IPV6]);
        io.read_packet_batch(&mut packets, 2).await.unwrap();
        assert_eq!(packets, [IPV4]);

        assert!(adapter.try_send(IPV6.to_vec()));
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            io.read_packet_batch(&mut packets, 2),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(packets, [IPV6]);
    }

    #[tokio::test]
    async fn common_ingress_batch_keeps_invalid_packets_isolated_and_bounds_ready_drain() {
        let (io, adapter) = memory_io(TUN_PACKET_BATCH_SIZE + 1, || Ok(()));
        for index in 0..=TUN_PACKET_BATCH_SIZE {
            let packet = match index {
                1 => vec![0xff],
                2 => IPV6.to_vec(),
                _ => IPV4.to_vec(),
            };
            assert!(adapter.try_send(packet));
        }
        let mut packets = vec![Vec::new(); TUN_PACKET_BATCH_SIZE];
        let mut outcomes = Vec::new();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), TUN_PACKET_BATCH_SIZE);
        assert!(matches!(outcomes[0], Ok(IpVersion::V4)));
        assert!(matches!(outcomes[1], Err(VCoreError::InvalidPacket(_))));
        assert!(matches!(outcomes[2], Ok(IpVersion::V6)));
        assert_eq!(packets[0], IPV4);
        assert_eq!(packets[1], [0xff]);
        assert_eq!(packets[2], IPV6);

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            io.read_packets(&mut packets, &mut outcomes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0], Ok(IpVersion::V4)));
        assert_eq!(packets[0], IPV4);
    }

    #[tokio::test]
    async fn common_ingress_batch_keeps_received_prefix_before_channel_close() {
        let (io, adapter) = memory_io(2, || Ok(()));
        assert!(adapter.try_send(IPV4.to_vec()));
        assert!(adapter.try_send(IPV6.to_vec()));
        drop(adapter);
        let mut packets = vec![Vec::new(); TUN_PACKET_BATCH_SIZE];
        let mut outcomes = Vec::new();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(outcomes[0], Ok(IpVersion::V4)));
        assert!(matches!(outcomes[1], Ok(IpVersion::V6)));
        assert!(matches!(
            io.read_packets(&mut packets, &mut outcomes).await,
            Err(VCoreError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn common_egress_batch_wakes_once_and_keeps_drop_current_semantics() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let observed = wakes.clone();
        let (io, adapter) = memory_io(2, move || {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let mut outcomes = Vec::new();
        io.write_packets(&[IPV4, &[0xff], IPV6, IPV4], &mut outcomes)
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 4);
        assert!(matches!(outcomes[0], Ok(IpVersion::V4)));
        assert!(matches!(outcomes[1], Err(VCoreError::InvalidPacket(_))));
        assert!(matches!(outcomes[2], Ok(IpVersion::V6)));
        assert!(matches!(outcomes[3], Ok(IpVersion::V4)));
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(adapter.pop_egress().as_deref(), Some(IPV4));
        assert_eq!(adapter.pop_egress().as_deref(), Some(IPV6));
        assert!(adapter.pop_egress().is_none());
        assert_eq!(adapter.stats().egress_queue_dropped, 1);

        io.write_packets(&[IPV6], &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(wakes.load(Ordering::Relaxed), 2);
        io.write_packets(&[IPV4], &mut outcomes).await.unwrap();
        assert_eq!(wakes.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn common_egress_batch_reports_accepted_packets_before_wake_failure() {
        let (io, adapter) = memory_io(3, || {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "wake failed"))
        });
        let mut outcomes = Vec::new();
        assert!(matches!(
            io.write_packets(&[IPV4, &[0xff], IPV6], &mut outcomes).await,
            Err(VCoreError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        assert_eq!(outcomes.len(), 3);
        assert!(matches!(outcomes[0], Ok(IpVersion::V4)));
        assert!(matches!(outcomes[1], Err(VCoreError::InvalidPacket(_))));
        assert!(matches!(outcomes[2], Ok(IpVersion::V6)));
        assert_eq!(adapter.pop_egress().as_deref(), Some(IPV4));
        assert_eq!(adapter.pop_egress().as_deref(), Some(IPV6));
        assert!(adapter.pop_egress().is_none());
    }

    #[tokio::test]
    async fn packet_channel_ingress_skips_invalid_ip_with_a_bounded_attempt_count() {
        let (io, adapter) = memory_io(4, || Ok(()));
        assert!(adapter.try_send(IPV4.to_vec()));
        assert!(adapter.try_send(vec![0xff]));
        assert!(adapter.try_send(IPV6.to_vec()));
        let mut packets = Vec::new();
        io.read_packet_batch(&mut packets, 2).await.unwrap();
        assert_eq!(packets, [IPV4]);
        io.read_packet_batch(&mut packets, 2).await.unwrap();
        assert_eq!(packets, [IPV6]);

        assert!(adapter.try_send(vec![0xff]));
        assert!(adapter.try_send(vec![0xff]));
        assert!(adapter.try_send(IPV4.to_vec()));
        io.read_packet_batch(&mut packets, 2).await.unwrap();
        assert!(packets.is_empty());
        io.read_packet_batch(&mut packets, 2).await.unwrap();
        assert_eq!(packets, [IPV4]);
    }

    #[tokio::test]
    async fn packet_channel_ingress_rejects_invalid_frame_lengths() {
        for packet in [Vec::new(), vec![0x45; TEST_MTU + 1]] {
            let (io, adapter) = memory_io(1, || Ok(()));
            assert!(adapter.try_send(packet));
            assert!(matches!(
                io.read_packet_batch(&mut Vec::new(), TUN_PACKET_BATCH_SIZE).await,
                Err(VCoreError::Io(error)) if error.kind() == io::ErrorKind::InvalidData
            ));
        }
    }

    #[tokio::test]
    async fn common_batches_reject_empty_and_oversized_slices_without_dequeuing() {
        let (io, adapter) = memory_io(1, || Ok(()));
        assert!(adapter.try_send(IPV4.to_vec()));
        let mut outcomes = vec![Ok(IpVersion::V4)];
        assert!(matches!(
            io.read_packets(&mut [], &mut outcomes).await,
            Err(VCoreError::Platform(_))
        ));
        assert!(outcomes.is_empty());
        let mut packets = vec![Vec::new(); TUN_PACKET_BATCH_SIZE + 1];
        assert!(matches!(
            io.read_packets(&mut packets, &mut outcomes).await,
            Err(VCoreError::Platform(_))
        ));
        assert!(outcomes.is_empty());
        assert!(matches!(
            io.write_packets(&[], &mut outcomes).await,
            Err(VCoreError::Platform(_))
        ));
        assert!(matches!(
            io.write_packets(&[IPV4; TUN_PACKET_BATCH_SIZE + 1], &mut outcomes)
                .await,
            Err(VCoreError::Platform(_))
        ));
        assert!(outcomes.is_empty());
        assert!(adapter.pop_egress().is_none());

        io.read_packets(&mut packets[..1], &mut outcomes)
            .await
            .unwrap();
        assert_eq!(packets[0], IPV4);
        assert_eq!(outcomes.len(), 1);
    }

    #[tokio::test]
    async fn packets_cross_the_windows_packet_adapter_and_wake_once() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let observed = wakes.clone();
        let (io, adapter) = memory_io(2, move || {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        assert!(adapter.try_send(IPV4.to_vec()));
        assert!(adapter.try_send(IPV6.to_vec()));
        assert!(!adapter.try_send(IPV4.to_vec()));
        let mut packet = Vec::new();
        assert_eq!(
            io.read_packet(&mut packet).await.unwrap(),
            crate::IpVersion::V4
        );
        assert_eq!(packet, IPV4);
        assert_eq!(
            io.read_packet(&mut packet).await.unwrap(),
            crate::IpVersion::V6
        );
        assert_eq!(packet, IPV6);

        assert_eq!(io.write_packet(IPV4).await.unwrap(), crate::IpVersion::V4);
        assert_eq!(io.write_packet(IPV6).await.unwrap(), crate::IpVersion::V6);
        assert_eq!(io.write_packet(IPV4).await.unwrap(), crate::IpVersion::V4);
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(adapter.pop_egress().as_deref(), Some(IPV4));
        assert_eq!(adapter.pop_egress().as_deref(), Some(IPV6));
        assert!(adapter.pop_egress().is_none());
        assert_eq!(
            adapter.stats(),
            WindowsPacketStats {
                ingress_queue_dropped: 1,
                ingress_closed: 0,
                egress_queue_dropped: 1,
            }
        );

        io.write_packet(IPV4).await.unwrap();
        assert_eq!(wakes.load(Ordering::Relaxed), 2);
        drop(io);
        assert!(!adapter.try_send(IPV4.to_vec()));
        assert_eq!(adapter.stats().ingress_closed, 1);
    }
}
