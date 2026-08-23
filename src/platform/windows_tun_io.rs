use std::{
    collections::VecDeque,
    fmt, io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::{IpVersion, Result, TunFraming, VCoreError};

const TUN_MTU: usize = 1_500;

type Wake = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

struct Shared {
    egress: Mutex<VecDeque<Vec<u8>>>,
    capacity: usize,
    wake: Wake,
    ingress_dropped: AtomicU64,
    ingress_closed: AtomicU64,
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
        wake: impl Fn() -> io::Result<()> + Send + Sync + 'static,
    ) -> (Self, WindowsPacketAdapter) {
        let (ingress, receiver) = mpsc::channel(capacity);
        let shared = Arc::new(Shared {
            egress: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            wake: Arc::new(wake),
            ingress_dropped: AtomicU64::new(0),
            ingress_closed: AtomicU64::new(0),
            egress_dropped: AtomicU64::new(0),
        });
        (
            Self {
                ingress: AsyncMutex::new(receiver),
                shared: shared.clone(),
            },
            WindowsPacketAdapter { ingress, shared },
        )
    }

    pub(crate) async fn read_packet(&self, packet: &mut Vec<u8>) -> Result<IpVersion> {
        let received = self.ingress.lock().await.recv().await.ok_or_else(|| {
            VCoreError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Windows packet ingress closed",
            ))
        })?;
        if received.len() > TUN_MTU {
            return Err(VCoreError::InvalidPacket(
                "TUN packet exceeds configured MTU",
            ));
        }
        let (version, _) = TunFraming::RawIp.decode(&received)?;
        *packet = received;
        Ok(version)
    }

    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<IpVersion> {
        if packet.len() > TUN_MTU {
            return Err(VCoreError::InvalidPacket(
                "TUN packet exceeds configured MTU",
            ));
        }
        let (version, _) = TunFraming::RawIp.decode(packet)?;
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
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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

    pub(crate) fn pop_egress(&self) -> Option<Vec<u8>> {
        self.shared.egress.lock().ok()?.pop_front()
    }

    pub(crate) fn stats(&self) -> WindowsPacketStats {
        WindowsPacketStats {
            ingress_queue_dropped: self.shared.ingress_dropped.load(Ordering::Relaxed),
            ingress_closed: self.shared.ingress_closed.load(Ordering::Relaxed),
            egress_queue_dropped: self.shared.egress_dropped.load(Ordering::Relaxed),
        }
    }
}

fn saturating_increment(counter: &AtomicU64) {
    _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
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

    const IPV4: &[u8] = &[
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    const IPV6: &[u8] = &[
        0x60, 0, 0, 0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    #[tokio::test]
    async fn packets_cross_the_windows_packet_adapter_and_wake_once() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let observed = wakes.clone();
        let (io, adapter) = WindowsTunIo::new(2, move || {
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
