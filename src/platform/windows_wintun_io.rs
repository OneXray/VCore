use std::{
    fmt, io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{IpVersion, Result};

use super::windows_tun_io::{
    WindowsPacketAdapter, WindowsTunIo, packet_version, validate_batch_size,
};

const INGRESS_CAPACITY: usize = 256;
const WRITE_RETRY_DELAY: Duration = Duration::from_millis(1);

// A blocking read must be released by shutdown. Only this small device seam is
// substituted in memory tests; the production backend remains tun-rs/Wintun.
trait PacketDevice: Send + Sync + 'static {
    fn recv(&self, packet: &mut [u8]) -> io::Result<usize>;
    fn try_send(&self, packet: &[u8]) -> io::Result<usize>;
    fn shutdown(&self) -> io::Result<()>;
}

pub(crate) struct WindowsWintunIo {
    device: Arc<dyn PacketDevice>,
    ingress: WindowsTunIo,
    mtu: usize,
    stopping: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl fmt::Debug for WindowsWintunIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsWintunIo")
            .finish_non_exhaustive()
    }
}

impl WindowsWintunIo {
    #[cfg(all(windows, feature = "windows-wintun"))]
    pub(crate) fn open(device_name: &str, mtu: u16) -> io::Result<Self> {
        if mtu == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Wintun MTU",
            ));
        }
        let executable =
            std::env::current_exe().map_err(|error| device_error("locate executable", &error))?;
        let parent = executable.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable directory unavailable",
            )
        })?;
        // Always supply the absolute executable-relative DLL to tun-rs. Its
        // default DLL search is never used, including during validation failure.
        let dll = parent.join("wintun.dll");
        let dll = dll
            .canonicalize()
            .map_err(|error| device_error("open executable-directory wintun.dll", &error))?;
        let dll = dll.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wintun DLL path is not Unicode",
            )
        })?;
        let interrupt = tun_rs::InterruptEvent::new()
            .map_err(|error| device_error("create reader interrupt", &error))?;
        // Addresses, DNS, routes and physical egress remain host-owned. Neither
        // IPv4/IPv6 addresses nor route/metric settings are passed to the builder.
        let device = tun_rs::DeviceBuilder::new()
            .name(if device_name.is_empty() {
                "VCore"
            } else {
                device_name
            })
            .mtu(mtu)
            .wintun_file(dll.to_owned())
            .ring_capacity(0x20_0000)
            .wintun_log(false)
            .delete_driver(false)
            .build_sync()
            .map_err(|error| device_error("create adapter", &error))?;
        Self::from_device(Arc::new(NativeDevice { device, interrupt }), mtu)
    }

    fn from_device(device: Arc<dyn PacketDevice>, mtu: u16) -> io::Result<Self> {
        let (ingress, adapter) = WindowsTunIo::new(INGRESS_CAPACITY, mtu, || Ok(()))?;
        let stopping = Arc::new(AtomicBool::new(false));
        let reader_device = device.clone();
        let reader_stopping = stopping.clone();
        let reader = thread::Builder::new()
            .name("vcore-wintun-reader".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    read_packets(
                        &*reader_device,
                        &reader_stopping,
                        &adapter,
                        usize::from(mtu),
                    );
                }));
                if result.is_err() && !reader_stopping.load(Ordering::Acquire) {
                    adapter.fail_ingress(io::Error::other("Wintun packet reader panicked"));
                }
                // Dropping this sole sender closes ingress after the queued
                // prefix, allowing the async consumer to observe reader errors.
            });
        match reader {
            Ok(reader) => Ok(Self {
                device,
                ingress,
                mtu: usize::from(mtu),
                stopping,
                reader: Some(reader),
            }),
            Err(error) => {
                _ = device.shutdown();
                Err(device_error("start reader", &error))
            }
        }
    }

    pub(crate) async fn read_packets(
        &self,
        packets: &mut [Vec<u8>],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        self.ingress.read_packets(packets, outcomes).await
    }

    pub(crate) async fn write_packets(
        &self,
        packets: &[&[u8]],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        outcomes.clear();
        validate_batch_size(packets.len())?;
        for packet in packets {
            let version = match packet_version(packet, self.mtu) {
                Ok(version) => version,
                Err(error) => {
                    outcomes.push(Err(error));
                    continue;
                }
            };
            self.send_packet(packet).await?;
            outcomes.push(Ok(version));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<IpVersion> {
        let version = packet_version(packet, self.mtu)?;
        self.send_packet(packet).await?;
        Ok(version)
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        loop {
            match self.device.try_send(packet) {
                Ok(written) if written == packet.len() => return Ok(()),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial Wintun packet write",
                    )
                    .into());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // No packet was accepted. Only this packet is retried, and
                    // dropping the future cancels the delay with no detached I/O.
                    tokio::time::sleep(WRITE_RETRY_DELAY).await;
                }
                Err(error) => return Err(device_error("send packet", &error).into()),
            }
        }
    }
}

impl Drop for WindowsWintunIo {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        _ = self.device.shutdown();
        if let Some(reader) = self.reader.take() {
            // No timeout/detach: Stop only releases native handles after the
            // reader exits. Shutdown releases its interruptible read first.
            _ = reader.join();
        }
    }
}

fn read_packets(
    device: &dyn PacketDevice,
    stopping: &AtomicBool,
    adapter: &WindowsPacketAdapter,
    mtu: usize,
) {
    let mut packet = vec![0; mtu];
    while !stopping.load(Ordering::Acquire) {
        let received = device.recv(&mut packet);
        if stopping.load(Ordering::Acquire) {
            break;
        }
        match received {
            Ok(size) if size > 0 && size <= packet.len() => {
                // A full bounded queue drops this packet and immediately lets
                // Wintun release/reuse its ring storage; callbacks never wait.
                adapter.try_send(packet[..size].to_vec());
            }
            Ok(_) => {
                adapter.fail_ingress(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Wintun packet frame size",
                ));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) => {
                adapter.fail_ingress(device_error("receive packet", &error));
                break;
            }
        }
    }
}

// Never surface the native error's arbitrary text (which may contain a DLL
// path or other host data). Operation, error kind and numeric OS code suffice.
fn device_error(operation: &'static str, error: &io::Error) -> io::Error {
    let message = match error.raw_os_error() {
        Some(code) => format!("Wintun {operation} failed (OS error {code})"),
        None => format!("Wintun {operation} failed"),
    };
    io::Error::new(error.kind(), message)
}

#[cfg(all(windows, feature = "windows-wintun"))]
struct NativeDevice {
    device: tun_rs::SyncDevice,
    interrupt: tun_rs::InterruptEvent,
}

#[cfg(all(windows, feature = "windows-wintun"))]
impl PacketDevice for NativeDevice {
    fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        // The event is the normal stop wake. A finite native wait also lets the
        // owned reader exit if the OS rejects both event/shutdown wake calls.
        self.device
            .recv_intr_timeout(packet, &self.interrupt, Some(Duration::from_millis(100)))
    }

    fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
        self.device.try_send(packet)
    }

    fn shutdown(&self) -> io::Result<()> {
        let interrupted = self.interrupt.trigger();
        let shutdown = self.device.shutdown();
        interrupted.and(shutdown)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::{Future, poll_fn},
        sync::{Condvar, Mutex},
        task::Poll,
    };

    use crate::{VCoreError, platform::TUN_PACKET_BATCH_SIZE};

    use super::*;

    const TEST_MTU: usize = 1_500;

    #[tokio::test]
    async fn configured_jumbo_mtu_reaches_reader_and_native_writer() {
        let mut packet = vec![0; 9000];
        packet[..20].copy_from_slice(IPV4);
        packet[2..4].copy_from_slice(&9000u16.to_be_bytes());
        let device =
            FakeDevice::with_input([Ok(packet.clone()), Err(io::ErrorKind::BrokenPipe.into())]);
        let mut io = WindowsWintunIo::from_device(device.clone(), 9000).unwrap();
        io.reader.take().unwrap().join().unwrap();
        let mut packets = vec![Vec::new(); 1];
        let mut outcomes = Vec::new();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(packets[0], packet);
        assert!(outcomes[0].is_ok());
        io.write_packets(&[&packet], &mut outcomes).await.unwrap();
        assert_eq!(device.state.lock().unwrap().accepted, [packet]);
    }

    const IPV4: &[u8] = &[
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    const IPV6: &[u8] = &[
        0x60, 0, 0, 0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    enum SendAction {
        Complete,
        Full,
        Partial,
        Error,
    }

    #[derive(Default)]
    struct FakeState {
        incoming: VecDeque<io::Result<Vec<u8>>>,
        send_actions: VecDeque<SendAction>,
        attempts: Vec<Vec<u8>>,
        accepted: Vec<Vec<u8>>,
        stopped: bool,
        waiting: bool,
        ring_full: bool,
    }

    #[derive(Default)]
    struct FakeDevice {
        state: Mutex<FakeState>,
        ready: Condvar,
    }

    impl FakeDevice {
        fn with_input(incoming: impl IntoIterator<Item = io::Result<Vec<u8>>>) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(FakeState {
                    incoming: incoming.into_iter().collect(),
                    ..FakeState::default()
                }),
                ready: Condvar::new(),
            })
        }

        fn wait_for_reader(&self) {
            let guard = self.state.lock().unwrap();
            let (_guard, timeout) = self
                .ready
                .wait_timeout_while(guard, Duration::from_secs(1), |state| !state.waiting)
                .unwrap();
            assert!(!timeout.timed_out(), "memory reader failed to start");
        }
    }

    impl PacketDevice for FakeDevice {
        fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
            let mut state = self.state.lock().unwrap();
            loop {
                if state.stopped {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if let Some(incoming) = state.incoming.pop_front() {
                    let incoming = incoming?;
                    if incoming.len() > packet.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "private native details",
                        ));
                    }
                    packet[..incoming.len()].copy_from_slice(&incoming);
                    return Ok(incoming.len());
                }
                state.waiting = true;
                self.ready.notify_all();
                state = self.ready.wait(state).unwrap();
            }
        }

        fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            let mut state = self.state.lock().unwrap();
            state.attempts.push(packet.to_vec());
            match state.send_actions.pop_front() {
                Some(SendAction::Full) => return Err(io::ErrorKind::WouldBlock.into()),
                Some(SendAction::Partial) => return Ok(packet.len() - 1),
                Some(SendAction::Error) => {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "private details"));
                }
                Some(SendAction::Complete) => {}
                None if state.ring_full => return Err(io::ErrorKind::WouldBlock.into()),
                None => {}
            }
            state.accepted.push(packet.to_vec());
            Ok(packet.len())
        }

        fn shutdown(&self) -> io::Result<()> {
            self.state.lock().unwrap().stopped = true;
            self.ready.notify_all();
            Ok(())
        }
    }

    fn joined_input(device: Arc<FakeDevice>) -> WindowsWintunIo {
        let mut io = WindowsWintunIo::from_device(device, TEST_MTU as u16).unwrap();
        // Every caller supplies a terminal input error. Joining makes ready
        // drain assertions deterministic without a host event or timed sleep.
        io.reader.take().unwrap().join().unwrap();
        io
    }

    #[tokio::test]
    async fn ingress_keeps_invalid_neighbours_and_delivers_sanitized_terminal_error() {
        let io = joined_input(FakeDevice::with_input([
            Ok(IPV4.to_vec()),
            Ok(vec![0x70]),
            Ok(IPV6.to_vec()),
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "private DLL path and traffic details",
            )),
        ]));
        let mut packets = vec![Vec::new(); TUN_PACKET_BATCH_SIZE];
        let mut outcomes = Vec::new();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), 3);
        assert_eq!(outcomes[0].as_ref().unwrap(), &IpVersion::V4);
        assert!(matches!(outcomes[1], Err(VCoreError::InvalidPacket(_))));
        assert_eq!(outcomes[2].as_ref().unwrap(), &IpVersion::V6);
        let error = io
            .read_packets(&mut packets, &mut outcomes)
            .await
            .unwrap_err();
        assert!(outcomes.is_empty());
        assert!(
            matches!(&error, VCoreError::Io(error) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(error.to_string(), "Wintun receive packet failed");
    }

    #[tokio::test]
    async fn reader_queue_is_bounded_and_never_waits_for_consumers() {
        let incoming = (0..INGRESS_CAPACITY + 2)
            .map(|_| Ok(IPV4.to_vec()))
            .chain([Err(io::ErrorKind::BrokenPipe.into())]);
        let io = joined_input(FakeDevice::with_input(incoming));
        let mut packets = vec![Vec::new(); TUN_PACKET_BATCH_SIZE];
        let mut outcomes = Vec::new();
        let mut received = 0;
        loop {
            match io.read_packets(&mut packets, &mut outcomes).await {
                Ok(()) => {
                    // Tokio's cooperative budget may yield before the queue
                    // empties. Each returned prefix remains bounded and valid.
                    assert!((1..=TUN_PACKET_BATCH_SIZE).contains(&outcomes.len()));
                    assert!(outcomes.iter().all(|result| result.is_ok()));
                    received += outcomes.len();
                }
                Err(VCoreError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe => break,
                Err(error) => panic!("unexpected memory reader error: {error}"),
            }
        }
        assert_eq!(received, INGRESS_CAPACITY);
    }

    #[tokio::test]
    async fn oversized_native_frame_is_a_sanitized_read_failure() {
        let io = joined_input(FakeDevice::with_input([Ok(vec![0x45; TEST_MTU + 1])]));
        let mut packets = vec![Vec::new(); 1];
        let mut outcomes = Vec::new();
        let error = io
            .read_packets(&mut packets, &mut outcomes)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, VCoreError::Io(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(error.to_string(), "Wintun receive packet failed");
    }

    #[test]
    fn drop_interrupts_and_joins_reader_before_releasing_device() {
        let device = Arc::new(FakeDevice::default());
        let io = WindowsWintunIo::from_device(device.clone(), TEST_MTU as u16).unwrap();
        device.wait_for_reader();
        assert_eq!(Arc::strong_count(&device), 3);
        drop(io);
        assert!(device.state.lock().unwrap().stopped);
        assert_eq!(Arc::strong_count(&device), 1);
    }

    #[tokio::test]
    async fn partial_write_preserves_completed_prefix_and_never_sends_suffix() {
        let device = Arc::new(FakeDevice::default());
        device.state.lock().unwrap().send_actions =
            [SendAction::Complete, SendAction::Partial].into();
        let io = WindowsWintunIo::from_device(device.clone(), TEST_MTU as u16).unwrap();
        let mut outcomes = Vec::new();
        let error = io
            .write_packets(&[IPV4, &[0x70], IPV6, IPV4], &mut outcomes)
            .await
            .unwrap_err();
        assert!(matches!(error, VCoreError::Io(error) if error.kind() == io::ErrorKind::WriteZero));
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0].is_ok());
        assert!(matches!(outcomes[1], Err(VCoreError::InvalidPacket(_))));
        let state = device.state.lock().unwrap();
        assert_eq!(state.accepted, [IPV4]);
        assert_eq!(state.attempts, [IPV4, IPV6]);
    }

    #[tokio::test]
    async fn ring_full_retries_only_unaccepted_packet() {
        let device = Arc::new(FakeDevice::default());
        device.state.lock().unwrap().send_actions = [
            SendAction::Complete,
            SendAction::Full,
            SendAction::Complete,
            SendAction::Complete,
        ]
        .into();
        let io = WindowsWintunIo::from_device(device.clone(), TEST_MTU as u16).unwrap();
        let mut outcomes = Vec::new();
        io.write_packets(&[IPV4, IPV6, IPV4], &mut outcomes)
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 3);
        let state = device.state.lock().unwrap();
        assert_eq!(state.accepted, [IPV4, IPV6, IPV4]);
        assert_eq!(state.attempts, [IPV4, IPV6, IPV6, IPV4]);
    }

    #[tokio::test]
    async fn cancel_ring_full_write_leaves_prefix_and_no_background_io() {
        let device = Arc::new(FakeDevice::default());
        {
            let mut state = device.state.lock().unwrap();
            state.send_actions.push_back(SendAction::Complete);
            state.ring_full = true;
        }
        let io = WindowsWintunIo::from_device(device.clone(), TEST_MTU as u16).unwrap();
        let mut outcomes = Vec::new();
        let packets = [IPV4, IPV6, IPV4];
        let mut write = Box::pin(io.write_packets(&packets, &mut outcomes));
        assert!(
            poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(write);
        assert_eq!(outcomes.len(), 1);
        device.state.lock().unwrap().ring_full = false;
        tokio::task::yield_now().await;
        io.write_packet(IPV4).await.unwrap();
        let state = device.state.lock().unwrap();
        assert_eq!(state.attempts, [IPV4, IPV6, IPV4]);
        assert_eq!(state.accepted, [IPV4, IPV4]);
    }

    #[tokio::test]
    async fn write_errors_and_mtu_checks_do_not_leak_or_send_more_packets() {
        let device = Arc::new(FakeDevice::default());
        device
            .state
            .lock()
            .unwrap()
            .send_actions
            .push_back(SendAction::Error);
        let io = WindowsWintunIo::from_device(device.clone(), TEST_MTU as u16).unwrap();
        assert!(matches!(
            io.write_packet(&vec![0x45; TEST_MTU + 1]).await,
            Err(VCoreError::InvalidPacket(_))
        ));
        let mut outcomes = Vec::new();
        let error = io
            .write_packets(&[IPV4, IPV6], &mut outcomes)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Wintun send packet failed");
        assert!(outcomes.is_empty());
        assert_eq!(device.state.lock().unwrap().attempts, [IPV4]);
    }
}
