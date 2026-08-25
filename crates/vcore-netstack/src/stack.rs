use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use smoltcp::{
    iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, SocketHandle, SocketSet,
    },
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpCidr, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use thiserror::Error;
use tokio::sync::{Notify, mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    NetStackConfig, Packet,
    config::ConfigError,
    device::RawIpDevice,
    icmp::{IcmpIngress, classify as classify_icmp},
    tcp::{FlowKey, TcpListener, TcpStream, TcpStreamHandle},
    udp::{UdpDatagram, UdpSocket, parse_udp_packet},
};

/// Running stack and all of its application-facing endpoints.
pub struct NetStack {
    parts: NetStackParts,
}

/// Endpoints produced by [`NetStack::into_parts`].
pub struct NetStackParts {
    pub packet_sink: PacketSink,
    pub packet_stream: PacketStream,
    pub tcp_listener: TcpListener,
    pub udp_socket: UdpSocket,
    pub control: NetStackControl,
    pub stats: NetStackStats,
}

impl NetStack {
    /// Starts one netstack driver on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns [`NetStackError::Config`] for inconsistent bounds and
    /// [`NetStackError::NoRuntime`] when called outside a Tokio runtime.
    pub fn start(config: NetStackConfig) -> Result<Self, NetStackError> {
        config.validate()?;
        tokio::runtime::Handle::try_current().map_err(|_| NetStackError::NoRuntime)?;

        let cancellation = CancellationToken::new();
        let notify = Arc::new(Notify::new());
        let stats = NetStackStats::default();
        let (raw_inbound_tx, raw_inbound_rx) = mpsc::channel(config.packet_queue);
        let (raw_outbound_tx, raw_outbound_rx) = mpsc::channel(config.packet_queue);
        let (tcp_accept_tx, tcp_accept_rx) = mpsc::channel(config.tcp_accept_queue);
        let (udp_tx, udp_rx) = mpsc::channel(config.udp_queue);
        let (stopped_tx, stopped_rx) = watch::channel(false);

        let mtu = config.mtu;
        let driver = Driver::new(
            config,
            raw_inbound_rx,
            raw_outbound_tx.clone(),
            tcp_accept_tx,
            udp_tx,
            cancellation.clone(),
            notify,
            stats.clone(),
            stopped_tx,
        );
        tokio::spawn(driver.run());

        Ok(Self {
            parts: NetStackParts {
                packet_sink: PacketSink {
                    sender: raw_inbound_tx,
                    cancellation: cancellation.clone(),
                    mtu,
                },
                packet_stream: PacketStream {
                    receiver: raw_outbound_rx,
                    cancellation: cancellation.clone(),
                },
                tcp_listener: TcpListener {
                    receiver: tcp_accept_rx,
                    cancellation: cancellation.clone(),
                },
                udp_socket: UdpSocket {
                    receiver: udp_rx,
                    raw_outbound: raw_outbound_tx,
                    cancellation: cancellation.clone(),
                    mtu,
                },
                control: NetStackControl {
                    cancellation,
                    stopped: stopped_rx,
                },
                stats,
            },
        })
    }

    #[must_use]
    pub fn into_parts(self) -> NetStackParts {
        self.parts
    }
}

/// Bounded TUN-to-stack packet endpoint.
#[derive(Clone)]
pub struct PacketSink {
    sender: mpsc::Sender<Packet>,
    cancellation: CancellationToken,
    mtu: usize,
}

impl PacketSink {
    /// Applies backpressure once the configured raw ingress queue is full.
    ///
    /// # Errors
    ///
    /// Returns an input validation error for malformed or oversized packets,
    /// or [`NetStackError::Stopped`] once shutdown begins.
    pub async fn send(&self, packet: impl Into<Packet>) -> Result<(), NetStackError> {
        let packet = packet.into();
        validate_raw_packet(&packet, self.mtu)?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(NetStackError::Stopped),
            result = self.sender.send(packet) => {
                result.map_err(|_| NetStackError::Stopped)
            }
        }
    }

    /// Non-blocking ingress used by edge-triggered TUN adapters.
    ///
    /// # Errors
    ///
    /// Returns [`NetStackError::Backpressure`] when the ingress queue is full,
    /// [`NetStackError::Stopped`] during shutdown, or an input validation error.
    pub fn try_send(&self, packet: impl Into<Packet>) -> Result<(), NetStackError> {
        if self.cancellation.is_cancelled() {
            return Err(NetStackError::Stopped);
        }
        let packet = packet.into();
        validate_raw_packet(&packet, self.mtu)?;
        self.sender.try_send(packet).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => NetStackError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => NetStackError::Stopped,
        })
    }
}

/// Bounded stack-to-TUN packet endpoint.
pub struct PacketStream {
    receiver: mpsc::Receiver<Packet>,
    cancellation: CancellationToken,
}

impl PacketStream {
    pub async fn recv(&mut self) -> Option<Packet> {
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => None,
            packet = self.receiver.recv() => packet,
        }
    }
}

/// Cancellation handle with a completion barrier.
#[derive(Clone)]
pub struct NetStackControl {
    cancellation: CancellationToken,
    stopped: watch::Receiver<bool>,
}

impl NetStackControl {
    /// Requests cancellation without waiting for cleanup.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Requests cancellation and returns only after all sockets are released.
    pub async fn stop(&self) {
        self.cancel();
        self.wait_stopped().await;
    }

    /// Waits for a stop requested by any owner.
    pub async fn wait_stopped(&self) {
        let mut stopped = self.stopped.clone();
        while !*stopped.borrow() {
            if stopped.changed().await.is_err() {
                break;
            }
        }
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        *self.stopped.borrow()
    }
}

#[derive(Clone, Default)]
pub struct NetStackStats(Arc<Counters>);

#[derive(Default)]
struct Counters {
    active_tcp: AtomicUsize,
    active_tcp_peak: AtomicUsize,
    half_open_tcp: AtomicUsize,
    half_open_tcp_peak: AtomicUsize,
    rejected_tcp: AtomicUsize,
    dropped_udp: AtomicUsize,
    invalid_packets: AtomicUsize,
    icmp_replied: AtomicUsize,
    icmp_dropped: AtomicUsize,
}

impl NetStackStats {
    #[must_use]
    pub fn snapshot(&self) -> ResourceSnapshot {
        ResourceSnapshot {
            active_tcp: self.0.active_tcp.load(Ordering::Acquire),
            active_tcp_peak: self.0.active_tcp_peak.load(Ordering::Acquire),
            half_open_tcp: self.0.half_open_tcp.load(Ordering::Acquire),
            half_open_tcp_peak: self.0.half_open_tcp_peak.load(Ordering::Acquire),
            rejected_tcp: self.0.rejected_tcp.load(Ordering::Acquire),
            dropped_udp: self.0.dropped_udp.load(Ordering::Acquire),
            invalid_packets: self.0.invalid_packets.load(Ordering::Acquire),
            icmp_replied: self.0.icmp_replied.load(Ordering::Acquire),
            icmp_dropped: self.0.icmp_dropped.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceSnapshot {
    pub active_tcp: usize,
    pub active_tcp_peak: usize,
    pub half_open_tcp: usize,
    pub half_open_tcp_peak: usize,
    pub rejected_tcp: usize,
    pub dropped_udp: usize,
    pub invalid_packets: usize,
    pub icmp_replied: usize,
    pub icmp_dropped: usize,
}

#[derive(Debug, Error)]
pub enum NetStackError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("NetStack::start must run inside a Tokio runtime")]
    NoRuntime,
    #[error("raw packet is empty")]
    EmptyPacket,
    #[error("raw packet is not IPv4 or IPv6")]
    InvalidIpVersion,
    #[error("raw packet length {packet_size} exceeds configured MTU {mtu}")]
    MtuExceeded { packet_size: usize, mtu: usize },
    #[error("bounded packet queue is full")]
    Backpressure,
    #[error("netstack is stopping or stopped")]
    Stopped,
}

fn validate_raw_packet(packet: &Packet, mtu: usize) -> Result<(), NetStackError> {
    if packet.is_empty() {
        return Err(NetStackError::EmptyPacket);
    }
    if packet.len() > mtu {
        return Err(NetStackError::MtuExceeded {
            packet_size: packet.len(),
            mtu,
        });
    }
    if !matches!(packet.data()[0] >> 4, 4 | 6) {
        return Err(NetStackError::InvalidIpVersion);
    }
    Ok(())
}

struct TcpEntry {
    socket: SocketHandle,
    handle: Arc<TcpStreamHandle>,
}

struct Driver {
    config: NetStackConfig,
    raw_inbound: mpsc::Receiver<Packet>,
    raw_outbound: mpsc::Sender<Packet>,
    tcp_accept: mpsc::Sender<TcpStream>,
    udp_outbound: mpsc::Sender<UdpDatagram>,
    cancellation: CancellationToken,
    notify: Arc<Notify>,
    stats: NetStackStats,
    stopped: watch::Sender<bool>,
    interface: Interface,
    device: RawIpDevice,
    sockets: SocketSet<'static>,
    tcp_entries: HashMap<FlowKey, TcpEntry>,
    half_open: HashSet<FlowKey>,
}

impl Driver {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: NetStackConfig,
        raw_inbound: mpsc::Receiver<Packet>,
        raw_outbound: mpsc::Sender<Packet>,
        tcp_accept: mpsc::Sender<TcpStream>,
        udp_outbound: mpsc::Sender<UdpDatagram>,
        cancellation: CancellationToken,
        notify: Arc<Notify>,
        stats: NetStackStats,
        stopped: watch::Sender<bool>,
    ) -> Self {
        let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = 0x4f_6e_65_56_43_6f_72_65;
        let mut device = RawIpDevice::new(config.mtu, config.packet_queue);
        let mut interface = Interface::new(interface_config, &mut device, Instant::now());
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(Ipv4Address::new(10, 0, 0, 1).into(), 24))
                .expect("smoltcp IP address capacity");
            addresses
                .push(IpCidr::new(
                    Ipv6Address::new(0xfd00, 0x5643, 0x6f72, 0x6500, 0, 0, 0, 1).into(),
                    64,
                ))
                .expect("smoltcp IP address capacity");
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
            .expect("smoltcp IPv4 route capacity");
        interface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfd00, 0x5643, 0x6f72, 0x6500, 0, 0, 0, 1))
            .expect("smoltcp IPv6 route capacity");

        Self {
            config,
            raw_inbound,
            raw_outbound,
            tcp_accept,
            udp_outbound,
            cancellation,
            notify,
            stats,
            stopped,
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_entries: HashMap::new(),
            half_open: HashSet::new(),
        }
    }

    async fn run(mut self) {
        loop {
            self.drive();
            if self.cancellation.is_cancelled() {
                break;
            }

            let delay = self.next_delay();
            tokio::select! {
                biased;
                () = self.cancellation.cancelled() => break,
                () = self.notify.notified() => {}
                packet = self.raw_inbound.recv(), if !self.device.tx_is_full() => {
                    let Some(packet) = packet else { break; };
                    self.handle_packet(packet);
                }
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    fn handle_packet(&mut self, packet: Packet) {
        if self.config.fake_icmp_echo {
            match classify_icmp(&packet) {
                IcmpIngress::NotIcmp => {}
                IcmpIngress::Dropped => {
                    self.stats.0.icmp_dropped.fetch_add(1, Ordering::AcqRel);
                    return;
                }
                IcmpIngress::Smoltcp => {
                    self.handle_icmp_packet(packet);
                    return;
                }
            }
        }
        match packet_protocol(&packet) {
            Some(IpProtocol::Tcp) => self.handle_tcp_packet(packet),
            Some(IpProtocol::Udp) => {
                if let Some(datagram) = parse_udp_packet(&packet) {
                    if self.udp_outbound.try_send(datagram).is_err() {
                        self.stats.0.dropped_udp.fetch_add(1, Ordering::AcqRel);
                    }
                } else {
                    self.stats.0.invalid_packets.fetch_add(1, Ordering::AcqRel);
                }
            }
            Some(_) => {}
            None => {
                self.stats.0.invalid_packets.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    fn handle_icmp_packet(&mut self, packet: Packet) {
        if !self.device.rx_is_empty()
            || self.device.tx_is_full()
            || self.raw_outbound.capacity() == 0
        {
            self.stats.0.icmp_dropped.fetch_add(1, Ordering::AcqRel);
            return;
        }

        // Keep low-priority fake echo replies out of the shared device TX backlog.
        // One synchronous ingress poll gives this request at most one immediate reply.
        let tx_checkpoint = self.device.tx_checkpoint();
        if self.device.push_rx(packet).is_err() {
            self.stats.0.icmp_dropped.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let result =
            self.interface
                .poll_ingress_single(Instant::now(), &mut self.device, &mut self.sockets);
        debug_assert_ne!(result, PollIngressSingleResult::None);

        let replied = self
            .device
            .pop_tx_after(tx_checkpoint)
            .is_some_and(|reply| self.raw_outbound.try_send(reply).is_ok());
        let counter = if replied {
            &self.stats.0.icmp_replied
        } else {
            &self.stats.0.icmp_dropped
        };
        counter.fetch_add(1, Ordering::AcqRel);
    }

    fn handle_tcp_packet(&mut self, packet: Packet) {
        let Some((flow, syn, ack)) = parse_tcp_flow(&packet) else {
            self.stats.0.invalid_packets.fetch_add(1, Ordering::AcqRel);
            return;
        };

        if !self.tcp_entries.contains_key(&flow) && (!syn || ack || !self.admit_tcp(flow)) {
            return;
        }
        if self.device.push_rx(packet).is_err() {
            // This can only occur when the fixed device ingress queue is full.
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn admit_tcp(&mut self, flow: FlowKey) -> bool {
        if self.tcp_accept.capacity() == 0 {
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
            return false;
        }

        let layer_buffer = self.config.layer_buffer_size();
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0_u8; layer_buffer]),
            tcp::SocketBuffer::new(vec![0_u8; layer_buffer]),
        );
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
        socket.set_timeout(Some(self.config.tcp_idle_timeout.into()));
        socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        if socket.listen(flow.destination).is_err() {
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
            return false;
        }

        let handle = Arc::new(TcpStreamHandle::new(layer_buffer, self.notify.clone()));
        let socket_handle = self.sockets.add(socket);
        let stream = TcpStream::new(flow, handle.clone());
        if self.tcp_accept.try_send(stream).is_err() {
            self.sockets.remove(socket_handle);
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
            return false;
        }
        self.tcp_entries.insert(
            flow,
            TcpEntry {
                socket: socket_handle,
                handle,
            },
        );
        self.half_open.insert(flow);
        self.update_flow_stats();
        true
    }

    fn drive(&mut self) {
        self.flush_raw_output();
        if !self.device.tx_is_full() {
            self.interface
                .poll(Instant::now(), &mut self.device, &mut self.sockets);
        }
        self.drive_tcp_sockets();
        if !self.device.tx_is_full() {
            self.interface
                .poll(Instant::now(), &mut self.device, &mut self.sockets);
        }
        self.flush_raw_output();
    }

    fn drive_tcp_sockets(&mut self) {
        let mut inactive = Vec::new();
        for (flow, entry) in &self.tcp_entries {
            let socket = self.sockets.get_mut::<tcp::Socket>(entry.socket);
            let handle = &entry.handle;

            let mut received = false;
            while socket.can_recv() && !handle.app_recv.is_full() {
                match socket.recv(|bytes| {
                    let count = handle.app_recv.write(bytes);
                    (count, count)
                }) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => received = true,
                }
            }
            if received {
                handle.recv_waker.wake();
            }

            let mut sent = false;
            while socket.can_send() && !handle.app_send.is_empty() {
                match socket.send(|bytes| {
                    let count = handle.app_send.read(bytes);
                    (count, count)
                }) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => sent = true,
                }
            }
            if sent {
                handle.send_waker.wake();
            }

            let past_handshake = !matches!(
                socket.state(),
                tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
            );
            if past_handshake {
                self.half_open.remove(flow);
            }
            if past_handshake && !socket.may_recv() && !socket.can_recv() {
                handle.read_closed.store(true, Ordering::Release);
                handle.recv_waker.wake();
            }
            if past_handshake && !socket.may_send() {
                handle.write_closed.store(true, Ordering::Release);
                handle.send_waker.wake();
            }

            if handle.dropped.load(Ordering::Acquire) && !past_handshake {
                // The dispatcher rejected the flow before the handshake
                // completed. Abort immediately instead of retaining a
                // half-open socket until the idle timeout.
                socket.abort();
            } else if (handle.write_shutdown.load(Ordering::Acquire)
                || handle.dropped.load(Ordering::Acquire))
                && handle.app_send.is_empty()
                && socket.may_send()
            {
                socket.close();
            }
            if !socket.is_active() {
                inactive.push(*flow);
            }
        }

        for flow in inactive {
            if let Some(entry) = self.tcp_entries.remove(&flow) {
                self.sockets.remove(entry.socket);
                self.half_open.remove(&flow);
                entry.handle.socket_closed.store(true, Ordering::Release);
                entry.handle.write_closed.store(true, Ordering::Release);
                entry.handle.wake_all();
            }
        }
        self.update_flow_stats();
    }

    fn flush_raw_output(&mut self) {
        while let Some(packet) = self.device.pop_tx() {
            match self.raw_outbound.try_send(packet) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(packet)) => {
                    self.device.push_tx_front(packet);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.cancellation.cancel();
                    break;
                }
            }
        }
    }

    fn next_delay(&mut self) -> Duration {
        let smoltcp_delay = self
            .interface
            .poll_delay(Instant::now(), &self.sockets)
            .map_or(self.config.max_poll_interval, Into::into);
        smoltcp_delay.min(self.config.max_poll_interval)
    }

    fn update_flow_stats(&self) {
        let active_tcp = self.tcp_entries.len();
        let half_open_tcp = self.half_open.len();
        self.stats
            .0
            .active_tcp_peak
            .fetch_max(active_tcp, Ordering::AcqRel);
        self.stats.0.active_tcp.store(active_tcp, Ordering::Release);
        self.stats
            .0
            .half_open_tcp_peak
            .fetch_max(half_open_tcp, Ordering::AcqRel);
        self.stats
            .0
            .half_open_tcp
            .store(half_open_tcp, Ordering::Release);
    }

    fn shutdown(&mut self) {
        self.cancellation.cancel();
        for entry in self.tcp_entries.values() {
            entry.handle.mark_stopped();
        }
        self.tcp_entries.clear();
        self.half_open.clear();
        self.sockets = SocketSet::new(Vec::new());
        self.update_flow_stats();
        let _ = self.stopped.send(true);
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn packet_protocol(packet: &Packet) -> Option<IpProtocol> {
    match IpVersion::of_packet(packet.data()).ok()? {
        IpVersion::Ipv4 => Some(Ipv4Packet::new_checked(packet.data()).ok()?.next_header()),
        IpVersion::Ipv6 => Some(Ipv6Packet::new_checked(packet.data()).ok()?.next_header()),
    }
}

fn parse_tcp_flow(packet: &Packet) -> Option<(FlowKey, bool, bool)> {
    let (source_ip, destination_ip, payload) = match IpVersion::of_packet(packet.data()).ok()? {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(packet.data()).ok()?;
            (
                IpAddr::from(ip.src_addr()),
                IpAddr::from(ip.dst_addr()),
                ip.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(packet.data()).ok()?;
            (
                IpAddr::from(ip.src_addr()),
                IpAddr::from(ip.dst_addr()),
                ip.payload(),
            )
        }
    };
    let tcp = TcpPacket::new_checked(payload).ok()?;
    Some((
        FlowKey {
            source: SocketAddr::new(source_ip, tcp.src_port()),
            destination: SocketAddr::new(destination_ip, tcp.dst_port()),
        },
        tcp.syn(),
        tcp.ack(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_raw_packet_bounds() {
        assert!(matches!(
            validate_raw_packet(&Packet::new(Vec::new()), 1_500),
            Err(NetStackError::EmptyPacket)
        ));
        assert!(matches!(
            validate_raw_packet(&Packet::new(vec![0x70]), 1_500),
            Err(NetStackError::InvalidIpVersion)
        ));
        assert!(matches!(
            validate_raw_packet(&Packet::new(vec![0x45; 1_501]), 1_500),
            Err(NetStackError::MtuExceeded { .. })
        ));
    }
}
