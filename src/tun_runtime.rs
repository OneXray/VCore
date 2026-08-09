use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt as _,
    sync::mpsc,
    task::JoinSet,
    time::{Instant as TokioInstant, MissedTickBehavior, interval_at, timeout},
};
use tokio_util::sync::CancellationToken;
use vcore_netstack::{
    NetStack, NetStackConfig, NetStackError, NetStackStats, Packet, PacketSink, PacketStream,
    TcpListener, TcpStream, UdpDatagram, UdpSocket,
};

use crate::{
    ResourceLimits, VCoreError,
    config::SnifferConfig,
    dispatch::{DatagramTransport, DispatchError, Dispatcher},
    dns::{
        classify_query,
        runtime::{DnsQueryPermit, RuntimeDns},
    },
    platform::TunIo,
    quic_sniffer::{
        QuicConnectionKey, QuicSniffOutcome, QuicSniffer, quic_connection_key,
        quic_has_unsupported_version,
    },
    resources::{ResourceActivity, ResourceActivityGuard, ResourceQueue, RuntimeResourceStats},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
    tcp_sniffer::{SniffOutcome, SniffProtocol, TcpSniffer},
    traffic::TunTrafficStats,
};

#[cfg(test)]
use crate::dns::{ClassifiedDnsQuery, synthesize_servfail_response};

const TUN_MTU: usize = 1_500;
const TCP_RELAY_BUFFER: usize = 4 * 1024;
const UDP_ASSOCIATION_QUEUE_MAX: usize = 16;
const QUIC_SNIFF_FLOW_MAX: usize = 4;
const QUIC_SNIFF_PENDING_DATAGRAM_MAX: usize = 8;
const QUIC_SNIFF_PENDING_BYTES_MAX: usize = 32 * 1024;
const QUIC_SNIFF_READY_DATAGRAM_MAX: usize = QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1;
const QUIC_SNIFF_TIMEOUT: Duration = Duration::from_millis(500);
const OUTBOUND_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_IDLE_TIMEOUT_SECONDS: u64 = 30;
const UDP_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const UDP_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const TUN_NETSTACK_STATS_INTERVAL: Duration = Duration::from_secs(30);
const TUN_NETSTACK_STATS_PERIODIC_EVENT: &str = "tun_netstack_stats_periodic";
const TUN_NETSTACK_STATS_FINAL_EVENT: &str = "tun_netstack_stats_final";

static NEXT_DIAGNOSTIC_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn tun_udp_ingress_queue_capacity(limits: ResourceLimits, dns_enabled: bool) -> usize {
    if dns_enabled {
        limits.tun_dns_ingress_queue_capacity
    } else {
        limits.event_queue_capacity
    }
}

fn tun_netstack_config(
    limits: ResourceLimits,
    dns_enabled: bool,
    fake_icmp_echo: bool,
) -> NetStackConfig {
    NetStackConfig {
        mtu: TUN_MTU.min(limits.tun_max_datagram_size),
        packet_queue: limits.packet_queue_capacity,
        tcp_accept_queue: limits.event_queue_capacity,
        udp_queue: tun_udp_ingress_queue_capacity(limits, dns_enabled),
        tcp_buffer_per_direction: limits.tcp_buffer_per_direction,
        fake_icmp_echo,
        ..NetStackConfig::default()
    }
}

pub(crate) struct TunRuntime {
    tun: Arc<TunIo>,
    limits: ResourceLimits,
    dispatcher: Arc<dyn Dispatcher>,
    dns: Option<Arc<RuntimeDns>>,
    fake_icmp_echo: bool,
    sniffer: Option<Arc<SnifferConfig>>,
    traffic_stats: Arc<TunTrafficStats>,
}

impl TunRuntime {
    #[cfg(test)]
    pub(crate) fn new(
        tun: TunIo,
        limits: ResourceLimits,
        dispatcher: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        fake_icmp_echo: bool,
        sniffer: Option<Arc<SnifferConfig>>,
    ) -> io::Result<Self> {
        Self::new_with_stats(
            tun,
            limits,
            dispatcher,
            dns,
            fake_icmp_echo,
            sniffer,
            Arc::new(TunTrafficStats::default()),
        )
    }

    pub(crate) fn new_with_stats(
        tun: TunIo,
        limits: ResourceLimits,
        dispatcher: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        fake_icmp_echo: bool,
        sniffer: Option<Arc<SnifferConfig>>,
        traffic_stats: Arc<TunTrafficStats>,
    ) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if limits.tun_max_datagram_size < 1_280 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN tun_max_datagram_size must be at least the IPv6 minimum MTU",
            ));
        }
        Ok(Self {
            tun: Arc::new(tun),
            limits,
            dispatcher,
            dns,
            fake_icmp_echo,
            sniffer,
            traffic_stats,
        })
    }

    pub(crate) async fn run(self, cancellation: CancellationToken) -> io::Result<()> {
        let config = tun_netstack_config(self.limits, self.dns.is_some(), self.fake_icmp_echo);
        let resource_stats = RuntimeResourceStats::new("tun_runtime");
        tracing::info!(
            mtu = config.mtu,
            packet_queue = self.limits.packet_queue_capacity,
            event_queue = self.limits.event_queue_capacity,
            udp_ingress_queue = config.udp_queue,
            dns_hijack = self.dns.is_some(),
            fake_icmp_echo = self.fake_icmp_echo,
            domain_sniffing = self.sniffer.is_some(),
            "TUN runtime starting"
        );
        let parts = NetStack::start(config)
            .map_err(netstack_to_io)?
            .into_parts();
        let control = parts.control.clone();
        let netstack_stats = parts.stats.clone();
        let mut tasks = JoinSet::new();

        tasks.spawn(netstack_stats_loop(
            netstack_stats.clone(),
            cancellation.clone(),
        ));
        tasks.spawn(
            self.traffic_stats
                .clone()
                .run_rate_clock(cancellation.clone()),
        );
        tasks.spawn(tun_read_loop(
            self.tun.clone(),
            parts.packet_sink,
            self.limits.packet_queue_capacity,
            resource_stats.clone(),
            self.traffic_stats.clone(),
            cancellation.clone(),
        ));
        tasks.spawn(tun_write_loop(
            self.tun,
            parts.packet_stream,
            self.traffic_stats,
            cancellation.clone(),
        ));
        let sniffer = self.sniffer;
        tasks.spawn(tcp_loop(
            parts.tcp_listener,
            self.dispatcher.clone(),
            sniffer.clone(),
            resource_stats.clone(),
            cancellation.clone(),
        ));
        tasks.spawn(udp_loop(
            parts.udp_socket,
            self.dispatcher,
            self.dns,
            sniffer,
            self.limits,
            resource_stats.clone(),
            cancellation.clone(),
        ));

        let mut first_error = tokio::select! {
            biased;
            () = cancellation.cancelled() => None,
            joined = tasks.join_next() => joined.and_then(join_result),
        };

        cancellation.cancel();
        control.stop().await;
        while let Some(joined) = tasks.join_next().await {
            if first_error.is_none() {
                first_error = join_result(joined);
            }
        }
        log_netstack_stats(TUN_NETSTACK_STATS_FINAL_EVENT, &netstack_stats);
        resource_stats.log_final();
        first_error.map_or(Ok(()), Err)
    }
}

async fn netstack_stats_loop(
    stats: NetStackStats,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut telemetry = interval_at(
        TokioInstant::now() + TUN_NETSTACK_STATS_INTERVAL,
        TUN_NETSTACK_STATS_INTERVAL,
    );
    telemetry.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            _ = telemetry.tick() => {
                log_netstack_stats(TUN_NETSTACK_STATS_PERIODIC_EVENT, &stats);
            }
        }
    }
}

fn log_netstack_stats(event: &'static str, stats: &NetStackStats) {
    let snapshot = stats.snapshot();
    tracing::info!(
        event,
        scope = "tun_netstack",
        active_tcp_current = snapshot.active_tcp,
        active_tcp_peak = snapshot.active_tcp_peak,
        half_open_tcp_current = snapshot.half_open_tcp,
        half_open_tcp_peak = snapshot.half_open_tcp_peak,
        rejected_tcp = snapshot.rejected_tcp,
        udp_drops = snapshot.dropped_udp,
        invalid_packets = snapshot.invalid_packets,
        icmp_replied = snapshot.icmp_replied,
        icmp_dropped = snapshot.icmp_dropped,
        "TUN netstack resource statistics"
    );
}

fn join_result(result: Result<io::Result<()>, tokio::task::JoinError>) -> Option<io::Error> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => None,
        Ok(Err(error)) => Some(error),
        Err(error) if error.is_cancelled() => None,
        Err(error) => Some(io::Error::other(error)),
    }
}

fn next_diagnostic_session_id() -> u64 {
    loop {
        let id = NEXT_DIAGNOSTIC_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

fn packet_ip_version(packet: &[u8]) -> u8 {
    packet.first().map_or(0, |byte| byte >> 4)
}

async fn tun_read_loop(
    tun: Arc<TunIo>,
    packet_sink: PacketSink,
    packet_queue_limit: usize,
    resource_stats: RuntimeResourceStats,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut packet = Vec::with_capacity(TUN_MTU);
    let mut first_read_logged = false;
    let mut first_ingress_logged = false;
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            result = tun.read_packet(&mut packet) => {
                match result {
                    Ok(_) => {}
                    Err(VCoreError::InvalidPacket(reason)) => {
                        tracing::debug!(%reason, "dropping invalid packet read from TUN");
                        continue;
                    }
                    Err(error) => return Err(vcore_to_io(error)),
                }
            }
        }
        traffic_stats.record_up(packet.len());
        if !first_read_logged {
            tracing::info!(
                packet_bytes = packet.len(),
                ip_version = packet_ip_version(&packet),
                "TUN received first packet"
            );
            first_read_logged = true;
        }
        let raw = Packet::new(Bytes::copy_from_slice(&packet));
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            result = packet_sink.send(raw) => match result {
                Ok(()) => {
                    if !first_ingress_logged {
                        tracing::info!("netstack accepted first TUN packet");
                        first_ingress_logged = true;
                    }
                }
                Err(NetStackError::Stopped) => return Ok(()),
                Err(error @ (NetStackError::EmptyPacket
                    | NetStackError::InvalidIpVersion
                    | NetStackError::MtuExceeded { .. }
                    | NetStackError::Backpressure)) => {
                    if matches!(error, NetStackError::Backpressure) {
                        resource_stats.queue_drop(ResourceQueue::Packet, packet_queue_limit);
                    }
                    tracing::debug!(error_code = ?error, "dropping packet rejected by netstack ingress");
                }
                Err(error) => return Err(netstack_to_io(error)),
            },
        }
    }
}

async fn tun_write_loop(
    tun: Arc<TunIo>,
    mut packet_stream: PacketStream,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut first_write_logged = false;
    loop {
        let packet = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            packet = packet_stream.recv() => packet,
        };
        let Some(packet) = packet else {
            return Ok(());
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            result = tun.write_packet(packet.data()) => {
                match result {
                    Ok(_) => {
                        traffic_stats.record_down(packet.data().len());
                        if !first_write_logged {
                            tracing::info!(
                                packet_bytes = packet.data().len(),
                                ip_version = packet_ip_version(packet.data()),
                                "TUN emitted first packet"
                            );
                            first_write_logged = true;
                        }
                    }
                    Err(VCoreError::InvalidPacket(reason)) => {
                        tracing::debug!(%reason, "dropping invalid packet emitted by netstack");
                    }
                    Err(error) => return Err(vcore_to_io(error)),
                }
            }
        }
    }
}

async fn tcp_loop(
    mut listener: TcpListener,
    dispatcher: Arc<dyn Dispatcher>,
    sniffer: Option<Arc<SnifferConfig>>,
    resource_stats: RuntimeResourceStats,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(
                        cancelled = error.is_cancelled(),
                        panicked = error.is_panic(),
                        "TUN TCP relay task failed"
                    );
                }
            }
            stream = listener.accept() => {
                let Some(stream) = stream else { break; };
                let session_id = next_diagnostic_session_id();
                let destination = stream.destination_addr();
                tracing::debug!(
                    session_id,
                    ip_version = if destination.is_ipv4() { 4 } else { 6 },
                    destination_port = destination.port(),
                    "TUN TCP session accepted"
                );
                let activity = resource_stats.begin_tun(ResourceActivity::TcpSession);
                sessions.spawn(relay_tcp(
                    session_id,
                    stream,
                    dispatcher.clone(),
                    sniffer.clone(),
                    activity,
                    cancellation.clone(),
                ));
            }
        }
    }
    while sessions.join_next().await.is_some() {}
    Ok(())
}

async fn relay_tcp(
    session_id: u64,
    mut inbound: TcpStream,
    dispatcher: Arc<dyn Dispatcher>,
    sniffer: Option<Arc<SnifferConfig>>,
    _activity: ResourceActivityGuard,
    cancellation: CancellationToken,
) {
    let destination = inbound.destination_addr();
    let destination_port = destination.port();
    let ip_version = if destination.is_ipv4() { 4 } else { 6 };
    let protocol = sniffer
        .as_deref()
        .and_then(|config| configured_sniff_protocol(config, destination_port));
    let (sniffed_domain, prefetched) = if let Some(protocol) = protocol {
        let mut sniffer = TcpSniffer::new(protocol);
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            outcome = sniffer.sniff(&mut inbound) => outcome,
        };
        let sniffed_domain = match outcome {
            Ok(SniffOutcome::Matched { protocol, domain }) => {
                tracing::debug!(
                    session_id,
                    ?protocol,
                    destination_port,
                    buffered_bytes = sniffer.buffered_len(),
                    "TUN TCP domain sniffed"
                );
                Some(domain)
            }
            Ok(outcome) => {
                tracing::debug!(
                    session_id,
                    ?outcome,
                    destination_port,
                    "TUN TCP domain sniffing completed without a domain"
                );
                None
            }
            Err(error) => {
                tracing::debug!(
                    session_id,
                    error_kind = ?error.kind(),
                    destination_port,
                    "TUN TCP domain sniffing failed open"
                );
                None
            }
        };
        (sniffed_domain, sniffer.into_buffered())
    } else {
        (None, Vec::new())
    };
    let session = StreamSession {
        inbound: InboundKind::Tun,
        source: inbound.source_addr(),
        destination: Destination::Ip(inbound.destination_addr()),
        sniffed_domain,
    };
    let connected = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        connected = timeout(OUTBOUND_OPEN_TIMEOUT, dispatcher.connect_tcp(session)) => connected,
    };
    let mut outbound = match connected {
        Ok(Ok(outbound)) => {
            tracing::debug!(
                session_id,
                ip_version,
                destination_port,
                "TUN TCP outbound connected"
            );
            outbound
        }
        Ok(Err(error)) => {
            tracing::warn!(
                session_id,
                ip_version,
                destination_port,
                error_code = error.diagnostic_code(),
                "TUN TCP outbound connect failed"
            );
            return;
        }
        Err(_) => {
            tracing::warn!(
                session_id,
                ip_version,
                destination_port,
                timeout_seconds = OUTBOUND_OPEN_TIMEOUT.as_secs(),
                "TUN TCP outbound connect timed out"
            );
            return;
        }
    };
    let prefetched_bytes = u64::try_from(prefetched.len()).unwrap_or(u64::MAX);
    if !prefetched.is_empty() {
        let replayed = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            replayed = timeout(OUTBOUND_SEND_TIMEOUT, outbound.write_all(&prefetched)) => replayed,
        };
        match replayed {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(
                    session_id,
                    error_kind = ?error.kind(),
                    prefetched_bytes,
                    "TUN TCP sniffed prefix replay failed"
                );
                return;
            }
            Err(_) => {
                tracing::warn!(
                    session_id,
                    prefetched_bytes,
                    timeout_seconds = OUTBOUND_SEND_TIMEOUT.as_secs(),
                    "TUN TCP sniffed prefix replay timed out"
                );
                return;
            }
        }
    }
    drop(prefetched);
    let relayed = tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok((0, 0)),
        copied = tokio::io::copy_bidirectional_with_sizes(
            &mut inbound,
            &mut outbound,
            TCP_RELAY_BUFFER,
            TCP_RELAY_BUFFER,
        ) => copied,
    };
    match relayed {
        Ok((uploaded_bytes, downloaded_bytes)) => tracing::debug!(
            session_id,
            uploaded_bytes = uploaded_bytes.saturating_add(prefetched_bytes),
            downloaded_bytes,
            "TUN TCP relay finished"
        ),
        Err(error) => tracing::warn!(
            session_id,
            error_kind = ?error.kind(),
            "TUN TCP relay failed"
        ),
    }
}

fn configured_sniff_protocol(config: &SnifferConfig, port: u16) -> Option<SniffProtocol> {
    if config.matches_http_port(port) {
        Some(SniffProtocol::Http)
    } else if config.matches_tls_port(port) {
        Some(SniffProtocol::Tls)
    } else {
        None
    }
}

fn configured_quic_sniffing(config: Option<&SnifferConfig>, port: u16) -> bool {
    config.is_some_and(|config| config.matches_quic_port(port))
}

#[derive(Clone)]
struct AssociationClock {
    started: StdInstant,
    #[cfg(test)]
    injected_tick: Option<Arc<AtomicU64>>,
}

impl AssociationClock {
    fn realtime() -> Self {
        Self {
            started: StdInstant::now(),
            #[cfg(test)]
            injected_tick: None,
        }
    }

    #[cfg(test)]
    fn injected(tick: Arc<AtomicU64>) -> Self {
        Self {
            started: StdInstant::now(),
            injected_tick: Some(tick),
        }
    }

    fn now(&self) -> u64 {
        #[cfg(test)]
        if let Some(tick) = &self.injected_tick {
            return tick.load(Ordering::Acquire);
        }
        self.started.elapsed().as_secs()
    }
}

struct UdpAssociation {
    generation: u64,
    sender: mpsc::Sender<UdpDatagram>,
    cancellation: CancellationToken,
    last_activity: Arc<AtomicU64>,
}

impl UdpAssociation {
    fn touch(&self, tick: u64) {
        self.last_activity.store(tick, Ordering::Release);
    }

    fn idle_seconds(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_activity.load(Ordering::Acquire))
    }
}

fn remove_completed_association(
    associations: &mut HashMap<SocketAddr, UdpAssociation>,
    source: SocketAddr,
    generation: u64,
) -> Option<UdpAssociation> {
    if associations
        .get(&source)
        .is_some_and(|association| association.generation == generation)
    {
        associations.remove(&source)
    } else {
        None
    }
}

fn take_expired_or_closed_associations(
    associations: &mut HashMap<SocketAddr, UdpAssociation>,
    now: u64,
) -> Vec<(SocketAddr, UdpAssociation)> {
    let sources = associations
        .iter()
        .filter_map(|(source, association)| {
            (association.sender.is_closed()
                || association.idle_seconds(now) >= UDP_IDLE_TIMEOUT_SECONDS)
                .then_some(*source)
        })
        .collect::<Vec<_>>();
    sources
        .into_iter()
        .filter_map(|source| {
            associations
                .remove(&source)
                .map(|association| (source, association))
        })
        .collect()
}

fn cancel_removed_associations(removed: Vec<(SocketAddr, UdpAssociation)>) {
    for (source, association) in removed {
        tracing::debug!(
            association_id = association.generation,
            %source,
            "TUN UDP association cleaned up"
        );
        // The map entry has already been removed, so a stale completion can
        // never delete a replacement generation for the same source.
        association.cancellation.cancel();
    }
}

enum AssociationInputResult {
    Queued,
    Full,
    Closed,
}

fn try_queue_association_input(
    association: &UdpAssociation,
    datagram: UdpDatagram,
    now: u64,
    association_queue: usize,
    resource_stats: &RuntimeResourceStats,
) -> AssociationInputResult {
    match association.sender.try_send(datagram) {
        Ok(()) => {
            association.touch(now);
            AssociationInputResult::Queued
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            resource_stats.queue_drop(ResourceQueue::Udp, association_queue);
            AssociationInputResult::Full
        }
        Err(mpsc::error::TrySendError::Closed(_)) => AssociationInputResult::Closed,
    }
}

async fn udp_loop(
    mut socket: UdpSocket,
    dispatcher: Arc<dyn Dispatcher>,
    dns: Option<Arc<RuntimeDns>>,
    sniffer: Option<Arc<SnifferConfig>>,
    limits: ResourceLimits,
    resource_stats: RuntimeResourceStats,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let association_queue = limits
        .event_queue_capacity
        .clamp(1, UDP_ASSOCIATION_QUEUE_MAX);
    let (responses_tx, mut responses_rx) = mpsc::channel(limits.event_queue_capacity);
    let (dns_responses_tx, mut dns_responses_rx) =
        mpsc::channel(limits.tun_dns_response_queue_capacity);
    let mut associations: HashMap<SocketAddr, UdpAssociation> = HashMap::new();
    let mut tasks: JoinSet<(SocketAddr, u64, io::Result<()>)> = JoinSet::new();
    let mut dns_tasks: JoinSet<()> = JoinSet::new();
    let association_clock = AssociationClock::realtime();
    let mut cleanup = interval_at(
        TokioInstant::now() + UDP_CLEANUP_INTERVAL,
        UDP_CLEANUP_INTERVAL,
    );

    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = cleanup.tick() => {
                let removed =
                    take_expired_or_closed_associations(&mut associations, association_clock.now());
                cancel_removed_associations(removed);
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok((source, association_id, result))) => {
                        remove_completed_association(&mut associations, source, association_id);
                        match result {
                            Ok(()) => tracing::debug!(association_id, "TUN UDP association closed"),
                            Err(error) => tracing::warn!(
                                association_id,
                                error_kind = ?error.kind(),
                                "TUN UDP association failed"
                            ),
                        }
                    }
                    Some(Err(error)) => {
                        tracing::warn!(
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "TUN UDP association task failed"
                        );
                    }
                    None => {}
                }
            }
            joined = dns_tasks.join_next(), if !dns_tasks.is_empty() => {
                match joined {
                    Some(Ok(())) | None => {}
                    Some(Err(error)) => {
                        tracing::warn!(
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "TUN DNS query task failed"
                        );
                    }
                }
            }
            response = responses_rx.recv() => {
                let Some(response) = response else { break; };
                if !emit_udp_response(&socket, response).await {
                    break;
                }
            }
            response = dns_responses_rx.recv() => {
                let Some(response) = response else { break; };
                if !emit_udp_response(&socket, response).await {
                    break;
                }
            }
            datagram = socket.recv() => {
                let Some(datagram) = datagram else { break; };
                if datagram.destination.port() == 53
                    && let Some(dns) = &dns
                {
                    match classify_query(&datagram.payload) {
                        Ok(_) => {}
                        Err(error) => {
                            tracing::debug!(%error, "dropping invalid TUN DNS datagram");
                            continue;
                        }
                    }
                    let permit = dns.begin_query();
                    dns_tasks.spawn(run_tun_dns_query(
                        dns.clone(),
                        permit,
                        datagram,
                        dns_responses_tx.clone(),
                        resource_stats.clone(),
                        cancellation.clone(),
                    ));
                    continue;
                }
                let source = datagram.source;
                if let Entry::Vacant(entry) = associations.entry(source) {
                    let association_id = next_diagnostic_session_id();
                    tracing::debug!(association_id, "TUN UDP association created");
                    let (sender, receiver) = mpsc::channel(association_queue);
                    let child_cancellation = cancellation.child_token();
                    let last_activity = Arc::new(AtomicU64::new(association_clock.now()));
                    entry.insert(UdpAssociation {
                        generation: association_id,
                        sender,
                        cancellation: child_cancellation.clone(),
                        last_activity: last_activity.clone(),
                    });
                    let activity =
                        resource_stats.begin_tun(ResourceActivity::UdpAssociation);
                    tasks.spawn(run_udp_association(
                        receiver,
                        activity,
                        UdpAssociationTaskContext {
                            association_id,
                            source,
                            responses: responses_tx.clone(),
                            dispatcher: dispatcher.clone(),
                            resource_stats: resource_stats.clone(),
                            association_clock: association_clock.clone(),
                            last_activity,
                            sniffer: sniffer.clone(),
                            cancellation: child_cancellation,
                        },
                    ));
                }
                let Some(association) = associations.get(&source) else {
                    continue;
                };
                match try_queue_association_input(
                    association,
                    datagram,
                    association_clock.now(),
                    association_queue,
                    &resource_stats,
                ) {
                    AssociationInputResult::Queued => {}
                    AssociationInputResult::Full => {
                        // One slow source must not apply backpressure to the
                        // global TUN UDP loop. UDP loss is local to this one
                        // datagram; other associations and ready responses
                        // remain able to advance.
                    }
                    AssociationInputResult::Closed => {
                        let generation = association.generation;
                        let removed =
                            remove_completed_association(&mut associations, source, generation)
                                .into_iter()
                                .map(|association| (source, association))
                                .collect();
                        cancel_removed_associations(removed);
                        tracing::debug!("dropping TUN UDP datagram for a closing association");
                    }
                }
            }
        }
    }

    drop(responses_tx);
    drop(dns_responses_tx);
    dns_tasks.abort_all();
    while dns_tasks.join_next().await.is_some() {}
    let removed = associations.drain().collect::<Vec<_>>();
    for (_, association) in &removed {
        association.cancellation.cancel();
    }
    drop(removed);
    while tasks.join_next().await.is_some() {}
    Ok(())
}

struct QueuedUdpResponse {
    datagram: UdpDatagram,
    dns_permit: Option<DnsQueryPermit>,
}

impl QueuedUdpResponse {
    fn ordinary(datagram: UdpDatagram) -> Self {
        Self {
            datagram,
            dns_permit: None,
        }
    }

    fn dns(datagram: UdpDatagram, permit: DnsQueryPermit) -> Self {
        Self {
            datagram,
            dns_permit: Some(permit),
        }
    }
}

impl Deref for QueuedUdpResponse {
    type Target = UdpDatagram;

    fn deref(&self) -> &Self::Target {
        &self.datagram
    }
}

async fn emit_udp_response(socket: &UdpSocket, response: QueuedUdpResponse) -> bool {
    let QueuedUdpResponse {
        datagram,
        dns_permit,
    } = response;
    let result = socket.send(datagram).await;
    drop(dns_permit);
    match result {
        Ok(()) => true,
        Err(vcore_netstack::UdpError::Stopped) => false,
        Err(
            error @ (vcore_netstack::UdpError::MtuExceeded { .. }
            | vcore_netstack::UdpError::AddressFamilyMismatch),
        ) => {
            tracing::debug!(
                error_code = ?error,
                "dropping UDP response that cannot be emitted to TUN"
            );
            true
        }
    }
}

async fn run_tun_dns_query(
    dns: Arc<RuntimeDns>,
    permit: DnsQueryPermit,
    request: UdpDatagram,
    responses: mpsc::Sender<QueuedUdpResponse>,
    resource_stats: RuntimeResourceStats,
    cancellation: CancellationToken,
) {
    let response = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        response = dns.exchange_admitted(&request.payload, &permit) => match response {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(%error, "dropping invalid TUN DNS datagram");
                return;
            }
        },
    };
    if let Some(response) = complete_tun_dns_response(&request, response) {
        try_queue_tun_dns_response(&responses, response, Some(permit), &resource_stats);
    }
}

fn try_queue_tun_dns_response(
    responses: &mpsc::Sender<QueuedUdpResponse>,
    response: UdpDatagram,
    permit: Option<DnsQueryPermit>,
    resource_stats: &RuntimeResourceStats,
) {
    let response = match permit {
        Some(permit) => QueuedUdpResponse::dns(response, permit),
        None => QueuedUdpResponse::ordinary(response),
    };
    match responses.try_send(response) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            resource_stats.queue_drop(ResourceQueue::Dns, responses.max_capacity());
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("dropping TUN DNS response because the response queue is closed");
        }
    }
}

enum ResponseQueueResult {
    Queued,
    Dropped,
    Closed,
}

fn try_queue_tun_udp_response(
    responses: &mpsc::Sender<QueuedUdpResponse>,
    response: UdpDatagram,
    last_activity: &AtomicU64,
    now: u64,
    resource_stats: &RuntimeResourceStats,
) -> ResponseQueueResult {
    match responses.try_send(QueuedUdpResponse::ordinary(response)) {
        Ok(()) => {
            last_activity.store(now, Ordering::Release);
            ResponseQueueResult::Queued
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            resource_stats.queue_drop(ResourceQueue::Udp, responses.max_capacity());
            ResponseQueueResult::Dropped
        }
        Err(mpsc::error::TrySendError::Closed(_)) => ResponseQueueResult::Closed,
    }
}

fn complete_tun_dns_response(request: &UdpDatagram, response: Vec<u8>) -> Option<UdpDatagram> {
    if response.len()
        > usize::from(
            DatagramSession::new(InboundKind::Tun, request.source).max_response_payload_size(),
        )
    {
        tracing::debug!(
            response_bytes = response.len(),
            "dropping oversized TUN DNS UDP response"
        );
        return None;
    }
    Some(UdpDatagram::new(
        request.destination,
        request.source,
        response,
    ))
}

#[cfg(test)]
fn tun_dns_servfail_response(request: &UdpDatagram, query: &ClassifiedDnsQuery) -> UdpDatagram {
    UdpDatagram::new(
        request.destination,
        request.source,
        synthesize_servfail_response(query),
    )
}

enum AssociationEvent {
    Cancelled,
    SniffDeadline,
    ReadySend,
    Inbound(Option<UdpDatagram>),
    Outbound(Result<Datagram, DispatchError>),
}

trait QuicSniffEngine {
    fn ingest(&mut self, packet: &[u8]) -> QuicSniffOutcome;

    fn authenticated_initial_in_last_ingest(&self) -> bool;
}

impl QuicSniffEngine for QuicSniffer {
    fn ingest(&mut self, packet: &[u8]) -> QuicSniffOutcome {
        QuicSniffer::ingest(self, packet)
    }

    fn authenticated_initial_in_last_ingest(&self) -> bool {
        QuicSniffer::authenticated_initial_in_last_ingest(self)
    }
}

struct PreparedTunUdpDatagram {
    datagram: UdpDatagram,
    sniffed_domain: Option<Arc<str>>,
}

impl PreparedTunUdpDatagram {
    fn without_domain(datagram: UdpDatagram) -> Self {
        Self {
            datagram,
            sniffed_domain: None,
        }
    }

    fn with_domain(datagram: UdpDatagram, domain: Arc<str>) -> Self {
        Self {
            datagram,
            sniffed_domain: Some(domain),
        }
    }
}

struct PendingQuicFlow<S> {
    sniffer: S,
    connection_key: Option<QuicConnectionKey>,
    datagrams: VecDeque<PreparedTunUdpDatagram>,
    buffered_bytes: usize,
    deadline: TokioInstant,
}

struct CompletedQuicFlow {
    connection_key: Option<QuicConnectionKey>,
    last_used: TokioInstant,
}

enum QuicFlowState<S> {
    Pending(PendingQuicFlow<S>),
    Matched {
        domain: Arc<str>,
        completed: CompletedQuicFlow,
    },
    NoDomain(CompletedQuicFlow),
}

enum QuicIngressResult {
    Buffered,
    Forward(PreparedTunUdpDatagram),
    Replay(VecDeque<PreparedTunUdpDatagram>),
}

fn starts_new_quic_connection(
    current: &Option<QuicConnectionKey>,
    observed: &Option<QuicConnectionKey>,
) -> bool {
    observed
        .as_ref()
        .is_some_and(|observed| current.as_ref() != Some(observed))
}

fn prepend_quic_replay(
    mut replay: VecDeque<PreparedTunUdpDatagram>,
    next: QuicIngressResult,
) -> QuicIngressResult {
    if replay.is_empty() {
        return next;
    }
    match next {
        QuicIngressResult::Buffered => QuicIngressResult::Replay(replay),
        QuicIngressResult::Forward(prepared) => {
            replay.push_back(prepared);
            QuicIngressResult::Replay(replay)
        }
        QuicIngressResult::Replay(mut next) => {
            replay.append(&mut next);
            QuicIngressResult::Replay(replay)
        }
    }
}

struct UdpQuicSniffState<S, F> {
    flows: HashMap<SocketAddr, QuicFlowState<S>>,
    pending_datagrams: usize,
    pending_bytes: usize,
    new_sniffer: F,
}

impl<S, F> UdpQuicSniffState<S, F>
where
    S: QuicSniffEngine,
    F: FnMut() -> S,
{
    fn new(new_sniffer: F) -> Self {
        Self {
            flows: HashMap::new(),
            pending_datagrams: 0,
            pending_bytes: 0,
            new_sniffer,
        }
    }

    fn next_deadline(&self) -> Option<TokioInstant> {
        self.flows
            .values()
            .filter_map(|state| match state {
                QuicFlowState::Pending(pending) => Some(pending.deadline),
                QuicFlowState::Matched { .. } | QuicFlowState::NoDomain(_) => None,
            })
            .min()
    }

    fn ingest_datagram(&mut self, datagram: UdpDatagram, now: TokioInstant) -> QuicIngressResult {
        let destination = datagram.destination;
        let connection_key = quic_connection_key(&datagram.payload);
        let state = self.flows.remove(&destination);
        if connection_key.is_none() && quic_has_unsupported_version(&datagram.payload) {
            return self.fail_open_unsupported_version(datagram, state, now);
        }
        let Some(state) = state else {
            return self.start_flow(datagram, connection_key, now);
        };
        match state {
            QuicFlowState::Matched {
                domain,
                mut completed,
            } => {
                if starts_new_quic_connection(&completed.connection_key, &connection_key) {
                    let mut candidate = (self.new_sniffer)();
                    let outcome = candidate.ingest(&datagram.payload);
                    if candidate.authenticated_initial_in_last_ingest() {
                        return self.commit_started_flow(
                            datagram,
                            connection_key,
                            now,
                            candidate,
                            outcome,
                        );
                    }
                }
                completed.last_used = now;
                self.flows.insert(
                    destination,
                    QuicFlowState::Matched {
                        domain: domain.clone(),
                        completed,
                    },
                );
                QuicIngressResult::Forward(PreparedTunUdpDatagram::with_domain(datagram, domain))
            }
            QuicFlowState::NoDomain(mut completed) => {
                if starts_new_quic_connection(&completed.connection_key, &connection_key) {
                    let mut candidate = (self.new_sniffer)();
                    let outcome = candidate.ingest(&datagram.payload);
                    if candidate.authenticated_initial_in_last_ingest() {
                        return self.commit_started_flow(
                            datagram,
                            connection_key,
                            now,
                            candidate,
                            outcome,
                        );
                    }
                }
                completed.last_used = now;
                self.flows
                    .insert(destination, QuicFlowState::NoDomain(completed));
                QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram))
            }
            QuicFlowState::Pending(mut pending) => {
                if starts_new_quic_connection(&pending.connection_key, &connection_key) {
                    let outcome = pending.sniffer.ingest(&datagram.payload);
                    if pending.sniffer.authenticated_initial_in_last_ingest() {
                        return self.apply_pending_outcome(
                            destination,
                            pending,
                            datagram,
                            outcome,
                            now,
                        );
                    }
                    let mut candidate = (self.new_sniffer)();
                    let outcome = candidate.ingest(&datagram.payload);
                    if !candidate.authenticated_initial_in_last_ingest() {
                        self.flows
                            .insert(destination, QuicFlowState::Pending(pending));
                        return QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(
                            datagram,
                        ));
                    }
                    self.release_pending(&pending);
                    let replay = pending.datagrams;
                    let next =
                        self.commit_started_flow(datagram, connection_key, now, candidate, outcome);
                    return prepend_quic_replay(replay, next);
                }
                let outcome = pending.sniffer.ingest(&datagram.payload);
                self.apply_pending_outcome(destination, pending, datagram, outcome, now)
            }
        }
    }

    fn fail_open_unsupported_version(
        &mut self,
        datagram: UdpDatagram,
        state: Option<QuicFlowState<S>>,
        now: TokioInstant,
    ) -> QuicIngressResult {
        let destination = datagram.destination;
        match state {
            Some(QuicFlowState::Pending(mut pending)) => {
                self.release_pending(&pending);
                pending
                    .datagrams
                    .push_back(PreparedTunUdpDatagram::without_domain(datagram));
                self.flows.insert(
                    destination,
                    QuicFlowState::NoDomain(CompletedQuicFlow {
                        connection_key: None,
                        last_used: now,
                    }),
                );
                QuicIngressResult::Replay(pending.datagrams)
            }
            Some(QuicFlowState::Matched { .. }) | Some(QuicFlowState::NoDomain(_)) => {
                self.flows.insert(
                    destination,
                    QuicFlowState::NoDomain(CompletedQuicFlow {
                        connection_key: None,
                        last_used: now,
                    }),
                );
                QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram))
            }
            None => {
                if self.make_room_for_flow() {
                    self.flows.insert(
                        destination,
                        QuicFlowState::NoDomain(CompletedQuicFlow {
                            connection_key: None,
                            last_used: now,
                        }),
                    );
                }
                QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram))
            }
        }
    }

    fn start_flow(
        &mut self,
        datagram: UdpDatagram,
        connection_key: Option<QuicConnectionKey>,
        now: TokioInstant,
    ) -> QuicIngressResult {
        if !self.make_room_for_flow() {
            return QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram));
        }
        let mut sniffer = (self.new_sniffer)();
        let outcome = sniffer.ingest(&datagram.payload);
        self.commit_started_flow(datagram, connection_key, now, sniffer, outcome)
    }

    fn commit_started_flow(
        &mut self,
        datagram: UdpDatagram,
        connection_key: Option<QuicConnectionKey>,
        now: TokioInstant,
        sniffer: S,
        outcome: QuicSniffOutcome,
    ) -> QuicIngressResult {
        let destination = datagram.destination;
        match outcome {
            QuicSniffOutcome::NeedMoreData if self.can_buffer(datagram.payload.len()) => {
                let buffered_bytes = datagram.payload.len();
                let mut datagrams = VecDeque::new();
                datagrams.push_back(PreparedTunUdpDatagram::without_domain(datagram));
                self.pending_datagrams += 1;
                self.pending_bytes += buffered_bytes;
                self.flows.insert(
                    destination,
                    QuicFlowState::Pending(PendingQuicFlow {
                        sniffer,
                        connection_key,
                        datagrams,
                        buffered_bytes,
                        deadline: now + QUIC_SNIFF_TIMEOUT,
                    }),
                );
                QuicIngressResult::Buffered
            }
            QuicSniffOutcome::Matched(domain) => {
                let domain: Arc<str> = Arc::from(domain);
                self.flows.insert(
                    destination,
                    QuicFlowState::Matched {
                        domain: domain.clone(),
                        completed: CompletedQuicFlow {
                            connection_key,
                            last_used: now,
                        },
                    },
                );
                QuicIngressResult::Forward(PreparedTunUdpDatagram::with_domain(datagram, domain))
            }
            QuicSniffOutcome::NeedMoreData
            | QuicSniffOutcome::EchExtensionPresent
            | QuicSniffOutcome::NotMatched
            | QuicSniffOutcome::LimitReached => {
                self.flows.insert(
                    destination,
                    QuicFlowState::NoDomain(CompletedQuicFlow {
                        connection_key,
                        last_used: now,
                    }),
                );
                QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram))
            }
        }
    }

    fn apply_pending_outcome(
        &mut self,
        destination: SocketAddr,
        mut pending: PendingQuicFlow<S>,
        datagram: UdpDatagram,
        outcome: QuicSniffOutcome,
        now: TokioInstant,
    ) -> QuicIngressResult {
        match outcome {
            QuicSniffOutcome::NeedMoreData if self.can_buffer(datagram.payload.len()) => {
                let payload_len = datagram.payload.len();
                pending.buffered_bytes += payload_len;
                pending
                    .datagrams
                    .push_back(PreparedTunUdpDatagram::without_domain(datagram));
                self.pending_datagrams += 1;
                self.pending_bytes += payload_len;
                self.flows
                    .insert(destination, QuicFlowState::Pending(pending));
                QuicIngressResult::Buffered
            }
            QuicSniffOutcome::Matched(domain) => {
                self.finish_pending(destination, pending, datagram, Some(Arc::from(domain)), now)
            }
            QuicSniffOutcome::NeedMoreData
            | QuicSniffOutcome::EchExtensionPresent
            | QuicSniffOutcome::NotMatched
            | QuicSniffOutcome::LimitReached => {
                self.finish_pending(destination, pending, datagram, None, now)
            }
        }
    }

    fn make_room_for_flow(&mut self) -> bool {
        if self.flows.len() < QUIC_SNIFF_FLOW_MAX {
            return true;
        }
        let oldest_completed = self
            .flows
            .iter()
            .filter_map(|(destination, state)| match state {
                QuicFlowState::Matched { completed, .. } | QuicFlowState::NoDomain(completed) => {
                    Some((*destination, completed.last_used))
                }
                QuicFlowState::Pending(_) => None,
            })
            .min_by_key(|(_, last_used)| *last_used)
            .map(|(destination, _)| destination);
        if let Some(destination) = oldest_completed {
            self.flows.remove(&destination);
            true
        } else {
            false
        }
    }

    fn can_buffer(&self, bytes: usize) -> bool {
        self.pending_datagrams < QUIC_SNIFF_PENDING_DATAGRAM_MAX
            && self
                .pending_bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= QUIC_SNIFF_PENDING_BYTES_MAX)
    }

    fn finish_pending(
        &mut self,
        destination: SocketAddr,
        mut pending: PendingQuicFlow<S>,
        datagram: UdpDatagram,
        domain: Option<Arc<str>>,
        now: TokioInstant,
    ) -> QuicIngressResult {
        self.release_pending(&pending);
        pending
            .datagrams
            .push_back(PreparedTunUdpDatagram::without_domain(datagram));
        if let Some(domain) = &domain {
            for buffered in &mut pending.datagrams {
                buffered.sniffed_domain = Some(domain.clone());
            }
        }
        let completed = CompletedQuicFlow {
            connection_key: pending.connection_key,
            last_used: now,
        };
        self.flows.insert(
            destination,
            match domain {
                Some(domain) => QuicFlowState::Matched { domain, completed },
                None => QuicFlowState::NoDomain(completed),
            },
        );
        QuicIngressResult::Replay(pending.datagrams)
    }

    fn expire(&mut self, now: TokioInstant) -> VecDeque<PreparedTunUdpDatagram> {
        let destinations = self
            .flows
            .iter()
            .filter_map(|(destination, state)| match state {
                QuicFlowState::Pending(pending) if pending.deadline <= now => Some(*destination),
                QuicFlowState::Pending(_)
                | QuicFlowState::Matched { .. }
                | QuicFlowState::NoDomain(_) => None,
            })
            .collect::<Vec<_>>();
        let mut replay = VecDeque::new();
        for destination in destinations {
            let Some(QuicFlowState::Pending(mut pending)) = self.flows.remove(&destination) else {
                continue;
            };
            self.release_pending(&pending);
            replay.append(&mut pending.datagrams);
            self.flows.insert(
                destination,
                QuicFlowState::NoDomain(CompletedQuicFlow {
                    connection_key: pending.connection_key,
                    last_used: now,
                }),
            );
        }
        replay
    }

    fn release_pending(&mut self, pending: &PendingQuicFlow<S>) {
        self.pending_datagrams = self
            .pending_datagrams
            .saturating_sub(pending.datagrams.len());
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.buffered_bytes);
    }
}

struct UdpAssociationTaskContext {
    association_id: u64,
    source: SocketAddr,
    responses: mpsc::Sender<QueuedUdpResponse>,
    dispatcher: Arc<dyn Dispatcher>,
    resource_stats: RuntimeResourceStats,
    association_clock: AssociationClock,
    last_activity: Arc<AtomicU64>,
    sniffer: Option<Arc<SnifferConfig>>,
    cancellation: CancellationToken,
}

async fn run_udp_association(
    mut inbound: mpsc::Receiver<UdpDatagram>,
    _activity: ResourceActivityGuard,
    context: UdpAssociationTaskContext,
) -> (SocketAddr, u64, io::Result<()>) {
    let result = run_udp_association_inner(&mut inbound, &context).await;
    (context.source, context.association_id, result)
}

async fn run_udp_association_inner(
    inbound: &mut mpsc::Receiver<UdpDatagram>,
    context: &UdpAssociationTaskContext,
) -> io::Result<()> {
    run_udp_association_inner_with_quic_factory(inbound, context, QuicSniffer::new).await
}

async fn wait_for_quic_sniff_deadline(deadline: Option<TokioInstant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn send_tun_udp_datagram(
    transport: &mut dyn DatagramTransport,
    prepared: PreparedTunUdpDatagram,
    context: &UdpAssociationTaskContext,
) -> io::Result<bool> {
    let PreparedTunUdpDatagram {
        datagram,
        sniffed_domain,
    } = prepared;
    let send = tokio::select! {
        biased;
        () = context.cancellation.cancelled() => return Ok(false),
        result = timeout(OUTBOUND_SEND_TIMEOUT, transport.send(Datagram {
            remote: Destination::Ip(datagram.destination),
            payload: datagram.payload,
            sniffed_domain,
        })) => result,
    };
    match send {
        Ok(Ok(())) => Ok(true),
        Ok(Err(error)) => Err(dispatch_to_io(error)),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TUN UDP outbound send timed out",
        )),
    }
}

fn append_ready_datagrams(
    ready: &mut VecDeque<PreparedTunUdpDatagram>,
    mut datagrams: VecDeque<PreparedTunUdpDatagram>,
) -> io::Result<()> {
    if ready
        .len()
        .checked_add(datagrams.len())
        .is_none_or(|total| total > QUIC_SNIFF_READY_DATAGRAM_MAX)
    {
        return Err(io::Error::other(
            "TUN UDP QUIC replay queue exceeded its fixed capacity",
        ));
    }
    ready.append(&mut datagrams);
    Ok(())
}

fn queue_quic_ingress_result(
    ready: &mut VecDeque<PreparedTunUdpDatagram>,
    result: QuicIngressResult,
) -> io::Result<()> {
    match result {
        QuicIngressResult::Buffered => Ok(()),
        QuicIngressResult::Forward(prepared) => {
            append_ready_datagrams(ready, VecDeque::from([prepared]))
        }
        QuicIngressResult::Replay(replay) => append_ready_datagrams(ready, replay),
    }
}

async fn run_udp_association_inner_with_quic_factory<S, F>(
    inbound: &mut mpsc::Receiver<UdpDatagram>,
    context: &UdpAssociationTaskContext,
    new_sniffer: F,
) -> io::Result<()>
where
    S: QuicSniffEngine,
    F: FnMut() -> S,
{
    let association_id = context.association_id;
    let source = context.source;
    let session = DatagramSession::new(InboundKind::Tun, source);
    let opened = tokio::select! {
        biased;
        () = context.cancellation.cancelled() => return Ok(()),
        opened = timeout(
            OUTBOUND_OPEN_TIMEOUT,
            context.dispatcher.open_datagram(session),
        ) => opened,
    };
    let mut transport = match opened {
        Ok(Ok(transport)) => {
            tracing::debug!(association_id, "TUN UDP outbound opened");
            transport
        }
        Ok(Err(error)) => return Err(dispatch_to_io(error)),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TUN UDP outbound open timed out",
            ));
        }
    };

    let mut quic_sniff = UdpQuicSniffState::new(new_sniffer);
    let mut ready = VecDeque::with_capacity(QUIC_SNIFF_READY_DATAGRAM_MAX);
    let mut first_response_logged = false;
    loop {
        let sniff_deadline = quic_sniff.next_deadline();
        let event = tokio::select! {
            biased;
            () = context.cancellation.cancelled() => AssociationEvent::Cancelled,
            () = wait_for_quic_sniff_deadline(sniff_deadline), if sniff_deadline.is_some() => {
                AssociationEvent::SniffDeadline
            }
            // Drain a ready response before accepting another datagram from
            // this same source. Fairness between the ordinary and DNS TUN
            // response queues is handled independently by `udp_loop`.
            datagram = transport.receive() => AssociationEvent::Outbound(datagram),
            () = std::future::ready(()), if !ready.is_empty() => AssociationEvent::ReadySend,
            datagram = inbound.recv() => AssociationEvent::Inbound(datagram),
        };
        match event {
            AssociationEvent::Cancelled | AssociationEvent::Inbound(None) => break,
            AssociationEvent::SniffDeadline => {
                append_ready_datagrams(&mut ready, quic_sniff.expire(TokioInstant::now()))?;
            }
            AssociationEvent::ReadySend => {
                let prepared = ready
                    .pop_front()
                    .expect("ready-send event requires a queued datagram");
                if !send_tun_udp_datagram(transport.as_mut(), prepared, context).await? {
                    break;
                }
            }
            AssociationEvent::Inbound(Some(datagram)) => {
                let sniff_quic = configured_quic_sniffing(
                    context.sniffer.as_deref(),
                    datagram.destination.port(),
                );
                let result = if sniff_quic {
                    quic_sniff.ingest_datagram(datagram, TokioInstant::now())
                } else {
                    QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram))
                };
                queue_quic_ingress_result(&mut ready, result)?;
            }
            AssociationEvent::Outbound(Err(error)) => {
                return Err(dispatch_to_io(error));
            }
            AssociationEvent::Outbound(Ok(datagram)) => {
                if !first_response_logged {
                    tracing::debug!(association_id, "TUN UDP received first outbound response");
                    first_response_logged = true;
                }
                let Destination::Ip(remote) = datagram.remote else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TUN XUDP response contained a domain source",
                    ));
                };
                let response = UdpDatagram::new(remote, source, datagram.payload);
                match try_queue_tun_udp_response(
                    &context.responses,
                    response,
                    &context.last_activity,
                    context.association_clock.now(),
                    &context.resource_stats,
                ) {
                    ResponseQueueResult::Queued => {}
                    ResponseQueueResult::Dropped => {}
                    ResponseQueueResult::Closed => {
                        tracing::debug!(association_id, "TUN UDP response channel closed");
                        break;
                    }
                }
            }
        }
    }
    match timeout(UDP_CLOSE_TIMEOUT, transport.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(
                association_id,
                error_code = error.diagnostic_code(),
                "TUN UDP outbound close failed"
            );
        }
        Err(_) => {
            tracing::warn!(
                association_id,
                error_code = "timed_out",
                "TUN UDP outbound close failed"
            );
        }
    }
    Ok(())
}

fn vcore_to_io(error: VCoreError) -> io::Error {
    match error {
        VCoreError::Io(error) => error,
        error => io::Error::other(error),
    }
}

fn netstack_to_io(error: NetStackError) -> io::Error {
    match error {
        NetStackError::Stopped => io::Error::new(io::ErrorKind::Interrupted, error),
        NetStackError::Backpressure => io::Error::new(io::ErrorKind::WouldBlock, error),
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn dispatch_to_io(error: DispatchError) -> io::Error {
    match error {
        DispatchError::NotAllowed => io::Error::from(io::ErrorKind::PermissionDenied),
        DispatchError::NetworkUnreachable => io::Error::from(io::ErrorKind::NetworkUnreachable),
        DispatchError::HostUnreachable => io::Error::from(io::ErrorKind::HostUnreachable),
        DispatchError::ConnectionRefused => io::Error::from(io::ErrorKind::ConnectionRefused),
        DispatchError::TimedOut => io::Error::from(io::ErrorKind::TimedOut),
        DispatchError::Other(message) => io::Error::other(message),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        os::fd::AsRawFd,
        os::unix::net::UnixDatagram,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::{Notify, mpsc},
    };

    use super::*;
    use crate::{
        config::{
            DnsConfig, DnsNameserver, DnsRoute, DnsTransport, PortRange, RuleAction, RuleKind,
            RuleSpec, SnifferConfig,
        },
        dispatch::{BoxStream, DatagramTransport},
        dns::{QueryType, build_query, synthesize_empty_response},
        platform::TunFd,
        routing::{EmptyGeoMatcher, ProxyDispatchers, RuleSet},
    };

    fn test_sniffer(
        http_ports: &[PortRange],
        tls_ports: &[PortRange],
        quic_ports: &[PortRange],
    ) -> Arc<SnifferConfig> {
        Arc::new(SnifferConfig {
            enable: true,
            http_ports: http_ports.into(),
            tls_ports: tls_ports.into(),
            quic_ports: quic_ports.into(),
        })
    }

    #[test]
    fn tun_netstack_resource_event_contract_is_stable() {
        assert_eq!(TUN_NETSTACK_STATS_INTERVAL, Duration::from_secs(30));
        assert_eq!(
            TUN_NETSTACK_STATS_PERIODIC_EVENT,
            "tun_netstack_stats_periodic"
        );
        assert_eq!(TUN_NETSTACK_STATS_FINAL_EVENT, "tun_netstack_stats_final");
    }

    #[test]
    fn configured_sniffer_selects_custom_http_and_tls_ports() {
        let config = test_sniffer(
            &[PortRange {
                start: 8_080,
                end: 8_088,
            }],
            &[PortRange {
                start: 8_443,
                end: 8_443,
            }],
            &[],
        );
        assert_eq!(
            configured_sniff_protocol(&config, 8_084),
            Some(SniffProtocol::Http)
        );
        assert_eq!(
            configured_sniff_protocol(&config, 8_443),
            Some(SniffProtocol::Tls)
        );
        assert_eq!(configured_sniff_protocol(&config, 80), None);
        assert_eq!(configured_sniff_protocol(&config, 443), None);
    }

    struct ScriptedQuicSniffer {
        outcomes: VecDeque<QuicSniffOutcome>,
        authentications: VecDeque<bool>,
        authenticated_initial_in_last_ingest: bool,
    }

    impl QuicSniffEngine for ScriptedQuicSniffer {
        fn ingest(&mut self, _packet: &[u8]) -> QuicSniffOutcome {
            self.authenticated_initial_in_last_ingest =
                self.authentications.pop_front().unwrap_or(true);
            self.outcomes
                .pop_front()
                .expect("scripted QUIC sniffer outcome exhausted")
        }

        fn authenticated_initial_in_last_ingest(&self) -> bool {
            self.authenticated_initial_in_last_ingest
        }
    }

    fn scripted_quic_state(
        scripts: Vec<Vec<QuicSniffOutcome>>,
    ) -> UdpQuicSniffState<ScriptedQuicSniffer, impl FnMut() -> ScriptedQuicSniffer> {
        let mut scripts = scripts
            .into_iter()
            .map(VecDeque::from)
            .collect::<VecDeque<_>>();
        UdpQuicSniffState::new(move || ScriptedQuicSniffer {
            outcomes: scripts
                .pop_front()
                .expect("scripted QUIC flow factory exhausted"),
            authentications: VecDeque::new(),
            authenticated_initial_in_last_ingest: false,
        })
    }

    fn scripted_quic_state_with_authentication(
        scripts: Vec<Vec<(QuicSniffOutcome, bool)>>,
    ) -> UdpQuicSniffState<ScriptedQuicSniffer, impl FnMut() -> ScriptedQuicSniffer> {
        let mut sniffers = scripts
            .into_iter()
            .map(|script| {
                let (outcomes, authentications) = script.into_iter().unzip();
                ScriptedQuicSniffer {
                    outcomes,
                    authentications,
                    authenticated_initial_in_last_ingest: false,
                }
            })
            .collect::<VecDeque<_>>();
        UdpQuicSniffState::new(move || {
            sniffers
                .pop_front()
                .expect("scripted QUIC flow factory exhausted")
        })
    }

    fn test_udp_datagram(
        source: SocketAddr,
        destination: SocketAddr,
        payload: &'static [u8],
    ) -> UdpDatagram {
        UdpDatagram::new(source, destination, Bytes::from_static(payload))
    }

    fn quic_connection_marker(destination_connection_id: &[u8]) -> Bytes {
        assert!((1..=20).contains(&destination_connection_id.len()));
        let mut datagram = vec![
            0xc0, // QUIC v1 long header, Initial packet.
            0x00,
            0x00,
            0x00,
            0x01,
            u8::try_from(destination_connection_id.len()).unwrap(),
        ];
        datagram.extend_from_slice(destination_connection_id);
        datagram.extend_from_slice(&[
            0x00, // Empty source connection ID.
            0x00, // Empty token.
            0x11, // One packet-number byte plus a 16-byte AEAD tag.
        ]);
        datagram.extend_from_slice(&[0; 17]);
        let datagram = Bytes::from(datagram);
        assert!(quic_connection_key(&datagram).is_some());
        datagram
    }

    fn quic_non_initial_marker(packet_type: u8, destination_connection_id: &[u8]) -> Bytes {
        assert!((1..=3).contains(&packet_type));
        assert!((1..=20).contains(&destination_connection_id.len()));
        let mut datagram = vec![
            0xc0 | (packet_type << 4),
            0x00,
            0x00,
            0x00,
            0x01,
            u8::try_from(destination_connection_id.len()).unwrap(),
        ];
        datagram.extend_from_slice(destination_connection_id);
        datagram.extend_from_slice(&[
            0x00, // Empty source connection ID.
            0x11, // Protected payload length.
        ]);
        datagram.extend_from_slice(&[0; 17]);
        let datagram = Bytes::from(datagram);
        assert!(quic_connection_key(&datagram).is_none());
        assert!(!quic_has_unsupported_version(&datagram));
        datagram
    }

    fn unsupported_quic_version_marker(destination_connection_id: &[u8]) -> Bytes {
        assert!((1..=20).contains(&destination_connection_id.len()));
        let mut datagram = vec![
            0xc0,
            0xfa,
            0xce,
            0xb0,
            0x0c,
            u8::try_from(destination_connection_id.len()).unwrap(),
        ];
        datagram.extend_from_slice(destination_connection_id);
        let datagram = Bytes::from(datagram);
        assert!(quic_connection_key(&datagram).is_none());
        assert!(quic_has_unsupported_version(&datagram));
        datagram
    }

    #[test]
    fn quic_fragmentation_sends_nothing_early_then_replays_every_datagram_in_order() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![vec![
            QuicSniffOutcome::NeedMoreData,
            QuicSniffOutcome::Matched("api.example.com".to_owned()),
        ]]);

        assert!(matches!(
            state.ingest_datagram(test_udp_datagram(source, destination, b"initial-one"), now,),
            QuicIngressResult::Buffered
        ));
        assert_eq!(state.pending_datagrams, 1);
        assert_eq!(state.pending_bytes, b"initial-one".len());

        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            test_udp_datagram(source, destination, b"initial-two"),
            now + Duration::from_millis(1),
        ) else {
            panic!("the completed ClientHello must release the buffered Initial flight");
        };
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(
            replay
                .iter()
                .map(|prepared| prepared.datagram.payload.as_ref())
                .collect::<Vec<_>>(),
            vec![b"initial-one".as_slice(), b"initial-two".as_slice()]
        );
        assert!(replay.iter().all(|prepared| {
            prepared.sniffed_domain.as_deref() == Some("api.example.com")
                && prepared.datagram.destination == destination
        }));

        let QuicIngressResult::Forward(next) = state.ingest_datagram(
            test_udp_datagram(source, destination, b"short-header"),
            now + Duration::from_millis(2),
        ) else {
            panic!("a resolved QUIC flow must forward later datagrams immediately");
        };
        assert_eq!(next.sniffed_domain.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn quic_completed_flow_lru_makes_room_for_a_fifth_sniffer() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destinations = (0..=QUIC_SNIFF_FLOW_MAX)
            .map(|index| {
                SocketAddr::new(
                    "198.51.100.20".parse().unwrap(),
                    443 + u16::try_from(index).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(
            (0..=QUIC_SNIFF_FLOW_MAX)
                .map(|index| {
                    vec![QuicSniffOutcome::Matched(format!(
                        "node-{index}.example.com"
                    ))]
                })
                .collect(),
        );

        for (index, destination) in destinations[..QUIC_SNIFF_FLOW_MAX].iter().enumerate() {
            let result = state.ingest_datagram(
                UdpDatagram::new(
                    source,
                    *destination,
                    quic_connection_marker(&[u8::try_from(index + 1).unwrap()]),
                ),
                now + Duration::from_millis(u64::try_from(index).unwrap()),
            );
            assert!(matches!(result, QuicIngressResult::Forward(_)));
        }
        assert_eq!(state.flows.len(), QUIC_SNIFF_FLOW_MAX);

        let touched = state.ingest_datagram(
            test_udp_datagram(source, destinations[0], b"short-header"),
            now + Duration::from_millis(10),
        );
        assert!(matches!(touched, QuicIngressResult::Forward(_)));

        let QuicIngressResult::Forward(fifth) = state.ingest_datagram(
            UdpDatagram::new(
                source,
                destinations[QUIC_SNIFF_FLOW_MAX],
                quic_connection_marker(b"fifth"),
            ),
            now + Duration::from_millis(11),
        ) else {
            panic!("a completed flow must be evicted so the fifth flow can be sniffed");
        };
        assert_eq!(fifth.sniffed_domain.as_deref(), Some("node-4.example.com"));
        assert_eq!(state.flows.len(), QUIC_SNIFF_FLOW_MAX);
        assert!(state.flows.contains_key(&destinations[0]));
        assert!(!state.flows.contains_key(&destinations[1]));
        assert!(state.flows.contains_key(&destinations[2]));
        assert!(state.flows.contains_key(&destinations[3]));
        assert!(state.flows.contains_key(&destinations[4]));
    }

    #[test]
    fn quic_new_dcid_replaces_a_matched_domain_for_the_same_destination() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![
            vec![QuicSniffOutcome::Matched("old.example.com".to_owned())],
            vec![QuicSniffOutcome::Matched("new.example.com".to_owned())],
        ]);

        let QuicIngressResult::Forward(old) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"old")),
            now,
        ) else {
            panic!("the first QUIC connection must be sniffed");
        };
        assert_eq!(old.sniffed_domain.as_deref(), Some("old.example.com"));

        let QuicIngressResult::Forward(new) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"new")),
            now + Duration::from_millis(1),
        ) else {
            panic!("a new DCID must create a fresh QUIC sniffer");
        };
        assert_eq!(new.sniffed_domain.as_deref(), Some("new.example.com"));

        let QuicIngressResult::Forward(short_header) = state.ingest_datagram(
            test_udp_datagram(source, destination, b"short-header"),
            now + Duration::from_millis(2),
        ) else {
            panic!("the replacement domain must be retained for short-header traffic");
        };
        assert_eq!(
            short_header.sniffed_domain.as_deref(),
            Some("new.example.com")
        );
    }

    #[test]
    fn quic_unauthenticated_new_dcid_keeps_the_completed_domain_without_waiting() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state_with_authentication(vec![
            vec![(
                QuicSniffOutcome::Matched("stable.example.com".to_owned()),
                true,
            )],
            vec![(QuicSniffOutcome::NeedMoreData, false)],
        ]);

        let QuicIngressResult::Forward(first) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"old")),
            now,
        ) else {
            panic!("the first QUIC connection must be sniffed");
        };
        assert_eq!(first.sniffed_domain.as_deref(), Some("stable.example.com"));

        let QuicIngressResult::Forward(candidate) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"new")),
            now + Duration::from_millis(1),
        ) else {
            panic!("an unauthenticated candidate must not enter the pending state");
        };
        assert_eq!(
            candidate.sniffed_domain.as_deref(),
            Some("stable.example.com")
        );
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);

        let QuicIngressResult::Forward(short_header) = state.ingest_datagram(
            test_udp_datagram(source, destination, b"short-header"),
            now + Duration::from_millis(2),
        ) else {
            panic!("the authenticated completed hint must be retained");
        };
        assert_eq!(
            short_header.sniffed_domain.as_deref(),
            Some("stable.example.com")
        );
    }

    #[test]
    fn quic_pending_flow_accepts_a_new_header_dcid_authenticated_by_its_old_keys() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state_with_authentication(vec![vec![
            (QuicSniffOutcome::NeedMoreData, true),
            (
                QuicSniffOutcome::Matched("same-connection.example.com".to_owned()),
                true,
            ),
        ]]);

        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-a")),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-b")),
            now + Duration::from_millis(1),
        ) else {
            panic!("old Initial keys must be tried before treating a new DCID as a new flow");
        };
        assert_eq!(replay.len(), 2);
        assert!(replay.iter().all(|prepared| {
            prepared.sniffed_domain.as_deref() == Some("same-connection.example.com")
        }));
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }

    #[test]
    fn quic_pending_flow_keeps_old_state_when_neither_key_authenticates_a_candidate() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state_with_authentication(vec![
            vec![
                (QuicSniffOutcome::NeedMoreData, true),
                (QuicSniffOutcome::NotMatched, false),
                (
                    QuicSniffOutcome::Matched("old-flow.example.com".to_owned()),
                    true,
                ),
            ],
            vec![(QuicSniffOutcome::NeedMoreData, false)],
        ]);

        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-a")),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Forward(unverified) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-b")),
            now + Duration::from_millis(1),
        ) else {
            panic!("an unverified candidate must fail open independently");
        };
        assert!(unverified.sniffed_domain.is_none());
        assert_eq!(state.pending_datagrams, 1);

        let QuicIngressResult::Replay(old_flow) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-a")),
            now + Duration::from_millis(2),
        ) else {
            panic!("the old pending parser and buffered flight must be retained");
        };
        assert_eq!(old_flow.len(), 2);
        assert!(
            old_flow
                .iter()
                .all(|prepared| prepared.sniffed_domain.as_deref() == Some("old-flow.example.com"))
        );
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }

    #[test]
    fn quic_zero_rtt_and_handshake_dcid_changes_do_not_reset_a_completed_hint() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![vec![QuicSniffOutcome::Matched(
            "stable.example.com".to_owned(),
        )]]);

        let QuicIngressResult::Forward(initial) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"initial")),
            now,
        ) else {
            panic!("the Initial must establish a completed hint");
        };
        assert_eq!(
            initial.sniffed_domain.as_deref(),
            Some("stable.example.com")
        );

        for (index, datagram) in [
            quic_non_initial_marker(1, b"zero-rtt"),
            quic_non_initial_marker(2, b"handshake"),
        ]
        .into_iter()
        .enumerate()
        {
            let QuicIngressResult::Forward(forwarded) = state.ingest_datagram(
                UdpDatagram::new(source, destination, datagram),
                now + Duration::from_millis(u64::try_from(index + 1).unwrap()),
            ) else {
                panic!("a non-Initial long header must not trigger a new sniffer");
            };
            assert_eq!(
                forwarded.sniffed_domain.as_deref(),
                Some("stable.example.com")
            );
        }
    }

    #[test]
    fn unsupported_quic_version_clears_completed_hint_and_releases_pending_flight() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let completed_destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let pending_destination: SocketAddr = "198.51.100.21:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![
            vec![QuicSniffOutcome::Matched(
                "must-not-leak.example.com".to_owned(),
            )],
            vec![QuicSniffOutcome::NeedMoreData],
        ]);

        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(
                    source,
                    completed_destination,
                    quic_connection_marker(b"completed"),
                ),
                now,
            ),
            QuicIngressResult::Forward(_)
        ));
        let QuicIngressResult::Forward(unsupported) = state.ingest_datagram(
            UdpDatagram::new(
                source,
                completed_destination,
                unsupported_quic_version_marker(b"unknown"),
            ),
            now + Duration::from_millis(1),
        ) else {
            panic!("an unsupported version must fail open without waiting");
        };
        assert!(unsupported.sniffed_domain.is_none());
        let QuicIngressResult::Forward(short_header) = state.ingest_datagram(
            test_udp_datagram(source, completed_destination, b"short-header"),
            now + Duration::from_millis(2),
        ) else {
            panic!("the stale completed hint must remain cleared");
        };
        assert!(short_header.sniffed_domain.is_none());

        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(
                    source,
                    pending_destination,
                    quic_connection_marker(b"pending"),
                ),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            UdpDatagram::new(
                source,
                pending_destination,
                unsupported_quic_version_marker(b"unknown"),
            ),
            now + Duration::from_millis(1),
        ) else {
            panic!("an unsupported version must release a pending flight");
        };
        assert_eq!(replay.len(), 2);
        assert!(
            replay
                .iter()
                .all(|prepared| prepared.sniffed_domain.is_none())
        );
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }

    #[test]
    fn quic_new_dcid_retries_sniffing_after_a_no_domain_result() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![
            vec![QuicSniffOutcome::NotMatched],
            vec![QuicSniffOutcome::Matched(
                "recovered.example.com".to_owned(),
            )],
        ]);

        let QuicIngressResult::Forward(first) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"old")),
            now,
        ) else {
            panic!("the first QUIC connection must fail open");
        };
        assert!(first.sniffed_domain.is_none());

        let QuicIngressResult::Forward(recovered) = state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"new")),
            now + Duration::from_millis(1),
        ) else {
            panic!("a new DCID must retry sniffing after a terminal result");
        };
        assert_eq!(
            recovered.sniffed_domain.as_deref(),
            Some("recovered.example.com")
        );
    }

    #[test]
    fn quic_new_dcid_releases_an_old_pending_flight_before_the_new_connection() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let old_payload = quic_connection_marker(b"old");
        let new_payload = quic_connection_marker(b"new");
        let mut state = scripted_quic_state_with_authentication(vec![
            vec![
                (QuicSniffOutcome::NeedMoreData, true),
                (QuicSniffOutcome::NotMatched, false),
            ],
            vec![(
                QuicSniffOutcome::Matched("new.example.com".to_owned()),
                true,
            )],
        ]);

        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(source, destination, old_payload.clone()),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            UdpDatagram::new(source, destination, new_payload.clone()),
            now + Duration::from_millis(1),
        ) else {
            panic!("a new DCID must release the stale flight before forwarding itself");
        };
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].datagram.payload, old_payload);
        assert!(replay[0].sniffed_domain.is_none());
        assert_eq!(replay[1].datagram.payload, new_payload);
        assert_eq!(replay[1].sniffed_domain.as_deref(), Some("new.example.com"));
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }

    #[tokio::test]
    async fn quic_association_holds_the_first_fragment_then_sends_the_original_flight() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let datagrams = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Notify::new());
        let dispatcher = Arc::new(RecordingUdpDispatcher {
            datagrams: datagrams.clone(),
            sent: sent.clone(),
        });
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let (responses, _responses_rx) = mpsc::channel(4);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let mut scripts = VecDeque::from([VecDeque::from([
            QuicSniffOutcome::NeedMoreData,
            QuicSniffOutcome::Matched("api.example.com".to_owned()),
        ])]);
        let task = tokio::spawn(async move {
            run_udp_association_inner_with_quic_factory(
                &mut inbound_rx,
                &UdpAssociationTaskContext {
                    association_id: 1,
                    source,
                    responses,
                    dispatcher,
                    resource_stats: RuntimeResourceStats::new("tun_runtime_quic_test"),
                    association_clock: AssociationClock::realtime(),
                    last_activity: Arc::new(AtomicU64::new(0)),
                    sniffer: Some(test_sniffer(
                        &[],
                        &[],
                        &[PortRange {
                            start: 443,
                            end: 443,
                        }],
                    )),
                    cancellation: child,
                },
                move || ScriptedQuicSniffer {
                    outcomes: scripts
                        .pop_front()
                        .expect("scripted QUIC flow factory exhausted"),
                    authentications: VecDeque::new(),
                    authenticated_initial_in_last_ingest: false,
                },
            )
            .await
        });

        inbound_tx
            .send(test_udp_datagram(source, destination, b"initial-one"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(30), sent.notified())
                .await
                .is_err(),
            "the first incomplete Initial was sent before sniffing completed"
        );
        assert!(datagrams.lock().unwrap().is_empty());

        inbound_tx
            .send(test_udp_datagram(source, destination, b"initial-two"))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while datagrams.lock().unwrap().len() != 2 {
                sent.notified().await;
            }
        })
        .await
        .expect("the completed QUIC Initial flight was not replayed");
        {
            let recorded = datagrams.lock().unwrap();
            assert_eq!(
                recorded
                    .iter()
                    .map(|datagram| datagram.payload.as_ref())
                    .collect::<Vec<_>>(),
                vec![b"initial-one".as_slice(), b"initial-two".as_slice()]
            );
            assert!(recorded.iter().all(|datagram| {
                datagram.remote == Destination::Ip(destination)
                    && datagram.sniffed_domain.as_deref() == Some("api.example.com")
            }));
        }

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("QUIC association did not stop")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_ready_response_is_processed_before_the_next_replay_send_blocks() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let send_count = Arc::new(AtomicUsize::new(0));
        let blocked_send_started = Arc::new(Notify::new());
        let dispatcher = Arc::new(ReplayFairDispatcher {
            response: Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"ready-response"),
                sniffed_domain: None,
            },
            send_count: send_count.clone(),
            blocked_send_started: blocked_send_started.clone(),
        });
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let (responses, mut responses_rx) = mpsc::channel(4);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let mut scripts = VecDeque::from([VecDeque::from([
            QuicSniffOutcome::NeedMoreData,
            QuicSniffOutcome::Matched("api.example.com".to_owned()),
        ])]);
        let task = tokio::spawn(async move {
            run_udp_association_inner_with_quic_factory(
                &mut inbound_rx,
                &UdpAssociationTaskContext {
                    association_id: 1,
                    source,
                    responses,
                    dispatcher,
                    resource_stats: RuntimeResourceStats::new("tun_runtime_quic_fairness_test"),
                    association_clock: AssociationClock::realtime(),
                    last_activity: Arc::new(AtomicU64::new(0)),
                    sniffer: Some(test_sniffer(
                        &[],
                        &[],
                        &[PortRange {
                            start: 443,
                            end: 443,
                        }],
                    )),
                    cancellation: child,
                },
                move || ScriptedQuicSniffer {
                    outcomes: scripts
                        .pop_front()
                        .expect("scripted QUIC flow factory exhausted"),
                    authentications: VecDeque::new(),
                    authenticated_initial_in_last_ingest: false,
                },
            )
            .await
        });

        let marker = quic_connection_marker(b"flow");
        inbound_tx
            .send(UdpDatagram::new(source, destination, marker.clone()))
            .await
            .unwrap();
        inbound_tx
            .send(UdpDatagram::new(source, destination, marker))
            .await
            .unwrap();

        let response = timeout(Duration::from_secs(1), responses_rx.recv())
            .await
            .expect("a blocked second replay send starved the ready response")
            .expect("response channel closed");
        assert_eq!(&response.payload[..], b"ready-response");
        timeout(Duration::from_secs(1), blocked_send_started.notified())
            .await
            .expect("the second replay send did not enter its blocked state");
        assert_eq!(send_count.load(Ordering::Relaxed), 2);

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("QUIC association did not stop")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn quic_failure_and_timeout_fail_open_with_exact_buffered_payloads() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let failed_destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let timed_out_destination: SocketAddr = "198.51.100.21:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![
            vec![QuicSniffOutcome::NeedMoreData, QuicSniffOutcome::NotMatched],
            vec![QuicSniffOutcome::NeedMoreData],
        ]);

        assert!(matches!(
            state.ingest_datagram(
                test_udp_datagram(source, failed_destination, b"failed-one"),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Replay(failed) = state.ingest_datagram(
            test_udp_datagram(source, failed_destination, b"failed-two"),
            now + Duration::from_millis(1),
        ) else {
            panic!("a parse failure must release the original datagrams");
        };
        assert_eq!(
            failed
                .iter()
                .map(|prepared| prepared.datagram.payload.as_ref())
                .collect::<Vec<_>>(),
            vec![b"failed-one".as_slice(), b"failed-two".as_slice()]
        );
        assert!(
            failed
                .iter()
                .all(|prepared| prepared.sniffed_domain.is_none())
        );

        assert!(matches!(
            state.ingest_datagram(
                test_udp_datagram(source, timed_out_destination, b"timed-out"),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        assert!(
            state
                .expire(now + QUIC_SNIFF_TIMEOUT - Duration::from_millis(1))
                .is_empty()
        );
        let timed_out = state.expire(now + QUIC_SNIFF_TIMEOUT);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(&timed_out[0].datagram.payload[..], b"timed-out");
        assert!(timed_out[0].sniffed_domain.is_none());
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }

    #[test]
    fn quic_ech_and_parser_limit_release_buffered_datagrams_without_a_domain() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let now = TokioInstant::now();
        for (index, terminal) in [
            QuicSniffOutcome::EchExtensionPresent,
            QuicSniffOutcome::LimitReached,
        ]
        .into_iter()
        .enumerate()
        {
            let destination = SocketAddr::new(
                "198.51.100.20".parse().unwrap(),
                443 + u16::try_from(index).unwrap(),
            );
            let mut state =
                scripted_quic_state(vec![vec![QuicSniffOutcome::NeedMoreData, terminal]]);
            assert!(matches!(
                state.ingest_datagram(test_udp_datagram(source, destination, b"initial-one"), now,),
                QuicIngressResult::Buffered
            ));
            let QuicIngressResult::Replay(replay) =
                state.ingest_datagram(test_udp_datagram(source, destination, b"initial-two"), now)
            else {
                panic!("a terminal QUIC outcome must release buffered datagrams");
            };
            assert_eq!(replay.len(), 2);
            assert!(
                replay
                    .iter()
                    .all(|prepared| prepared.sniffed_domain.is_none())
            );
        }
    }

    #[test]
    fn quic_pending_datagram_and_flow_tables_are_hard_bounded() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![vec![
            QuicSniffOutcome::NeedMoreData;
            QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1
        ]]);
        for index in 0..QUIC_SNIFF_PENDING_DATAGRAM_MAX {
            assert!(matches!(
                state.ingest_datagram(
                    UdpDatagram::new(source, destination, vec![u8::try_from(index).unwrap()]),
                    now,
                ),
                QuicIngressResult::Buffered
            ));
        }
        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            UdpDatagram::new(source, destination, Bytes::from_static(b"overflow")),
            now,
        ) else {
            panic!("the ninth pending datagram must fail open");
        };
        assert_eq!(replay.len(), QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1);
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);

        let scripts = (0..QUIC_SNIFF_FLOW_MAX)
            .map(|_| vec![QuicSniffOutcome::NeedMoreData])
            .collect();
        let mut state = scripted_quic_state(scripts);
        for index in 0..QUIC_SNIFF_FLOW_MAX {
            let destination = SocketAddr::new(
                "198.51.100.20".parse().unwrap(),
                443 + u16::try_from(index).unwrap(),
            );
            assert!(matches!(
                state.ingest_datagram(test_udp_datagram(source, destination, b"pending"), now,),
                QuicIngressResult::Buffered
            ));
        }
        let overflow_destination: SocketAddr = "198.51.100.30:8443".parse().unwrap();
        let QuicIngressResult::Forward(overflow) = state.ingest_datagram(
            test_udp_datagram(source, overflow_destination, b"fifth-flow"),
            now,
        ) else {
            panic!("a fifth QUIC flow must fail open without creating a parser");
        };
        assert!(overflow.sniffed_domain.is_none());
        assert_eq!(state.flows.len(), QUIC_SNIFF_FLOW_MAX);
    }

    #[test]
    fn quic_pending_byte_budget_accepts_32_kib_and_replays_the_overflow_datagram() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![vec![
            QuicSniffOutcome::NeedMoreData,
            QuicSniffOutcome::NeedMoreData,
        ]]);

        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(
                    source,
                    destination,
                    vec![0xaa; QUIC_SNIFF_PENDING_BYTES_MAX],
                ),
                now,
            ),
            QuicIngressResult::Buffered
        ));
        assert_eq!(state.pending_datagrams, 1);
        assert_eq!(state.pending_bytes, QUIC_SNIFF_PENDING_BYTES_MAX);

        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            UdpDatagram::new(source, destination, Bytes::from_static(b"x")),
            now,
        ) else {
            panic!("a datagram above the aggregate byte budget must fail open");
        };
        assert_eq!(replay.len(), 2);
        assert_eq!(
            replay[0].datagram.payload.len(),
            QUIC_SNIFF_PENDING_BYTES_MAX
        );
        assert_eq!(&replay[1].datagram.payload[..], b"x");
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }

    #[test]
    fn quic_flow_state_is_isolated_by_destination_and_unconfigured_ports_are_skipped() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination_a: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let destination_b: SocketAddr = "198.51.100.21:443".parse().unwrap();
        let now = TokioInstant::now();
        let mut state = scripted_quic_state(vec![
            vec![
                QuicSniffOutcome::NeedMoreData,
                QuicSniffOutcome::Matched("a.example.com".to_owned()),
            ],
            vec![QuicSniffOutcome::Matched("b.example.com".to_owned())],
        ]);

        assert!(matches!(
            state.ingest_datagram(test_udp_datagram(source, destination_a, b"a-one"), now,),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Forward(b) =
            state.ingest_datagram(test_udp_datagram(source, destination_b, b"b-one"), now)
        else {
            panic!("one destination must not wait for another destination");
        };
        assert_eq!(b.sniffed_domain.as_deref(), Some("b.example.com"));
        let QuicIngressResult::Replay(a) =
            state.ingest_datagram(test_udp_datagram(source, destination_a, b"a-two"), now)
        else {
            panic!("the first destination must retain its independent parser");
        };
        assert!(
            a.iter()
                .all(|prepared| prepared.sniffed_domain.as_deref() == Some("a.example.com"))
        );

        let config = test_sniffer(
            &[],
            &[],
            &[PortRange {
                start: 443,
                end: 443,
            }],
        );
        assert!(configured_quic_sniffing(Some(&config), 443));
        assert!(!configured_quic_sniffing(Some(&config), 8_443));
        assert!(!configured_quic_sniffing(None, 443));
    }

    #[test]
    fn tun_dns_ingress_capacity_is_an_independent_queue_boundary() {
        let tun = ResourceLimits::tun();
        assert_eq!(tun_udp_ingress_queue_capacity(tun, false), 128);
        assert_eq!(tun_udp_ingress_queue_capacity(tun, true), 128);
        let altered = ResourceLimits {
            tun_dns_ingress_queue_capacity: 96,
            ..tun
        };
        assert_eq!(tun_udp_ingress_queue_capacity(altered, true), 96);
        assert_eq!(
            tun_udp_ingress_queue_capacity(ResourceLimits::default(), true),
            ResourceLimits::default().tun_dns_ingress_queue_capacity
        );
    }

    #[test]
    fn tun_netstack_keeps_queue_and_per_flow_bounds_without_a_flow_count_ceiling() {
        let limits = ResourceLimits::tun();
        let config = tun_netstack_config(limits, true, false);

        assert_eq!(config.tcp_accept_queue, limits.event_queue_capacity);
        assert_eq!(
            config.tcp_buffer_per_direction,
            limits.tcp_buffer_per_direction
        );
        assert_eq!(config.mtu, 1_500);
        assert_eq!(limits.max_datagram_size, 65_535);
    }

    fn test_association(
        generation: u64,
        last_activity: u64,
    ) -> (
        UdpAssociation,
        mpsc::Receiver<UdpDatagram>,
        CancellationToken,
    ) {
        let (sender, receiver) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        (
            UdpAssociation {
                generation,
                sender,
                cancellation: cancellation.clone(),
                last_activity: Arc::new(AtomicU64::new(last_activity)),
            },
            receiver,
            cancellation,
        )
    }

    #[test]
    fn stale_association_completion_cannot_remove_a_replacement_generation() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let (replacement, _receiver, _) = test_association(2, 0);
        let mut associations = HashMap::from([(source, replacement)]);

        assert!(remove_completed_association(&mut associations, source, 1).is_none());
        assert_eq!(associations.get(&source).unwrap().generation, 2);
        assert!(remove_completed_association(&mut associations, source, 2).is_some());
        assert!(associations.is_empty());
    }

    #[test]
    fn association_activity_clock_refreshes_only_successfully_queued_work() {
        let tick = Arc::new(AtomicU64::new(100));
        let clock = AssociationClock::injected(tick.clone());
        let (association, mut receiver, _) = test_association(1, 5);
        let stats = RuntimeResourceStats::new("tun_runtime_test");
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();

        assert!(matches!(
            try_queue_association_input(
                &association,
                UdpDatagram::new(source, destination, b"queued".as_slice()),
                clock.now(),
                1,
                &stats,
            ),
            AssociationInputResult::Queued
        ));
        assert_eq!(association.last_activity.load(Ordering::Acquire), 100);

        tick.store(110, Ordering::Release);
        assert!(matches!(
            try_queue_association_input(
                &association,
                UdpDatagram::new(source, destination, b"full".as_slice()),
                clock.now(),
                1,
                &stats,
            ),
            AssociationInputResult::Full
        ));
        assert_eq!(association.last_activity.load(Ordering::Acquire), 100);
        assert_eq!(stats.snapshot().udp_queue_drops, 1);

        receiver.try_recv().unwrap();
        drop(receiver);
        tick.store(120, Ordering::Release);
        assert!(matches!(
            try_queue_association_input(
                &association,
                UdpDatagram::new(source, destination, b"closed".as_slice()),
                clock.now(),
                1,
                &stats,
            ),
            AssociationInputResult::Closed
        ));
        assert_eq!(association.last_activity.load(Ordering::Acquire), 100);
    }

    #[test]
    fn periodic_cleanup_removes_expired_and_closed_but_preserves_active_entries() {
        let now = 100;
        let expired_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let closed_source: SocketAddr = "192.0.2.11:12001".parse().unwrap();
        let active_source: SocketAddr = "192.0.2.12:12002".parse().unwrap();
        let (expired, _expired_receiver, expired_cancellation) = test_association(1, 70);
        let (closed, closed_receiver, closed_cancellation) = test_association(2, 99);
        let (active, _active_receiver, _) = test_association(3, 80);
        drop(closed_receiver);
        let mut associations = HashMap::from([
            (expired_source, expired),
            (closed_source, closed),
            (active_source, active),
        ]);

        let removed = take_expired_or_closed_associations(&mut associations, now);
        assert_eq!(removed.len(), 2);
        assert!(associations.contains_key(&active_source));
        assert!(!expired_cancellation.is_cancelled());
        assert!(!closed_cancellation.is_cancelled());
        cancel_removed_associations(removed);
        assert!(expired_cancellation.is_cancelled());
        assert!(closed_cancellation.is_cancelled());
    }

    #[derive(Default)]
    struct MockDispatcher {
        tcp_sessions: Mutex<Vec<StreamSession>>,
        udp_sessions: Mutex<Vec<DatagramSession>>,
        tcp_called: Notify,
    }

    #[async_trait]
    impl Dispatcher for MockDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_sessions.lock().unwrap().push(session);
            self.tcp_called.notify_one();
            let (client, mut server) = tokio::io::duplex(1_024);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 256];
                while let Ok(size) = server.read(&mut buffer).await {
                    if size == 0 || server.write_all(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_sessions.lock().unwrap().push(session);
            Ok(Box::new(EchoDatagrams::new()))
        }
    }

    struct EchoDatagrams {
        sender: mpsc::Sender<Datagram>,
        receiver: mpsc::Receiver<Datagram>,
    }

    struct BlockingDispatcher {
        send_started: Arc<Notify>,
        send_count: Arc<AtomicUsize>,
        open_count: Arc<AtomicUsize>,
    }

    struct RecordingUdpDispatcher {
        datagrams: Arc<Mutex<Vec<Datagram>>>,
        sent: Arc<Notify>,
    }

    struct RecordingUdpTransport {
        datagrams: Arc<Mutex<Vec<Datagram>>>,
        sent: Arc<Notify>,
    }

    struct ReplayFairDispatcher {
        response: Datagram,
        send_count: Arc<AtomicUsize>,
        blocked_send_started: Arc<Notify>,
    }

    struct ReplayFairDatagrams {
        response: Option<Datagram>,
        send_count: Arc<AtomicUsize>,
        blocked_send_started: Arc<Notify>,
    }

    #[async_trait]
    impl Dispatcher for RecordingUdpDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused TCP path".to_owned()))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Ok(Box::new(RecordingUdpTransport {
                datagrams: self.datagrams.clone(),
                sent: self.sent.clone(),
            }))
        }
    }

    #[async_trait]
    impl DatagramTransport for RecordingUdpTransport {
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            self.datagrams.lock().unwrap().push(datagram);
            self.sent.notify_one();
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl Dispatcher for ReplayFairDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused TCP path".to_owned()))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Ok(Box::new(ReplayFairDatagrams {
                response: Some(self.response.clone()),
                send_count: self.send_count.clone(),
                blocked_send_started: self.blocked_send_started.clone(),
            }))
        }
    }

    #[async_trait]
    impl DatagramTransport for ReplayFairDatagrams {
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            let send_index = self.send_count.fetch_add(1, Ordering::Relaxed);
            if send_index == 0 {
                return Ok(());
            }
            self.blocked_send_started.notify_one();
            std::future::pending().await
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if self.send_count.load(Ordering::Relaxed) != 0
                && let Some(response) = self.response.take()
            {
                return Ok(response);
            }
            std::future::pending().await
        }
    }

    #[async_trait]
    impl Dispatcher for BlockingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused TCP path".to_owned()))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.open_count.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(BlockingDatagrams {
                send_started: self.send_started.clone(),
                send_count: Some(self.send_count.clone()),
            }))
        }
    }

    struct BlockingDatagrams {
        send_started: Arc<Notify>,
        send_count: Option<Arc<AtomicUsize>>,
    }

    #[derive(Default)]
    struct DnsReplyDispatcher {
        udp_sessions: Mutex<Vec<DatagramSession>>,
    }

    #[async_trait]
    impl Dispatcher for DnsReplyDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused TCP path".to_owned()))
        }

        async fn open_datagram(
            &self,
            session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_sessions.lock().unwrap().push(session);
            Ok(Box::new(DnsReplyDatagrams::new()))
        }
    }

    struct DnsReplyDatagrams {
        sender: mpsc::Sender<Datagram>,
        receiver: mpsc::Receiver<Datagram>,
    }

    impl DnsReplyDatagrams {
        fn new() -> Self {
            let (sender, receiver) = mpsc::channel(1);
            Self { sender, receiver }
        }
    }

    #[async_trait]
    impl DatagramTransport for DnsReplyDatagrams {
        async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
            let query = classify_query(&datagram.payload)
                .map_err(|error| DispatchError::Other(error.to_string()))?;
            datagram.payload = synthesize_empty_response(&query, 0)
                .map_err(|error| DispatchError::Other(error.to_string()))?
                .into();
            self.sender
                .send(datagram)
                .await
                .map_err(|_| DispatchError::Other("DNS reply transport stopped".to_owned()))
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| DispatchError::Other("DNS reply transport stopped".to_owned()))
        }
    }

    struct ResponseFirstDispatcher {
        response: Datagram,
    }

    struct SourceSelectiveDispatcher {
        blocked_source: SocketAddr,
        send_started: Arc<Notify>,
    }

    #[async_trait]
    impl Dispatcher for ResponseFirstDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused TCP path".to_owned()))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Ok(Box::new(ResponseFirstDatagrams {
                response: Some(self.response.clone()),
            }))
        }
    }

    #[async_trait]
    impl Dispatcher for SourceSelectiveDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused TCP path".to_owned()))
        }

        async fn open_datagram(
            &self,
            session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            if session.source == self.blocked_source {
                Ok(Box::new(BlockingDatagrams {
                    send_started: self.send_started.clone(),
                    send_count: None,
                }))
            } else {
                Ok(Box::new(EchoDatagrams::new()))
            }
        }
    }

    struct ResponseFirstDatagrams {
        response: Option<Datagram>,
    }

    #[async_trait]
    impl DatagramTransport for ResponseFirstDatagrams {
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            std::future::pending().await
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if let Some(response) = self.response.take() {
                return Ok(response);
            }
            std::future::pending().await
        }
    }

    #[async_trait]
    impl DatagramTransport for BlockingDatagrams {
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            if let Some(send_count) = &self.send_count {
                send_count.fetch_add(1, Ordering::Relaxed);
            }
            self.send_started.notify_one();
            std::future::pending().await
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }

    impl EchoDatagrams {
        fn new() -> Self {
            let (sender, receiver) = mpsc::channel(1);
            Self { sender, receiver }
        }
    }

    #[async_trait]
    impl DatagramTransport for EchoDatagrams {
        async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
            if datagram.payload.as_ref() == b"oversize-response" {
                datagram.payload = Bytes::from(vec![0_u8; TUN_MTU]);
            }
            self.sender
                .send(datagram)
                .await
                .map_err(|_| DispatchError::Other("echo transport stopped".to_owned()))
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| DispatchError::Other("echo transport stopped".to_owned()))
        }
    }

    fn test_runtime_dns(dispatcher: Arc<dyn Dispatcher>) -> Arc<RuntimeDns> {
        let config = DnsConfig {
            enable: true,
            ipv6: true,
            nameservers: vec![DnsNameserver {
                transport: DnsTransport::Udp,
                address: Ipv4Addr::new(198, 51, 100, 53).into(),
                port: 53,
                route: DnsRoute::Direct,
            }],
            nameserver_policies: Vec::new(),
        };
        let proxies = ProxyDispatchers::new(vec![dispatcher.clone()]).unwrap();
        let rules = RuleSet::compile(vec![RuleSpec {
            kind: RuleKind::Match,
            action: RuleAction::Direct,
            no_resolve: false,
        }])
        .unwrap();
        let limits = ResourceLimits::default();
        Arc::new(RuntimeDns::new_routed_proxies_with_cache_limits(
            &config,
            proxies,
            dispatcher,
            rules,
            Arc::new(EmptyGeoMatcher),
            limits.dns_address_cache_entries,
            limits.dns_redir_host_entries,
        ))
    }

    #[tokio::test]
    async fn synthetic_fd_with_dns_disabled_dispatches_tcp_and_reuses_udp_association() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let dispatcher = Arc::new(MockDispatcher::default());
        let limits = ResourceLimits {
            packet_queue_capacity: 8,
            event_queue_capacity: 4,
            tun_max_datagram_size: TUN_MTU,
            ..ResourceLimits::default()
        };
        let runtime = TunRuntime::new(
            tun,
            limits,
            dispatcher.clone(),
            None,
            false,
            Some(test_sniffer(
                &[PortRange {
                    start: 8_080,
                    end: 8_080,
                }],
                &[],
                &[],
            )),
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));

        let udp_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let udp_destination: SocketAddr = "198.51.100.20:53".parse().unwrap();

        let mut oversized_ingress = vec![0_u8; TUN_MTU + 1];
        oversized_ingress[0] = 0x45;
        peer.send(&oversized_ingress).await.unwrap();

        peer.send(&build_udp(
            udp_source,
            udp_destination,
            b"oversize-response",
        ))
        .await
        .unwrap();
        let mut dropped = [0_u8; TUN_MTU];
        assert!(
            timeout(Duration::from_millis(100), peer.recv(&mut dropped))
                .await
                .is_err(),
            "oversized UDP response unexpectedly reached TUN",
        );

        for destination in ["198.51.100.20:53", "203.0.113.30:443"] {
            let destination: SocketAddr = destination.parse().unwrap();
            peer.send(&build_udp(udp_source, destination, b"query"))
                .await
                .unwrap();
            let mut response = [0_u8; TUN_MTU];
            let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
                .await
                .expect("UDP response timed out")
                .unwrap();
            assert_udp_response(&response[..size], destination, udp_source, b"query");
        }
        assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
        assert_eq!(
            dispatcher.udp_sessions.lock().unwrap()[0],
            DatagramSession::new(InboundKind::Tun, udp_source)
        );

        let tcp_source: SocketAddr = "192.0.2.11:13000".parse().unwrap();
        let tcp_destination: SocketAddr = "198.51.100.21:8080".parse().unwrap();
        peer.send(&build_tcp_syn(tcp_source, tcp_destination))
            .await
            .unwrap();
        let mut syn_ack = [0_u8; TUN_MTU];
        let size = timeout(Duration::from_secs(2), peer.recv(&mut syn_ack))
            .await
            .expect("TCP SYN-ACK timed out")
            .unwrap();
        assert!(size >= 40);
        assert_eq!(syn_ack[20 + 13] & 0x12, 0x12);
        let server_sequence = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
        let request = b"GET / HTTP/1.1\r\nHost: Sniff.Example.COM\r\n\r\n";
        peer.send(&build_tcp_segment(
            tcp_source,
            tcp_destination,
            2,
            server_sequence.wrapping_add(1),
            0x18,
            request,
        ))
        .await
        .unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                if !dispatcher.tcp_sessions.lock().unwrap().is_empty() {
                    break;
                }
                dispatcher.tcp_called.notified().await;
            }
        })
        .await
        .expect("TCP dispatcher was not called");
        assert_eq!(
            dispatcher.tcp_sessions.lock().unwrap()[0],
            StreamSession {
                inbound: InboundKind::Tun,
                source: tcp_source,
                destination: Destination::Ip(tcp_destination),
                sniffed_domain: Some("sniff.example.com".to_owned()),
            }
        );
        let echoed = timeout(Duration::from_secs(2), async {
            let mut echoed = Vec::with_capacity(request.len());
            while echoed.len() < request.len() {
                let size = peer.recv(&mut syn_ack).await.unwrap();
                if size < 40 || syn_ack[9] != 6 {
                    continue;
                }
                let ip_header_length = usize::from(syn_ack[0] & 0x0f) * 4;
                let tcp_header_length = usize::from(syn_ack[ip_header_length + 12] >> 4) * 4;
                let payload_offset = ip_header_length + tcp_header_length;
                if payload_offset < size {
                    echoed.extend_from_slice(&syn_ack[payload_offset..size]);
                }
            }
            echoed
        })
        .await
        .expect("sniffed TCP prefix was not replayed through the outbound");
        assert_eq!(echoed, request);

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("TUN runtime stop timed out")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unconfigured_tls_port_dispatches_without_reading_a_prefix() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let dispatcher = Arc::new(MockDispatcher::default());
        let limits = ResourceLimits {
            packet_queue_capacity: 4,
            event_queue_capacity: 2,
            tun_max_datagram_size: TUN_MTU,
            ..ResourceLimits::default()
        };
        let runtime = TunRuntime::new(
            tun,
            limits,
            dispatcher.clone(),
            None,
            false,
            Some(test_sniffer(
                &[],
                &[PortRange {
                    start: 8_443,
                    end: 8_443,
                }],
                &[],
            )),
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));

        let source: SocketAddr = "192.0.2.12:14000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.22:443".parse().unwrap();
        peer.send(&build_tcp_syn(source, destination))
            .await
            .unwrap();
        let mut syn_ack = [0_u8; TUN_MTU];
        let size = timeout(Duration::from_secs(2), peer.recv(&mut syn_ack))
            .await
            .expect("TCP SYN-ACK timed out")
            .unwrap();
        assert!(size >= 40);
        assert_eq!(syn_ack[20 + 13] & 0x12, 0x12);
        let server_sequence = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());

        // Complete the handshake without sending any TLS bytes. A mistakenly
        // enabled sniffer would wait for its 200 ms read deadline here.
        peer.send(&build_tcp_segment(
            source,
            destination,
            2,
            server_sequence.wrapping_add(1),
            0x10,
            &[],
        ))
        .await
        .unwrap();
        timeout(Duration::from_millis(100), async {
            loop {
                if !dispatcher.tcp_sessions.lock().unwrap().is_empty() {
                    break;
                }
                dispatcher.tcp_called.notified().await;
            }
        })
        .await
        .expect("unconfigured TLS port delayed dispatch for a prefix read");
        assert_eq!(
            dispatcher.tcp_sessions.lock().unwrap()[0],
            StreamSession {
                inbound: InboundKind::Tun,
                source,
                destination: Destination::Ip(destination),
                sniffed_domain: None,
            }
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("TUN runtime stop timed out")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn enabled_dns_fast_path_replies_without_opening_a_tun_udp_association() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let dispatcher = Arc::new(MockDispatcher::default());
        let dns_dispatcher = Arc::new(DnsReplyDispatcher::default());
        let dns = test_runtime_dns(dns_dispatcher.clone());
        let limits = ResourceLimits {
            packet_queue_capacity: 16,
            event_queue_capacity: 8,
            tun_max_datagram_size: TUN_MTU,
            ..ResourceLimits::default()
        };
        let runtime = TunRuntime::new(
            tun,
            limits,
            dispatcher.clone(),
            Some(dns),
            false,
            Some(test_sniffer(&[], &[], &[PortRange { start: 53, end: 53 }])),
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));

        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
        peer.send(&build_udp(source, requested_server, b"invalid"))
            .await
            .unwrap();
        let mut response = [0_u8; TUN_MTU];
        assert!(
            timeout(Duration::from_millis(100), peer.recv(&mut response))
                .await
                .is_err(),
            "malformed DNS query unexpectedly produced a response",
        );
        assert!(dispatcher.udp_sessions.lock().unwrap().is_empty());
        assert!(dns_dispatcher.udp_sessions.lock().unwrap().is_empty());

        let query = build_query(0x1234, "example.com", QueryType::A).unwrap();
        peer.send(&build_udp(source, requested_server, &query))
            .await
            .unwrap();
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .expect("TUN DNS response timed out")
            .unwrap();
        assert!(size > 30);
        assert_eq!(response[9], 17);
        assert_eq!(
            u16::from_be_bytes(response[20..22].try_into().unwrap()),
            requested_server.port()
        );
        assert_eq!(
            u16::from_be_bytes(response[22..24].try_into().unwrap()),
            source.port()
        );
        assert_ne!(response[30] & 0x80, 0);
        assert_eq!(&response[28..30], &0x1234_u16.to_be_bytes());
        assert!(dispatcher.udp_sessions.lock().unwrap().is_empty());
        assert_eq!(dns_dispatcher.udp_sessions.lock().unwrap().len(), 1);
        assert_eq!(
            dns_dispatcher.udp_sessions.lock().unwrap()[0].inbound,
            InboundKind::InternalDns
        );

        let ordinary_destination: SocketAddr = "203.0.113.30:443".parse().unwrap();
        peer.send(&build_udp(source, ordinary_destination, b"ordinary"))
            .await
            .unwrap();
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .expect("ordinary UDP response timed out")
            .unwrap();
        assert_udp_response(&response[..size], ordinary_destination, source, b"ordinary");
        assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("TUN runtime stop timed out")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn queued_dns_response_is_bounded_and_a_full_queue_drops_the_new_response() {
        let dns = test_runtime_dns(Arc::new(DnsReplyDispatcher::default()));
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
        let request = UdpDatagram::new(
            source,
            requested_server,
            build_query(0x2100, "queued.example", QueryType::A).unwrap(),
        );
        let (responses, mut queued) = mpsc::channel(1);
        let resource_stats = RuntimeResourceStats::new("tun_runtime_test");

        let permit = dns.begin_query();
        run_tun_dns_query(
            dns.clone(),
            permit,
            request,
            responses.clone(),
            resource_stats.clone(),
            CancellationToken::new(),
        )
        .await;
        let response = queued.recv().await.unwrap();
        assert_eq!(response.source, requested_server);
        assert_eq!(response.destination, source);
        drop(response);

        responses
            .send(QueuedUdpResponse::ordinary(UdpDatagram::new(
                requested_server,
                source,
                b"occupied".as_slice(),
            )))
            .await
            .unwrap();
        let request = UdpDatagram::new(
            source,
            requested_server,
            build_query(0x2101, "full.example", QueryType::A).unwrap(),
        );
        let permit = dns.begin_query();
        run_tun_dns_query(
            dns.clone(),
            permit,
            request,
            responses,
            resource_stats.clone(),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(resource_stats.snapshot().dns_queue_drops, 1);
        assert_eq!(&queued.recv().await.unwrap().payload[..], b"occupied");
    }

    #[tokio::test]
    async fn ordinary_and_dns_responses_have_independent_queue_capacity() {
        let dns = test_runtime_dns(Arc::new(DnsReplyDispatcher::default()));
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let server: SocketAddr = "198.51.100.20:53".parse().unwrap();
        let stats = RuntimeResourceStats::new("tun_runtime_test");
        let (ordinary_tx, mut ordinary_rx) = mpsc::channel(1);
        let (dns_tx, mut dns_rx) = mpsc::channel(1);

        ordinary_tx
            .send(QueuedUdpResponse::ordinary(UdpDatagram::new(
                server,
                source,
                b"ordinary-occupied".as_slice(),
            )))
            .await
            .unwrap();
        let permit = dns.begin_query();
        try_queue_tun_dns_response(
            &dns_tx,
            UdpDatagram::new(server, source, b"dns-independent".as_slice()),
            Some(permit),
            &stats,
        );

        let dns_response = dns_rx.recv().await.unwrap();
        assert_eq!(&dns_response.payload[..], b"dns-independent");
        drop(dns_response);
        assert_eq!(
            &ordinary_rx.recv().await.unwrap().payload[..],
            b"ordinary-occupied"
        );
    }

    #[tokio::test]
    async fn full_ordinary_response_queue_drops_without_refreshing_activity() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let server: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let stats = RuntimeResourceStats::new("tun_runtime_test");
        let last_activity = AtomicU64::new(5);
        let (responses, mut queued) = mpsc::channel(1);

        assert!(matches!(
            try_queue_tun_udp_response(
                &responses,
                UdpDatagram::new(server, source, b"queued".as_slice()),
                &last_activity,
                100,
                &stats,
            ),
            ResponseQueueResult::Queued
        ));
        assert_eq!(last_activity.load(Ordering::Acquire), 100);
        assert!(matches!(
            try_queue_tun_udp_response(
                &responses,
                UdpDatagram::new(server, source, b"dropped".as_slice()),
                &last_activity,
                110,
                &stats,
            ),
            ResponseQueueResult::Dropped
        ));
        assert_eq!(last_activity.load(Ordering::Acquire), 100);
        assert_eq!(stats.snapshot().udp_queue_drops, 1);
        assert_eq!(&queued.recv().await.unwrap().payload[..], b"queued");
    }

    #[tokio::test]
    async fn dns_fast_path_allows_sixteen_concurrent_sources_and_keeps_udp_responsive() {
        const QUERY_COUNT: usize = 16;

        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let dispatcher = Arc::new(MockDispatcher::default());
        let send_started = Arc::new(Notify::new());
        let send_count = Arc::new(AtomicUsize::new(0));
        let open_count = Arc::new(AtomicUsize::new(0));
        let dns_dispatcher = Arc::new(BlockingDispatcher {
            send_started,
            send_count: send_count.clone(),
            open_count: open_count.clone(),
        });
        let dns = test_runtime_dns(dns_dispatcher);
        let limits = ResourceLimits {
            packet_queue_capacity: 64,
            event_queue_capacity: 32,
            tun_max_datagram_size: TUN_MTU,
            ..ResourceLimits::default()
        };
        let runtime =
            TunRuntime::new(tun, limits, dispatcher.clone(), Some(dns), false, None).unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));
        let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();

        let malformed_source: SocketAddr = "192.0.2.10:11999".parse().unwrap();
        peer.send(&build_udp(malformed_source, requested_server, b"invalid"))
            .await
            .unwrap();

        for index in 0..QUERY_COUNT {
            let source = SocketAddr::new(
                Ipv4Addr::new(192, 0, 2, 10).into(),
                12_000 + u16::try_from(index).unwrap(),
            );
            let domain = format!("stall-{index}.example");
            let query = build_query(
                0x1000 + u16::try_from(index).unwrap(),
                &domain,
                QueryType::A,
            )
            .unwrap();
            peer.send(&build_udp(source, requested_server, &query))
                .await
                .unwrap();
        }
        timeout(Duration::from_secs(2), async {
            while send_count.load(Ordering::Relaxed) < QUERY_COUNT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the DNS queries did not reach their stalled upstreams");
        assert!(dispatcher.udp_sessions.lock().unwrap().is_empty());
        assert_eq!(open_count.load(Ordering::Relaxed), QUERY_COUNT);

        let ordinary_source: SocketAddr = "192.0.2.99:13000".parse().unwrap();
        let ordinary_destination: SocketAddr = "203.0.113.30:443".parse().unwrap();
        peer.send(&build_udp(
            ordinary_source,
            ordinary_destination,
            b"still-responsive",
        ))
        .await
        .unwrap();
        let mut response = [0_u8; TUN_MTU];
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .expect("stalled DNS queries blocked ordinary UDP")
            .unwrap();
        assert_udp_response(
            &response[..size],
            ordinary_destination,
            ordinary_source,
            b"still-responsive",
        );

        assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
        assert_eq!(open_count.load(Ordering::Relaxed), QUERY_COUNT);
        assert_eq!(send_count.load(Ordering::Relaxed), QUERY_COUNT);

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("stalled DNS tasks prevented the TUN stop barrier")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn oversized_tun_dns_response_is_dropped() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
        let query = build_query(0x3456, "example.com", QueryType::A).unwrap();
        let request = UdpDatagram::new(source, requested_server, query.clone());
        let ceiling =
            usize::from(DatagramSession::new(InboundKind::Tun, source).max_response_payload_size());
        assert!(complete_tun_dns_response(&request, vec![0_u8; ceiling + 1]).is_none());
    }

    #[test]
    fn ipv6_tun_dns_responses_preserve_the_requested_server_and_client_endpoints() {
        let source: SocketAddr = "[2001:db8::10]:12000".parse().unwrap();
        let requested_server: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
        let query = build_query(0x4567, "example.com", QueryType::Aaaa).unwrap();
        let classified = classify_query(&query).unwrap();
        let request = UdpDatagram::new(source, requested_server, query);
        let response =
            complete_tun_dns_response(&request, synthesize_empty_response(&classified, 0).unwrap())
                .unwrap();
        assert_eq!(response.source, requested_server);
        assert_eq!(response.destination, source);
        let parsed = crate::dns::parse_response(&response.payload).unwrap();
        assert_eq!(parsed.id, classified.id);

        let servfail = tun_dns_servfail_response(&request, &classified);
        assert_eq!(servfail.source, requested_server);
        assert_eq!(servfail.destination, source);
        assert_eq!(
            u16::from_be_bytes([servfail.payload[2], servfail.payload[3]]) & 0x000f,
            2
        );
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_blocked_udp_send_and_completes_the_stop_barrier() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let send_started = Arc::new(Notify::new());
        let dispatcher = Arc::new(BlockingDispatcher {
            send_started: send_started.clone(),
            send_count: Arc::new(AtomicUsize::new(0)),
            open_count: Arc::new(AtomicUsize::new(0)),
        });
        let runtime = TunRuntime::new(
            tun,
            ResourceLimits::default(),
            dispatcher,
            None,
            false,
            None,
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));

        peer.send(&build_udp(
            "192.0.2.10:12000".parse().unwrap(),
            "198.51.100.20:53".parse().unwrap(),
            b"block",
        ))
        .await
        .unwrap();
        timeout(Duration::from_secs(2), send_started.notified())
            .await
            .expect("UDP transport send was not polled");

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("blocked UDP send prevented the TUN stop barrier")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn fresh_udp_source_beyond_the_old_sixty_four_limit_is_accepted() {
        const OLD_UDP_LIMIT: usize = 64;

        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let send_started = Arc::new(Notify::new());
        let send_count = Arc::new(AtomicUsize::new(0));
        let open_count = Arc::new(AtomicUsize::new(0));
        let dispatcher = Arc::new(BlockingDispatcher {
            send_started,
            send_count: send_count.clone(),
            open_count: open_count.clone(),
        });
        let limits = ResourceLimits {
            packet_queue_capacity: 128,
            event_queue_capacity: 128,
            tun_max_datagram_size: TUN_MTU,
            ..ResourceLimits::default()
        };
        let runtime = TunRuntime::new(tun, limits, dispatcher, None, false, None).unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();

        for index in 0..OLD_UDP_LIMIT {
            let source = SocketAddr::new(
                Ipv4Addr::new(192, 0, 2, 10).into(),
                12_000 + u16::try_from(index).unwrap(),
            );
            peer.send(&build_udp(source, destination, b"held"))
                .await
                .unwrap();
            timeout(Duration::from_secs(2), async {
                while open_count.load(Ordering::Acquire) <= index {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("a UDP association was not opened");
        }
        assert_eq!(send_count.load(Ordering::Acquire), OLD_UDP_LIMIT);
        assert_eq!(open_count.load(Ordering::Acquire), OLD_UDP_LIMIT);

        let sixty_fifth_source: SocketAddr = "192.0.2.99:13000".parse().unwrap();
        peer.send(&build_udp(sixty_fifth_source, destination, b"accepted"))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while open_count.load(Ordering::Acquire) == OLD_UDP_LIMIT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the sixty-fifth fresh UDP source was not accepted");
        assert_eq!(open_count.load(Ordering::Acquire), OLD_UDP_LIMIT + 1);

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("TUN runtime stop timed out")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn queued_udp_response_is_drained_before_a_same_source_ingress_burst() {
        let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let server: SocketAddr = "198.51.100.20:53".parse().unwrap();
        let dispatcher = Arc::new(ResponseFirstDispatcher {
            response: Datagram {
                remote: Destination::Ip(server),
                payload: Bytes::from_static(b"response"),
                sniffed_domain: None,
            },
        });
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        inbound_tx
            .send(UdpDatagram::new(source, server, b"next-query".as_slice()))
            .await
            .unwrap();
        let (responses_tx, mut responses_rx) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(async move {
            run_udp_association_inner(
                &mut inbound_rx,
                &UdpAssociationTaskContext {
                    association_id: 1,
                    source,
                    responses: responses_tx,
                    dispatcher,
                    resource_stats: RuntimeResourceStats::new("tun_runtime_test"),
                    association_clock: AssociationClock::realtime(),
                    last_activity: Arc::new(AtomicU64::new(0)),
                    sniffer: None,
                    cancellation: child,
                },
            )
            .await
        });

        let response = timeout(Duration::from_secs(1), responses_rx.recv())
            .await
            .expect("ready response was starved behind the same-source query")
            .expect("response channel closed");
        assert_eq!(response.source, server);
        assert_eq!(response.destination, source);
        assert_eq!(&response.payload[..], b"response");

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("association did not stop")
            .unwrap()
            .unwrap();
        drop(inbound_tx);
    }

    #[tokio::test]
    async fn full_udp_association_queue_does_not_block_other_sources() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate(host.as_raw_fd()).unwrap();
        let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let blocked_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
        let responsive_source: SocketAddr = "192.0.2.11:12001".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:53".parse().unwrap();
        let send_started = Arc::new(Notify::new());
        let dispatcher = Arc::new(SourceSelectiveDispatcher {
            blocked_source,
            send_started: send_started.clone(),
        });
        let limits = ResourceLimits {
            packet_queue_capacity: 64,
            event_queue_capacity: 64,
            tun_max_datagram_size: TUN_MTU,
            ..ResourceLimits::default()
        };
        let runtime = TunRuntime::new(tun, limits, dispatcher, None, false, None).unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(runtime.run(cancellation.clone()));

        peer.send(&build_udp(blocked_source, destination, b"block"))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), send_started.notified())
            .await
            .expect("blocked association did not enter outbound send");

        for _ in 0..=UDP_ASSOCIATION_QUEUE_MAX {
            peer.send(&build_udp(blocked_source, destination, b"queued"))
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
        peer.send(&build_udp(
            responsive_source,
            destination,
            b"still-responsive",
        ))
        .await
        .unwrap();

        let mut response = [0_u8; TUN_MTU];
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .expect("a full source queue blocked another UDP association")
            .unwrap();
        assert_udp_response(
            &response[..size],
            destination,
            responsive_source,
            b"still-responsive",
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), task)
            .await
            .expect("TUN runtime stop timed out")
            .unwrap()
            .unwrap();
    }

    fn build_udp(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
            panic!("test helper requires IPv4");
        };
        let mut udp = vec![0_u8; 8 + payload.len()];
        udp[..2].copy_from_slice(&source.port().to_be_bytes());
        udp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        let udp_len = u16::try_from(udp.len()).unwrap();
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[8..].copy_from_slice(payload);
        let checksum = transport_checksum(*source.ip(), *destination.ip(), 17, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        build_ipv4(*source.ip(), *destination.ip(), 17, &udp)
    }

    fn build_tcp_syn(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
        build_tcp_segment(source, destination, 1, 0, 0x02, &[])
    }

    fn build_tcp_segment(
        source: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
            panic!("test helper requires IPv4");
        };
        let mut tcp = vec![0_u8; 20 + payload.len()];
        tcp[..2].copy_from_slice(&source.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        let checksum = transport_checksum(*source.ip(), *destination.ip(), 6, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        build_ipv4(*source.ip(), *destination.ip(), 6, &tcp)
    }

    fn build_ipv4(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        transport: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + transport.len()];
        let packet_len = u16::try_from(packet.len()).unwrap();
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet[20..].copy_from_slice(transport);
        packet
    }

    fn assert_udp_response(
        packet: &[u8],
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) {
        assert_eq!(packet[9], 17);
        assert_eq!(
            u16::from_be_bytes(packet[20..22].try_into().unwrap()),
            source.port()
        );
        assert_eq!(
            u16::from_be_bytes(packet[22..24].try_into().unwrap()),
            destination.port()
        );
        assert_eq!(&packet[28..], payload);
    }

    fn transport_checksum(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        transport: &[u8],
    ) -> u16 {
        let mut sum = 0_u32;
        add_bytes(&mut sum, &source.octets());
        add_bytes(&mut sum, &destination.octets());
        sum += u32::from(protocol);
        sum += u32::try_from(transport.len()).unwrap();
        add_bytes(&mut sum, transport);
        fold(sum)
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        add_bytes(&mut sum, bytes);
        fold(sum)
    }

    fn add_bytes(sum: &mut u32, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            *sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            *sum += u32::from(*byte) << 8;
        }
    }

    fn fold(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = !u16::try_from(sum).unwrap();
        if checksum == 0 { u16::MAX } else { checksum }
    }
}
