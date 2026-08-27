#![allow(non_snake_case)]

use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    slice,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use windows::{
    ApplicationModel::{
        Background::{IBackgroundTask, IBackgroundTask_Impl, IBackgroundTaskInstance},
        Core::CoreApplication,
    },
    Networking::{
        Connectivity::{ConnectionProfile, NetworkInformation, NetworkStatusChangedEventHandler},
        HostName, HostNameType,
        Sockets::DatagramSocket,
        Vpn::{
            IVpnPlugIn, IVpnPlugIn_Impl, VpnChannel, VpnDomainNameAssignment, VpnDomainNameInfo,
            VpnDomainNameType, VpnInterfaceId, VpnPacketBuffer, VpnPacketBufferList, VpnRoute,
            VpnRouteAssignment,
        },
    },
    Storage::{
        ApplicationData,
        Streams::{Buffer, IOutputStream},
    },
    Win32::{
        Foundation::{
            CLASS_E_CLASSNOTAVAILABLE, E_BOUNDS, E_FAIL, ERROR_BUFFER_OVERFLOW, NO_ERROR,
        },
        NetworkManagement::IpHelper::{
            GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::AF_UNSPEC,
        System::WinRT::{
            IActivationFactory, IActivationFactory_Impl, IBufferByteAccess, RO_INIT_MULTITHREADED,
            RoInitialize, RoUninitialize,
        },
    },
    core::{
        Error, GUID, HRESULT, HSTRING, IInspectable, Interface as _, OutRef, Ref, Result,
        StaticComObject, implement,
    },
};
use windows_collections::IVectorView;
use windows_core::{AgileReference, IUnknownImpl as _};

use crate::{
    platform::{TunIo, WindowsPacketAdapter, WindowsPacketStats},
    windows_log,
    windows_packet_channel::{
        AddressBindingV4, AddressBindingV6, PacketCounters, PhysicalBinding, ProviderPacketSession,
    },
    windows_profile::{WindowsNetworkSettings, WindowsProfileConfiguration},
};

const CLASS_NAME: &str = "VCore.VpnBackgroundTask";
const PACKET_QUEUE_CAPACITY: usize = 256;
const FAIL_CLOSED_IDLE: u8 = 0;
const FAIL_CLOSED_STOPPING: u8 = 1;
const FAIL_CLOSED_CANCELLED: u8 = 2;
const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_secs(2);
static VPN_RUNNING: AtomicBool = AtomicBool::new(false);
static EXIT_AFTER_RUN: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct FailClosedHandle {
    signal: Arc<FailClosedSignal>,
}

struct FailClosedSignal {
    armed: AtomicBool,
    requested: AtomicBool,
    network_generation: AtomicU64,
    phase: AtomicU8,
    worker: OnceLock<thread::Thread>,
}

impl FailClosedSignal {
    fn wake(&self) {
        if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
    }

    fn request(&self, reason: &'static str) {
        if self.phase.load(Ordering::Acquire) != FAIL_CLOSED_IDLE {
            return;
        }
        if !self.requested.swap(true, Ordering::AcqRel) {
            log(&format!("fail-closed stop requested: {reason}"));
        }
        self.wake();
    }
}

impl FailClosedHandle {
    fn arm(&self) {
        if self.signal.phase.load(Ordering::Acquire) == FAIL_CLOSED_IDLE {
            self.signal.armed.store(true, Ordering::Release);
            self.signal.wake();
        }
    }

    fn request(&self, reason: &'static str) {
        self.signal.request(reason);
    }

    fn network_changed(&self) {
        if self.signal.phase.load(Ordering::Acquire) == FAIL_CLOSED_IDLE {
            self.signal
                .network_generation
                .fetch_add(1, Ordering::AcqRel);
            self.signal.wake();
        }
    }
}

struct FailClosedStop {
    signal: Arc<FailClosedSignal>,
    thread: Option<JoinHandle<()>>,
}

impl FailClosedStop {
    fn start(channel: &VpnChannel, physical: PhysicalNetwork) -> Result<(Self, FailClosedHandle)> {
        let channel = AgileReference::new(channel)?;
        let signal = Arc::new(FailClosedSignal {
            armed: AtomicBool::new(false),
            requested: AtomicBool::new(false),
            network_generation: AtomicU64::new(0),
            phase: AtomicU8::new(FAIL_CLOSED_IDLE),
            worker: OnceLock::new(),
        });
        let worker_signal = signal.clone();
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("vcore-windows-fail-closed".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
                match initialized {
                    Ok(()) => _ = startup_tx.send(Ok(())),
                    Err(error) => {
                        _ = startup_tx.send(Err(error.to_string()));
                        return;
                    }
                }
                let mut checked_network_generation = 0;
                loop {
                    if worker_signal.phase.load(Ordering::Acquire) == FAIL_CLOSED_CANCELLED {
                        break;
                    }
                    if worker_signal.armed.load(Ordering::Acquire)
                        && worker_signal.requested.load(Ordering::Acquire)
                        && worker_signal
                            .phase
                            .compare_exchange(
                                FAIL_CLOSED_IDLE,
                                FAIL_CLOSED_STOPPING,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                    {
                        match channel.resolve().and_then(|channel| channel.Stop()) {
                            Ok(()) => log("fail-closed channel Stop completed"),
                            Err(error) => log(&format!("fail-closed channel Stop failed: {error}")),
                        }
                        break;
                    }

                    let network_generation =
                        worker_signal.network_generation.load(Ordering::Acquire);
                    if worker_signal.armed.load(Ordering::Acquire)
                        && network_generation != checked_network_generation
                    {
                        let deadline = Instant::now() + NETWORK_CHANGE_DEBOUNCE;
                        while Instant::now() < deadline
                            && worker_signal.phase.load(Ordering::Acquire) == FAIL_CLOSED_IDLE
                            && !worker_signal.requested.load(Ordering::Acquire)
                            && worker_signal.network_generation.load(Ordering::Acquire)
                                == network_generation
                        {
                            thread::park_timeout(
                                deadline.saturating_duration_since(Instant::now()),
                            );
                        }
                        if worker_signal.network_generation.load(Ordering::Acquire)
                            != network_generation
                            || worker_signal.phase.load(Ordering::Acquire) != FAIL_CLOSED_IDLE
                            || worker_signal.requested.load(Ordering::Acquire)
                        {
                            continue;
                        }
                        checked_network_generation = network_generation;
                        match physical.is_available() {
                            Ok(true) => {}
                            Ok(false) => {
                                worker_signal.request("physical network is no longer available")
                            }
                            Err(_) => worker_signal.request("physical network validation failed"),
                        }
                        continue;
                    }
                    thread::park();
                }
                unsafe { RoUninitialize() };
            })
            .map_err(windows_error)?;
        _ = signal.worker.set(thread.thread().clone());

        let mut stop = Self {
            signal: signal.clone(),
            thread: Some(thread),
        };
        match startup_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok((stop, FailClosedHandle { signal })),
            Ok(Err(message)) => {
                _ = stop.shutdown();
                Err(Error::new(E_FAIL, message))
            }
            Err(error) => {
                _ = stop.shutdown();
                Err(Error::new(
                    E_FAIL,
                    format!("fail-closed worker startup failed: {error}"),
                ))
            }
        }
    }

    fn shutdown(&mut self) -> io::Result<()> {
        let phase = self
            .signal
            .phase
            .compare_exchange(
                FAIL_CLOSED_IDLE,
                FAIL_CLOSED_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .unwrap_or_else(|phase| phase);
        self.signal.wake();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        if phase == FAIL_CLOSED_STOPPING || thread.thread().id() == thread::current().id() {
            return Ok(());
        }
        thread
            .join()
            .map_err(|_| io::Error::other("fail-closed worker panicked"))
    }
}

impl Drop for FailClosedStop {
    fn drop(&mut self) {
        _ = self.signal.phase.compare_exchange(
            FAIL_CLOSED_IDLE,
            FAIL_CLOSED_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.signal.wake();
    }
}

#[derive(Debug, Clone, Copy)]
struct InterfaceIndices {
    ipv4: Option<NonZeroU32>,
    ipv6: Option<NonZeroU32>,
}

fn adapter_name_matches(name: &str, adapter_id: GUID) -> bool {
    name.trim()
        .trim_matches(|character| character == '{' || character == '}')
        .eq_ignore_ascii_case(&format!("{adapter_id:?}"))
}

fn adapter_interface_indices(adapter_id: GUID) -> Result<InterfaceIndices> {
    let mut storage = vec![0_usize; (15 * 1024_usize).div_ceil(size_of::<usize>())];
    for _ in 0..3 {
        let mut byte_count = u32::try_from(storage.len() * size_of::<usize>())
            .map_err(|_| Error::new(E_FAIL, "network adapter buffer is too large"))?;
        // SAFETY: `storage` is aligned for the returned structures and remains live while walked.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                GET_ADAPTERS_ADDRESSES_FLAGS(0),
                None,
                Some(storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut byte_count,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW.0 {
            storage.resize(
                (byte_count as usize)
                    .div_ceil(size_of::<usize>())
                    .max(storage.len() + 1),
                0,
            );
            continue;
        }
        if status != NO_ERROR.0 {
            return Err(Error::new(
                HRESULT::from_win32(status),
                "GetAdaptersAddresses failed",
            ));
        }

        let mut current = storage.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            // SAFETY: successful `GetAdaptersAddresses` linked these entries inside `storage`.
            let adapter = unsafe { &*current };
            if !adapter.AdapterName.is_null() {
                // SAFETY: `AdapterName` is a null-terminated string owned by `storage`.
                let name = unsafe { adapter.AdapterName.to_string() }
                    .map_err(|_| Error::new(E_FAIL, "network adapter name is not UTF-8"))?;
                if adapter_name_matches(&name, adapter_id) {
                    // SAFETY: `Anonymous` is the documented Length/IfIndex view of this union.
                    let ipv4 = NonZeroU32::new(unsafe { adapter.Anonymous1.Anonymous.IfIndex });
                    return Ok(InterfaceIndices {
                        ipv4,
                        ipv6: NonZeroU32::new(adapter.Ipv6IfIndex),
                    });
                }
            }
            current = adapter.Next;
        }
        return Err(Error::new(
            E_FAIL,
            "physical network adapter was not returned by GetAdaptersAddresses",
        ));
    }
    Err(Error::new(
        E_FAIL,
        "network adapter list changed while it was being read",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkIdentity {
    profile_name: String,
    network_names: Vec<String>,
}

fn network_identity(profile: &ConnectionProfile) -> Result<NetworkIdentity> {
    let names = profile.GetNetworkNames()?;
    let mut network_names = Vec::with_capacity(names.Size()? as usize);
    for index in 0..names.Size()? {
        network_names.push(names.GetAt(index)?.to_string());
    }
    network_names.sort_unstable();
    Ok(NetworkIdentity {
        profile_name: profile.ProfileName()?.to_string(),
        network_names,
    })
}

#[derive(Debug, Clone)]
struct PhysicalNetwork {
    adapter_id: GUID,
    identity: NetworkIdentity,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    ipv4_index: Option<NonZeroU32>,
    ipv6_index: Option<NonZeroU32>,
}

impl PhysicalNetwork {
    fn current() -> Result<Self> {
        let profile = NetworkInformation::GetInternetConnectionProfile()?;
        let adapter_id = profile.NetworkAdapter()?.NetworkAdapterId()?;
        let identity = network_identity(&profile)?;
        let host_names = NetworkInformation::GetHostNames()?;
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();

        for index in 0..host_names.Size()? {
            let host = host_names.GetAt(index)?;
            let Ok(adapter) = host.IPInformation().and_then(|info| info.NetworkAdapter()) else {
                continue;
            };
            if adapter.NetworkAdapterId()? != adapter_id {
                continue;
            }
            match host.Type()? {
                HostNameType::Ipv4 => {
                    let Ok(address) = host.CanonicalName()?.to_string().parse::<Ipv4Addr>() else {
                        continue;
                    };
                    if !address.is_loopback()
                        && !address.is_link_local()
                        && !address.is_unspecified()
                    {
                        ipv4.push(address);
                    }
                }
                HostNameType::Ipv6 => {
                    let Ok(address) = host.CanonicalName()?.to_string().parse::<Ipv6Addr>() else {
                        continue;
                    };
                    if !address.is_loopback()
                        && !address.is_unicast_link_local()
                        && !address.is_unspecified()
                        && !address.is_multicast()
                    {
                        ipv6.push(address);
                    }
                }
                _ => {}
            }
        }

        ipv4.sort_unstable();
        ipv4.dedup();
        ipv6.sort_unstable();
        ipv6.dedup();
        if ipv4.is_empty() && ipv6.is_empty() {
            return Err(Error::new(
                E_FAIL,
                "physical network has no usable IP address",
            ));
        }
        let ipv4 = ipv4.into_iter().next();
        let ipv6 = ipv6.into_iter().next();
        let indices = adapter_interface_indices(adapter_id)?;
        let ipv4_index = match ipv4 {
            Some(_) => Some(indices.ipv4.ok_or_else(|| {
                Error::new(E_FAIL, "physical network has no IPv4 interface index")
            })?),
            None => None,
        };
        let ipv6_index = match ipv6 {
            Some(_) => Some(indices.ipv6.ok_or_else(|| {
                Error::new(E_FAIL, "physical network has no IPv6 interface index")
            })?),
            None => None,
        };
        Ok(Self {
            adapter_id,
            identity,
            ipv4,
            ipv6,
            ipv4_index,
            ipv6_index,
        })
    }

    fn packet_binding(&self) -> PhysicalBinding {
        PhysicalBinding {
            adapter_id: format!("{:?}", self.adapter_id),
            profile_name: self.identity.profile_name.clone(),
            network_names: self.identity.network_names.clone(),
            ipv4: self
                .ipv4
                .zip(self.ipv4_index)
                .map(|(source, index)| AddressBindingV4 {
                    source,
                    interface_index: index.get(),
                }),
            ipv6: self
                .ipv6
                .zip(self.ipv6_index)
                .map(|(source, index)| AddressBindingV6 {
                    source,
                    interface_index: index.get(),
                }),
        }
    }

    fn is_available(&self) -> Result<bool> {
        let host_names = NetworkInformation::GetHostNames()?;
        let mut ipv4_found = self.ipv4.is_none();
        let mut ipv6_found = self.ipv6.is_none();
        for index in 0..host_names.Size()? {
            let host = host_names.GetAt(index)?;
            let Ok(adapter) = host.IPInformation().and_then(|info| info.NetworkAdapter()) else {
                continue;
            };
            if adapter.NetworkAdapterId()? != self.adapter_id {
                continue;
            }
            let canonical = host.CanonicalName()?.to_string();
            ipv4_found |= self.ipv4.is_some_and(|expected| {
                canonical.parse::<Ipv4Addr>().is_ok_and(|ip| ip == expected)
            });
            ipv6_found |= self.ipv6.is_some_and(|expected| {
                canonical.parse::<Ipv6Addr>().is_ok_and(|ip| ip == expected)
            });
        }
        if !ipv4_found || !ipv6_found {
            return Ok(false);
        }

        let profiles = NetworkInformation::GetConnectionProfiles()?;
        for index in 0..profiles.Size()? {
            let profile = profiles.GetAt(index)?;
            let Ok(adapter) = profile.NetworkAdapter() else {
                continue;
            };
            if adapter.NetworkAdapterId()? == self.adapter_id
                && network_identity(&profile)? == self.identity
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct ProviderState {
    transport: Option<DatagramSocket>,
    back_transport: Option<DatagramSocket>,
    packets: Option<WindowsPacketAdapter>,
    session: Option<ProviderPacketSession>,
    fail_closed: Option<FailClosedStop>,
    network_status_token: Option<i64>,
    encapsulated: u64,
    decapsulated: u64,
}

impl ProviderState {
    const fn new() -> Self {
        Self {
            transport: None,
            back_transport: None,
            packets: None,
            session: None,
            fail_closed: None,
            network_status_token: None,
            encapsulated: 0,
            decapsulated: 0,
        }
    }
}

#[implement(IVpnPlugIn)]
struct VpnProvider {
    operation: Mutex<()>,
    state: Mutex<ProviderState>,
}

impl VpnProvider {
    const fn new() -> Self {
        Self {
            operation: Mutex::new(()),
            state: Mutex::new(ProviderState::new()),
        }
    }

    fn connect_inner(&self, channel: &VpnChannel) -> Result<()> {
        let local_folder = local_folder()?;
        let profile = WindowsProfileConfiguration::parse(
            &channel.Configuration()?.CustomField()?.to_string(),
        )?;
        let token = profile.snapshot_token().to_owned();
        let physical = PhysicalNetwork::current()?;

        let localhost = HostName::CreateHostName(&"127.0.0.1".into())?;
        let transport = DatagramSocket::new()?;
        let back_transport = DatagramSocket::new()?;
        channel.AssociateTransport(&transport, None::<&IInspectable>)?;
        transport
            .BindEndpointAsync(&localhost, &HSTRING::new())?
            .join()?;
        back_transport
            .BindEndpointAsync(&localhost, &HSTRING::new())?
            .join()?;
        transport
            .ConnectAsync(&localhost, &back_transport.Information()?.LocalPort()?)?
            .join()?;
        back_transport
            .ConnectAsync(&localhost, &transport.Information()?.LocalPort()?)?
            .join()?;
        let output = back_transport.OutputStream()?;

        let routes = vpn_routes()?;
        let (assigned_ipv4, assigned_ipv6) = vpn_client_addresses(profile.network_settings())?;
        let dns = vpn_dns_assignment(profile.network_settings())?;

        let wake_output = AgileReference::new(&output)?;
        let (tun, packets) = TunIo::new(PACKET_QUEUE_CAPACITY, move || {
            write_dummy(&wake_output.resolve().map_err(io::Error::other)?).map_err(io::Error::other)
        });
        let (fail_closed, fail_closed_handle) = FailClosedStop::start(channel, physical.clone())?;
        let unexpected_stop = fail_closed_handle.clone();
        let session = ProviderPacketSession::start(
            local_folder,
            token,
            physical.packet_binding(),
            tun,
            move || unexpected_stop.request("Session Host exited unexpectedly"),
        )
        .map_err(windows_error)?;

        {
            let mut state = self.lock_state()?;
            state.transport = Some(transport.clone());
            state.back_transport = Some(back_transport);
            state.packets = Some(packets);
            state.session = Some(session);
            state.fail_closed = Some(fail_closed);
        }

        channel.StartWithMainTransport(
            &assigned_ipv4,
            &assigned_ipv6,
            None::<&VpnInterfaceId>,
            &routes,
            &dns,
            1500,
            1512,
            false,
            &transport,
        )?;

        let network_stop = fail_closed_handle.clone();
        let handler = NetworkStatusChangedEventHandler::new(move |_| {
            network_stop.network_changed();
            Ok(())
        });
        let token = NetworkInformation::NetworkStatusChanged(&handler)?;
        self.lock_state()?.network_status_token = Some(token);
        fail_closed_handle.arm();

        log(&format!(
            "connect ok: ipv4={} ipv6={}",
            physical.ipv4.is_some(),
            physical.ipv6.is_some()
        ));
        Ok(())
    }

    fn lock_operation(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.operation
            .lock()
            .map_err(|_| Error::new(E_FAIL, "Windows VPN lifecycle lock poisoned"))
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ProviderState>> {
        self.state
            .lock()
            .map_err(|_| Error::new(E_FAIL, "Windows VPN provider state lock poisoned"))
    }

    fn stop_session(&self) -> Result<()> {
        let (token, mut fail_closed, session, counters) = {
            let mut state = self.lock_state()?;
            let packet_stats = state
                .packets
                .as_ref()
                .map_or_else(WindowsPacketStats::default, WindowsPacketAdapter::stats);
            (
                state.network_status_token.take(),
                state.fail_closed.take(),
                state.session.take(),
                PacketCounters {
                    encapsulated: state.encapsulated,
                    decapsulated: state.decapsulated,
                    ingress_queue_dropped: packet_stats.ingress_queue_dropped,
                    ingress_closed: packet_stats.ingress_closed,
                    egress_queue_dropped: packet_stats.egress_queue_dropped,
                },
            )
        };
        let mut first_error = None;
        if let Some(token) = token
            && let Err(error) = NetworkInformation::RemoveNetworkStatusChanged(token)
        {
            first_error = Some(error);
        }
        if let Some(stop) = fail_closed.as_mut()
            && let Err(error) = stop.shutdown()
        {
            first_error.get_or_insert_with(|| windows_error(error));
        }
        if let Some(session) = session {
            if let Err(error) = session.stop(counters) {
                first_error.get_or_insert_with(|| windows_error(error));
            } else {
                log("Session Host stopped");
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn reset_state(&self) -> Result<(u64, u64, WindowsPacketStats)> {
        let (counters, transport, back_transport) = {
            let mut state = self.lock_state()?;
            let counters = (
                state.encapsulated,
                state.decapsulated,
                state
                    .packets
                    .as_ref()
                    .map_or_else(WindowsPacketStats::default, WindowsPacketAdapter::stats),
            );
            let transport = state.transport.take();
            let back_transport = state.back_transport.take();
            *state = ProviderState::new();
            (counters, transport, back_transport)
        };
        let mut first_error = None;
        for socket in [transport, back_transport].into_iter().flatten() {
            if let Err(error) = socket.Close() {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(counters), Err)
    }
}

impl IVpnPlugIn_Impl for VpnProvider_Impl {
    fn Connect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        com_boundary(|| {
            let channel = channel.ok()?;
            let _operation = self.lock_operation()?;
            if self.lock_state()?.session.is_some() {
                let error = Error::new(E_FAIL, "Windows VPN provider is already running");
                log("duplicate Connect rejected without disturbing the active session");
                _ = channel.SetErrorMessage(&error.to_string().into());
                return Err(error);
            }
            VPN_RUNNING.store(true, Ordering::Release);
            if let Err(error) = com_boundary(|| self.connect_inner(channel)) {
                _ = self.stop_session();
                _ = self.reset_state();
                VPN_RUNNING.store(false, Ordering::Release);
                EXIT_AFTER_RUN.store(true, Ordering::Release);
                log(&format!("connect failed: {error}"));
                _ = channel.SetErrorMessage(&error.to_string().into());
                Err(error)
            } else {
                Ok(())
            }
        })
    }

    fn Disconnect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let result = com_boundary(|| {
            let channel = channel.ok()?;
            let _operation = self.lock_operation()?;
            let session_result = self.stop_session();
            let channel_result = channel.Stop();
            let (encapsulated, decapsulated, packet_stats) = self.reset_state()?;
            log(&format!(
                "disconnect: encapsulated={encapsulated} decapsulated={decapsulated} \
                 ingress_queue_dropped={} ingress_closed={} egress_queue_dropped={}",
                packet_stats.ingress_queue_dropped,
                packet_stats.ingress_closed,
                packet_stats.egress_queue_dropped
            ));
            VPN_RUNNING.store(false, Ordering::Release);
            EXIT_AFTER_RUN.store(true, Ordering::Release);
            channel_result?;
            session_result
        });
        if result.is_err() {
            VPN_RUNNING.store(false, Ordering::Release);
            EXIT_AFTER_RUN.store(true, Ordering::Release);
        }
        result
    }

    fn GetKeepAlivePayload(
        &self,
        _channel: Ref<VpnChannel>,
        packet: OutRef<VpnPacketBuffer>,
    ) -> Result<()> {
        com_boundary(|| packet.write(None))
    }

    fn Encapsulate(
        &self,
        _channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        _encapsulated: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        com_boundary(|| {
            let packets = packets.ok()?;
            let count = packets.Size()?;
            for _ in 0..count {
                let packet = packets.RemoveAtBegin()?;
                let copied = packet.Buffer().and_then(|buffer| read_buffer(&buffer));
                packets.Append(&packet)?;
                let bytes = copied?;
                let (adapter, first) = {
                    let mut state = self.lock_state()?;
                    state.encapsulated = state.encapsulated.saturating_add(1);
                    (state.packets.clone(), state.encapsulated == 1)
                };
                if first {
                    log(&format!(
                        "first VCore ingress packet: {} bytes",
                        bytes.len()
                    ));
                }
                _ = adapter.is_some_and(|adapter| adapter.try_send(bytes));
            }
            Ok(())
        })
    }

    fn Decapsulate(
        &self,
        channel: Ref<VpnChannel>,
        buffer: Ref<VpnPacketBuffer>,
        packets: Ref<VpnPacketBufferList>,
        control: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        com_boundary(|| {
            let channel = channel.ok()?;
            _ = buffer.ok()?;
            let packets = packets.ok()?;
            _ = control.ok()?;
            let adapter = self.lock_state()?.packets.clone();
            let Some(adapter) = adapter else {
                return Ok(());
            };
            while let Some(bytes) = adapter.pop_egress() {
                let packet = channel.GetVpnReceivePacketBuffer()?;
                write_buffer(&packet.Buffer()?, &bytes)?;
                packets.Append(&packet)?;
                let first = {
                    let mut state = self.lock_state()?;
                    state.decapsulated = state.decapsulated.saturating_add(1);
                    state.decapsulated == 1
                };
                if first {
                    log(&format!("first VCore egress packet: {} bytes", bytes.len()));
                }
            }
            Ok(())
        })
    }
}

#[implement(IBackgroundTask)]
struct BackgroundTask;

impl IBackgroundTask_Impl for BackgroundTask_Impl {
    fn Run(&self, task: Ref<IBackgroundTaskInstance>) -> Result<()> {
        com_boundary(|| {
            let task = task.ok()?;
            let deferral = task.GetDeferral()?;
            let result = com_boundary(|| {
                log("background task activated");
                let properties = CoreApplication::Properties()?;
                let key: HSTRING = "windows-vpn-provider".into();
                let provider: IVpnPlugIn = if properties.HasKey(&key)? {
                    properties.Lookup(&key)?.cast()?
                } else {
                    let provider: IVpnPlugIn = VpnProvider::new().into();
                    let inspectable: IInspectable = provider.cast()?;
                    properties.Insert(&key, &inspectable)?;
                    provider
                };
                let trigger = task.TriggerDetails()?;
                VpnChannel::ProcessEventAsync(&provider, &trigger)
            });
            let completed = deferral.Complete();
            let result = result.and(completed);
            if EXIT_AFTER_RUN.swap(false, Ordering::AcqRel) && !VPN_RUNNING.load(Ordering::Acquire)
            {
                _ = CoreApplication::Exit();
            }
            result
        })
    }
}

#[implement(IActivationFactory)]
struct ClassFactory;

impl IActivationFactory_Impl for ClassFactory_Impl {
    fn ActivateInstance(&self) -> Result<IInspectable> {
        com_boundary(|| Ok(BackgroundTask.into()))
    }
}

static CLASS_FACTORY: StaticComObject<ClassFactory> = ClassFactory.into_static();

#[unsafe(no_mangle)]
extern "system" fn DllGetActivationFactory(
    name: Ref<HSTRING>,
    factory: OutRef<IActivationFactory>,
) -> HRESULT {
    catch_unwind(AssertUnwindSafe(|| {
        if *name == CLASS_NAME {
            factory.write(Some(CLASS_FACTORY.to_interface())).into()
        } else {
            _ = factory.write(None);
            CLASS_E_CLASSNOTAVAILABLE
        }
    }))
    .unwrap_or(E_FAIL)
}

fn vpn_routes() -> Result<VpnRouteAssignment> {
    let routes = VpnRouteAssignment::new()?;
    routes.SetExcludeLocalSubnets(true)?;
    for network in ["0.0.0.0", "128.0.0.0"] {
        routes
            .Ipv4InclusionRoutes()?
            .Append(&VpnRoute::CreateVpnRoute(
                &HostName::CreateHostName(&network.into())?,
                1,
            )?)?;
    }
    for network in ["::", "8000::"] {
        routes
            .Ipv6InclusionRoutes()?
            .Append(&VpnRoute::CreateVpnRoute(
                &HostName::CreateHostName(&network.into())?,
                1,
            )?)?;
    }
    Ok(routes)
}

fn vpn_client_addresses(
    settings: &WindowsNetworkSettings,
) -> Result<(IVectorView<HostName>, IVectorView<HostName>)> {
    Ok((
        IVectorView::from(vec![Some(HostName::CreateHostName(
            &settings.ipv4_address().to_string().into(),
        )?)]),
        IVectorView::from(vec![Some(HostName::CreateHostName(
            &settings.ipv6_address().to_string().into(),
        )?)]),
    ))
}

fn vpn_dns_assignment(settings: &WindowsNetworkSettings) -> Result<VpnDomainNameAssignment> {
    let dns_servers = IVectorView::from(vec![
        Some(HostName::CreateHostName(
            &settings.dns_ipv4_address().to_string().into(),
        )?),
        Some(HostName::CreateHostName(
            &settings.dns_ipv6_address().to_string().into(),
        )?),
    ]);
    let proxy_servers = IVectorView::from(Vec::<Option<HostName>>::new());
    let info = VpnDomainNameInfo::CreateVpnDomainNameInfo(
        &".".into(),
        VpnDomainNameType::Suffix,
        &dns_servers,
        &proxy_servers,
    )?;
    let assignment = VpnDomainNameAssignment::new()?;
    assignment.DomainNameList()?.Append(&info)?;
    Ok(assignment)
}

fn com_boundary<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        log("panic contained at Windows COM boundary");
        Err(Error::new(E_FAIL, "Windows VPN provider panicked"))
    })
}

fn read_buffer(buffer: &Buffer) -> Result<Vec<u8>> {
    let length = buffer.Length()? as usize;
    let access: IBufferByteAccess = buffer.cast()?;
    let pointer = unsafe { access.Buffer()? };
    if pointer.is_null() && length != 0 {
        return Err(Error::new(E_FAIL, "buffer returned a null pointer"));
    }
    Ok(unsafe { slice::from_raw_parts(pointer, length) }.to_vec())
}

fn write_buffer(buffer: &Buffer, bytes: &[u8]) -> Result<()> {
    if bytes.len() > buffer.Capacity()? as usize {
        return Err(Error::from_hresult(E_BOUNDS));
    }
    let access: IBufferByteAccess = buffer.cast()?;
    let pointer = unsafe { access.Buffer()? };
    if pointer.is_null() && !bytes.is_empty() {
        return Err(Error::new(E_FAIL, "buffer returned a null pointer"));
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, bytes.len()) };
    buffer.SetLength(bytes.len() as u32)
}

fn write_dummy(output: &IOutputStream) -> Result<()> {
    let dummy = Buffer::Create(1)?;
    write_buffer(&dummy, &[0])?;
    _ = output.WriteAsync(&dummy)?.join()?;
    Ok(())
}

fn local_folder() -> Result<PathBuf> {
    Ok(PathBuf::from(
        ApplicationData::Current()?
            .LocalFolder()?
            .Path()?
            .to_string(),
    ))
}

fn windows_error(error: impl std::fmt::Display) -> Error {
    Error::new(E_FAIL, error.to_string())
}

fn log(message: &str) {
    if let Ok(path) = local_folder() {
        windows_log::append(&path, "provider", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WinRtGuard;

    impl WinRtGuard {
        fn enter() -> Self {
            unsafe { RoInitialize(RO_INIT_MULTITHREADED).unwrap() };
            Self
        }
    }

    impl Drop for WinRtGuard {
        fn drop(&mut self) {
            unsafe { RoUninitialize() };
        }
    }

    #[test]
    fn adapter_name_matches_winrt_network_adapter_id() {
        let id = GUID::from_u128(0xc2afe445_9ed9_423d_8c29_6b2cd49691d2);
        assert!(adapter_name_matches(
            "{C2AFE445-9ED9-423D-8C29-6B2CD49691D2}",
            id
        ));
        assert!(!adapter_name_matches(
            "{00000000-0000-0000-0000-000000000000}",
            id
        ));
    }

    #[test]
    fn network_identity_is_exact_and_order_independent() {
        let mut names = vec!["network-b".to_owned(), "network-a".to_owned()];
        names.sort_unstable();
        let first = NetworkIdentity {
            profile_name: "Ethernet".to_owned(),
            network_names: names,
        };
        let same = NetworkIdentity {
            profile_name: "Ethernet".to_owned(),
            network_names: vec!["network-a".to_owned(), "network-b".to_owned()],
        };
        let other = NetworkIdentity {
            profile_name: "Wi-Fi".to_owned(),
            network_names: same.network_names.clone(),
        };
        assert_eq!(first, same);
        assert_ne!(first, other);
    }

    #[test]
    fn provider_assignments_use_profile_addresses() {
        let _winrt = WinRtGuard::enter();
        let digest = "0123456789abcdef".repeat(4);
        let profile = crate::windows_profile::WindowsProfileConfiguration::parse(&format!(
            r#"{{"version":2,"snapshotToken":"vcore-session-v2:{digest}","networkSettings":{{"ipv4Address":"192.168.8.1","ipv6Address":"fd00:8::2","dnsIpv4Address":"223.5.5.5","dnsIpv6Address":"2400:3200::1"}}}}"#
        ))
        .unwrap();

        let (ipv4, ipv6) = vpn_client_addresses(profile.network_settings()).unwrap();
        assert_eq!(ipv4.GetAt(0).unwrap().DisplayName().unwrap(), "192.168.8.1");
        assert_eq!(ipv6.GetAt(0).unwrap().DisplayName().unwrap(), "fd00:8::2");

        let dns = vpn_dns_assignment(profile.network_settings()).unwrap();
        let info = dns.DomainNameList().unwrap().GetAt(0).unwrap();
        let servers = info.DnsServers().unwrap();
        assert_eq!(
            servers.GetAt(0).unwrap().DisplayName().unwrap(),
            "223.5.5.5"
        );
        assert_eq!(
            servers.GetAt(1).unwrap().DisplayName().unwrap(),
            "2400:3200::1"
        );
    }

    #[test]
    fn panic_is_contained_at_the_com_boundary() {
        let error = com_boundary(|| -> Result<()> { panic!("test panic") }).unwrap_err();
        assert_eq!(error.code(), E_FAIL);
    }
}
