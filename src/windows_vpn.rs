#![allow(non_snake_case)]

use std::{
    fs::OpenOptions,
    io::{self, Write as _},
    net::{Ipv4Addr, Ipv6Addr},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    slice,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::SyncSender,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use tokio::sync::oneshot;
use windows::{
    ApplicationModel::{
        Background::{IBackgroundTask, IBackgroundTask_Impl, IBackgroundTaskInstance},
        Core::CoreApplication,
    },
    Networking::{
        Connectivity::{
            NetworkConnectivityLevel, NetworkInformation, NetworkStatusChangedEventHandler,
        },
        HostName, HostNameType,
        Sockets::DatagramSocket,
        Vpn::{
            IVpnPlugIn, IVpnPlugIn_Impl, VpnChannel, VpnDomainNameAssignment, VpnDomainNameInfo,
            VpnDomainNameType, VpnInterfaceId, VpnPacketBuffer, VpnPacketBufferList, VpnRoute,
            VpnRouteAssignment,
        },
    },
    Storage::{
        ApplicationData, CreationCollisionOption,
        Streams::{Buffer, IOutputStream},
    },
    Win32::{
        Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_BOUNDS, E_FAIL},
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
    ResourceLimits,
    config::Config,
    dialer::{Dialer, SystemResolver},
    geodata::GeoDataManager,
    platform::{TunIo, WindowsPacketAdapter, WindowsPacketStats},
    runtime::{PreparedCore, RunningCore},
};

const CLASS_NAME: &str = "OneVCore.VpnBackgroundTask";
const PACKET_QUEUE_CAPACITY: usize = 256;
const VIRTUAL_IPV4: &str = "192.168.3.1";
const VIRTUAL_IPV6: &str = "fd00::2";
const VIRTUAL_DNS_IPV4: &str = "192.168.3.2";
const VIRTUAL_DNS_IPV6: &str = "fd00::1";
const FAIL_CLOSED_IDLE: u8 = 0;
const FAIL_CLOSED_STOPPING: u8 = 1;
const FAIL_CLOSED_CANCELLED: u8 = 2;
static VPN_RUNNING: AtomicBool = AtomicBool::new(false);
const CONFIG_YAML: &str = r#"tun:
  enable: true
dns:
  enable: true
  ipv6: true
  nameserver:
    - udp://223.5.5.5:53#DIRECT
    - tcp://223.5.5.5:53#DIRECT
proxies:
  - name: unused
    type: socks5
    server: 127.0.0.1
    port: 9
    udp: false
rules:
  - IP-CIDR,223.5.5.5/32,DIRECT,no-resolve
  - NETWORK,UDP,DIRECT
  - MATCH,unused
"#;

#[derive(Clone)]
struct FailClosedHandle {
    signal: Arc<FailClosedSignal>,
}

struct FailClosedSignal {
    armed: AtomicBool,
    requested: AtomicBool,
    phase: AtomicU8,
    worker: OnceLock<thread::Thread>,
}

impl FailClosedSignal {
    fn wake(&self) {
        if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
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
        if self.signal.phase.load(Ordering::Acquire) != FAIL_CLOSED_IDLE {
            return;
        }
        if !self.signal.requested.swap(true, Ordering::AcqRel) {
            log(&format!("fail-closed stop requested: {reason}"));
        }
        self.signal.wake();
    }

    fn network_changed(&self, physical: PhysicalNetwork) {
        match physical.is_available() {
            Ok(true) => {}
            Ok(false) => self.request("physical network is no longer available"),
            Err(_) => self.request("physical network validation failed"),
        }
    }
}

struct FailClosedStop {
    signal: Arc<FailClosedSignal>,
    thread: Option<JoinHandle<()>>,
}

impl FailClosedStop {
    fn start(channel: &VpnChannel) -> Result<(Self, FailClosedHandle)> {
        let channel = AgileReference::new(channel)?;
        let signal = Arc::new(FailClosedSignal {
            armed: AtomicBool::new(false),
            requested: AtomicBool::new(false),
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
struct PhysicalNetwork {
    adapter_id: GUID,
    connectivity: NetworkConnectivityLevel,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

impl PhysicalNetwork {
    fn current() -> Result<Self> {
        let profile = NetworkInformation::GetInternetConnectionProfile()?;
        let adapter_id = profile.NetworkAdapter()?.NetworkAdapterId()?;
        let connectivity = profile.GetNetworkConnectivityLevel()?;
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
                "physical network has no bindable IP address",
            ));
        }
        Ok(Self {
            adapter_id,
            connectivity,
            ipv4: ipv4.into_iter().next(),
            ipv6: ipv6.into_iter().next(),
        })
    }

    fn is_available(self) -> Result<bool> {
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
                && profile.GetNetworkConnectivityLevel()? == self.connectivity
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct ProviderRuntime {
    stop: Option<oneshot::Sender<()>>,
    stop_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl ProviderRuntime {
    fn start(
        local_folder: PathBuf,
        physical: PhysicalNetwork,
        tun: TunIo,
        fail_closed: FailClosedHandle,
    ) -> Result<Self> {
        let (stop_tx, stop_rx) = oneshot::channel();
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let startup_failure = startup_tx.clone();
        let startup_complete = Arc::new(AtomicBool::new(false));
        let thread_startup_complete = startup_complete.clone();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let log_path = local_folder.join("phase1.log");
        let thread = thread::Builder::new()
            .name("vcore-windows-vpn".into())
            .stack_size(1024 * 1024)
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
                    if let Err(error) = initialized {
                        let message = format!("WinRT initialization failed: {error}");
                        _ = startup_tx.send(Err(message.clone()));
                        return Err(io::Error::other(message));
                    }
                    let result = run_vcore(
                        &local_folder,
                        physical,
                        tun,
                        stop_rx,
                        startup_tx,
                        &thread_startup_complete,
                    );
                    unsafe { RoUninitialize() };
                    result
                }))
                .unwrap_or_else(|_| {
                    let message = "VCore runtime thread panicked";
                    _ = startup_failure.send(Err(message.into()));
                    Err(io::Error::other(message))
                });

                if thread_startup_complete.load(Ordering::Acquire)
                    && !thread_stop_requested.load(Ordering::Acquire)
                {
                    fail_closed.request("VCore runtime exited unexpectedly");
                }
                if let Err(error) = &result {
                    log_to(&log_path, &format!("VCore runtime failed: {error}"));
                }
                result
            })
            .map_err(windows_error)?;

        let runtime = Self {
            stop: Some(stop_tx),
            stop_requested,
            thread: Some(thread),
        };
        match startup_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(runtime),
            Ok(Err(message)) => {
                let _ = runtime.stop();
                Err(Error::new(E_FAIL, message))
            }
            Err(error) => {
                let _ = runtime.stop();
                Err(Error::new(E_FAIL, format!("VCore startup failed: {error}")))
            }
        }
    }

    fn stop(mut self) -> io::Result<()> {
        self.stop_requested.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            _ = stop.send(());
        }
        self.thread
            .take()
            .ok_or_else(|| io::Error::other("VCore runtime thread is missing"))?
            .join()
            .map_err(|_| io::Error::other("VCore runtime thread panicked"))?
    }
}

impl Drop for ProviderRuntime {
    fn drop(&mut self) {
        self.stop_requested.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            _ = stop.send(());
        }
    }
}

fn run_vcore(
    local_folder: &Path,
    physical: PhysicalNetwork,
    tun: TunIo,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<std::result::Result<(), String>>,
    startup_complete: &AtomicBool,
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let started = runtime.block_on(async {
        let config = Config::parse_yaml(CONFIG_YAML.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let geodata = GeoDataManager::open(
            local_folder.join("phase1-geodata"),
            Duration::from_secs(24 * 60 * 60),
        )
        .map_err(io::Error::other)?;
        let prepared = PreparedCore::prepare_config(
            config,
            geodata,
            &SystemResolver,
            ResourceLimits::for_runtime(true),
        )
        .await?;
        prepared
            .start_tun(
                tun,
                Dialer::default().with_source_ips(physical.ipv4, physical.ipv6),
            )
            .await
    });
    let running: RunningCore = match started {
        Ok(running) => {
            startup_complete.store(true, Ordering::Release);
            if startup.send(Ok(())).is_err() {
                return runtime.block_on(running.stop());
            }
            running
        }
        Err(error) => {
            let message = error.to_string();
            _ = startup.send(Err(message));
            return Err(error);
        }
    };
    runtime.block_on(running.run_until_shutdown(async move {
        _ = stop.await;
        Ok(())
    }))
}

struct ProviderState {
    transport: Option<DatagramSocket>,
    back_transport: Option<DatagramSocket>,
    packets: Option<WindowsPacketAdapter>,
    runtime: Option<ProviderRuntime>,
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
            runtime: None,
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
        let physical = PhysicalNetwork::current()?;
        let local_folder_object = ApplicationData::Current()?.LocalFolder()?;
        local_folder_object
            .CreateFolderAsync(
                &"phase1-geodata".into(),
                CreationCollisionOption::OpenIfExists,
            )?
            .join()?;
        let local_folder = PathBuf::from(local_folder_object.Path()?.to_string());

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
        let assigned_ipv4 =
            IVectorView::from(vec![Some(HostName::CreateHostName(&VIRTUAL_IPV4.into())?)]);
        let assigned_ipv6 =
            IVectorView::from(vec![Some(HostName::CreateHostName(&VIRTUAL_IPV6.into())?)]);
        let dns = vpn_dns_assignment()?;

        let wake_output = AgileReference::new(&output)?;
        let (tun, packets) = TunIo::new(PACKET_QUEUE_CAPACITY, move || {
            write_dummy(&wake_output.resolve().map_err(io::Error::other)?).map_err(io::Error::other)
        });
        let (fail_closed, fail_closed_handle) = FailClosedStop::start(channel)?;
        let runtime =
            ProviderRuntime::start(local_folder, physical, tun, fail_closed_handle.clone())?;

        {
            let mut state = self.lock_state()?;
            state.transport = Some(transport.clone());
            state.back_transport = Some(back_transport);
            state.packets = Some(packets);
            state.runtime = Some(runtime);
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
            network_stop.network_changed(physical);
            Ok(())
        });
        let token = NetworkInformation::NetworkStatusChanged(&handler)?;
        self.lock_state()?.network_status_token = Some(token);
        fail_closed_handle.arm();

        log(&format!(
            "connect ok: adapter={:?} physical_ipv4={:?} physical_ipv6={:?}",
            physical.adapter_id, physical.ipv4, physical.ipv6
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

    fn stop_runtime(&self) -> Result<()> {
        let (token, mut fail_closed, runtime) = {
            let mut state = self.lock_state()?;
            (
                state.network_status_token.take(),
                state.fail_closed.take(),
                state.runtime.take(),
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
        if let Some(runtime) = runtime {
            if let Err(error) = runtime.stop() {
                first_error.get_or_insert_with(|| windows_error(error));
            } else {
                log("VCore runtime stopped");
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
            if self.lock_state()?.runtime.is_some() {
                let error = Error::new(E_FAIL, "Windows VPN provider is already running");
                log("duplicate Connect rejected without disturbing the active runtime");
                _ = channel.SetErrorMessage(&error.to_string().into());
                return Err(error);
            }
            VPN_RUNNING.store(true, Ordering::Release);
            if let Err(error) = com_boundary(|| self.connect_inner(channel)) {
                _ = self.stop_runtime();
                _ = self.reset_state();
                VPN_RUNNING.store(false, Ordering::Release);
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
            let runtime_result = self.stop_runtime();
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
            channel_result?;
            runtime_result
        });
        if result.is_err() {
            VPN_RUNNING.store(false, Ordering::Release);
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
            if !VPN_RUNNING.load(Ordering::Acquire) {
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

fn vpn_dns_assignment() -> Result<VpnDomainNameAssignment> {
    let dns_servers = IVectorView::from(vec![
        Some(HostName::CreateHostName(&VIRTUAL_DNS_IPV4.into())?),
        Some(HostName::CreateHostName(&VIRTUAL_DNS_IPV6.into())?),
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

static LOG_LOCK: Mutex<()> = Mutex::new(());

fn log(message: &str) {
    if let Ok(path) = local_folder() {
        log_to(&path.join("phase1.log"), message);
    }
}

fn log_to(path: &Path, message: &str) {
    let Ok(_guard) = LOG_LOCK.lock() else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        _ = writeln!(file, "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_configuration_is_current_bounded_and_enables_dns() {
        assert!(CONFIG_YAML.len() < 1024);
        let config = Config::parse_yaml(CONFIG_YAML.as_bytes()).unwrap();
        assert!(config.dns.enable);
    }

    #[test]
    fn panic_is_contained_at_the_com_boundary() {
        let error = com_boundary(|| -> Result<()> { panic!("test panic") }).unwrap_err();
        assert_eq!(error.code(), E_FAIL);
    }
}
