#![allow(non_snake_case)]

use std::{
    fs::OpenOptions,
    io::{self, Write as _},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    slice,
    sync::{Mutex, mpsc::SyncSender},
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
        HostName,
        Sockets::DatagramSocket,
        Vpn::{
            IVpnPlugIn, IVpnPlugIn_Impl, VpnChannel, VpnDomainNameAssignment, VpnInterfaceId,
            VpnPacketBuffer, VpnPacketBufferList, VpnRoute, VpnRouteAssignment,
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
        Error, HRESULT, HSTRING, IInspectable, Interface as _, OutRef, Ref, Result,
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
    platform::{TunIo, WindowsPacketAdapter},
    runtime::{PreparedCore, RunningCore},
};

const CLASS_NAME: &str = "OneVCore.VpnBackgroundTask";
const PACKET_QUEUE_CAPACITY: usize = 256;
const CONFIG_YAML: &str = r#"tun:
  enable: true
proxies:
  - name: unused
    type: socks5
    server: 127.0.0.1
    port: 9
    udp: false
rules:
  - IP-CIDR,223.5.5.5/32,DIRECT,no-resolve
  - MATCH,unused
"#;

struct ProviderRuntime {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl ProviderRuntime {
    fn start(local_folder: PathBuf, physical_ip: Ipv4Addr, tun: TunIo) -> Result<Self> {
        let (stop_tx, stop_rx) = oneshot::channel();
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let log_path = local_folder.join("phase1.log");
        let thread = thread::Builder::new()
            .name("vcore-windows-vpn".into())
            .stack_size(1024 * 1024)
            .spawn(move || {
                let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
                if let Err(error) = initialized {
                    let message = format!("WinRT initialization failed: {error}");
                    let _ = startup_tx.send(Err(message.clone()));
                    return Err(io::Error::other(message));
                }
                let result = run_vcore(&local_folder, physical_ip, tun, stop_rx, startup_tx);
                if let Err(error) = &result {
                    log_to(&log_path, &format!("VCore runtime failed: {error}"));
                }
                unsafe { RoUninitialize() };
                result
            })
            .map_err(windows_error)?;

        let runtime = Self {
            stop: Some(stop_tx),
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
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
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
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn run_vcore(
    local_folder: &Path,
    physical_ip: Ipv4Addr,
    tun: TunIo,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<std::result::Result<(), String>>,
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
                Dialer::default().with_source_ip(IpAddr::V4(physical_ip)),
            )
            .await
    });
    let running: RunningCore = match started {
        Ok(running) => {
            if startup.send(Ok(())).is_err() {
                return runtime.block_on(running.stop());
            }
            running
        }
        Err(error) => {
            let message = error.to_string();
            let _ = startup.send(Err(message));
            return Err(error);
        }
    };
    runtime.block_on(running.run_until_shutdown(async move {
        let _ = stop.await;
        Ok(())
    }))
}

struct ProviderState {
    transport: Option<DatagramSocket>,
    back_transport: Option<DatagramSocket>,
    packets: Option<WindowsPacketAdapter>,
    runtime: Option<ProviderRuntime>,
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
            encapsulated: 0,
            decapsulated: 0,
        }
    }
}

#[implement(IVpnPlugIn)]
struct VpnProvider {
    state: Mutex<ProviderState>,
}

impl VpnProvider {
    const fn new() -> Self {
        Self {
            state: Mutex::new(ProviderState::new()),
        }
    }

    fn connect_inner(&self, channel: &VpnChannel) -> Result<()> {
        let physical_ip = channel
            .Configuration()?
            .CustomField()?
            .to_string()
            .parse::<Ipv4Addr>()
            .map_err(|error| Error::new(E_FAIL, format!("invalid physical IPv4: {error}")))?;
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

        let routes = VpnRouteAssignment::new()?;
        routes.SetExcludeLocalSubnets(true)?;
        let ipv4_routes = routes.Ipv4InclusionRoutes()?;
        ipv4_routes.Append(&VpnRoute::CreateVpnRoute(
            &HostName::CreateHostName(&"0.0.0.0".into())?,
            1,
        )?)?;
        ipv4_routes.Append(&VpnRoute::CreateVpnRoute(
            &HostName::CreateHostName(&"128.0.0.0".into())?,
            1,
        )?)?;
        let assigned_ipv4 =
            IVectorView::from(vec![Some(HostName::CreateHostName(&"192.168.3.1".into())?)]);

        let wake_output = AgileReference::new(&output)?;
        let (tun, packets) = TunIo::new(PACKET_QUEUE_CAPACITY, move || {
            write_dummy(&wake_output.resolve().map_err(io::Error::other)?).map_err(io::Error::other)
        });
        let runtime = ProviderRuntime::start(local_folder, physical_ip, tun)?;

        {
            let mut state = self.lock_state()?;
            if state.runtime.is_some() {
                return Err(Error::new(
                    E_FAIL,
                    "Windows VPN provider is already running",
                ));
            }
            state.transport = Some(transport.clone());
            state.back_transport = Some(back_transport);
            state.packets = Some(packets);
            state.runtime = Some(runtime);
        }

        channel.StartWithMainTransport(
            &assigned_ipv4,
            None::<&IVectorView<HostName>>,
            None::<&VpnInterfaceId>,
            &routes,
            None::<&VpnDomainNameAssignment>,
            1500,
            1512,
            false,
            &transport,
        )?;
        log(&format!("connect ok: physical_ipv4={physical_ip}"));
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ProviderState>> {
        self.state
            .lock()
            .map_err(|_| Error::new(E_FAIL, "Windows VPN provider state lock poisoned"))
    }

    fn stop_runtime(&self) -> Result<()> {
        let runtime = self.lock_state()?.runtime.take();
        if let Some(runtime) = runtime {
            runtime.stop().map_err(windows_error)?;
            log("VCore runtime stopped");
        }
        Ok(())
    }

    fn reset_state(&self) -> Result<(u64, u64)> {
        let mut state = self.lock_state()?;
        let counters = (state.encapsulated, state.decapsulated);
        *state = ProviderState::new();
        Ok(counters)
    }
}

impl IVpnPlugIn_Impl for VpnProvider_Impl {
    fn Connect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.ok()?;
        if let Err(error) = self.connect_inner(channel) {
            let _ = self.stop_runtime();
            let _ = self.reset_state();
            log(&format!("connect failed: {error}"));
            _ = channel.SetErrorMessage(&error.to_string().into());
            Err(error)
        } else {
            Ok(())
        }
    }

    fn Disconnect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.ok()?;
        let runtime_result = self.stop_runtime();
        let channel_result = channel.Stop();
        let (encapsulated, decapsulated) = self.reset_state()?;
        log(&format!(
            "disconnect: encapsulated={encapsulated} decapsulated={decapsulated}"
        ));
        channel_result?;
        runtime_result
    }

    fn GetKeepAlivePayload(
        &self,
        _channel: Ref<VpnChannel>,
        packet: OutRef<VpnPacketBuffer>,
    ) -> Result<()> {
        packet.write(None).into()
    }

    fn Encapsulate(
        &self,
        _channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        _encapsulated: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let packets = packets.ok()?;
        let count = packets.Size()?;
        for _ in 0..count {
            let packet = packets.RemoveAtBegin()?;
            let copied = packet.Buffer().and_then(|buffer| read_buffer(&buffer));
            packets.Append(&packet)?;
            let bytes = copied?;
            let (adapter, first) = {
                let mut state = self.lock_state()?;
                state.encapsulated += 1;
                (state.packets.clone(), state.encapsulated == 1)
            };
            if first {
                log(&format!(
                    "first VCore ingress packet: {} bytes",
                    bytes.len()
                ));
            }
            if !adapter.is_some_and(|adapter| adapter.try_send(bytes)) {
                log("VCore ingress queue unavailable: packet dropped");
            }
        }
        Ok(())
    }

    fn Decapsulate(
        &self,
        channel: Ref<VpnChannel>,
        buffer: Ref<VpnPacketBuffer>,
        packets: Ref<VpnPacketBufferList>,
        control: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
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
                state.decapsulated += 1;
                state.decapsulated == 1
            };
            if first {
                log(&format!("first VCore egress packet: {} bytes", bytes.len()));
            }
        }
        Ok(())
    }
}

#[implement(IBackgroundTask)]
struct BackgroundTask;

impl IBackgroundTask_Impl for BackgroundTask_Impl {
    fn Run(&self, task: Ref<IBackgroundTaskInstance>) -> Result<()> {
        let task = task.ok()?;
        let deferral = task.GetDeferral()?;
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
        let result = VpnChannel::ProcessEventAsync(&provider, &trigger);
        _ = deferral.Complete();
        result
    }
}

#[implement(IActivationFactory)]
struct ClassFactory;

impl IActivationFactory_Impl for ClassFactory_Impl {
    fn ActivateInstance(&self) -> Result<IInspectable> {
        Ok(BackgroundTask.into())
    }
}

static CLASS_FACTORY: StaticComObject<ClassFactory> = ClassFactory.into_static();

#[unsafe(no_mangle)]
extern "system" fn DllGetActivationFactory(
    name: Ref<HSTRING>,
    factory: OutRef<IActivationFactory>,
) -> HRESULT {
    if *name == CLASS_NAME {
        factory.write(Some(CLASS_FACTORY.to_interface())).into()
    } else {
        _ = factory.write(None);
        CLASS_E_CLASSNOTAVAILABLE
    }
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
    fn embedded_configuration_is_current_and_bounded() {
        assert!(CONFIG_YAML.len() < 1024);
        Config::parse_yaml(CONFIG_YAML.as_bytes()).unwrap();
    }
}
