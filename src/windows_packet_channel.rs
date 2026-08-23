use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::windows::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(test)]
use std::io::Read;

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::windows::named_pipe::ServerOptions,
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{Isolation::GetAppContainerNamedObjectPath, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use crate::{platform::TunIo, windows_snapshot::SnapshotReference};

pub(crate) const PROTOCOL_VERSION: u32 = 1;
pub(crate) const CONTROL_LEAF: &str = "OneVCore.Vpn.Control.v1";
pub(crate) const DATA_LEAF: &str = "OneVCore.Vpn.Data.v1";
pub(crate) const RENDEZVOUS_FILE: &str = "vcore/windows/rendezvous.json";
const MAX_CONTROL_BYTES: usize = 16 * 1024;
const MAX_RENDEZVOUS_BYTES: usize = 4 * 1024;
const MAX_ERROR_BYTES: usize = 4 * 1024;
const MAX_PACKET_BYTES: usize = 1_500;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const SESSION_START_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AddressBindingV4 {
    pub(crate) source: Ipv4Addr,
    pub(crate) interface_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AddressBindingV6 {
    pub(crate) source: Ipv6Addr,
    pub(crate) interface_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PhysicalBinding {
    pub(crate) adapter_id: String,
    pub(crate) profile_name: String,
    pub(crate) network_names: Vec<String>,
    pub(crate) ipv4: Option<AddressBindingV4>,
    pub(crate) ipv6: Option<AddressBindingV6>,
}

impl PhysicalBinding {
    fn validate(&self) -> io::Result<()> {
        if self.adapter_id.is_empty()
            || self.profile_name.is_empty()
            || self
                .ipv4
                .as_ref()
                .is_some_and(|binding| binding.interface_index == 0)
            || self
                .ipv6
                .as_ref()
                .is_some_and(|binding| binding.interface_index == 0)
            || self.ipv4.is_none() && self.ipv6.is_none()
        {
            return Err(invalid_data("invalid physical network binding"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PacketCounters {
    pub(crate) encapsulated: u64,
    pub(crate) decapsulated: u64,
    pub(crate) ingress_queue_dropped: u64,
    pub(crate) ingress_closed: u64,
    pub(crate) egress_queue_dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum ControlMessage {
    SessionHello {
        version: u32,
        snapshot_token: String,
    },
    ProviderHello {
        version: u32,
        snapshot_token: String,
        physical_binding: PhysicalBinding,
    },
    RuntimeReady {
        version: u32,
    },
    RuntimeFailed {
        version: u32,
        code: String,
        redacted_message: String,
    },
    Stop {
        version: u32,
        packet_counters: PacketCounters,
    },
    Stopped {
        version: u32,
        packet_counters: PacketCounters,
    },
}

impl ControlMessage {
    fn validate(&self) -> io::Result<()> {
        let version = match self {
            Self::SessionHello { version, .. }
            | Self::ProviderHello { version, .. }
            | Self::RuntimeReady { version }
            | Self::RuntimeFailed { version, .. }
            | Self::Stop { version, .. }
            | Self::Stopped { version, .. } => *version,
        };
        if version != PROTOCOL_VERSION {
            return Err(invalid_data("unsupported Windows packet-channel version"));
        }
        match self {
            Self::SessionHello { snapshot_token, .. }
            | Self::ProviderHello { snapshot_token, .. } => {
                SnapshotReference::parse(snapshot_token).map_err(io::Error::other)?;
            }
            _ => {}
        }
        if let Self::ProviderHello {
            physical_binding, ..
        } = self
        {
            physical_binding.validate()?;
        }
        if let Self::RuntimeFailed {
            code,
            redacted_message,
            ..
        } = self
            && (code.is_empty() || code.len() > 128 || redacted_message.len() > MAX_ERROR_BYTES)
        {
            return Err(invalid_data("invalid Windows runtime failure"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Rendezvous {
    pub(crate) protocol_version: u32,
    pub(crate) snapshot_token: String,
    pub(crate) object_path: String,
    pub(crate) control_leaf: String,
    pub(crate) data_leaf: String,
}

impl Rendezvous {
    #[allow(dead_code)] // Provider publication lands in Phase 3.
    pub(crate) fn new(snapshot_token: String, object_path: String) -> io::Result<Self> {
        let rendezvous = Self {
            protocol_version: PROTOCOL_VERSION,
            snapshot_token,
            object_path,
            control_leaf: CONTROL_LEAF.to_owned(),
            data_leaf: DATA_LEAF.to_owned(),
        };
        rendezvous.validate()?;
        Ok(rendezvous)
    }

    pub(crate) fn from_json(bytes: &[u8], expected_token: &str) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RENDEZVOUS_BYTES {
            return Err(invalid_data("invalid Windows rendezvous size"));
        }
        let rendezvous: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid_data("invalid Windows rendezvous JSON"))?;
        rendezvous.validate()?;
        if rendezvous.snapshot_token != expected_token {
            return Err(invalid_data("Windows rendezvous snapshot mismatch"));
        }
        Ok(rendezvous)
    }

    #[allow(dead_code)] // Provider publication lands in Phase 3.
    pub(crate) fn to_json(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.len() > MAX_RENDEZVOUS_BYTES {
            return Err(invalid_data("Windows rendezvous exceeds its size limit"));
        }
        Ok(bytes)
    }

    pub(crate) fn qualified_names(&self, session_id: u32) -> io::Result<(String, String)> {
        self.validate()?;
        let prefix = format!(r"\\.\pipe\Sessions\{session_id}\{}", self.object_path);
        Ok((
            format!(r"{prefix}\{}", self.control_leaf),
            format!(r"{prefix}\{}", self.data_leaf),
        ))
    }

    fn validate(&self) -> io::Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.control_leaf != CONTROL_LEAF
            || self.data_leaf != DATA_LEAF
            || !valid_object_path(&self.object_path)
        {
            return Err(invalid_data("invalid Windows rendezvous"));
        }
        SnapshotReference::parse(&self.snapshot_token).map_err(io::Error::other)?;
        Ok(())
    }
}

pub(crate) struct ProviderPacketSession {
    stop: Option<oneshot::Sender<PacketCounters>>,
    stop_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl ProviderPacketSession {
    pub(crate) fn start(
        local_folder: PathBuf,
        token: String,
        physical_binding: PhysicalBinding,
        tun: TunIo,
        unexpected_exit: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let (stop_tx, stop_rx) = oneshot::channel();
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let startup_fallback = startup_tx.clone();
        let startup_complete = Arc::new(AtomicBool::new(false));
        let thread_startup_complete = Arc::clone(&startup_complete);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = Arc::clone(&stop_requested);
        let unexpected_exit = Arc::new(unexpected_exit);
        let thread = thread::Builder::new()
            .name("vcore-windows-packet-channel".to_owned())
            .stack_size(512 * 1024)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()?;
                let result = runtime.block_on(run_provider_session(
                    &local_folder,
                    &token,
                    physical_binding,
                    tun,
                    stop_rx,
                    startup_tx,
                    &thread_startup_complete,
                ));
                if thread_startup_complete.load(Ordering::Acquire)
                    && !thread_stop_requested.load(Ordering::Acquire)
                {
                    unexpected_exit();
                }
                if let Err(error) = &result {
                    _ = startup_fallback.try_send(Err(error.to_string()));
                }
                result
            })?;
        let session = Self {
            stop: Some(stop_tx),
            stop_requested,
            thread: Some(thread),
        };
        match startup_rx.recv_timeout(SESSION_START_TIMEOUT) {
            Ok(Ok(())) => Ok(session),
            Ok(Err(message)) => {
                _ = session.stop(PacketCounters::default());
                Err(io::Error::other(message))
            }
            Err(error) => {
                _ = session.stop(PacketCounters::default());
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Windows packet channel startup failed: {error}"),
                ))
            }
        }
    }

    pub(crate) fn stop(mut self, counters: PacketCounters) -> io::Result<()> {
        self.stop_requested.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            _ = stop.send(counters);
        }
        self.thread
            .take()
            .ok_or_else(|| io::Error::other("Windows packet-channel thread is missing"))?
            .join()
            .map_err(|_| io::Error::other("Windows packet-channel thread panicked"))?
    }
}

impl Drop for ProviderPacketSession {
    fn drop(&mut self) {
        self.stop_requested.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            _ = stop.send(PacketCounters::default());
        }
    }
}

async fn run_provider_session(
    local_folder: &Path,
    token: &str,
    physical_binding: PhysicalBinding,
    tun: TunIo,
    stop: oneshot::Receiver<PacketCounters>,
    startup: mpsc::SyncSender<Result<(), String>>,
    startup_complete: &AtomicBool,
) -> io::Result<()> {
    let control_name = format!(r"\\.\pipe\LOCAL\{CONTROL_LEAF}");
    let data_name = format!(r"\\.\pipe\LOCAL\{DATA_LEAF}");
    let control = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&control_name)?;
    let data = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&data_name)?;
    let rendezvous = Rendezvous::new(token.to_owned(), current_appcontainer_object_path()?)?;
    publish_rendezvous(local_folder, &rendezvous)?;
    let _cleanup = RendezvousCleanup(local_folder);

    timeout(SESSION_START_TIMEOUT, async {
        tokio::try_join!(control.connect(), data.connect())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Session Host did not connect"))??;
    remove_rendezvous(local_folder)?;

    let (mut control_read, mut control_write) = tokio::io::split(control);
    match read_control_async(&mut control_read).await? {
        ControlMessage::SessionHello { snapshot_token, .. } if snapshot_token == token => {}
        _ => return Err(invalid_data("invalid Session Host handshake")),
    }
    write_control_async(
        &mut control_write,
        &ControlMessage::ProviderHello {
            version: PROTOCOL_VERSION,
            snapshot_token: token.to_owned(),
            physical_binding,
        },
    )
    .await?;
    match read_control_async(&mut control_read).await? {
        ControlMessage::RuntimeReady { .. } => {}
        ControlMessage::RuntimeFailed { .. } => {
            return Err(io::Error::other("Session Host runtime failed to start"));
        }
        _ => return Err(invalid_data("invalid Session Host startup response")),
    }

    let tun = Arc::new(tun);
    let (mut data_read, mut data_write) = tokio::io::split(data);
    let mut data_tasks = JoinSet::new();
    let ingress = Arc::clone(&tun);
    data_tasks.spawn(async move {
        let mut packet = Vec::with_capacity(MAX_PACKET_BYTES);
        loop {
            ingress
                .read_packet(&mut packet)
                .await
                .map_err(io::Error::other)?;
            write_packet_frame_async(&mut data_write, &packet).await?;
        }
    });
    let egress = Arc::clone(&tun);
    data_tasks.spawn(async move {
        loop {
            let packet = read_packet_frame_async(&mut data_read).await?;
            egress
                .write_packet(&packet)
                .await
                .map_err(io::Error::other)?;
        }
    });

    startup_complete.store(true, Ordering::Release);
    if startup.send(Ok(())).is_err() {
        return Ok(());
    }

    enum End {
        Stop(PacketCounters),
        Failed(io::Error),
    }
    let end = tokio::select! {
        counters = stop => End::Stop(counters.unwrap_or_default()),
        message = read_control_async(&mut control_read) => End::Failed(match message {
            Ok(ControlMessage::RuntimeFailed { .. }) => io::Error::other("Session Host runtime failed"),
            Ok(_) => invalid_data("unexpected Session Host control message"),
            Err(error) => error,
        }),
        joined = data_tasks.join_next() => End::Failed(match joined {
            Some(Ok(Ok(()))) | None => io::Error::new(io::ErrorKind::UnexpectedEof, "packet task exited"),
            Some(Ok(Err(error))) => error,
            Some(Err(error)) => io::Error::other(error),
        }),
    };

    let result = match end {
        End::Stop(packet_counters) => {
            write_control_async(
                &mut control_write,
                &ControlMessage::Stop {
                    version: PROTOCOL_VERSION,
                    packet_counters,
                },
            )
            .await?;
            match timeout(SESSION_STOP_TIMEOUT, read_control_async(&mut control_read)).await {
                Ok(Ok(ControlMessage::Stopped {
                    packet_counters: returned,
                    ..
                })) if returned == packet_counters => Ok(()),
                Ok(Ok(_)) => Err(invalid_data("invalid Session Host stop response")),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Session Host stop timed out",
                )),
            }
        }
        End::Failed(error) => Err(error),
    };
    data_tasks.abort_all();
    while data_tasks.join_next().await.is_some() {}
    result
}

struct RendezvousCleanup<'a>(&'a Path);

impl Drop for RendezvousCleanup<'_> {
    fn drop(&mut self) {
        _ = remove_rendezvous(self.0);
    }
}

fn publish_rendezvous(local_folder: &Path, rendezvous: &Rendezvous) -> io::Result<()> {
    let target = local_folder.join(RENDEZVOUS_FILE);
    let directory = target
        .parent()
        .ok_or_else(|| invalid_data("Windows rendezvous directory is missing"))?;
    fs::create_dir_all(directory)?;
    for path in [
        local_folder.join("vcore"),
        local_folder.join("vcore/windows"),
    ] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_data("invalid Windows rendezvous directory"));
        }
    }
    let staging = directory.join(format!("rendezvous-{}.staging", std::process::id()));
    _ = fs::remove_file(&staging);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)?;
    file.write_all(&rendezvous.to_json()?)?;
    file.sync_all()?;
    drop(file);
    _ = fs::remove_file(&target);
    let result = fs::rename(&staging, &target);
    if result.is_err() {
        _ = fs::remove_file(staging);
    }
    result
}

fn current_appcontainer_object_path() -> io::Result<String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(io::Error::other)?;
    let mut required = 0;
    _ = unsafe { GetAppContainerNamedObjectPath(Some(token), None, None, &mut required) };
    if required == 0 {
        unsafe { _ = CloseHandle(token) };
        return Err(io::Error::other("AppContainer object path length is zero"));
    }
    let mut buffer = vec![0_u16; required as usize];
    let result = unsafe {
        GetAppContainerNamedObjectPath(Some(token), None, Some(&mut buffer), &mut required)
    };
    unsafe { _ = CloseHandle(token) };
    result.map_err(io::Error::other)?;
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).map_err(io::Error::other)
}

#[cfg(test)]
pub(crate) fn write_control(writer: &mut impl Write, message: &ControlMessage) -> io::Result<()> {
    message.validate()?;
    let bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(invalid_data(
            "Windows control message exceeds its size limit",
        ));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

#[cfg(test)]
pub(crate) fn read_control(reader: &mut impl Read) -> io::Result<ControlMessage> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_CONTROL_BYTES {
        return Err(invalid_data("invalid Windows control message size"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let message: ControlMessage = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_data("invalid Windows control message"))?;
    message.validate()?;
    Ok(message)
}

pub(crate) async fn write_control_async(
    writer: &mut (impl AsyncWrite + Unpin),
    message: &ControlMessage,
) -> io::Result<()> {
    message.validate()?;
    let bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(invalid_data(
            "Windows control message exceeds its size limit",
        ));
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

pub(crate) async fn read_control_async(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<ControlMessage> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_CONTROL_BYTES {
        return Err(invalid_data("invalid Windows control message size"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    let message: ControlMessage = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_data("invalid Windows control message"))?;
    message.validate()?;
    Ok(message)
}

#[cfg(test)]
pub(crate) fn write_packet_frame(writer: &mut impl Write, packet: &[u8]) -> io::Result<()> {
    if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
        return Err(invalid_data("invalid Windows packet frame size"));
    }
    writer.write_all(&(packet.len() as u16).to_be_bytes())?;
    writer.write_all(packet)?;
    writer.flush()
}

#[cfg(test)]
pub(crate) fn read_packet_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0; 2];
    reader.read_exact(&mut header)?;
    let length = u16::from_be_bytes(header) as usize;
    if !(1..=MAX_PACKET_BYTES).contains(&length) {
        return Err(invalid_data("invalid Windows packet frame size"));
    }
    let mut packet = vec![0; length];
    reader.read_exact(&mut packet)?;
    Ok(packet)
}

pub(crate) async fn write_packet_frame_async(
    writer: &mut (impl AsyncWrite + Unpin),
    packet: &[u8],
) -> io::Result<()> {
    if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
        return Err(invalid_data("invalid Windows packet frame size"));
    }
    writer
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(packet).await?;
    writer.flush().await
}

pub(crate) async fn read_packet_frame_async(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<Vec<u8>> {
    let length = reader.read_u16().await? as usize;
    if !(1..=MAX_PACKET_BYTES).contains(&length) {
        return Err(invalid_data("invalid Windows packet frame size"));
    }
    let mut packet = vec![0; length];
    reader.read_exact(&mut packet).await?;
    Ok(packet)
}

pub(crate) fn read_rendezvous(local_folder: &Path, expected_token: &str) -> io::Result<Rendezvous> {
    let path = local_folder.join(RENDEZVOUS_FILE);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() == 0
        || metadata.len() > MAX_RENDEZVOUS_BYTES as u64
    {
        return Err(invalid_data("invalid Windows rendezvous file"));
    }
    Rendezvous::from_json(&fs::read(path)?, expected_token)
}

pub(crate) fn remove_rendezvous(local_folder: &Path) -> io::Result<()> {
    match fs::remove_file(local_folder.join(RENDEZVOUS_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn valid_object_path(path: &str) -> bool {
    let Some(sid) = path.strip_prefix("AppContainerNamedObjects\\S-1-15-2-") else {
        return false;
    };
    let mut parts = sid.split('-');
    (0..7).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const TOKEN: &str =
        "onevcore-v1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OBJECT_PATH: &str = "AppContainerNamedObjects\\S-1-15-2-3625493040-1926059196-1414268811-1331793124-1328616665-2242015017-1330142422";

    fn binding() -> PhysicalBinding {
        PhysicalBinding {
            adapter_id: "C2AFE445-9ED9-423D-8C29-6B2CD49691D2".to_owned(),
            profile_name: "Ethernet".to_owned(),
            network_names: vec!["network".to_owned()],
            ipv4: Some(AddressBindingV4 {
                source: Ipv4Addr::new(172, 16, 29, 130),
                interface_index: 10,
            }),
            ipv6: None,
        }
    }

    #[test]
    fn control_messages_round_trip_through_the_bounded_wire_format() {
        let expected = ControlMessage::ProviderHello {
            version: PROTOCOL_VERSION,
            snapshot_token: TOKEN.to_owned(),
            physical_binding: binding(),
        };
        let mut wire = Vec::new();
        write_control(&mut wire, &expected).unwrap();
        assert_eq!(read_control(&mut Cursor::new(wire)).unwrap(), expected);
    }

    #[test]
    fn control_messages_reject_unknown_fields_and_versions() {
        for payload in [
            br#"{"type":"runtimeReady","version":1,"extra":true}"#.as_slice(),
            br#"{"type":"runtimeReady","version":2}"#.as_slice(),
        ] {
            let mut wire = Vec::new();
            wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(payload);
            assert!(read_control(&mut Cursor::new(wire)).is_err());
        }
    }

    #[test]
    fn packet_frames_preserve_boundaries_and_reject_invalid_lengths() {
        let packet = vec![0x45; MAX_PACKET_BYTES];
        let mut wire = Vec::new();
        write_packet_frame(&mut wire, &packet).unwrap();
        assert_eq!(read_packet_frame(&mut Cursor::new(wire)).unwrap(), packet);

        assert!(write_packet_frame(&mut Vec::new(), &[]).is_err());
        assert!(write_packet_frame(&mut Vec::new(), &[0; MAX_PACKET_BYTES + 1]).is_err());
        assert!(read_packet_frame(&mut Cursor::new([0, 0])).is_err());
    }

    #[test]
    fn rendezvous_file_is_bounded_strict_and_removed_idempotently() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(RENDEZVOUS_FILE);
        let rendezvous = Rendezvous::new(TOKEN.to_owned(), OBJECT_PATH.to_owned()).unwrap();
        publish_rendezvous(root.path(), &rendezvous).unwrap();
        assert_eq!(read_rendezvous(root.path(), TOKEN).unwrap(), rendezvous);
        remove_rendezvous(root.path()).unwrap();
        remove_rendezvous(root.path()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn rendezvous_accepts_only_the_canonical_appcontainer_path_and_token() {
        let rendezvous = Rendezvous::new(TOKEN.to_owned(), OBJECT_PATH.to_owned()).unwrap();
        let json = rendezvous.to_json().unwrap();
        assert_eq!(Rendezvous::from_json(&json, TOKEN).unwrap(), rendezvous);
        assert_eq!(
            rendezvous.qualified_names(1).unwrap(),
            (
                format!(r"\\.\pipe\Sessions\1\{OBJECT_PATH}\{CONTROL_LEAF}"),
                format!(r"\\.\pipe\Sessions\1\{OBJECT_PATH}\{DATA_LEAF}"),
            )
        );

        for path in [
            r"AppContainerNamedObjects\S-1-15-2-1-2-3-4-5-6",
            r"AppContainerNamedObjects\S-1-15-2-1-2-3-4-5-6-7\..",
            r"Sessions\1\AppContainerNamedObjects\S-1-15-2-1-2-3-4-5-6-7",
        ] {
            assert!(Rendezvous::new(TOKEN.to_owned(), path.to_owned()).is_err());
        }
        assert!(Rendezvous::from_json(&json, &TOKEN.replace('0', "1")).is_err());
    }
}
