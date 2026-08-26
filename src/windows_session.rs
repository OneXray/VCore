use std::{
    io,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::BufReader,
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    sync::Notify,
    task::JoinSet,
    time::{Instant, sleep},
};
use windows::{
    Storage::ApplicationData,
    Win32::System::{
        RemoteDesktop::ProcessIdToSessionId,
        WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
    },
};

use crate::{
    ResourceLimits,
    config::Config,
    dialer::{Dialer, SystemResolver},
    geodata::GeoDataManager,
    platform::TunIo,
    runtime::{PreparedCore, RunningCore},
    windows_log,
    windows_packet_channel::{
        ControlMessage, DATA_PIPE_READ_BUFFER_BYTES, MAX_PACKET_BATCH_PACKETS, PROTOCOL_VERSION,
        PhysicalBinding, Rendezvous, read_control_async, read_packet_frame_async, read_rendezvous,
        write_control_async, write_packet_batch_async,
    },
    windows_snapshot::SnapshotReference,
};

const PACKET_QUEUE_CAPACITY: usize = 256;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

struct WinRtGuard;

impl WinRtGuard {
    fn enter() -> io::Result<Self> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .map(|()| Self)
            .map_err(io::Error::other)
    }
}

impl Drop for WinRtGuard {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

#[doc(hidden)]
pub fn run() -> io::Result<()> {
    let _winrt = WinRtGuard::enter()?;
    let token = parse_args(std::env::args().skip(1))?;
    let local_folder = local_folder()?;
    windows_log::append(&local_folder, "session", "Session Host starting");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let result = runtime.block_on(run_async(&local_folder, &token));
    windows_log::append(
        &local_folder,
        "session",
        if result.is_ok() {
            "Session Host stopped"
        } else {
            "Session Host failed"
        },
    );
    result
}

#[doc(hidden)]
pub fn log_startup_failure(_error: &io::Error) {
    if let Ok(local_folder) = local_folder() {
        windows_log::append(&local_folder, "session", "Session Host startup failed");
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> io::Result<String> {
    let args: Vec<String> = args.into_iter().collect();
    let [flag, token] = args.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Session Host arguments",
        ));
    };
    if flag != "--snapshot-token" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Session Host arguments",
        ));
    }
    SnapshotReference::parse(token).map_err(io::Error::other)?;
    Ok(token.clone())
}

async fn run_async(local_folder: &Path, token: &str) -> io::Result<()> {
    let rendezvous = wait_for_rendezvous(local_folder, token).await?;
    let session_id = current_session_id()?;
    let (control_name, data_name) = rendezvous.qualified_names(session_id)?;
    let control = open_pipe(&control_name, STARTUP_TIMEOUT).await?;
    let data = open_pipe(&data_name, STARTUP_TIMEOUT).await?;
    // The Provider publishes and removes rendezvous; competing deletes can return ACCESS_DENIED.

    let (mut control_read, mut control_write) = tokio::io::split(control);
    write_control_async(
        &mut control_write,
        &ControlMessage::SessionHello {
            version: PROTOCOL_VERSION,
            snapshot_token: token.to_owned(),
        },
    )
    .await?;
    let binding = match read_control_async(&mut control_read).await? {
        ControlMessage::ProviderHello {
            snapshot_token,
            physical_binding,
            ..
        } if snapshot_token == token => physical_binding,
        _ => return Err(invalid_data("invalid Provider handshake")),
    };

    let started = start_vcore(local_folder, token, binding, data).await;
    let (running, mut data_tasks) = match started {
        Ok(started) => started,
        Err(error) => {
            _ = write_control_async(
                &mut control_write,
                &ControlMessage::RuntimeFailed {
                    version: PROTOCOL_VERSION,
                    code: "runtime-start-failed".to_owned(),
                    redacted_message: "VCore runtime failed to start".to_owned(),
                },
            )
            .await;
            return Err(error);
        }
    };
    write_control_async(
        &mut control_write,
        &ControlMessage::RuntimeReady {
            version: PROTOCOL_VERSION,
        },
    )
    .await?;

    let mut stopped_counters = None;
    let result = running
        .run_until_shutdown(async {
            tokio::select! {
                message = read_control_async(&mut control_read) => match message {
                    Ok(ControlMessage::Stop { packet_counters, .. }) => {
                        stopped_counters = Some(packet_counters);
                        Ok(())
                    }
                    Err(error) if is_pipe_closed(&error) => Ok(()),
                    Ok(_) => Err(invalid_data("invalid control message during runtime")),
                    Err(error) => Err(error),
                },
                joined = data_tasks.join_next() => match joined {
                    Some(Ok(Ok(()))) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "packet task exited")),
                    Some(Ok(Err(error))) => Err(error),
                    Some(Err(error)) => Err(io::Error::other(error)),
                    None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "packet tasks exited")),
                }
            }
        })
        .await;
    data_tasks.abort_all();
    while data_tasks.join_next().await.is_some() {}

    match (result, stopped_counters) {
        (Ok(()), Some(packet_counters)) => {
            write_control_async(
                &mut control_write,
                &ControlMessage::Stopped {
                    version: PROTOCOL_VERSION,
                    packet_counters,
                },
            )
            .await
        }
        (Ok(()), None) => Ok(()),
        (Err(error), _) => {
            _ = write_control_async(
                &mut control_write,
                &ControlMessage::RuntimeFailed {
                    version: PROTOCOL_VERSION,
                    code: "runtime-failed".to_owned(),
                    redacted_message: "VCore runtime stopped unexpectedly".to_owned(),
                },
            )
            .await;
            Err(error)
        }
    }
}

async fn start_vcore(
    local_folder: &Path,
    token: &str,
    binding: PhysicalBinding,
    data: NamedPipeClient,
) -> io::Result<(RunningCore, JoinSet<io::Result<()>>)> {
    let config_yaml = SnapshotReference::parse(token)
        .map_err(io::Error::other)?
        .read_yaml(local_folder)
        .map_err(io::Error::other)?;
    let config = Config::parse_yaml(&config_yaml)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let geodata = GeoDataManager::open(
        local_folder.join("vcore/geodata"),
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

    let wake = Arc::new(Notify::new());
    let observed = Arc::clone(&wake);
    let (tun, packets) = TunIo::new(PACKET_QUEUE_CAPACITY, move || {
        observed.notify_one();
        Ok(())
    });
    let (data_read, mut data_write) = tokio::io::split(data);
    let mut data_read = BufReader::with_capacity(DATA_PIPE_READ_BUFFER_BYTES, data_read);
    let mut tasks = JoinSet::new();
    let ingress = packets.clone();
    tasks.spawn(async move {
        loop {
            let packet = read_packet_frame_async(&mut data_read).await?;
            _ = ingress.try_send(packet);
        }
    });
    tasks.spawn(async move {
        let mut packet_batch = Vec::with_capacity(MAX_PACKET_BATCH_PACKETS);
        let mut frame_buffer = Vec::new();
        loop {
            wake.notified().await;
            while let Some(packet) = packets.pop_egress() {
                packet_batch.clear();
                packet_batch.push(packet);
                while packet_batch.len() < MAX_PACKET_BATCH_PACKETS {
                    let Some(packet) = packets.pop_egress() else {
                        break;
                    };
                    packet_batch.push(packet);
                }
                write_packet_batch_async(&mut data_write, &packet_batch, &mut frame_buffer).await?;
            }
        }
    });

    let running = prepared
        .start_tun(tun, dialer_from_binding(&binding)?)
        .await?;
    Ok((running, tasks))
}

fn dialer_from_binding(binding: &PhysicalBinding) -> io::Result<Dialer> {
    let ipv4 = binding
        .ipv4
        .as_ref()
        .map(|binding| {
            NonZeroU32::new(binding.interface_index)
                .map(|index| (binding.source, index))
                .ok_or_else(|| invalid_data("invalid IPv4 interface index"))
        })
        .transpose()?;
    let ipv6 = binding
        .ipv6
        .as_ref()
        .map(|binding| {
            NonZeroU32::new(binding.interface_index)
                .map(|index| (binding.source, index))
                .ok_or_else(|| invalid_data("invalid IPv6 interface index"))
        })
        .transpose()?;
    Ok(Dialer::default().with_windows_interface(ipv4, ipv6))
}

async fn wait_for_rendezvous(local_folder: &Path, token: &str) -> io::Result<Rendezvous> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        match read_rendezvous(local_folder, token) {
            Ok(rendezvous) => return Ok(rendezvous),
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn open_pipe(name: &str, timeout: Duration) -> io::Result<NamedPipeClient> {
    let deadline = Instant::now() + timeout;
    loop {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return Ok(pipe),
            Err(error) if Instant::now() < deadline => {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return Err(error);
                }
                sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn current_session_id() -> io::Result<u32> {
    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(std::process::id(), &mut session_id) }
        .map_err(io::Error::other)?;
    Ok(session_id)
}

fn local_folder() -> io::Result<PathBuf> {
    let path = ApplicationData::Current()
        .and_then(|data| data.LocalFolder())
        .and_then(|folder| folder.Path())
        .map_err(io::Error::other)?;
    Ok(PathBuf::from(path.to_string()))
}

fn is_pipe_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "vcore-v1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn session_host_accepts_only_one_canonical_snapshot_argument() {
        assert_eq!(
            parse_args(["--snapshot-token".to_owned(), TOKEN.to_owned()]).unwrap(),
            TOKEN
        );
        for args in [
            vec![],
            vec![TOKEN.to_owned()],
            vec!["--config".to_owned(), TOKEN.to_owned()],
            vec![
                "--snapshot-token".to_owned(),
                TOKEN.to_owned(),
                "extra".to_owned(),
            ],
        ] {
            assert!(parse_args(args).is_err());
        }
    }

    #[test]
    fn physical_binding_builds_the_existing_paired_windows_dialer() {
        let binding = PhysicalBinding {
            adapter_id: "adapter".to_owned(),
            profile_name: "Ethernet".to_owned(),
            network_names: vec![],
            ipv4: Some(crate::windows_packet_channel::AddressBindingV4 {
                source: "192.0.2.10".parse().unwrap(),
                interface_index: 10,
            }),
            ipv6: None,
        };
        let debug = format!("{:?}", dialer_from_binding(&binding).unwrap());
        assert!(debug.contains("192.0.2.10"));
        assert!(debug.contains("10"));
    }
}
