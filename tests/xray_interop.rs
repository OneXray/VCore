//! Opt-in interoperability coverage against an installed Xray-core binary.
//!
//! Run with `bash tests/run_xray_interop.sh`.
//! The REALITY phase uses a local ECDSA-only TLS 1.3 camouflage target and all
//! proxied echo targets are local, so the test does not depend on public nodes.

#![cfg(feature = "outbound-vless")]

use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "ffi")]
use std::{
    ffi::{CStr, CString},
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UdpSocket},
    sync::Barrier,
};
use vcore::{
    config::{Config, ProxyProtocol, VlessOutboundConfig},
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::Dispatcher as _,
    outbound::VlessOutbound,
    security::SecurityClient,
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

const REALITY_PUBLIC_KEY: &str = "TrotdL9Y_dMWo-eqNe5dGfx7AbY1vNJjuEvRs4WR2y4";
const REALITY_SHORT_ID: &str = "0123456789abcdef";

fn sole_vless(config: &Config) -> &VlessOutboundConfig {
    match &config.proxies[0].protocol {
        ProxyProtocol::Vless(vless) => vless,
        ProxyProtocol::Socks5(_) => panic!("interop config must contain VLESS"),
        ProxyProtocol::AnyTls(_) => panic!("interop config must contain VLESS"),
    }
}

fn reality_config(server: SocketAddr, mode: &str, public_key: &str, short_id: &str) -> Config {
    let yaml = format!(
        r#"port: 18080
authentication:
  - measure:secret
proxies:
  - name: xray-interop
    type: vless
    server: 127.0.0.1
    port: {}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: www.cloudflare.com
    alpn: [h2]
    reality-opts:
      public-key: {public_key}
      short-id: "{short_id}"
    xhttp-opts:
      path: /onev
      host: www.cloudflare.com
      mode: {mode}
rules:
  - MATCH,xray-interop
"#,
        server.port()
    );
    Config::parse_yaml(yaml.as_bytes()).expect("interop config must be valid")
}

fn reality_outbound(
    server: SocketAddr,
    mode: &str,
    public_key: &str,
    short_id: &str,
) -> VlessOutbound {
    let config = reality_config(server, mode, public_key, short_id);
    let endpoint = ResolvedEndpoint {
        logical_host: "127.0.0.1".to_owned(),
        port: server.port(),
        addresses: vec![server],
    };
    VlessOutbound::new(
        sole_vless(&config),
        endpoint,
        Dialer::default().with_timeout(Duration::from_secs(3)),
    )
    .expect("interop outbound must build")
}

async fn check_shared_reality_connector_concurrency(
    config: &VlessOutboundConfig,
    xray_address: SocketAddr,
) -> io::Result<()> {
    const HANDSHAKE_COUNT: usize = 8;
    let security = SecurityClient::from_proxy(config)?;
    let sockets = tokio::time::timeout(
        Duration::from_secs(5),
        futures_util::future::try_join_all(
            (0..HANDSHAKE_COUNT).map(|_| tokio::net::TcpStream::connect(xray_address)),
        ),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "shared REALITY connector TCP setup timed out",
        )
    })??;
    let barrier = Arc::new(Barrier::new(HANDSHAKE_COUNT));
    let handshakes = sockets.into_iter().map(|socket| {
        let barrier = Arc::clone(&barrier);
        let security = &security;
        async move {
            barrier.wait().await;
            let stream = security.connect(Box::new(socket)).await?;
            drop(stream);
            Ok::<_, io::Error>(())
        }
    });
    let results = tokio::time::timeout(
        Duration::from_secs(10),
        futures_util::future::join_all(handshakes),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "eight shared REALITY connector handshakes timed out",
        )
    })?;

    let mut failures = Vec::new();
    for (index, result) in results.into_iter().enumerate() {
        if let Err(error) = result {
            failures.push(format!("handshake {index}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "shared REALITY connector completed with {} failure(s): {}",
            failures.len(),
            failures.join("; ")
        )))
    }
}

async fn check_cancelled_reality_handshake_can_reconnect(
    config: &VlessOutboundConfig,
    xray_address: SocketAddr,
) -> io::Result<()> {
    let security = SecurityClient::from_proxy(config)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let stalled_address = listener.local_addr()?;
    let (client, (mut server, _)) = tokio::try_join!(
        tokio::net::TcpStream::connect(stalled_address),
        listener.accept()
    )?;
    let cancelled_security = security.clone();
    let handshake = tokio::spawn(async move { cancelled_security.connect(Box::new(client)).await });

    let mut record_header = [0_u8; 5];
    tokio::time::timeout(
        Duration::from_secs(5),
        server.read_exact(&mut record_header),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "cancelled REALITY handshake did not send a ClientHello",
        )
    })??;
    if record_header[0] != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cancelled REALITY handshake did not start with a TLS handshake record",
        ));
    }
    handshake.abort();
    let cancelled = handshake.await;
    if !matches!(cancelled, Err(error) if error.is_cancelled()) {
        return Err(io::Error::other(
            "stalled REALITY handshake was not cancelled",
        ));
    }
    drop(server);

    let socket = tokio::net::TcpStream::connect(xray_address).await?;
    let stream = tokio::time::timeout(Duration::from_secs(5), security.connect(Box::new(socket)))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "REALITY reconnect after cancellation timed out",
            )
        })??;
    drop(stream);
    Ok(())
}

#[cfg(feature = "interop-test")]
fn tls_outbound(server: SocketAddr, mode: &str, test_root_der: Option<Vec<u8>>) -> VlessOutbound {
    let yaml = format!(
        r#"port: 18080
authentication:
  - measure:secret
proxies:
  - name: xray-tls-interop
    type: vless
    server: 127.0.0.1
    port: {}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: vcore.test
    alpn: [h2]
    xhttp-opts:
      path: /onev
      host: vcore.test
      mode: {mode}
rules:
  - MATCH,xray-tls-interop
"#,
        server.port()
    );
    let config = Config::parse_yaml(yaml.as_bytes()).expect("TLS interop config must be valid");
    let endpoint = ResolvedEndpoint {
        logical_host: "127.0.0.1".to_owned(),
        port: server.port(),
        addresses: vec![server],
    };
    let dialer = Dialer::default().with_timeout(Duration::from_secs(3));
    match test_root_der {
        Some(root) => {
            VlessOutbound::new_with_test_tls_roots(sole_vless(&config), endpoint, dialer, [root])
        }
        None => VlessOutbound::new(sole_vless(&config), endpoint, dialer),
    }
    .expect("TLS interop outbound must build")
}

async fn check_tcp_echo(outbound: &VlessOutbound) -> io::Result<()> {
    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = listener.local_addr()?;

    let server = async move {
        let (mut stream, _) = listener.accept().await?;
        let mut payload = [0_u8; 14];
        stream.read_exact(&mut payload).await?;
        stream.write_all(&payload).await?;
        Ok::<_, io::Error>(())
    };
    let client = async {
        let mut stream = tokio::time::timeout(
            IO_TIMEOUT,
            outbound.connect_tcp(StreamSession {
                inbound: InboundKind::Http,
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                destination: Destination::Ip(target),
                sniffed_domain: None,
            }),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS connect timed out"))?
        .map_err(io::Error::other)?;
        tokio::time::timeout(IO_TIMEOUT, stream.write_all(b"vcore-tcp-echo"))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS write timed out"))??;
        stream.flush().await?;
        let mut payload = [0_u8; 14];
        tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS read timed out"))??;
        assert_eq!(&payload, b"vcore-tcp-echo");
        stream.shutdown().await
    };

    tokio::try_join!(server, client)?;
    Ok(())
}

async fn check_udp_echo(outbound: &VlessOutbound) -> io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = socket.local_addr()?;

    let server = async move {
        let mut payload = [0_u8; 256];
        let (length, peer) = socket.recv_from(&mut payload).await?;
        socket.send_to(&payload[..length], peer).await?;
        Ok::<_, io::Error>(())
    };
    let client = async {
        let mut transport = outbound
            .open_datagram(DatagramSession::new(
                InboundKind::Http,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12346),
            ))
            .await
            .map_err(io::Error::other)?;
        let expected = Datagram {
            remote: Destination::Ip(target),
            payload: Bytes::from_static(b"vcore-udp-echo"),
            sniffed_domain: None,
        };
        transport
            .send(expected.clone())
            .await
            .map_err(io::Error::other)?;
        let received = transport.receive().await.map_err(io::Error::other)?;
        assert_eq!(received, expected);
        transport.close().await.map_err(io::Error::other)
    };

    tokio::try_join!(server, client)?;
    Ok(())
}

async fn check_echoes(outbound: &VlessOutbound, label: &str) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(7), check_tcp_echo(outbound))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{label} TCP timed out")))??;
    tokio::time::timeout(Duration::from_secs(7), check_udp_echo(outbound))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, format!("{label} XUDP timed out"))
        })??;
    Ok(())
}

async fn expect_connect_rejected(outbound: &VlessOutbound, label: &str) -> io::Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        outbound.connect_tcp(StreamSession {
            inbound: InboundKind::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12344),
            destination: Destination::domain("example.com", 80)?,
            sniffed_domain: None,
        }),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{label} timed out")))?;
    if result.is_ok() {
        return Err(io::Error::other(format!(
            "{label} was unexpectedly accepted"
        )));
    }
    Ok(())
}

#[cfg(feature = "ffi")]
fn ffi_invoke(request: serde_json::Value) -> io::Result<serde_json::Value> {
    let request = CString::new(request.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invoke JSON contains NUL"))?;
    // SAFETY: CString provides a live NUL-terminated request for the duration
    // of the call. The returned allocation is copied and freed exactly once.
    let response = unsafe { vcore::ffi::VCoreInvoke(request.as_ptr()) };
    if response.is_null() {
        return Err(io::Error::other("VCoreInvoke returned NULL"));
    }
    // SAFETY: a non-null VCoreInvoke response is a live NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(response) }.to_bytes().to_vec();
    // SAFETY: response came from VCoreInvoke and has not been freed.
    unsafe { vcore::ffi::VCoreFree(response) };
    let response: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if response["success"] != true {
        return Err(io::Error::other(format!(
            "VCore Invoke failed: {}",
            response["error"].as_str().unwrap_or("unknown error")
        )));
    }
    Ok(response)
}

#[cfg(feature = "ffi")]
fn ffi_method(
    method: &str,
    instance_id: Option<&str>,
    payload: serde_json::Value,
) -> io::Result<serde_json::Value> {
    let mut request = serde_json::json!({
        "apiVersion": vcore::INVOKE_API_VERSION,
        "method": method,
        "payload": payload,
    });
    if let Some(instance_id) = instance_id {
        request["instanceId"] = serde_json::Value::String(instance_id.to_owned());
    }
    ffi_invoke(request).map(|response| response["data"].clone())
}

#[cfg(feature = "ffi")]
fn ffi_measure_delay_batch(
    config_paths: &[PathBuf],
    timeout_seconds: u64,
    target_url: String,
) -> io::Result<Vec<u64>> {
    let data = ffi_method(
        "measureDelay",
        None,
        serde_json::json!({
            "configPaths": config_paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            "timeout": timeout_seconds,
            "url": target_url,
        }),
    )?;
    let results = data["results"].as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("measureDelay returned no results array: {data}"),
        )
    })?;
    if results.len() != config_paths.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "measureDelay returned {} results, expected {}",
                results.len(),
                config_paths.len()
            ),
        ));
    }
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            if result["success"] != true {
                return Err(io::Error::other(format!(
                    "measureDelay result {index} failed: {}",
                    result["error"].as_str().unwrap_or("unknown error")
                )));
            }
            result["delay"].as_u64().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "measureDelay result {index} returned a non-integer or negative delay: {result}"
                    ),
                )
            })
        })
        .collect()
}

#[cfg(feature = "ffi")]
fn ffi_stop_instance(instance_id: &str) -> io::Result<()> {
    let stop = ffi_method("stop", Some(instance_id), serde_json::json!({}));
    let destroy = ffi_method("destroyInstance", Some(instance_id), serde_json::json!({}));
    stop.and(destroy).map(drop)
}

#[cfg(feature = "ffi")]
fn ffi_start_single_instance(config_path: &Path) -> io::Result<String> {
    let data = ffi_method("createInstance", None, serde_json::json!({}))?;
    let instance_id = data["instanceId"]
        .as_str()
        .ok_or_else(|| io::Error::other("createInstance returned no instanceId"))?
        .to_owned();

    match ffi_method("createInstance", None, serde_json::json!({})) {
        Err(error) if error.to_string().contains("already exists") => {}
        Err(error) => {
            let _ = ffi_stop_instance(&instance_id);
            return Err(io::Error::other(format!(
                "second createInstance failed for the wrong reason: {error}"
            )));
        }
        Ok(second) => {
            if let Some(second_id) = second["instanceId"].as_str() {
                let _ = ffi_stop_instance(second_id);
            }
            let _ = ffi_stop_instance(&instance_id);
            return Err(io::Error::other(
                "second createInstance unexpectedly succeeded",
            ));
        }
    }

    if let Err(error) = ffi_method(
        "prepare",
        Some(&instance_id),
        serde_json::json!({"configPath": config_path.to_string_lossy().into_owned()}),
    ) {
        let _ = ffi_stop_instance(&instance_id);
        return Err(error);
    }
    if let Err(error) = ffi_method("start", Some(&instance_id), serde_json::json!({})) {
        let _ = ffi_stop_instance(&instance_id);
        return Err(error);
    }
    Ok(instance_id)
}

#[cfg(feature = "ffi")]
async fn proxy_tcp_echo(proxy: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = listener.local_addr()?;
    let payload = b"vcore-public-lifecycle".to_vec();
    let expected = payload.clone();

    let server = async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = vec![0_u8; expected.len()];
        stream.read_exact(&mut received).await?;
        if received != expected {
            return Err(io::Error::other("echo target received unexpected payload"));
        }
        stream.write_all(&received).await?;
        Ok::<_, io::Error>(())
    };
    let client = async move {
        let mut stream = tokio::net::TcpStream::connect(proxy).await?;
        stream
            .write_all(
                format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic bWVhc3VyZTpzZWNyZXQ=\r\nConnection: close\r\n\r\n"
                )
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::with_capacity(128);
        while !response.ends_with(b"\r\n\r\n") {
            if response.len() >= 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP proxy response head is too large",
                ));
            }
            let byte = stream.read_u8().await?;
            response.push(byte);
        }
        if !response.starts_with(b"HTTP/1.1 200") {
            return Err(io::Error::other(format!(
                "HTTP proxy CONNECT failed: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        stream.write_all(&payload).await?;
        stream.flush().await?;
        let mut echoed = vec![0_u8; payload.len()];
        stream.read_exact(&mut echoed).await?;
        if echoed != payload {
            return Err(io::Error::other("HTTP proxy returned unexpected payload"));
        }
        stream.shutdown().await
    };

    tokio::try_join!(server, client)?;
    Ok(())
}

#[cfg(feature = "ffi")]
async fn serve_measure_delay_target(
    listener: TcpListener,
    expected_requests: usize,
) -> io::Result<()> {
    const MAX_REQUEST_HEAD: usize = 8 * 1024;
    let mut clients = Vec::with_capacity(expected_requests);
    for _ in 0..expected_requests {
        let (mut stream, _) = listener.accept().await?;
        let mut head = Vec::with_capacity(256);
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_REQUEST_HEAD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "measureDelay request head is too large",
                ));
            }
            head.push(stream.read_u8().await?);
        }
        let request_line = head.split(|byte| *byte == b'\r').next().unwrap_or_default();
        if !request_line.starts_with(b"HEAD ") || !request_line.ends_with(b" HTTP/1.1") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "measureDelay target expected an HTTP/1.1 HEAD request, got: {}",
                    String::from_utf8_lossy(request_line)
                ),
            ));
        }
        clients.push(stream);
    }

    // Hold every request until the full batch has arrived. This proves that
    // one Invoke owns multiple overlapping private measurement workers.
    for mut stream in clients {
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
    }
    Ok(())
}

#[cfg(feature = "ffi")]
async fn check_ffi_batch_measure_and_single_lifecycle(
    xray_address: SocketAddr,
    mode: &str,
) -> io::Result<()> {
    const MEASURE_COUNT: usize = 5;
    const MEASURE_TIMEOUT_SECONDS: u64 = 10;
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target_address = target_listener.local_addr()?;
    let directory = tempfile::tempdir()?;
    ffi_method(
        "initialize",
        None,
        serde_json::json!({"dataDir": directory.path().to_string_lossy().into_owned()}),
    )?;
    let config_directory = directory.path().join("configs");
    let mut measure_config_paths = Vec::with_capacity(MEASURE_COUNT);
    for index in 0..MEASURE_COUNT {
        let path = config_directory.join(format!("measure-{index}.yaml"));
        std::fs::write(
            &path,
            format!(
                r#"proxies:
  - name: proxy
    type: vless
    server: {}
    port: {}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: www.cloudflare.com
    alpn: [h2]
    reality-opts:
      public-key: TrotdL9Y_dMWo-eqNe5dGfx7AbY1vNJjuEvRs4WR2y4
      short-id: "0123456789abcdef"
    xhttp-opts:
      path: /onev
      host: www.cloudflare.com
      mode: {mode}
"#,
                xray_address.ip(),
                xray_address.port(),
            ),
        )?;
        measure_config_paths.push(path);
    }

    let target_task = tokio::spawn(async move {
        match tokio::time::timeout(
            Duration::from_secs(20),
            serve_measure_delay_target(target_listener, MEASURE_COUNT),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "measureDelay target timed out waiting for five concurrent requests",
            )),
        }
    });
    let measurement_paths = measure_config_paths.clone();
    let measurement = tokio::task::spawn_blocking(move || {
        ffi_measure_delay_batch(
            &measurement_paths,
            MEASURE_TIMEOUT_SECONDS,
            format!("http://{target_address}/measure"),
        )
    })
    .await;
    let delays = match measurement {
        Ok(Ok(delays)) => delays,
        Ok(Err(error)) => {
            target_task.abort();
            let _ = target_task.await;
            return Err(error);
        }
        Err(error) => {
            target_task.abort();
            let _ = target_task.await;
            return Err(io::Error::other(format!(
                "VCore measureDelay task failed: {error}"
            )));
        }
    };
    if delays.len() != MEASURE_COUNT {
        return Err(io::Error::other(format!(
            "measureDelay returned {} results, expected {MEASURE_COUNT}",
            delays.len()
        )));
    }
    target_task
        .await
        .map_err(|error| io::Error::other(format!("measureDelay target task failed: {error}")))??;

    let reservation = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let http_port = reservation.local_addr()?.port();
    drop(reservation);
    let runtime_config_path = config_directory.join("runtime.yaml");
    std::fs::write(
        &runtime_config_path,
        format!(
            r#"port: {http_port}
authentication:
  - measure:secret
proxies:
  - name: proxy
    type: vless
    server: {}
    port: {}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: www.cloudflare.com
    alpn: [h2]
    reality-opts:
      public-key: TrotdL9Y_dMWo-eqNe5dGfx7AbY1vNJjuEvRs4WR2y4
      short-id: "0123456789abcdef"
    xhttp-opts:
      path: /onev
      host: www.cloudflare.com
      mode: {mode}
rules:
  - MATCH,proxy
"#,
            xray_address.ip(),
            xray_address.port(),
        ),
    )?;

    // A successful batch must leave the one public lifecycle slot untouched.
    // While that lifecycle is live, a second create must still fail closed.
    let instance_id =
        tokio::task::spawn_blocking(move || ffi_start_single_instance(&runtime_config_path))
            .await
            .map_err(|error| io::Error::other(format!("VCore setup task failed: {error}")))??;

    let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), http_port);
    let probe_result = proxy_tcp_echo(proxy).await;
    let cleanup_result = tokio::task::spawn_blocking(move || ffi_stop_instance(&instance_id))
        .await
        .map_err(|error| io::Error::other(format!("VCore cleanup task failed: {error}")))?;
    probe_result?;
    cleanup_result
}

async fn run_interop() -> io::Result<()> {
    let xray_address = env::var("XRAY_INTEROP_ADDRESS")
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "XRAY_INTEROP_ADDRESS is missing; run tests/run_xray_interop.sh",
            )
        })?
        .parse::<SocketAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mode = env::var("XRAY_INTEROP_MODE").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XRAY_INTEROP_MODE is missing; run tests/run_xray_interop.sh",
        )
    })?;
    if !matches!(mode.as_str(), "packet-up" | "stream-one") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XRAY_INTEROP_MODE must be packet-up or stream-one",
        ));
    }
    let security = env::var("XRAY_INTEROP_SECURITY").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XRAY_INTEROP_SECURITY is missing; run tests/run_xray_interop.sh",
        )
    })?;

    match security.as_str() {
        "reality" => {
            let first = reality_outbound(xray_address, &mode, REALITY_PUBLIC_KEY, REALITY_SHORT_ID);
            let second =
                reality_outbound(xray_address, &mode, REALITY_PUBLIC_KEY, REALITY_SHORT_ID);
            let first_label = format!("REALITY {mode} instance 1");
            let second_label = format!("REALITY {mode} instance 2");
            tokio::try_join!(
                check_echoes(&first, &first_label),
                check_echoes(&second, &second_label),
            )?;

            let shared_config =
                reality_config(xray_address, &mode, REALITY_PUBLIC_KEY, REALITY_SHORT_ID);
            check_shared_reality_connector_concurrency(sole_vless(&shared_config), xray_address)
                .await?;
            check_cancelled_reality_handshake_can_reconnect(
                sole_vless(&shared_config),
                xray_address,
            )
            .await?;

            #[cfg(feature = "ffi")]
            check_ffi_batch_measure_and_single_lifecycle(xray_address, &mode).await?;

            // Run these last: Xray deliberately keeps camouflage fallbacks
            // alive, which can occupy XHTTP accept workers.
            let invalid_key = reality_outbound(
                xray_address,
                &mode,
                "MFcIAGWIFW5SAUDTxj4W2UpuaH70MS71vq4DlxhRzTM",
                REALITY_SHORT_ID,
            );
            expect_connect_rejected(&invalid_key, "invalid REALITY public key").await?;
            let invalid_short_id =
                reality_outbound(xray_address, &mode, REALITY_PUBLIC_KEY, "0123456789abcdee");
            expect_connect_rejected(&invalid_short_id, "invalid REALITY short ID").await
        }
        "tls" => {
            #[cfg(feature = "interop-test")]
            {
                let root_path = env::var("XRAY_INTEROP_CA_DER").map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "XRAY_INTEROP_CA_DER is missing",
                    )
                })?;
                let root = std::fs::read(root_path)?;
                let first = tls_outbound(xray_address, &mode, Some(root.clone()));
                let second = tls_outbound(xray_address, &mode, Some(root));
                let first_label = format!("TLS {mode} instance 1");
                let second_label = format!("TLS {mode} instance 2");
                tokio::try_join!(
                    check_echoes(&first, &first_label),
                    check_echoes(&second, &second_label),
                )?;

                // The normal constructor must continue to reject the local CA.
                let production = tls_outbound(xray_address, &mode, None);
                expect_connect_rejected(&production, "untrusted standard TLS certificate").await
            }
            #[cfg(not(feature = "interop-test"))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TLS interop requires the interop-test feature",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XRAY_INTEROP_SECURITY must be reality or tls",
        )),
    }
}

#[tokio::test]
#[ignore = "requires installed Xray-core and OpenSSL binaries"]
async fn xray_vless_xhttp_tcp_and_xudp_echo() {
    tokio::time::timeout(Duration::from_secs(60), run_interop())
        .await
        .expect("Xray interoperability test timed out")
        .expect("Xray interoperability test failed");
}
