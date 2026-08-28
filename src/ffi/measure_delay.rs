//! Batched, node-only latency measurement owned entirely by VCore.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use futures_util::{FutureExt, StreamExt, stream};
use rustls::{ClientConfig, RootCertStore, client::Resumption, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use crate::{
    ResourceLimits,
    config::MeasureConfig,
    dialer::{Dialer, SystemResolver},
    dispatch::{BoxStream, DispatchError, Dispatcher},
    inbound::DEFAULT_HEADER_LIMIT,
    outbound::{OutboundDiagnostic, capture_outbound_diagnostic},
    runtime::PreparedMeasurement,
    session::{Destination, InboundKind, StreamSession},
};

use super::{InvokeFailure, registry};

const MIN_TIMEOUT_SECONDS: u32 = 1;
const MAX_TIMEOUT_SECONDS: u32 = 30;
pub(super) const MAX_MEASURE_CONFIGS: usize = 5;
const MAX_MEASURE_WORKERS: usize = 5;
const MAX_ITEM_ERROR_BYTES: usize = 1_024;

static MEASURE_DELAY_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct MeasureDelayPayload {
    config_yamls: Vec<String>,
    timeout: u32,
    url: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct MeasureDelayResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    delay: Option<u64>,
    error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetHost {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone)]
struct Target {
    scheme: TargetScheme,
    destination: Destination,
    authority: String,
    origin_form: String,
    tls_server_name: String,
}

struct MeasureRequest {
    config_yamls: Vec<String>,
    timeout: Duration,
    target: Target,
}

struct MeasureDelayAdmission<'a> {
    active: &'a AtomicBool,
}

impl MeasureDelayAdmission<'_> {
    fn try_acquire(active: &AtomicBool) -> Result<MeasureDelayAdmission<'_>, InvokeFailure> {
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| MeasureDelayAdmission { active })
            .map_err(|_| InvokeFailure::invalid_state("measureDelay is busy"))
    }
}

impl Drop for MeasureDelayAdmission<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

pub(super) fn measure_delay(
    payload: MeasureDelayPayload,
) -> Result<Vec<MeasureDelayResult>, InvokeFailure> {
    let request = MeasureRequest::parse(payload)?;
    let _admission = MeasureDelayAdmission::try_acquire(&MEASURE_DELAY_ACTIVE)?;
    let _data_directory = registry().data_directory()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(InvokeFailure::from)?;
    let results = runtime.block_on(run_batch(request));
    runtime.shutdown_timeout(Duration::from_millis(100));
    Ok(results)
}

impl MeasureRequest {
    fn parse(payload: MeasureDelayPayload) -> Result<Self, InvokeFailure> {
        if payload.config_yamls.is_empty() || payload.config_yamls.len() > MAX_MEASURE_CONFIGS {
            return Err(InvokeFailure::invalid_request(format!(
                "configYamls must contain between 1 and {MAX_MEASURE_CONFIGS} entries"
            )));
        }
        if payload.config_yamls.iter().any(String::is_empty) {
            return Err(InvokeFailure::invalid_request(
                "configYamls must not contain an empty YAML document",
            ));
        }
        if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&payload.timeout) {
            return Err(InvokeFailure::invalid_request(format!(
                "timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds"
            )));
        }
        Ok(Self {
            config_yamls: payload.config_yamls,
            timeout: Duration::from_secs(u64::from(payload.timeout)),
            target: Target::parse(&payload.url)?,
        })
    }
}

impl MeasureDelayResult {
    fn success(delay: u64) -> Self {
        Self {
            success: true,
            delay: Some(delay),
            error: String::new(),
        }
    }

    fn failure(error: impl std::fmt::Display) -> Self {
        Self {
            success: false,
            delay: None,
            error: truncate_utf8(&error.to_string(), MAX_ITEM_ERROR_BYTES),
        }
    }

    fn panic() -> Self {
        Self::failure("internal error: panic caught in a measureDelay worker")
    }
}

impl Target {
    fn parse(raw: &str) -> Result<Self, InvokeFailure> {
        let url = Url::parse(raw)
            .map_err(|_| InvokeFailure::invalid_request("url is not a valid absolute URL"))?;
        let scheme = match url.scheme() {
            "http" => TargetScheme::Http,
            "https" => TargetScheme::Https,
            _ => {
                return Err(InvokeFailure::invalid_request(
                    "url scheme must be http or https",
                ));
            }
        };
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(InvokeFailure::invalid_request(
                "url must not contain authentication or a fragment",
            ));
        }
        let host = match url.host() {
            Some(Host::Domain(domain)) => {
                if domain.len() > u8::MAX as usize {
                    return Err(InvokeFailure::invalid_request("url host is too long"));
                }
                TargetHost::Domain(domain.to_owned())
            }
            Some(Host::Ipv4(address)) => TargetHost::Ip(IpAddr::V4(address)),
            Some(Host::Ipv6(address)) => TargetHost::Ip(IpAddr::V6(address)),
            None => return Err(InvokeFailure::invalid_request("url must contain a host")),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| InvokeFailure::invalid_request("url must contain a port"))?;
        let destination = match &host {
            TargetHost::Domain(domain) => {
                Destination::domain(domain.clone(), port).map_err(InvokeFailure::invalid_request)?
            }
            TargetHost::Ip(address) => Destination::Ip(SocketAddr::new(*address, port)),
        };
        let authority = authority(&host, port);
        let mut origin_form = url.path().to_owned();
        if origin_form.is_empty() {
            origin_form.push('/');
        }
        if let Some(query) = url.query() {
            origin_form.push('?');
            origin_form.push_str(query);
        }
        let tls_server_name = match &host {
            TargetHost::Domain(domain) => domain.clone(),
            TargetHost::Ip(address) => address.to_string(),
        };
        Ok(Self {
            scheme,
            destination,
            authority,
            origin_form,
            tls_server_name,
        })
    }
}

fn authority(host: &TargetHost, port: u16) -> String {
    match host {
        TargetHost::Domain(domain) => format!("{domain}:{port}"),
        TargetHost::Ip(IpAddr::V4(address)) => format!("{address}:{port}"),
        TargetHost::Ip(IpAddr::V6(address)) => format!("[{address}]:{port}"),
    }
}

async fn run_batch(request: MeasureRequest) -> Vec<MeasureDelayResult> {
    let MeasureRequest {
        config_yamls,
        timeout,
        target,
    } = request;
    let jobs = config_yamls.into_iter().map(|config_yaml| {
        let target = target.clone();
        async move {
            match AssertUnwindSafe(measure_one(config_yaml, &target, timeout))
                .catch_unwind()
                .await
            {
                Ok(Ok(delay)) => MeasureDelayResult::success(delay),
                Ok(Err(error)) => MeasureDelayResult::failure(error.message),
                Err(_) => MeasureDelayResult::panic(),
            }
        }
    });
    collect_ordered_bounded(jobs).await
}

async fn collect_ordered_bounded<I, F, T>(jobs: I) -> Vec<T>
where
    I: IntoIterator<Item = F>,
    F: Future<Output = T>,
{
    stream::iter(jobs)
        .buffered(MAX_MEASURE_WORKERS)
        .collect()
        .await
}

async fn measure_one(
    config_yaml: String,
    target: &Target,
    timeout: Duration,
) -> Result<u64, InvokeFailure> {
    let config = MeasureConfig::parse_yaml(config_yaml.as_bytes()).map_err(InvokeFailure::from)?;
    drop(config_yaml);
    let prepared =
        PreparedMeasurement::prepare_config(config, &SystemResolver, ResourceLimits::default())
            .await
            .map_err(InvokeFailure::from)?;
    let runtime = prepared
        .into_runtime(Dialer::default())
        .map_err(InvokeFailure::from)?;
    let result = run_probe(target, runtime.dispatcher(), timeout).await;
    runtime.shutdown().await;
    result
}

async fn run_probe(
    target: &Target,
    dispatcher: Arc<dyn Dispatcher>,
    timeout: Duration,
) -> Result<u64, InvokeFailure> {
    let connector = (target.scheme == TargetScheme::Https)
        .then(build_tls_connector)
        .transpose()
        .map_err(InvokeFailure::from)?;
    let started = Instant::now();
    match tokio::time::timeout(timeout, probe_once(target, dispatcher, connector.as_ref())).await {
        Ok(Ok(())) => u64::try_from(started.elapsed().as_millis())
            .map_err(|_| InvokeFailure::internal("measureDelay duration overflow")),
        Ok(Err(error)) => Err(InvokeFailure::new(format!(
            "measureDelay probe failed: {error}"
        ))),
        Err(_) => Err(InvokeFailure::new(format!(
            "measureDelay timed out after {} seconds",
            timeout.as_secs()
        ))),
    }
}

fn build_tls_connector() -> io::Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn probe_once(
    target: &Target,
    dispatcher: Arc<dyn Dispatcher>,
    tls_connector: Option<&TlsConnector>,
) -> io::Result<()> {
    let session = StreamSession {
        inbound: InboundKind::InternalMeasure,
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        destination: target.destination.clone(),
        sniffed_domain: None,
    };
    let (stream, diagnostic) = capture_outbound_diagnostic(dispatcher.connect_tcp(session)).await;
    let stream = stream.map_err(|error| outbound_connect_error(error, diagnostic.as_ref()))?;
    let stream = if target.scheme == TargetScheme::Https {
        let connector = tls_connector
            .ok_or_else(|| io::Error::other("HTTPS probe is missing its TLS connector"))?;
        connect_target_tls(connector, stream, &target.tls_server_name).await?
    } else {
        stream
    };
    send_head_and_read_response(stream, &target.origin_form, &target.authority).await
}

fn outbound_connect_error(
    error: DispatchError,
    diagnostic: Option<&OutboundDiagnostic>,
) -> io::Error {
    let diagnostic = diagnostic.map_or_else(String::new, |diagnostic| {
        format!(
            " (VCore outbound stage={} kind={} error={:?})",
            diagnostic.stage(),
            diagnostic.kind(),
            diagnostic.message()
        )
    });
    io::Error::other(format!("outbound connect failed: {error}{diagnostic}"))
}

async fn connect_target_tls(
    connector: &TlsConnector,
    stream: BoxStream,
    server_name: &str,
) -> io::Result<BoxStream> {
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    connector
        .connect(server_name, stream)
        .await
        .map(|stream| Box::new(stream) as BoxStream)
        .map_err(io::Error::other)
}

async fn send_head_and_read_response(
    mut stream: BoxStream,
    request_target: &str,
    authority: &str,
) -> io::Result<()> {
    stream
        .write_all(
            format!(
                "HEAD {request_target} HTTP/1.1\r\nHost: {authority}\r\nAccept: */*\r\nUser-Agent: VCore/{}\r\nConnection: close\r\n\r\n",
                env!("CARGO_PKG_VERSION")
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    read_response_status(&mut stream).await.map(drop)
}

async fn read_response_status<R>(reader: &mut R) -> io::Result<u16>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    let mut input = Vec::with_capacity(1024);
    let mut total_read = 0_usize;
    loop {
        if let Some(end) = input.windows(4).position(|window| window == b"\r\n\r\n") {
            let status = parse_status(&input[..end])?;
            if (100..200).contains(&status) && status != 101 {
                input.drain(..end + 4);
                continue;
            }
            return Ok(status);
        }
        if total_read >= DEFAULT_HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP response heads exceed their aggregate limit",
            ));
        }
        let mut chunk = [0_u8; 1024];
        let remaining = DEFAULT_HEADER_LIMIT - total_read;
        let max_read = remaining.min(chunk.len());
        let length = reader.read(&mut chunk[..max_read]).await?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP connection closed before the response head",
            ));
        }
        total_read += length;
        input.extend_from_slice(&chunk[..length]);
    }
}

fn parse_status(head: &[u8]) -> io::Result<u16> {
    let line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(head.len());
    let line = &head[..line_end];
    let mut fields = line.splitn(3, |byte| *byte == b' ');
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if (version != b"HTTP/1.0" && version != b"HTTP/1.1")
        || status.len() != 3
        || !status.iter().all(u8::is_ascii_digit)
    {
        return Err(invalid_data("invalid HTTP response status line"));
    }
    let status = u16::from(status[0] - b'0') * 100
        + u16::from(status[1] - b'0') * 10
        + u16::from(status[2] - b'0');
    if !(100..=599).contains(&status) {
        return Err(invalid_data("HTTP response status is out of range"));
    }
    Ok(status)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum.saturating_sub(3).min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut truncated = value[..end].to_owned();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    use async_trait::async_trait;
    use tokio::io::AsyncReadExt as _;

    use crate::{
        dispatch::{DatagramTransport, DispatchError},
        session::{DatagramSession, StreamSession},
    };

    use super::*;

    struct TestDispatcher {
        stream: Mutex<Option<BoxStream>>,
        session: Mutex<Option<StreamSession>>,
    }

    #[async_trait]
    impl Dispatcher for TestDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            *self.session.lock().unwrap() = Some(session);
            self.stream
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| DispatchError::Other("test stream was already used".to_owned()))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::Other(
                "datagrams are not used by latency probes".to_owned(),
            ))
        }
    }

    #[test]
    fn validates_batch_request_and_target_url() {
        let payload: MeasureDelayPayload = serde_json::from_value(serde_json::json!({
            "configYamls": ["proxies: []"],
            "timeout": 5,
            "url": "https://example.com/"
        }))
        .unwrap();
        assert_eq!(payload.config_yamls, vec!["proxies: []"]);
        assert!(
            serde_json::from_value::<MeasureDelayPayload>(serde_json::json!({
                "configPaths": ["config.yaml"],
                "timeout": 5,
                "url": "https://example.com/"
            }))
            .is_err()
        );

        let request = MeasureRequest::parse(MeasureDelayPayload {
            config_yamls: (0..MAX_MEASURE_CONFIGS)
                .map(|index| format!("proxies:\n  - name: proxy-{index}"))
                .collect(),
            timeout: 5,
            url: "https://example.com/path?q=1".to_owned(),
        })
        .unwrap();
        assert_eq!(request.config_yamls.len(), MAX_MEASURE_CONFIGS);
        assert_eq!(request.target.authority, "example.com:443");
        assert_eq!(request.target.origin_form, "/path?q=1");
        assert_eq!(
            request.target.destination,
            Destination::domain("example.com", 443).unwrap()
        );

        for payload in [
            MeasureDelayPayload {
                config_yamls: vec![],
                timeout: 5,
                url: "https://example.com/".to_owned(),
            },
            MeasureDelayPayload {
                config_yamls: vec!["".to_owned()],
                timeout: 5,
                url: "https://example.com/".to_owned(),
            },
            MeasureDelayPayload {
                config_yamls: vec!["proxies: []".to_owned()],
                timeout: 0,
                url: "https://example.com/".to_owned(),
            },
            MeasureDelayPayload {
                config_yamls: vec!["proxies: []".to_owned()],
                timeout: 5,
                url: "ftp://example.com/".to_owned(),
            },
        ] {
            assert!(MeasureRequest::parse(payload).is_err());
        }
        assert!(Target::parse("https://user@example.com/").is_err());
        assert!(Target::parse("https://example.com/#fragment").is_err());

        assert!(
            MeasureRequest::parse(MeasureDelayPayload {
                config_yamls: (0..=MAX_MEASURE_CONFIGS)
                    .map(|index| format!("proxies:\n  - name: proxy-{index}"))
                    .collect(),
                timeout: 5,
                url: "https://example.com/".to_owned(),
            })
            .is_err()
        );
        assert!(
            MeasureRequest::parse(MeasureDelayPayload {
                config_yamls: vec!["proxies: []".to_owned()],
                timeout: 31,
                url: "https://example.com/".to_owned(),
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_a_second_measurement_until_the_guard_drops() {
        let active = AtomicBool::new(false);
        let first = MeasureDelayAdmission::try_acquire(&active).unwrap();
        assert!(MeasureDelayAdmission::try_acquire(&active).is_err());
        drop(first);
        assert!(MeasureDelayAdmission::try_acquire(&active).is_ok());
    }

    #[tokio::test]
    async fn bounded_scheduler_runs_concurrently_and_keeps_input_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let jobs = [40_u64, 5, 20, 1, 10, 0]
            .into_iter()
            .enumerate()
            .map(|(index, wait)| {
                let active = active.clone();
                let peak = peak.clone();
                async move {
                    let current = active.fetch_add(1, AtomicOrdering::AcqRel) + 1;
                    peak.fetch_max(current, AtomicOrdering::AcqRel);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    active.fetch_sub(1, AtomicOrdering::AcqRel);
                    index
                }
            });
        let results = collect_ordered_bounded(jobs).await;
        assert_eq!(results, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(peak.load(AtomicOrdering::Acquire), MAX_MEASURE_WORKERS);
        assert_eq!(active.load(AtomicOrdering::Acquire), 0);
    }

    #[tokio::test]
    async fn invalid_in_memory_yamls_fail_closed_per_item() {
        let results = run_batch(MeasureRequest {
            config_yamls: vec![
                "/tmp/config-that-must-not-be-read.yaml".to_owned(),
                "proxies: [".to_owned(),
            ],
            timeout: Duration::from_secs(5),
            target: Target::parse("https://example.com/").unwrap(),
        })
        .await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| !result.success));
        assert!(results.iter().all(|result| result.delay.is_none()));
        assert!(results.iter().all(|result| !result.error.is_empty()));
    }

    #[tokio::test]
    async fn direct_probe_uses_the_internal_measurement_session_and_sends_head() {
        let (client, mut server) = tokio::io::duplex(4096);
        let dispatcher = Arc::new(TestDispatcher {
            stream: Mutex::new(Some(Box::new(client))),
            session: Mutex::new(None),
        });
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"HEAD /path?q=1 HTTP/1.1\r\n"));
            assert!(
                request
                    .windows(b"Host: example.test:80\r\n".len())
                    .any(|window| window == b"Host: example.test:80\r\n")
            );
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        probe_once(
            &Target::parse("http://example.test/path?q=1").unwrap(),
            dispatcher.clone(),
            None,
        )
        .await
        .unwrap();
        server_task.await.unwrap();

        let session = dispatcher.session.lock().unwrap().take().unwrap();
        assert_eq!(session.inbound, InboundKind::InternalMeasure);
        assert_eq!(
            session.destination,
            Destination::domain("example.test", 80).unwrap()
        );
    }

    #[test]
    fn parses_http_status_lines_and_bounds_item_errors() {
        assert_eq!(parse_status(b"HTTP/1.1 204 No Content").unwrap(), 204);
        assert_eq!(parse_status(b"HTTP/1.0 599 Weird").unwrap(), 599);
        assert!(parse_status(b"HTTP/2 200").is_err());
        assert!(parse_status(b"HTTP/1.1 abc").is_err());
        assert!(parse_status(b"HTTP/1.1 999").is_err());

        let result = MeasureDelayResult::failure("界".repeat(MAX_ITEM_ERROR_BYTES));
        assert!(!result.success);
        assert!(result.delay.is_none());
        assert!(result.error.len() <= MAX_ITEM_ERROR_BYTES);
        assert!(result.error.ends_with("..."));
        assert!(std::str::from_utf8(result.error.as_bytes()).is_ok());

        assert_eq!(
            serde_json::to_value(MeasureDelayResult::success(123)).unwrap(),
            serde_json::json!({"success": true, "delay": 123, "error": ""})
        );
        assert_eq!(
            serde_json::to_value(MeasureDelayResult::failure("failed")).unwrap(),
            serde_json::json!({"success": false, "error": "failed"})
        );
    }

    #[tokio::test]
    async fn informational_and_final_heads_share_one_aggregate_limit() {
        let first = format!(
            "HTTP/1.1 103 Early Hints\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(16 * 1024)
        );
        let final_head = format!(
            "HTTP/1.1 200 OK\r\nX-Pad: {}\r\n\r\n",
            "b".repeat(20 * 1024)
        );
        let mut response = first.into_bytes();
        response.extend_from_slice(final_head.as_bytes());
        let (mut writer, mut reader) = tokio::io::duplex(response.len());
        writer.write_all(&response).await.unwrap();
        drop(writer);

        assert_eq!(
            read_response_status(&mut reader).await.unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
    }
}
