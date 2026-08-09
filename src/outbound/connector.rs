use std::{
    fmt::{self, Write as _},
    future::Future,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::time::{Instant, timeout_at};

use crate::{
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{DatagramSession, Destination, StreamSession},
};

use super::DirectOutbound;

const DEFAULT_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES: usize = 256;

tokio::task_local! {
    static OUTBOUND_DIAGNOSTIC: Arc<Mutex<Option<OutboundDiagnostic>>>;
}

/// One bounded, connection-local failure description for an opt-in diagnostic
/// caller. Stage names are fixed tokens and the message is the original error
/// display text truncated before it can consume unbounded memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundDiagnostic {
    stage: &'static str,
    kind: &'static str,
    message: String,
}

impl OutboundDiagnostic {
    #[must_use]
    pub(crate) const fn stage(&self) -> &'static str {
        self.stage
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> &'static str {
        self.kind
    }

    #[must_use]
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// Captures the first outbound setup failure observed while `future` runs.
///
/// The task-local slot is only installed by explicitly diagnostic local HTTP
/// callers. Normal TUN, SOCKS5, and HTTP traffic therefore pays no allocation
/// cost and cannot observe the diagnostic.
pub(crate) async fn capture_outbound_diagnostic<F>(
    future: F,
) -> (F::Output, Option<OutboundDiagnostic>)
where
    F: Future,
{
    let slot = Arc::new(Mutex::new(None));
    let output = OUTBOUND_DIAGNOSTIC.scope(slot.clone(), future).await;
    let diagnostic = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    (output, diagnostic)
}

fn record_io_diagnostic(operation: &'static str, error: &io::Error) -> String {
    let message = bounded_message(error);
    record_diagnostic(operation, io_error_kind(error.kind()), message.clone());
    message
}

fn record_dispatch_diagnostic(operation: &'static str, error: &DispatchError) {
    let message = match error {
        DispatchError::Other(message) => bounded_message(message),
        _ => bounded_message(error),
    };
    record_diagnostic(operation, error.diagnostic_code(), message);
}

fn record_timeout_diagnostic(operation: &'static str) {
    record_diagnostic(
        operation,
        "timed_out",
        "outbound setup deadline expired".to_owned(),
    );
}

fn record_diagnostic(operation: &'static str, kind: &'static str, message: String) {
    let _ = OUTBOUND_DIAGNOSTIC.try_with(|slot| {
        let mut slot = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(OutboundDiagnostic {
                stage: diagnostic_stage(operation),
                kind,
                message,
            });
        }
    });
}

fn diagnostic_stage(operation: &'static str) -> &'static str {
    match operation {
        "physical proxy-server connect" => "physical-connect",
        "direct TCP connect" => "direct-connect",
        "VLESS TLS/REALITY handshake" => "vless-security",
        "VLESS XHTTP handshake" => "vless-xhttp",
        "VLESS XUDP request header" => "vless-xudp-header",
        "SOCKS5 CONNECT handshake" => "socks5-connect",
        "SOCKS5 UDP ASSOCIATE handshake" => "socks5-udp-associate",
        "AnyTLS TLS handshake" => "anytls-tls",
        "AnyTLS authentication and session preface" => "anytls-session",
        "AnyTLS session open" => "anytls-stream",
        "upstream dispatcher connect" => "upstream-connect",
        "upstream dispatcher datagram setup" => "upstream-datagram",
        _ => "outbound",
    }
}

fn io_error_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::PermissionDenied => "not_allowed",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    }
}

fn bounded_message(value: &impl fmt::Display) -> String {
    let mut output = BoundedMessage::new();
    let _ = write!(output, "{value}");
    output.value
}

struct BoundedMessage {
    value: String,
    truncated: bool,
}

impl BoundedMessage {
    fn new() -> Self {
        Self {
            value: String::with_capacity(MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES),
            truncated: false,
        }
    }

    fn truncate_to_boundary(&mut self, maximum: usize) {
        let mut length = self.value.len().min(maximum);
        while !self.value.is_char_boundary(length) {
            length -= 1;
        }
        self.value.truncate(length);
    }
}

impl fmt::Write for BoundedMessage {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        const MARKER: &str = "...";
        if self.truncated {
            return Ok(());
        }
        if self.value.len() + value.len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES {
            self.value.push_str(value);
            return Ok(());
        }

        let content_limit = MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES - MARKER.len();
        self.truncate_to_boundary(content_limit);
        let remaining = content_limit.saturating_sub(self.value.len());
        let mut length = value.len().min(remaining);
        while !value.is_char_boundary(length) {
            length -= 1;
        }
        self.value.push_str(&value[..length]);
        self.value.push_str(MARKER);
        self.truncated = true;
        Ok(())
    }
}

/// One absolute deadline shared by every hop of a logical outbound setup.
///
/// A router builds this context once and passes it through the complete
/// configured chain so nested connectors share one timeout instead of restarting it at
/// every hop.
#[derive(Debug, Clone, Copy)]
pub struct EstablishContext {
    deadline: Instant,
}

impl EstablishContext {
    #[must_use]
    pub fn with_timeout(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
        }
    }

    #[must_use]
    pub const fn with_deadline(deadline: Instant) -> Self {
        Self { deadline }
    }

    #[must_use]
    pub const fn deadline(self) -> Instant {
        self.deadline
    }

    pub async fn run<T, F>(&self, operation: &'static str, future: F) -> Result<T, DispatchError>
    where
        F: Future<Output = Result<T, DispatchError>>,
    {
        match timeout_at(self.deadline, future).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(error)) => {
                record_dispatch_diagnostic(operation, &error);
                Err(error)
            }
            Err(_) => {
                record_timeout_diagnostic(operation);
                tracing::warn!(operation, error_code = "timed_out", "outbound setup failed");
                Err(DispatchError::TimedOut)
            }
        }
    }

    pub async fn run_io<T, F>(&self, operation: &'static str, future: F) -> Result<T, DispatchError>
    where
        F: Future<Output = io::Result<T>>,
    {
        self.run(operation, async move {
            future.await.map_err(|error| {
                let diagnostic = record_io_diagnostic(operation, &error);
                tracing::warn!(
                    operation,
                    error_kind = ?error.kind(),
                    error = %diagnostic,
                    "outbound setup I/O failed"
                );
                DispatchError::from(error)
            })
        })
        .await
    }
}

impl Default for EstablishContext {
    fn default() -> Self {
        Self::with_timeout(DEFAULT_ESTABLISH_TIMEOUT)
    }
}

/// A connected stream plus the peer identity effective at the connector
/// boundary.
///
/// A direct connector reports the selected IP address. A proxy connector
/// reports the logical destination it asked the remote proxy to reach. SOCKS5
/// uses this distinction to normalize wildcard UDP relay replies without
/// performing DNS after TUN startup.
pub struct ConnectedStream {
    pub io: BoxStream,
    pub effective_peer: Destination,
}

impl std::fmt::Debug for ConnectedStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectedStream")
            .field("effective_peer", &self.effective_peer)
            .finish_non_exhaustive()
    }
}

/// Datagram setup parameters propagated through nested proxy layers.
///
/// `max_response_payload_size` is the largest wire payload accepted from the
/// connector being opened. An encapsulating connector, such as SOCKS5, widens
/// the value before opening its upstream and enforces the original value after
/// decoding its own header.
#[derive(Debug, Clone)]
pub struct DatagramRequest {
    pub session: DatagramSession,
    max_response_payload_size: u16,
}

impl DatagramRequest {
    #[must_use]
    pub fn new(session: DatagramSession) -> Self {
        let max_response_payload_size = session.max_response_payload_size();
        Self {
            session,
            max_response_payload_size,
        }
    }

    #[must_use]
    pub const fn max_response_payload_size(&self) -> u16 {
        self.max_response_payload_size
    }

    #[must_use]
    pub fn with_max_response_payload_size(&self, maximum: u16) -> Self {
        Self {
            session: self.session.clone(),
            max_response_payload_size: maximum,
        }
    }
}

/// Internal composable outbound boundary.
///
/// Unlike [`Dispatcher`], this boundary retains effective-peer metadata,
/// propagates one setup context through every hop, and lets encapsulating UDP
/// protocols adjust their upstream response budget.
#[async_trait]
pub trait OutboundConnector: Send + Sync {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError>;

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError>;

    /// Prevents new protocol-owned background work from being created.
    ///
    /// Most connectors are stateless and need no action. Session-multiplexed
    /// protocols override this hook so the runtime can begin a deterministic
    /// two-phase shutdown before waiting for inbound tasks.
    fn begin_shutdown(&self) {}

    /// Waits until protocol-owned background work has exited.
    async fn shutdown(&self) {}
}

/// The path used by one configured proxy to reach its own server.
#[derive(Clone)]
pub enum UpstreamPath {
    /// The physical first hop. Its endpoint was resolved during prepare.
    Direct {
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
    },
    /// Another configured proxy node. The target server remains a logical
    /// destination and is resolved by that proxy rather than by the host.
    Proxy(Arc<dyn OutboundConnector>),
}

impl std::fmt::Debug for UpstreamPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { endpoint, dialer } => formatter
                .debug_struct("DirectUpstream")
                .field("endpoint", endpoint)
                .field("dialer", dialer)
                .finish(),
            Self::Proxy(_) => formatter.write_str("ProxyUpstream(..)"),
        }
    }
}

impl UpstreamPath {
    #[must_use]
    pub const fn direct(endpoint: ResolvedEndpoint, dialer: Dialer) -> Self {
        Self::Direct { endpoint, dialer }
    }

    #[must_use]
    pub fn proxy(connector: Arc<dyn OutboundConnector>) -> Self {
        Self::Proxy(connector)
    }

    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    pub async fn connect_server(
        &self,
        mut session: StreamSession,
        server: &Destination,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        session.destination = server.clone();
        match self {
            Self::Direct { endpoint, dialer } => {
                validate_prepared_endpoint(server, endpoint)?;
                let stream = context
                    .run_io("physical proxy-server connect", dialer.connect(endpoint))
                    .await?;
                let effective_peer =
                    Destination::Ip(stream.peer_addr().map_err(DispatchError::from)?);
                Ok(ConnectedStream {
                    io: Box::new(stream),
                    effective_peer,
                })
            }
            Self::Proxy(connector) => connector.connect_stream(session, context).await,
        }
    }

    pub async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        match self {
            Self::Direct { dialer, .. } => {
                let direct = DirectOutbound::new(dialer.clone());
                OutboundConnector::open_datagram(&direct, request, context).await
            }
            Self::Proxy(connector) => connector.open_datagram(request, context).await,
        }
    }
}

/// Creates the logical server destination retained by proxy connectors.
pub fn server_destination(address: &str, port: u16) -> io::Result<Destination> {
    if let Ok(address) = address.parse::<IpAddr>() {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy server port is zero",
            ));
        }
        Ok(Destination::Ip(std::net::SocketAddr::new(address, port)))
    } else {
        Destination::domain(address, port)
    }
}

fn validate_prepared_endpoint(
    server: &Destination,
    endpoint: &ResolvedEndpoint,
) -> Result<(), DispatchError> {
    if server.port() != endpoint.port || endpoint.addresses.is_empty() {
        return Err(DispatchError::Other(
            "prepared endpoint does not match the configured proxy server".to_owned(),
        ));
    }
    let matches = match server {
        Destination::Domain { host, .. } => host == &endpoint.logical_host,
        Destination::Ip(address) => {
            endpoint.logical_host.parse::<IpAddr>().ok() == Some(address.ip())
                && endpoint.addresses.iter().any(|item| item == address)
        }
    };
    if !matches {
        return Err(DispatchError::Other(
            "prepared endpoint does not match the configured proxy server".to_owned(),
        ));
    }
    Ok(())
}

/// Adapts an existing dispatcher for use as an upstream connector.
///
/// This is primarily useful for tests and incremental runtime migration. A
/// graph builder should prefer raw connectors so per-hop dispatcher wrappers
/// do not duplicate session or handshake observations.
pub struct DispatcherConnector {
    inner: Arc<dyn Dispatcher>,
}

impl DispatcherConnector {
    #[must_use]
    pub fn new(inner: Arc<dyn Dispatcher>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl OutboundConnector for DispatcherConnector {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let io = context
            .run(
                "upstream dispatcher connect",
                self.inner.connect_tcp(session),
            )
            .await?;
        Ok(ConnectedStream { io, effective_peer })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let maximum = request.max_response_payload_size();
        let session = request.session.with_max_response_payload_size(maximum);
        context
            .run(
                "upstream dispatcher datagram setup",
                self.inner.open_datagram(session),
            )
            .await
    }
}

/// Adapts a connector back to the stable inbound/router dispatcher boundary.
pub struct ConnectorDispatcher {
    inner: Arc<dyn OutboundConnector>,
    allow_udp: bool,
}

impl ConnectorDispatcher {
    #[must_use]
    pub fn new(inner: Arc<dyn OutboundConnector>) -> Self {
        Self {
            inner,
            allow_udp: true,
        }
    }

    /// Creates the routed boundary for one configured proxy.
    ///
    /// The capability applies only when rules select this node directly.
    /// Internal `dialer-proxy` hops keep using the raw connector so a parent
    /// carrying a child TCP stream is not rejected by the parent's UDP flag.
    #[must_use]
    pub fn with_udp_capability(inner: Arc<dyn OutboundConnector>, allow_udp: bool) -> Self {
        Self { inner, allow_udp }
    }
}

#[async_trait]
impl Dispatcher for ConnectorDispatcher {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.inner
            .connect_stream(session, &EstablishContext::default())
            .await
            .map(|connected| connected.io)
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if !self.allow_udp {
            return Err(DispatchError::NotAllowed);
        }
        self.inner
            .open_datagram(DatagramRequest::new(session), &EstablishContext::default())
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::atomic::{AtomicU16, Ordering},
    };

    use super::*;

    struct CapturingDispatcher {
        maximum: Arc<AtomicU16>,
    }

    #[async_trait]
    impl Dispatcher for CapturingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            unreachable!("the datagram adapter test does not connect TCP")
        }

        async fn open_datagram(
            &self,
            session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.maximum
                .store(session.max_response_payload_size(), Ordering::Relaxed);
            Ok(Box::new(EmptyDatagramTransport))
        }
    }

    struct EmptyDatagramTransport;

    #[async_trait]
    impl DatagramTransport for EmptyDatagramTransport {
        async fn send(&mut self, _datagram: crate::session::Datagram) -> Result<(), DispatchError> {
            Ok(())
        }

        async fn receive(&mut self) -> Result<crate::session::Datagram, DispatchError> {
            pending().await
        }
    }

    #[test]
    fn server_destination_keeps_domains_and_literals_distinct() {
        assert!(matches!(
            server_destination("example.com", 443).unwrap(),
            Destination::Domain { .. }
        ));
        assert!(matches!(
            server_destination("2001:db8::1", 443).unwrap(),
            Destination::Ip(_)
        ));
        assert!(server_destination("example.com", 0).is_err());
    }

    #[test]
    fn nested_datagram_budget_is_explicit_and_saturating_at_callers() {
        let session = DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        );
        let request = DatagramRequest::new(session);
        assert_eq!(request.max_response_payload_size(), 1_452);
        assert_eq!(
            request
                .with_max_response_payload_size(1_714)
                .max_response_payload_size(),
            1_714
        );
    }

    #[tokio::test]
    async fn establish_deadline_remains_a_typed_timeout() {
        let result = EstablishContext::with_timeout(Duration::ZERO)
            .run("test operation", pending::<Result<(), DispatchError>>())
            .await;
        assert!(matches!(result, Err(DispatchError::TimedOut)));
    }

    #[tokio::test]
    async fn routed_udp_capability_does_not_open_the_raw_connector() {
        let maximum = Arc::new(AtomicU16::new(0));
        let connector: Arc<dyn OutboundConnector> =
            Arc::new(DispatcherConnector::new(Arc::new(CapturingDispatcher {
                maximum: maximum.clone(),
            })));
        let dispatcher = ConnectorDispatcher::with_udp_capability(connector, false);
        let session = DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        );

        assert!(matches!(
            dispatcher.open_datagram(session).await,
            Err(DispatchError::NotAllowed)
        ));
        assert_eq!(maximum.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn diagnostic_capture_keeps_the_first_stage_and_bounds_utf8_error_text() {
        let context = EstablishContext::default();
        let raw = format!("握手失败\r\nInjected: yes {}", "界".repeat(100));
        let (result, diagnostic) = capture_outbound_diagnostic(context.run(
            "upstream dispatcher connect",
            context.run_io("VLESS TLS/REALITY handshake", async move {
                Err::<(), _>(io::Error::new(io::ErrorKind::InvalidData, raw))
            }),
        ))
        .await;

        assert!(matches!(result, Err(DispatchError::Other(_))));
        let diagnostic = diagnostic.unwrap();
        assert_eq!(diagnostic.stage(), "vless-security");
        assert_eq!(diagnostic.kind(), "invalid_data");
        assert!(
            diagnostic
                .message()
                .starts_with("握手失败\r\nInjected: yes ")
        );
        assert!(diagnostic.message().ends_with("..."));
        assert!(diagnostic.message().len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES);
        assert!(std::str::from_utf8(diagnostic.message().as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn diagnostic_capture_preserves_timeout_status_and_stage() {
        let context = EstablishContext::with_timeout(Duration::ZERO);
        let (result, diagnostic) = capture_outbound_diagnostic(context.run(
            "physical proxy-server connect",
            pending::<Result<(), DispatchError>>(),
        ))
        .await;

        assert!(matches!(result, Err(DispatchError::TimedOut)));
        let diagnostic = diagnostic.unwrap();
        assert_eq!(diagnostic.stage(), "physical-connect");
        assert_eq!(diagnostic.kind(), "timed_out");
        assert_eq!(diagnostic.message(), "outbound setup deadline expired");
    }

    #[tokio::test]
    async fn dispatcher_adapter_preserves_nested_datagram_budget() {
        let maximum = Arc::new(AtomicU16::new(0));
        let connector = DispatcherConnector::new(Arc::new(CapturingDispatcher {
            maximum: maximum.clone(),
        }));
        let session = DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        );
        let request = DatagramRequest::new(session).with_max_response_payload_size(1_714);

        let _transport =
            OutboundConnector::open_datagram(&connector, request, &EstablishContext::default())
                .await
                .unwrap();

        assert_eq!(maximum.load(Ordering::Relaxed), 1_714);
    }
}
