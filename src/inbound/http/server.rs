use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    dispatch::{DispatchError, Dispatcher},
    outbound::{
        MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES, OutboundDiagnostic, capture_outbound_diagnostic,
    },
    session::{InboundKind, StreamSession},
};

use super::super::DEFAULT_HEADER_LIMIT;
use super::parser::read_request_head;

pub(crate) const MEASURE_DIAGNOSTIC_HEADER: &str = "X-VCore-Measure-Diagnostic";
pub(crate) const MEASURE_DIAGNOSTIC_REQUEST: &str = "v1";
const MAX_MEASURE_DIAGNOSTIC_HEADER_BYTES: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub struct HttpBasicAuth {
    username: String,
    password: String,
}

impl std::fmt::Debug for HttpBasicAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpBasicAuth")
            .finish_non_exhaustive()
    }
}

impl HttpBasicAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> io::Result<Self> {
        let username = username.into();
        let password = password.into();
        validate_credential(&username, "username")?;
        validate_credential(&password, "password")?;
        if username.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP Basic username must not contain `:`",
            ));
        }
        Ok(Self { username, password })
    }

    #[must_use]
    pub fn authorization_header_value(&self) -> String {
        let mut plain = String::with_capacity(self.username.len() + 1 + self.password.len());
        plain.push_str(&self.username);
        plain.push(':');
        plain.push_str(&self.password);
        format!("Basic {}", STANDARD.encode(plain.as_bytes()))
    }

    fn verifies(&self, headers: &[(String, String)]) -> bool {
        let mut values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, value)| value.as_str());
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }

        let mut parts = value.split_ascii_whitespace();
        let (Some(scheme), Some(encoded), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(decoded) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((username, password)) = decoded.split_once(':') else {
            return false;
        };
        username == self.username && password == self.password
    }
}

fn validate_credential(value: &str, kind: &str) -> io::Result<()> {
    if !(1..=usize::from(u8::MAX)).contains(&value.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("HTTP Basic {kind} must contain between 1 and 255 UTF-8 bytes"),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub listen: SocketAddr,
    pub auth: HttpBasicAuth,
    pub header_limit: usize,
    pub header_timeout: Duration,
    pub connect_timeout: Duration,
}

impl HttpServerConfig {
    pub fn loopback(listen: SocketAddr, auth: HttpBasicAuth) -> io::Result<Self> {
        if !listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP listener must bind loopback",
            ));
        }
        Ok(Self {
            listen,
            auth,
            header_limit: DEFAULT_HEADER_LIMIT,
            header_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(15),
        })
    }
}

pub struct HttpServer {
    listener: TcpListener,
    config: HttpServerConfig,
    dispatcher: Arc<dyn Dispatcher>,
}

impl HttpServer {
    pub async fn bind(
        config: HttpServerConfig,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> io::Result<Self> {
        if !config.listen.ip().is_loopback() || config.header_limit < 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid HTTP listener configuration",
            ));
        }
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            config,
            dispatcher,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted?;
                    let dispatcher = self.dispatcher.clone();
                    let config = self.config.clone();
                    let child = cancellation.clone();
                    tasks.spawn(async move {
                        let _ = handle_connection(stream, peer, dispatcher, config, child).await;
                    });
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let _ = joined;
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

pub(crate) async fn handle_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    dispatcher: Arc<dyn Dispatcher>,
    config: HttpServerConfig,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let parsed = tokio::select! {
        () = cancellation.cancelled() => return Ok(()),
        result = timeout(
            config.header_timeout,
            read_request_head(&mut inbound, config.header_limit),
        ) => result,
    };
    let request = match parsed {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            let status = if error.kind() == io::ErrorKind::FileTooLarge {
                431
            } else {
                400
            };
            write_error(&mut inbound, status).await?;
            return Err(error);
        }
        Err(_) => {
            write_error(&mut inbound, 408).await?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP request head timed out",
            ));
        }
    };
    if !config.auth.verifies(&request.headers) {
        write_auth_required(&mut inbound).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP proxy authentication failed",
        ));
    }
    let diagnostic_requested = request.is_connect()
        && peer.ip().is_loopback()
        && requests_measure_diagnostic(&request.headers);

    if request.is_connect() {
        let destination = match request.connect_destination() {
            Ok(destination) => destination,
            Err(error) => {
                write_error(&mut inbound, 400).await?;
                return Err(error);
            }
        };
        let early_data = request.buffered;
        let session = StreamSession {
            inbound: InboundKind::Http,
            source: peer,
            destination,
            sniffed_domain: None,
        };
        let mut outbound = connect(
            &dispatcher,
            session,
            &config,
            &cancellation,
            &mut inbound,
            diagnostic_requested,
        )
        .await?;
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !early_data.is_empty() {
            write_outbound(&mut outbound, &early_data, &config, &cancellation).await?;
        }
        return tokio::select! {
            () = cancellation.cancelled() => Ok(()),
            copied = tokio::io::copy_bidirectional_with_sizes(
                &mut inbound,
                &mut outbound,
                4 * 1024,
                4 * 1024,
            ) => copied.map(|_| ()),
        };
    }

    let (destination, head, buffered) = match request.into_forward() {
        Ok(forward) => forward,
        Err(error) => {
            let status = if error.kind() == io::ErrorKind::Unsupported {
                501
            } else {
                400
            };
            write_error(&mut inbound, status).await?;
            return Err(error);
        }
    };
    let session = StreamSession {
        inbound: InboundKind::Http,
        source: peer,
        destination,
        sniffed_domain: None,
    };
    let mut outbound = connect(
        &dispatcher,
        session,
        &config,
        &cancellation,
        &mut inbound,
        false,
    )
    .await?;
    write_outbound(&mut outbound, &head, &config, &cancellation).await?;
    if !buffered.is_empty() {
        write_outbound(&mut outbound, &buffered, &config, &cancellation).await?;
    }
    tokio::select! {
        () = cancellation.cancelled() => Ok(()),
        copied = tokio::io::copy_bidirectional_with_sizes(
            &mut inbound,
            &mut outbound,
            4 * 1024,
            4 * 1024,
        ) => copied.map(|_| ()),
    }
}

async fn write_outbound(
    outbound: &mut crate::dispatch::BoxStream,
    bytes: &[u8],
    config: &HttpServerConfig,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "HTTP listener stopped during outbound preface write",
        )),
        written = timeout(config.connect_timeout, outbound.write_all(bytes)) => {
            written.map_err(|_| io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP outbound preface write timed out",
            ))?
        }
    }
}

async fn connect(
    dispatcher: &Arc<dyn Dispatcher>,
    session: StreamSession,
    config: &HttpServerConfig,
    cancellation: &CancellationToken,
    inbound: &mut TcpStream,
    diagnostic_requested: bool,
) -> io::Result<crate::dispatch::BoxStream> {
    let connect = async {
        tokio::select! {
            () = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "HTTP listener stopped")),
            result = timeout(config.connect_timeout, dispatcher.connect_tcp(session)) => Ok(result),
        }
    };
    let (connected, diagnostic) = if diagnostic_requested {
        capture_outbound_diagnostic(connect).await
    } else {
        (connect.await, None)
    };
    let connected = connected?;
    match connected {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            write_error_with_diagnostic(inbound, error.http_status(), diagnostic.as_ref()).await?;
            Err(dispatch_to_io(error))
        }
        Err(_) => {
            write_error_with_diagnostic(inbound, 504, diagnostic.as_ref()).await?;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP outbound connect timed out",
            ))
        }
    }
}

fn requests_measure_diagnostic(headers: &[(String, String)]) -> bool {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(MEASURE_DIAGNOSTIC_HEADER))
        .map(|(_, value)| value.as_str());
    matches!(
        (values.next(), values.next()),
        (Some(MEASURE_DIAGNOSTIC_REQUEST), None)
    )
}

async fn write_error(stream: &mut TcpStream, status: u16) -> io::Result<()> {
    write_error_with_diagnostic(stream, status, None).await
}

async fn write_auth_required(stream: &mut TcpStream) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"VCore\"\r\n\
              Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await
}

async fn write_error_with_diagnostic(
    stream: &mut TcpStream,
    status: u16,
    diagnostic: Option<&OutboundDiagnostic>,
) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Proxy Error",
    };
    let diagnostic = diagnostic.map(format_measure_diagnostic_header);
    let diagnostic = diagnostic.as_deref().map_or_else(String::new, |value| {
        format!("{MEASURE_DIAGNOSTIC_HEADER}: {value}\r\n")
    });
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\n{diagnostic}Connection: close\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
}

fn format_measure_diagnostic_header(diagnostic: &OutboundDiagnostic) -> String {
    debug_assert!(diagnostic.message().len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES);
    let error = URL_SAFE_NO_PAD.encode(diagnostic.message().as_bytes());
    let value = format!(
        "v1;stage={};kind={};error={error}",
        diagnostic.stage(),
        diagnostic.kind()
    );
    debug_assert!(value.len() <= MAX_MEASURE_DIAGNOSTIC_HEADER_BYTES);
    value
}

fn dispatch_to_io(error: DispatchError) -> io::Error {
    let kind = match error {
        DispatchError::NotAllowed => io::ErrorKind::PermissionDenied,
        DispatchError::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
        DispatchError::HostUnreachable => io::ErrorKind::HostUnreachable,
        DispatchError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        DispatchError::TimedOut => io::ErrorKind::TimedOut,
        DispatchError::Other(_) => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        dispatch::{BoxStream, DatagramTransport},
        outbound::EstablishContext,
        session::{DatagramSession, Destination},
    };

    const TEST_USERNAME: &str = "measure";
    const TEST_PASSWORD: &str = "secret";

    fn test_auth() -> HttpBasicAuth {
        HttpBasicAuth::new(TEST_USERNAME, TEST_PASSWORD).unwrap()
    }

    fn test_authorization() -> String {
        test_auth().authorization_header_value()
    }

    struct HttpTestDispatcher {
        request: Arc<Mutex<Vec<u8>>>,
    }

    struct FailingDispatcher {
        message: String,
    }

    #[async_trait]
    impl Dispatcher for HttpTestDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            let (client, mut remote) = tokio::io::duplex(8 * 1024);
            let recorded = self.request.clone();
            if session.destination == Destination::domain("example.com", 80).unwrap() {
                tokio::spawn(async move {
                    let mut input = Vec::new();
                    let mut byte = [0_u8; 1];
                    while remote.read_exact(&mut byte).await.is_ok() {
                        input.push(byte[0]);
                        if input.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    *recorded.lock().unwrap() = input;
                    let _ = remote
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            } else {
                tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(remote);
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::Other("unused".to_owned()))
        }
    }

    #[async_trait]
    impl Dispatcher for FailingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            let message = self.message.clone();
            EstablishContext::default()
                .run_io("VLESS TLS/REALITY handshake", async move {
                    Err::<(), _>(io::Error::new(io::ErrorKind::InvalidData, message))
                })
                .await?;
            unreachable!("the failing dispatcher never returns a stream")
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::Other("unused".to_owned()))
        }
    }

    async fn start_server() -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
        Arc<Mutex<Vec<u8>>>,
    ) {
        let request = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = Arc::new(HttpTestDispatcher {
            request: request.clone(),
        });
        let config =
            HttpServerConfig::loopback("127.0.0.1:0".parse().unwrap(), test_auth()).unwrap();
        let server = HttpServer::bind(config, dispatcher).await.unwrap();
        let address = server.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(server.serve(child));
        (address, cancellation, task, request)
    }

    async fn start_failing_server(
        message: String,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let config =
            HttpServerConfig::loopback("127.0.0.1:0".parse().unwrap(), test_auth()).unwrap();
        let server = HttpServer::bind(config, Arc::new(FailingDispatcher { message }))
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(server.serve(child));
        (address, cancellation, task)
    }

    #[test]
    fn basic_auth_validates_and_keeps_credentials_out_of_debug_output() {
        let auth = HttpBasicAuth::new("用户", "p:a:ss").unwrap();
        let value = auth.authorization_header_value();
        assert!(auth.verifies(&[(
            "Proxy-Authorization".to_owned(),
            value.replacen("Basic", "bAsIc", 1),
        )]));
        assert!(!auth.verifies(&[("Proxy-Authorization".to_owned(), "Basic !!!".to_owned(),)]));
        assert_eq!(format!("{auth:?}"), "HttpBasicAuth { .. }");

        assert!(HttpBasicAuth::new("", "password").is_err());
        assert!(HttpBasicAuth::new("user", "").is_err());
        assert!(HttpBasicAuth::new("user:name", "password").is_err());
        assert!(HttpBasicAuth::new("u".repeat(255), "p".repeat(255)).is_ok());
        assert!(HttpBasicAuth::new("u".repeat(256), "password").is_err());
        assert!(HttpBasicAuth::new("user", "p".repeat(256)).is_err());
    }

    #[tokio::test]
    async fn missing_malformed_wrong_and_duplicate_auth_are_rejected_before_dispatch() {
        let (address, cancellation, task, _) = start_server().await;
        let valid = test_authorization();
        let wrong = HttpBasicAuth::new(TEST_USERNAME, "wrong")
            .unwrap()
            .authorization_header_value();
        for headers in [
            String::new(),
            "Proxy-Authorization: Bearer token\r\n".to_owned(),
            "Proxy-Authorization: Basic !!!\r\n".to_owned(),
            format!(
                "Proxy-Authorization: {wrong}\r\n{MEASURE_DIAGNOSTIC_HEADER}: {MEASURE_DIAGNOSTIC_REQUEST}\r\n"
            ),
            format!("Proxy-Authorization: {valid}\r\nProxy-Authorization: {valid}\r\n"),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(
                    format!(
                        "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n{headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"VCore\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            );
        }

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn listener_keeps_accepting_beyond_the_former_connection_limit() {
        const HELD_CONNECTIONS: usize = 140;

        let (address, cancellation, task, _) = start_server().await;
        let mut held = Vec::with_capacity(HELD_CONNECTIONS);
        for _ in 0..HELD_CONNECTIONS {
            let mut client =
                tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(address))
                    .await
                    .expect("HTTP listener stopped accepting connections")
                    .unwrap();
            client.write_all(b"G").await.unwrap();
            held.push(client);
        }

        let mut probe = TcpStream::connect(address).await.unwrap();
        probe
            .write_all(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), probe.read_to_end(&mut response))
            .await
            .expect("a connection beyond the former limit was not handled")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"));

        cancellation.cancel();
        drop((held, probe));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_tunnels_early_and_late_data() {
        let (address, cancellation, task, _) = start_server().await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\nProxy-Authorization: {}\r\n\r\nearly",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let mut echoed = [0_u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"early");
        client.write_all(b"later").await.unwrap();
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"later");
        cancellation.cancel();
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn absolute_form_is_rewritten_and_proxy_headers_are_removed() {
        let (address, cancellation, task, request) = start_server().await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: stale\r\nProxy-Authorization: {}\r\nConnection: X-Drop\r\nX-Drop: yes\r\n\r\n",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        let forwarded = String::from_utf8(request.lock().unwrap().clone()).unwrap();
        assert!(forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(forwarded.contains("Host: example.com:80\r\n"));
        assert!(!forwarded.contains("Proxy-Authorization"));
        assert!(!forwarded.contains("X-Drop"));
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn origin_form_and_upgrade_are_rejected() {
        let (address, cancellation, task, _) = start_server().await;
        for request in [
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: {}\r\n\r\n",
                test_authorization()
            ),
            format!(
                "GET http://example.com/ HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Authorization: {}\r\n\r\n",
                test_authorization()
            ),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(request.as_bytes()).await.unwrap();
            let mut response = [0_u8; 64];
            let length = client.read(&mut response).await.unwrap();
            assert!(
                response[..length].starts_with(b"HTTP/1.1 4")
                    || response[..length].starts_with(b"HTTP/1.1 501")
            );
        }
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ordinary_connect_failure_keeps_the_compatible_plain_502_response() {
        let (address, cancellation, task) =
            start_failing_server("certificate rejected".to_owned()).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {}\r\n\r\n",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn opted_in_connect_failure_encodes_bounded_crlf_and_utf8_diagnostic() {
        let message = format!("证书失败\r\nInjected: yes {}", "界".repeat(100));
        let (address, cancellation, task) = start_failing_server(message).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {}\r\n{MEASURE_DIAGNOSTIC_HEADER}: {MEASURE_DIAGNOSTIC_REQUEST}\r\n\r\n",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(!response.contains("\r\nInjected: yes"));

        let header = response
            .split("\r\n")
            .find_map(|line| line.strip_prefix(&format!("{MEASURE_DIAGNOSTIC_HEADER}: ")))
            .unwrap();
        assert!(header.len() <= MAX_MEASURE_DIAGNOSTIC_HEADER_BYTES);
        assert!(header.starts_with("v1;stage=vless-security;kind=invalid_data;error="));
        let encoded = header.split_once(";error=").unwrap().1;
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let decoded = String::from_utf8(decoded).unwrap();
        assert!(decoded.starts_with("证书失败\r\nInjected: yes "));
        assert!(decoded.ends_with("..."));
        assert!(decoded.len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES);

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }
}
