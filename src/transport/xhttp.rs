use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use h2::{
    RecvStream, SendStream,
    client::{ResponseFuture, SendRequest},
};
use http::{Method, Request, StatusCode, Uri};
use rand::Rng as _;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};

use crate::dispatch::BoxStream;

const MIN_X_PADDING: usize = 100;
const MAX_X_PADDING: usize = 1_000;
const DEFAULT_UPLOAD_CHUNK_SIZE: usize = 64 * 1024;
const MAX_H2_HEADER_LIST_SIZE: u32 = 16 * 1024;
const DEFAULT_H2_SEND_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMode {
    StreamOne,
    PacketUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpConfig {
    pub host: String,
    pub path: String,
    pub mode: XHttpMode,
}

impl XHttpConfig {
    pub fn new(
        host: impl Into<String>,
        path: impl Into<String>,
        mode: XHttpMode,
    ) -> io::Result<Self> {
        let host = host.into();
        let path = path.into();
        if host.is_empty() || host.len() > 253 || host.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XHTTP host",
            ));
        }
        if path.is_empty() || path.len() > 2_048 || !path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XHTTP path",
            ));
        }
        Ok(Self { host, path, mode })
    }
}

#[derive(Debug, Clone)]
pub struct XHttpClient {
    mode: XHttpMode,
    request: RequestTemplate,
    send_buffer_size: usize,
    upload_chunk_size: usize,
}

impl XHttpClient {
    #[must_use]
    pub fn new(config: XHttpConfig) -> Self {
        let XHttpConfig { host, path, mode } = config;
        Self {
            mode,
            request: RequestTemplate {
                host: Arc::from(host),
                path: Arc::from(path),
            },
            send_buffer_size: DEFAULT_H2_SEND_BUFFER_SIZE,
            upload_chunk_size: DEFAULT_UPLOAD_CHUNK_SIZE,
        }
    }

    pub(crate) fn new_with_limits(
        config: XHttpConfig,
        send_buffer_size: usize,
        upload_chunk_size: usize,
    ) -> io::Result<Self> {
        if send_buffer_size == 0 || send_buffer_size > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP send buffer size must be between 1 and u32::MAX bytes",
            ));
        }
        if upload_chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP upload chunk size must be greater than zero",
            ));
        }
        let mut client = Self::new(config);
        client.send_buffer_size = send_buffer_size;
        client.upload_chunk_size = upload_chunk_size;
        Ok(client)
    }

    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        let mut builder = h2::client::Builder::new();
        builder
            .max_header_list_size(MAX_H2_HEADER_LIST_SIZE)
            .max_send_buffer_size(self.send_buffer_size)
            .enable_push(false);
        let (sender, connection) = builder.handshake(stream).await.map_err(io_other)?;
        let connection = ConnectionGuard::spawn(connection);
        match self.mode {
            XHttpMode::StreamOne => self.connect_stream_one(sender, connection).await,
            XHttpMode::PacketUp => self.connect_packet_up(sender, connection).await,
        }
    }

    async fn connect_stream_one(
        &self,
        sender: SendRequest<Bytes>,
        connection: ConnectionGuard,
    ) -> io::Result<BoxStream> {
        let mut sender = sender;
        let request = self.stream_request(Method::POST, None, None, true)?;
        let (response, upload) = sender.send_request(request, false).map_err(io_other)?;
        Ok(Box::new(StreamOne {
            upload,
            download: Downlink::pending(response, "stream-one"),
            upload_chunk_size: self.upload_chunk_size,
            send_closed: false,
            _connection: connection,
        }))
    }

    async fn connect_packet_up(
        &self,
        sender: SendRequest<Bytes>,
        connection: ConnectionGuard,
    ) -> io::Result<BoxStream> {
        let session_id: Arc<str> = Arc::from(random_session_id());
        let mut sender = sender;
        let request = self.stream_request(Method::GET, Some(session_id.as_ref()), None, false)?;
        let (response, _) = sender.send_request(request, true).map_err(io_other)?;
        let response = response.await.map_err(io_other)?;
        ensure_success(response.status(), "packet-up download")?;

        Ok(Box::new(PacketUp {
            sender,
            request: self.request.clone(),
            session_id,
            sequence: 0,
            upload_chunk_size: self.upload_chunk_size,
            pending_write: None,
            download: Downlink::active(response.into_body()),
            closed: false,
            _connection: connection,
        }))
    }

    fn stream_request(
        &self,
        method: Method,
        session_id: Option<&str>,
        sequence: Option<u64>,
        grpc_content_type: bool,
    ) -> io::Result<Request<()>> {
        self.request
            .build(method, session_id, sequence, grpc_content_type)
    }
}

#[derive(Debug, Clone)]
struct RequestTemplate {
    host: Arc<str>,
    path: Arc<str>,
}

impl RequestTemplate {
    fn build(
        &self,
        method: Method,
        session_id: Option<&str>,
        sequence: Option<u64>,
        grpc_content_type: bool,
    ) -> io::Result<Request<()>> {
        let uri = build_uri(self.host.as_ref(), self.path.as_ref(), session_id, sequence)?;
        let padding_len = rand::rng().random_range(MIN_X_PADDING..=MAX_X_PADDING);
        let referer = format!(
            "https://{}{}?x_padding={}",
            self.host,
            normalized_base_path(self.path.as_ref()),
            "X".repeat(padding_len)
        );

        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("referer", referer);
        if grpc_content_type {
            builder = builder.header("content-type", "application/grpc");
        }
        builder.body(()).map_err(io_other)
    }
}

struct ConnectionGuard {
    task: JoinHandle<()>,
}

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionGuard")
            .finish_non_exhaustive()
    }
}

impl ConnectionGuard {
    fn spawn<T>(connection: h2::client::Connection<T, Bytes>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let task = tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::warn!(
                    reason = ?error.reason(),
                    is_io = error.is_io(),
                    is_go_away = error.is_go_away(),
                    is_reset = error.is_reset(),
                    is_remote = error.is_remote(),
                    "XHTTP HTTP/2 connection failed"
                );
            }
        });
        Self { task }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum DownlinkState {
    Pending {
        response: Pin<Box<ResponseFuture>>,
        operation: &'static str,
    },
    Active(RecvStream),
    Eof,
}

struct Downlink {
    state: DownlinkState,
    current: Bytes,
}

impl Downlink {
    fn pending(response: ResponseFuture, operation: &'static str) -> Self {
        Self {
            state: DownlinkState::Pending {
                response: Box::pin(response),
                operation,
            },
            current: Bytes::new(),
        }
    }

    fn active(response: RecvStream) -> Self {
        Self {
            state: DownlinkState::Active(response),
            current: Bytes::new(),
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || matches!(self.state, DownlinkState::Eof) {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.current.has_remaining() {
                let count = self.current.remaining().min(output.remaining());
                output.put_slice(&self.current[..count]);
                self.current.advance(count);
                let DownlinkState::Active(stream) = &mut self.state else {
                    unreachable!("buffered data only exists for an active response")
                };
                stream
                    .flow_control()
                    .release_capacity(count)
                    .map_err(io_other)?;
                return Poll::Ready(Ok(()));
            }

            match &mut self.state {
                DownlinkState::Pending {
                    response,
                    operation,
                } => match response.as_mut().poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        if let Err(error) = ensure_success(response.status(), operation) {
                            self.state = DownlinkState::Eof;
                            return Poll::Ready(Err(error));
                        }
                        self.state = DownlinkState::Active(response.into_body());
                    }
                    Poll::Ready(Err(error)) => {
                        self.state = DownlinkState::Eof;
                        return Poll::Ready(Err(io_other(error)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                DownlinkState::Active(stream) => match stream.poll_data(cx) {
                    Poll::Ready(Some(Ok(data))) => self.current = data,
                    Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io_other(error))),
                    Poll::Ready(None) => {
                        self.state = DownlinkState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                DownlinkState::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

struct StreamOne {
    upload: SendStream<Bytes>,
    download: Downlink,
    upload_chunk_size: usize,
    send_closed: bool,
    _connection: ConnectionGuard,
}

impl AsyncRead for StreamOne {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.download.poll_read(cx, output)
    }
}

impl AsyncWrite for StreamOne {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP stream-one upload is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let requested = input.len().min(self.upload_chunk_size);
        self.upload.reserve_capacity(requested);
        let capacity = self.upload.capacity();
        let capacity = if capacity == 0 {
            match self.upload.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io_other(error))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XHTTP stream-one upload was reset",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        } else {
            capacity
        };
        let count = requested.min(capacity);
        self.upload
            .send_data(Bytes::copy_from_slice(&input[..count]), false)
            .map_err(io_other)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.send_closed {
            self.upload
                .send_data(Bytes::new(), true)
                .map_err(io_other)?;
            self.send_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

type PendingWrite = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'static>>;

struct PacketUp {
    sender: SendRequest<Bytes>,
    request: RequestTemplate,
    session_id: Arc<str>,
    sequence: u64,
    upload_chunk_size: usize,
    pending_write: Option<PendingWrite>,
    download: Downlink,
    closed: bool,
    _connection: ConnectionGuard,
}

impl AsyncRead for PacketUp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.download.poll_read(cx, output)
    }
}

impl AsyncWrite for PacketUp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP packet-up upload is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending_write.is_none() {
            let count = input.len().min(self.upload_chunk_size);
            let data = Bytes::copy_from_slice(&input[..count]);
            let sender = self.sender.clone();
            let request = self.request.clone();
            let session_id = self.session_id.clone();
            let sequence = self.sequence;
            self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "XHTTP sequence overflow")
            })?;
            self.pending_write = Some(Box::pin(async move {
                post_packet(sender, request, session_id, sequence, data).await?;
                Ok(count)
            }));
        }

        let future = self.pending_write.as_mut().expect("pending write exists");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.pending_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(future) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(_)) => {
                self.pending_write = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.pending_write = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

async fn post_packet(
    sender: SendRequest<Bytes>,
    request: RequestTemplate,
    session_id: Arc<str>,
    sequence: u64,
    data: Bytes,
) -> io::Result<()> {
    let mut sender = sender;
    let request = request.build(
        Method::POST,
        Some(session_id.as_ref()),
        Some(sequence),
        false,
    )?;
    let (response, mut upload) = sender.send_request(request, false).map_err(io_other)?;
    upload.send_data(data, true).map_err(io_other)?;
    let response = response.await.map_err(io_other)?;
    ensure_success(response.status(), "packet-up upload")?;
    Ok(())
}

fn build_uri(
    host: &str,
    raw_path: &str,
    session_id: Option<&str>,
    sequence: Option<u64>,
) -> io::Result<Uri> {
    let (path, query) = raw_path
        .split_once('?')
        .map_or((raw_path, None), |(path, query)| (path, Some(query)));
    let mut path = normalized_base_path(path);
    if let Some(session_id) = session_id {
        path.push_str(session_id);
    }
    if let Some(sequence) = sequence {
        path.push('/');
        path.push_str(&sequence.to_string());
    }
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        path.push('?');
        path.push_str(query);
    }
    Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query(path)
        .build()
        .map_err(io_other)
}

fn normalized_base_path(raw_path: &str) -> String {
    let path = raw_path.split_once('?').map_or(raw_path, |(path, _)| path);
    let mut path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn random_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn ensure_success(status: StatusCode, operation: &str) -> io::Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "XHTTP {operation} returned HTTP status {status}"
        )))
    }
}

fn io_other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn builds_canonical_default_paths() {
        assert_eq!(
            build_uri("example.com", "/x", None, None).unwrap(),
            "https://example.com/x/"
        );
        assert_eq!(
            build_uri("example.com", "/x?ed=1", Some("abc"), Some(7)).unwrap(),
            "https://example.com/x/abc/7?ed=1"
        );
    }

    #[test]
    fn default_and_bounded_clients_keep_distinct_buffer_limits() {
        let config = XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap();
        let default = XHttpClient::new(config.clone());
        assert_eq!(default.send_buffer_size, 64 * 1024);
        assert_eq!(default.upload_chunk_size, 64 * 1024);

        let limited = XHttpClient::new_with_limits(config.clone(), 16 * 1024, 16 * 1024).unwrap();
        assert_eq!(limited.send_buffer_size, 16 * 1024);
        assert_eq!(limited.upload_chunk_size, 16 * 1024);
        assert!(XHttpClient::new_with_limits(config.clone(), 0, 16 * 1024).is_err());
        assert!(XHttpClient::new_with_limits(config, 16 * 1024, 0).is_err());
    }

    #[test]
    fn request_templates_share_static_host_and_path_storage() {
        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
        let cloned = client.request.clone();

        assert!(Arc::ptr_eq(&client.request.host, &cloned.host));
        assert!(Arc::ptr_eq(&client.request.path, &cloned.path));
    }

    #[tokio::test]
    async fn stream_one_is_a_single_full_duplex_post() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (close_server, keep_server_alive) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.uri().path(), "/x/");
            assert_eq!(request.headers()["content-type"], "application/grpc");
            assert!(
                request.headers()["referer"]
                    .to_str()
                    .unwrap()
                    .contains("x_padding=")
            );

            let handler = tokio::spawn(async move {
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut body = request.into_body();
                while let Some(data) = body.data().await {
                    response.send_data(data.unwrap(), false).unwrap();
                }
                response.send_data(Bytes::new(), true).unwrap();
            });
            let mut keep_server_alive = keep_server_alive;
            tokio::select! {
                _ = &mut keep_server_alive => {}
                incoming = connection.accept() => {
                    assert!(incoming.is_none(), "unexpected second stream-one request");
                }
            }
            handler.await.unwrap();
        });

        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap());
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.connect(Box::new(client_io)),
        )
        .await
        .expect("stream-one connect timed out")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.write_all(b"hello"),
        )
        .await
        .expect("stream-one write timed out")
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.shutdown())
            .await
            .expect("stream-one shutdown timed out")
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("stream-one read timed out")
        .unwrap();
        assert_eq!(response, b"hello");
        let _ = close_server.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn packet_up_uses_a_download_stream_and_sequenced_posts() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (close_server, keep_server_alive) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (download, mut download_respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(download.method(), Method::GET);
            let session_path = download.uri().path().to_owned();
            let download_stream = download_respond
                .send_response(http::Response::new(()), false)
                .unwrap();

            let (upload, mut upload_respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(upload.method(), Method::POST);
            assert_eq!(upload.uri().path(), format!("{session_path}/0"));
            let handler = tokio::spawn(async move {
                let mut payload = Vec::new();
                let mut body = upload.into_body();
                while let Some(data) = body.data().await {
                    payload.extend_from_slice(&data.unwrap());
                }
                upload_respond
                    .send_response(http::Response::new(()), true)
                    .unwrap();
                let mut download_stream = download_stream;
                download_stream
                    .send_data(Bytes::from(payload), true)
                    .unwrap();
            });
            let mut keep_server_alive = keep_server_alive;
            tokio::select! {
                _ = &mut keep_server_alive => {}
                incoming = connection.accept() => {
                    assert!(incoming.is_none(), "unexpected second packet-up POST");
                }
            }
            handler.await.unwrap();
        });

        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.connect(Box::new(client_io)),
        )
        .await
        .expect("packet-up connect timed out")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.write_all(b"packet"),
        )
        .await
        .expect("packet-up write timed out")
        .unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("packet-up read timed out")
        .unwrap();
        assert_eq!(response, b"packet");
        let _ = close_server.send(());
        server.await.unwrap();
    }
}
