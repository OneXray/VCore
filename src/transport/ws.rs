use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::{Instant, timeout_at},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Error, Message,
        client::IntoClientRequest,
        error::ProtocolError,
        protocol::{Role, WebSocketConfig},
    },
};

use super::{STREAM_BUFFER_BYTES as LIMIT, STREAM_CHUNK_BYTES as CHUNK};
use crate::dispatch::BoxStream;

pub const MAX_EARLY_DATA_BYTES: usize = 2048;

#[derive(Clone)]
pub enum WebSocketEarlyData {
    Header {
        name: http::HeaderName,
        max_bytes: usize,
    },
    Path {
        max_bytes: usize,
    },
}

#[derive(Clone)]
pub struct WebSocketOptions {
    uri: http::Uri,
    headers: http::HeaderMap,
    early_data: Option<WebSocketEarlyData>,
}

impl std::fmt::Debug for WebSocketOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketOptions")
            .field("early_data", &self.early_data.is_some())
            .finish_non_exhaustive()
    }
}

impl WebSocketOptions {
    pub fn new(
        uri: &str,
        headers: http::HeaderMap,
        early_data: Option<WebSocketEarlyData>,
    ) -> io::Result<Self> {
        use super::http_head::{HTTP_HEAD_BYTES, HTTP_HEADER_COUNT};
        let uri: http::Uri = uri.parse().map_err(|_| invalid_options())?;
        if !matches!(uri.scheme_str(), Some("ws" | "wss"))
            || uri
                .authority()
                .is_none_or(|value| value.as_str().contains('@'))
            || !uri.path().starts_with('/')
            || headers.len() > HTTP_HEADER_COUNT
        {
            return Err(invalid_options());
        }
        let mut size = uri.to_string().len();
        for (name, value) in &headers {
            if reserved(name)
                || name == "sec-websocket-protocol"
                || headers.get_all(name).iter().count() != 1
            {
                return Err(invalid_options());
            }
            if name == "host" {
                let host = value.to_str().map_err(|_| invalid_options())?;
                let authority: http::uri::Authority =
                    host.parse().map_err(|_| invalid_options())?;
                if authority.as_str().contains('@') {
                    return Err(invalid_options());
                }
            }
            size = size
                .checked_add(name.as_str().len())
                .and_then(|size| size.checked_add(value.len() + 4))
                .ok_or_else(invalid_options)?;
        }
        if size > HTTP_HEAD_BYTES {
            return Err(invalid_options());
        }
        if let Some(early) = &early_data {
            let maximum = match early {
                WebSocketEarlyData::Header { name, max_bytes } => {
                    if reserved(name) || name == "host" || headers.contains_key(name) {
                        return Err(invalid_options());
                    }
                    *max_bytes
                }
                WebSocketEarlyData::Path { max_bytes } => {
                    if uri.query().is_some() {
                        return Err(invalid_options());
                    }
                    *max_bytes
                }
            };
            if !(1..=MAX_EARLY_DATA_BYTES).contains(&maximum) {
                return Err(invalid_options());
            }
        }
        Ok(Self {
            uri,
            headers,
            early_data,
        })
    }
}

fn reserved(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-accept"
            | "sec-websocket-extensions"
            | "content-length"
            | "transfer-encoding"
    )
}

fn invalid_options() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid WebSocket options")
}

/// Complete one upgrade on supplied IO under the caller's absolute deadline.
/// The protocol supplies its pre-read prefix explicitly; ED and frame remainders
/// are committed exactly once before returning, without a deferred write task.
pub async fn connect_websocket(
    stream: BoxStream,
    options: &WebSocketOptions,
    initial_data: &[u8],
    deadline: Instant,
) -> io::Result<BoxStream> {
    timeout_at(deadline, connect_inner(stream, options, initial_data))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

pub async fn websocket(stream: BoxStream, uri: &str, deadline: Instant) -> io::Result<BoxStream> {
    connect_websocket(
        stream,
        &WebSocketOptions::new(uri, Default::default(), None)?,
        &[],
        deadline,
    )
    .await
}

async fn connect_inner(
    stream: BoxStream,
    options: &WebSocketOptions,
    initial_data: &[u8],
) -> io::Result<BoxStream> {
    let mut uri = options.uri.clone();
    let mut headers = options.headers.clone();
    let mut sent_early = 0;
    let mut subprotocol = None;
    if let Some(early) = &options.early_data {
        let maximum = match early {
            WebSocketEarlyData::Header { max_bytes, .. }
            | WebSocketEarlyData::Path { max_bytes } => *max_bytes,
        };
        sent_early = maximum.min(initial_data.len());
        if sent_early > 0 {
            let encoded = URL_SAFE_NO_PAD.encode(&initial_data[..sent_early]);
            match early {
                WebSocketEarlyData::Header { name, .. } => {
                    let value: http::HeaderValue =
                        encoded.parse().map_err(|_| invalid_options())?;
                    if name == "sec-websocket-protocol" {
                        subprotocol = Some(value.clone());
                    }
                    headers.insert(name, value);
                }
                WebSocketEarlyData::Path { .. } => {
                    let mut parts = uri.into_parts();
                    let path = format!(
                        "{}{}",
                        parts.path_and_query.as_ref().unwrap().path(),
                        encoded
                    );
                    parts.path_and_query = Some(path.parse().map_err(|_| invalid_options())?);
                    uri = http::Uri::from_parts(parts).map_err(|_| invalid_options())?;
                }
            }
        }
    }
    let mut request = uri.into_client_request().map_err(|_| invalid_options())?;
    for (name, value) in &headers {
        request.headers_mut().insert(name.clone(), value.clone());
    }
    let (request, key) =
        tokio_tungstenite::tungstenite::handshake::client::generate_request(request)
            .map_err(|_| invalid_options())?;
    if request.len() > super::HTTP_HEAD_BYTES {
        return Err(invalid_options());
    }
    let clean_eof = Arc::new(AtomicBool::new(false));
    let mut stream = BoundaryIo {
        stream,
        clean_eof: clean_eof.clone(),
        boundary: Boundary::default(),
    };
    let config = WebSocketConfig::default()
        .read_buffer_size(CHUNK)
        .write_buffer_size(0)
        .max_write_buffer_size(LIMIT)
        .max_message_size(Some(LIMIT))
        .max_frame_size(Some(LIMIT));
    stream.write_all(&request).await?;
    stream.flush().await?;
    let (response, tail) = super::http_head::read_response(&mut stream).await?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid WebSocket upgrade");
    let single = |name| {
        let mut values = response.headers().get_all(name).iter();
        let value = values.next().ok_or_else(invalid)?;
        if values.next().is_some() {
            return Err(invalid());
        }
        Ok(value)
    };
    if response.status() != 101
        || response.version() != http::Version::HTTP_11
        || !single("upgrade")?
            .as_bytes()
            .eq_ignore_ascii_case(b"websocket")
        || !single("connection")?
            .to_str()
            .map_err(|_| invalid())?
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        || single("sec-websocket-accept")?.as_bytes()
            != tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
                .as_bytes()
        || response.headers().contains_key("sec-websocket-extensions")
    {
        return Err(invalid());
    }
    // ED in Sec-WebSocket-Protocol is not subprotocol negotiation. An absent
    // echo is valid, but an unsolicited or different echo is never accepted.
    if response.headers().contains_key("sec-websocket-protocol")
        && subprotocol.as_ref() != Some(single("sec-websocket-protocol")?)
    {
        return Err(invalid());
    }
    let stream =
        WebSocketStream::from_partially_read(stream, tail, Role::Client, Some(config)).await;
    let mut stream = WebSocket {
        stream,
        buffered: Bytes::new(),
        closing: false,
        eof: false,
        clean_eof,
    };
    stream.write_all(&initial_data[sent_early..]).await?;
    stream.flush().await?;
    Ok(Box::new(crate::resources::observation::ObservedIo::new(
        stream,
        crate::resources::observation::ResourceKind::Session,
    )))
}

struct WebSocket {
    stream: WebSocketStream<BoundaryIo>,
    buffered: Bytes,
    closing: bool,
    eof: bool,
    clean_eof: Arc<AtomicBool>,
}

impl AsyncRead for WebSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Bound work per poll, including a malicious stream of empty/control frames.
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if !self.buffered.is_empty() {
                let count = buf.remaining().min(self.buffered.len());
                buf.put_slice(&self.buffered[..count]);
                self.buffered.advance(count);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.stream).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => self.buffered = data,
                Some(Ok(Message::Text(data))) => self.buffered = data.into(),
                Some(Ok(Message::Close(_))) | None => self.eof = true,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Err(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)))
                    if self.clean_eof.load(Ordering::SeqCst) =>
                {
                    self.eof = true
                }
                // Never turn an arbitrary protocol/truncation error into EOF.
                Some(Err(_)) | Some(Ok(Message::Frame(_))) => {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// Tungstenite intentionally reports the same ResetWithoutClosingHandshake for
// EOF between frames and EOF in a partial frame. Mihomo permits the former for
// proxy CloseWrite. Observe only wire boundaries (14 header bytes, no payload
// copies) so that the compatibility mapping cannot conceal truncation. The
// The official library remains the WS frame validator and message decoder;
// the bounded HTTP upgrade above handles proxy ED's non-negotiated header.
#[derive(Default)]
struct Boundary {
    upgrade: usize,
    header: [u8; 14],
    used: usize,
    remaining: u64,
    fragmented: bool,
}

impl Boundary {
    fn accept(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.upgrade < 4 {
                let byte = data[0];
                data = &data[1..];
                self.upgrade = if byte == b"\r\n\r\n"[self.upgrade] {
                    self.upgrade + 1
                } else {
                    usize::from(byte == b'\r')
                };
                continue;
            }
            if self.remaining > 0 {
                let count = self.remaining.min(data.len() as u64) as usize;
                self.remaining -= count as u64;
                data = &data[count..];
                continue;
            }
            self.header[self.used] = data[0];
            self.used += 1;
            data = &data[1..];
            if self.used < 2 {
                continue;
            }
            let length = self.header[1] & 0x7f;
            let extended = match length {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let mask = if self.header[1] & 0x80 != 0 { 4 } else { 0 };
            if self.used < 2 + extended + mask {
                continue;
            }
            self.remaining = match length {
                126 => u16::from_be_bytes(self.header[2..4].try_into().unwrap()) as u64,
                127 => u64::from_be_bytes(self.header[2..10].try_into().unwrap()),
                value => u64::from(value),
            };
            let opcode = self.header[0] & 0x0f;
            if matches!(opcode, 0..=2) {
                self.fragmented = self.header[0] & 0x80 == 0;
            }
            self.used = 0;
        }
    }

    fn complete(&self) -> bool {
        self.upgrade == 4 && self.used == 0 && self.remaining == 0 && !self.fragmented
    }
}

struct BoundaryIo {
    stream: BoxStream,
    boundary: Boundary,
    clean_eof: Arc<AtomicBool>,
}

impl AsyncRead for BoundaryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let start = buf.filled().len();
        ready!(Pin::new(&mut self.stream).poll_read(cx, buf))?;
        let data = &buf.filled()[start..];
        if data.is_empty() {
            if !self.boundary.complete() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.clean_eof.store(true, Ordering::SeqCst);
        } else {
            self.boundary.accept(data);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BoundaryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncWrite for WebSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.stream).poll_ready(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
        let count = CHUNK.min(buf.len());
        Pin::new(&mut self.stream)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..count])))
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
        // A queued frame is accepted exactly once; a Pending flush must not
        // make AsyncWrite callers resubmit the same application bytes.
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_flush(cx)
            .map_err(|_| io::ErrorKind::ConnectionAborted.into())
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closing = true;
        ready!(self.as_mut().poll_flush(cx))?;
        // Ordinary Mihomo WS Relay bypasses WS Close via Upstream(). TLS (when
        // present) applies its close_notify contract; plain TCP sends FIN.
        Pin::new(self.stream.get_mut()).poll_shutdown(cx)
    }
}
