use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, timeout_at},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Error, Message, error::ProtocolError, protocol::WebSocketConfig},
};

use crate::{BoxStream, CHUNK, LIMIT};

pub async fn websocket(stream: BoxStream, uri: &str, deadline: Instant) -> io::Result<BoxStream> {
    let clean_eof = Arc::new(AtomicBool::new(false));
    let stream = BoundaryIo {
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
    let (stream, _) = timeout_at(
        deadline,
        tokio_tungstenite::client_async_with_config(uri, stream, Some(config)),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    Ok(Box::new(WebSocket {
        stream,
        buffered: Bytes::new(),
        closing: false,
        eof: false,
        clean_eof,
    }))
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
        for _ in 0..32 {
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
// official library remains the sole HTTP/WS validator and message decoder.
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
