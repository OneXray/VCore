use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use h2::{RecvStream, SendStream, client::ResponseFuture};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::{AbortHandle, JoinHandle},
    time::{Instant, timeout_at},
};

use super::{STREAM_BUFFER_BYTES as LIMIT, STREAM_CHUNK_BYTES as CHUNK};
use crate::dispatch::BoxStream;

#[derive(Default)]
struct Close {
    stopped: AtomicBool,
    reader: AtomicWaker,
}

impl Close {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.reader.wake();
    }
}

/// Owns one supplied HTTP/2 connection (not a multiplexing pool). Stop
/// owns the join barrier; Drop is cancellation fallback, never a PASS barrier.
pub struct Driver {
    task: Option<JoinHandle<Result<(), h2::Error>>>,
    close: Arc<Close>,
}

impl Driver {
    pub async fn stop(mut self) -> io::Result<()> {
        self.close.stop();
        if let Some(task) = self.task.take() {
            task.abort();
            if task.await.is_err_and(|error| !error.is_cancelled()) {
                return Err(io::ErrorKind::Other.into());
            }
        }
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.close.stop();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub async fn grpc(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
) -> io::Result<(BoxStream, Driver)> {
    connect(stream, uri, deadline, Framing::Gun).await
}

/// Legacy VMess/VLESS H2: PUT with an unframed byte stream, not gRPC.
pub async fn legacy_h2(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
) -> io::Result<(BoxStream, Driver)> {
    connect(stream, uri, deadline, Framing::Plain).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    Gun,
    Plain,
}

async fn connect(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
    framing: Framing,
) -> io::Result<(BoxStream, Driver)> {
    let uri: http::Uri = uri
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri
            .authority()
            .is_none_or(|value| value.as_str().contains('@'))
        || uri.to_string().len() > super::HTTP_HEAD_BYTES - 256
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let request = http::Request::builder()
        .method(if framing == Framing::Gun {
            "POST"
        } else {
            "PUT"
        })
        .uri(uri);
    let request = match framing {
        Framing::Gun => request
            .header("content-type", "application/grpc")
            .header("te", "trailers"),
        Framing::Plain => request.header("accept-encoding", "identity"),
    };
    let request = request
        .body(())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let (sender, connection) = timeout_at(
        deadline,
        h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(LIMIT as u32)
            .initial_connection_window_size((2 * LIMIT) as u32)
            .max_frame_size(CHUNK as u32)
            .max_header_list_size(CHUNK as u32)
            .max_concurrent_streams(1)
            .max_send_buffer_size(CHUNK)
            .handshake(stream),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    let close = Arc::new(Close::default());
    let task = crate::resources::observation::spawn(connection);
    let abort = task.abort_handle();
    // Immediately own the task, including cancellation during ready().
    let owner = Driver {
        task: Some(task),
        close: close.clone(),
    };
    let sender = timeout_at(deadline, sender.ready()).await;
    let mut sender = match sender {
        Ok(Ok(sender)) => sender,
        result => {
            owner.stop().await?;
            return Err(if result.is_err() {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::ConnectionAborted
            }
            .into());
        }
    };
    let (response, send) = match sender.send_request(request, false) {
        Ok(stream) => stream,
        Err(_) => {
            owner.stop().await?;
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
    };
    // Do not await response headers here: Mihomo may only flush them after the
    // first VLESS bytes. Request writing and response reading must be independent.
    Ok((
        Box::new(Grpc {
            _observation: crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Session,
            ),
            framing,
            response: Some(response),
            receive: None,
            send,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            frame: Bytes::new(),
            wire: BytesMut::new(),
            payload: Bytes::new(),
            queued: Bytes::new(),
            eof: false,
            data_eof: false,
            close,
            abort,
        }),
        owner,
    ))
}

struct Grpc {
    _observation: crate::resources::observation::Guard,
    framing: Framing,
    response: Option<ResponseFuture>,
    receive: Option<RecvStream>,
    send: SendStream<Bytes>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    frame: Bytes,
    wire: BytesMut,
    payload: Bytes,
    queued: Bytes,
    eof: bool,
    data_eof: bool,
    close: Arc<Close>,
    abort: AbortHandle,
}

impl Drop for Grpc {
    fn drop(&mut self) {
        self.close.stop();
        self.abort.abort();
    }
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

impl Grpc {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.queued.is_empty() {
                self.send.reserve_capacity(0);
                return Poll::Ready(Ok(()));
            }
            self.send.reserve_capacity(self.queued.len());
            let count = ready!(self.send.poll_capacity(cx))
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            if count == 0 {
                continue;
            }
            let count = count.min(self.queued.len());
            self.send
                .send_data(self.queued.split_to(count), false)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn record(&mut self) -> io::Result<bool> {
        if self.wire.len() < 5 {
            return Ok(false);
        }
        let length = u32::from_be_bytes(self.wire[1..5].try_into().unwrap()) as usize;
        if self.wire[0] != 0 || !(2..=LIMIT + 4).contains(&length) {
            return Err(invalid());
        }
        if self.wire.len() < length + 5 {
            return Ok(false);
        }
        if self.wire[5] != 0x0a {
            return Err(invalid());
        }
        let mut value = 0;
        let mut start = None;
        for index in 0..3 {
            let byte = *self.wire.get(6 + index).ok_or_else(invalid)?;
            value |= usize::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                start = Some(7 + index);
                break;
            }
        }
        let start = start.ok_or_else(invalid)?;
        if value > LIMIT || start + value != length + 5 {
            return Err(invalid());
        }
        self.payload = self.wire.split().freeze().slice(start..);
        Ok(true)
    }
}

impl AsyncRead for Grpc {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.close.reader.register(cx.waker());
        if this.close.stopped.load(Ordering::SeqCst) || this.eof {
            return Poll::Ready(Ok(()));
        }
        if let Some(response) = &mut this.response {
            match Pin::new(response).poll(cx) {
                Poll::Ready(result) => {
                    let response = result.map_err(|_| invalid())?;
                    if response.status() != 200
                        || (this.framing == Framing::Gun
                            && !response.headers().get("content-type").is_some_and(|value| {
                                matches!(
                                    value
                                        .as_bytes()
                                        .split(|byte| matches!(byte, b';' | b'+'))
                                        .next(),
                                    Some(b"application/grpc")
                                )
                            }))
                    {
                        return Poll::Ready(Err(invalid()));
                    }
                    this.response = None;
                    this.receive = Some(response.into_body());
                }
                Poll::Pending => {
                    if this.deadline.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                    }
                    return Poll::Pending;
                }
            }
        }
        if this.framing == Framing::Plain {
            let receive = this.receive.as_mut().unwrap();
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                if !this.frame.is_empty() {
                    let count = this.frame.len().min(output.remaining());
                    output.put_slice(&this.frame[..count]);
                    this.frame.advance(count);
                    receive
                        .flow_control()
                        .release_capacity(count)
                        .map_err(|_| invalid())?;
                    return Poll::Ready(Ok(()));
                }
                match ready!(receive.poll_data(cx)) {
                    Some(Ok(frame)) => this.frame = frame,
                    Some(Err(_)) => return Poll::Ready(Err(invalid())),
                    None => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if !this.payload.is_empty() {
                let count = this.payload.len().min(output.remaining());
                output.put_slice(&this.payload[..count]);
                this.payload.advance(count);
                return Poll::Ready(Ok(()));
            }
            if this.record()? {
                continue;
            }
            let receive = this.receive.as_mut().unwrap();
            if !this.frame.is_empty() {
                let needed = if this.wire.len() < 5 {
                    5
                } else {
                    5 + u32::from_be_bytes(this.wire[1..5].try_into().unwrap()) as usize
                };
                let count = (needed - this.wire.len()).min(this.frame.len());
                this.wire.extend_from_slice(&this.frame[..count]);
                this.frame.advance(count);
                // Only consumed bytes replenish the peer's window.
                receive
                    .flow_control()
                    .release_capacity(count)
                    .map_err(|_| invalid())?;
                continue;
            }
            if !this.data_eof {
                match ready!(receive.poll_data(cx)) {
                    Some(Ok(frame)) => {
                        this.frame = frame;
                        continue;
                    }
                    Some(Err(_)) => return Poll::Ready(Err(invalid())),
                    None => this.data_eof = true,
                }
            }
            if !this.wire.is_empty() {
                return Poll::Ready(Err(invalid()));
            }
            let trailers = ready!(receive.poll_trailers(cx)).map_err(|_| invalid())?;
            if trailers
                .as_ref()
                .and_then(|headers| headers.get("grpc-status"))
                .is_some_and(|status| status != "0")
            {
                return Poll::Ready(Err(invalid()));
            }
            this.eof = true;
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for Grpc {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.close.stopped.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(CHUNK);
        if self.framing == Framing::Plain {
            self.queued = Bytes::copy_from_slice(&input[..count]);
            return Poll::Ready(Ok(count));
        }
        let mut wire = Vec::with_capacity(count + 9);
        wire.extend_from_slice(&[0; 5]);
        wire.push(0x0a);
        let mut length = count;
        while length > 127 {
            wire.push((length as u8 & 0x7f) | 0x80);
            length >>= 7;
        }
        wire.push(length as u8);
        wire.extend_from_slice(&input[..count]);
        let total = (wire.len() - 5) as u32;
        wire[1..5].copy_from_slice(&total.to_be_bytes());
        self.queued = wire.into();
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Mihomo gun.Conn.Close and h2Conn.Close cancel the whole connection,
        // not just HTTP/2 END_STREAM. The owner's stop is the join barrier.
        self.close.stop();
        self.send.send_reset(h2::Reason::CANCEL);
        self.response = None;
        self.receive = None;
        self.queued = Bytes::new();
        self.abort.abort();
        Poll::Ready(Ok(()))
    }
}
