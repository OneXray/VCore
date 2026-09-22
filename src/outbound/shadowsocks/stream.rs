use crate::dispatch::BoxStream;
use shadowsocks::ProxyClientStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Keep each codec call bounded, including the target header on the first
// write. The upstream first-write wrapper expects that entire frame to fit
// within the SS 2022 u16 payload limit. Larger caller buffers use partial writes.
const WRITE_CHUNK: usize = 16 * 1024;

enum Start {
    Fresh,
    EmptyPending,
    Started,
}

pub(super) struct SsStream {
    inner: ProxyClientStream<BoxStream>,
    start: Start,
}

impl SsStream {
    pub(super) fn new(inner: ProxyClientStream<BoxStream>) -> Self {
        Self {
            inner,
            start: Start::Fresh,
        }
    }
    fn finish_empty(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.start, Start::EmptyPending) {
            ready!(Pin::new(&mut self.inner).poll_write(cx, &[])).map_err(super::safe_io)?;
            self.start = Start::Started;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Client-first writes remain combined with the target header. Reading
        // before the first write requests the upstream's empty handshake.
        if matches!(self.start, Start::Fresh) {
            self.start = Start::EmptyPending;
        }
        ready!(self.finish_empty(cx))?;
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(super::safe_io)
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.finish_empty(cx))?;
        // Mark before polling: a concurrent read must not replace an in-flight
        // first payload with an empty write while upstream reports Pending.
        self.start = Start::Started;
        let buf = &buf[..buf.len().min(WRITE_CHUNK)];
        Pin::new(&mut self.inner)
            .poll_write(cx, buf)
            .map_err(super::safe_io)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.finish_empty(cx))?;
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(super::safe_io)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A write EOF still needs to deliver the target header so the peer can
        // connect and respond. Resume any pending empty handshake before FIN.
        if matches!(self.start, Start::Fresh) {
            self.start = Start::EmptyPending;
        }
        ready!(self.finish_empty(cx))?;
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(super::safe_io)
    }
}
