//! TLS CloseWrite follows Mihomo: flush close_notify, keep the supplied
//! transport/read direction alive. Drop still owns the entire connection.
use crate::dispatch::BoxStream;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Sleep,
};

pub const CLOSE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct TlsStream {
    inner: tokio_rustls::client::TlsStream<BoxStream>,
    closing: Option<Pin<Box<Sleep>>>,
}

impl TlsStream {
    pub(super) fn new(inner: tokio_rustls::client::TlsStream<BoxStream>) -> Self {
        Self {
            inner,
            closing: None,
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing.is_none() {
            self.inner.get_mut().1.send_close_notify();
            self.closing = Some(Box::pin(tokio::time::sleep(CLOSE_NOTIFY_TIMEOUT)));
        }
        if let Poll::Ready(result) = Pin::new(&mut self.inner).poll_flush(cx) {
            return Poll::Ready(result);
        }
        if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Poll::Pending
    }
}
