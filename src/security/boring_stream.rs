//! BoringSSL CloseWrite over caller-owned IO. Native shutdown must never
//! propagate FIN to the underlay or wait for the peer's close_notify.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct KeepOpen<S>(pub(super) S);
impl<S: AsyncRead + Unpin> AsyncRead for KeepOpen<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for KeepOpen<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush separately, so a pending flush cannot cause SSL_shutdown to be
        // called twice (the second call could wait for the peer's alert).
        Poll::Ready(Ok(()))
    }
}

pub(super) struct BoringStream<S> {
    pub(super) inner: tokio_boring::SslStream<KeepOpen<S>>,
    closing: Option<Pin<Box<tokio::time::Sleep>>>,
    alert_sent: bool,
    closed: bool,
    write_limit: usize,
}
impl<S> BoringStream<S> {
    pub(super) fn new(inner: tokio_boring::SslStream<KeepOpen<S>>, buffer_limit: usize) -> Self {
        Self {
            inner,
            closing: None,
            alert_sent: false,
            closed: false,
            write_limit: buffer_limit.min(16 * 1024),
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for BoringStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for BoringStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(self.write_limit);
        Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.closing.is_none() {
            self.closing = Some(Box::pin(tokio::time::sleep(super::CLOSE_NOTIFY_TIMEOUT)));
        }
        if !self.alert_sent {
            match Pin::new(&mut self.inner).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => self.alert_sent = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if self.alert_sent {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Poll::Pending
    }
}
