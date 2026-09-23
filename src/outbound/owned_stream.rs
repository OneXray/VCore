use crate::{
    dispatch::BoxStream,
    resources::observation::{self, ResourceKind},
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

pub(crate) struct OwnedStream {
    stream: Option<BoxStream>,
    cancellation: CancellationToken,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    _observation: observation::Guard,
}

impl OwnedStream {
    pub(crate) fn new(stream: BoxStream, cancellation: CancellationToken) -> Self {
        Self {
            stream: Some(stream),
            cancelled: Box::pin(cancellation.clone().cancelled_owned()),
            cancellation,
            _observation: observation::track(ResourceKind::Session),
        }
    }
    fn open(&mut self, cx: &mut Context<'_>) -> io::Result<&mut BoxStream> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.stream.take();
        }
        self.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "outbound session stopped")
        })
    }
}

impl Drop for OwnedStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl AsyncRead for OwnedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.open(cx)?).poll_read(cx, buf)
    }
}
impl AsyncWrite for OwnedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.open(cx)?).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.open(cx)?).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.open(cx)?).poll_shutdown(cx)
    }
}
