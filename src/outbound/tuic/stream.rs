use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A logical stream owns both directions. Cancellation resets only this stream;
/// application EOF follows Mihomo's close-both-directions wrapper semantics.
pub(super) struct Stream {
    lease: Option<super::activity::Lease>,
    runtime: Arc<crate::transport::quic::OwnedRuntime>,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    reader: futures_util::task::AtomicWaker,
}

impl Stream {
    pub fn new(
        (send, recv): (quinn::SendStream, quinn::RecvStream),
        lease: super::activity::Lease,
        runtime: Arc<crate::transport::quic::OwnedRuntime>,
    ) -> Self {
        Self {
            lease: Some(lease),
            runtime,
            send: Some(send),
            recv: Some(recv),
            reader: Default::default(),
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(0_u8.into());
        }
        self.recv.take();
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.reader.register(cx.waker());
        let Some(recv) = &mut self.recv else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        Pin::new(recv)
            .poll_read(cx, buf)
            .map(|v| v.map_err(super::failure))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(send) = &mut self.send else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        AsyncWrite::poll_write(Pin::new(send), cx, buf).map(|v| v.map_err(super::failure))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(send) = &mut self.send else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        Pin::new(send)
            .poll_flush(cx)
            .map(|v| v.map_err(super::failure))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.recv.take();
        self.reader.wake();
        let lease = self.lease.take();
        let Some(mut send) = self.send.take() else {
            return Poll::Ready(Ok(()));
        };
        if let Err(error) = send.finish() {
            return Poll::Ready(Err(super::failure(error)));
        }
        // finish queues a FIN; it is not peer acknowledgement. Keep the retired
        // pool alive until FIN/data are acknowledged, or the bounded grace ends.
        // Mihomo retains closed TCP stream owners for its five-second TCP
        // timeout. Application shutdown remains immediate; node Stop cancels
        // and joins this work rather than waiting out the grace.
        let _ = self.runtime.spawn_owned(async move {
            let _lease = lease;
            let _ = tokio::time::timeout(
                Duration::from_secs(crate::limits::TUIC_FIN_GRACE_SECONDS as u64),
                send.stopped(),
            )
            .await;
        });
        Poll::Ready(Ok(()))
    }
}
