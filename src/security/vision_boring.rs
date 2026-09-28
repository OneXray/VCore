//! The same record boundary and switch controls as rustls, with no access to
//! native TLS internals. SSL_pending drains only already-decrypted plaintext.
use super::*;
use crate::security::boring_stream::{BoringStream, KeepOpen};

pub(in crate::security) struct BoringSplice {
    tls: BoringStream<RecordIo>,
    control: SpliceControl,
    stats: Arc<SpliceStats>,
    write_switched: bool,
    closing: Option<Pin<Box<tokio::time::Sleep>>>,
    closed: bool,
}
impl BoringSplice {
    pub(in crate::security) fn wrap(
        tls: tokio_boring::SslStream<KeepOpen<RecordIo>>,
        stats: Arc<SpliceStats>,
        buffer_limit: usize,
    ) -> io::Result<(BoxStream, SpliceControl)> {
        if tls.ssl().version2() != Some(::boring::ssl::SslVersion::TLS1_3) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Vision requires TLS 1.3",
            ));
        }
        let control = SpliceControl::default();
        Ok((
            Box::new(Self {
                tls: BoringStream::new(tls, buffer_limit),
                control: control.clone(),
                stats,
                write_switched: false,
                closing: None,
                closed: false,
            }),
            control,
        ))
    }
    fn prepare_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.write.load(Ordering::Acquire) && !self.write_switched {
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            self.write_switched = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for BoringSplice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.control.read.load(Ordering::Acquire) {
            let pending = this.tls.inner.ssl().pending();
            if pending != 0 {
                let count = pending.min(out.remaining());
                let mut part = ReadBuf::new(&mut out.initialize_unfilled()[..count]);
                ready!(Pin::new(&mut this.tls).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                out.advance(n);
                return Poll::Ready(Ok(()));
            }
            let io = &mut this.tls.inner.get_mut().0;
            if !io.boundary() {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            let before = out.filled().len();
            let result = Pin::new(&mut io.raw).poll_read(cx, out);
            this.stats
                .read
                .fetch_add((out.filled().len() - before) as u64, Ordering::Relaxed);
            return result;
        }
        // SSL_read returns one application record, unlike a greedy deframer.
        Pin::new(&mut this.tls).poll_read(cx, out)
    }
}
impl AsyncWrite for BoringSplice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.prepare_write(cx))?;
        if self.write_switched {
            let result = Pin::new(&mut self.tls.inner.get_mut().0.raw).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = result {
                self.stats.written.fetch_add(n as u64, Ordering::Relaxed);
            }
            result
        } else {
            Pin::new(&mut self.tls).poll_write(cx, buf)
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.prepare_write(cx))?;
        if self.write_switched {
            Pin::new(&mut self.tls.inner.get_mut().0.raw).poll_flush(cx)
        } else {
            Pin::new(&mut self.tls).poll_flush(cx)
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.closing.is_none() {
            self.closing = Some(Box::pin(tokio::time::sleep(
                crate::security::CLOSE_NOTIFY_TIMEOUT,
            )));
        }
        // Start the deadline before flushing a pending direct marker.
        if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        ready!(self.prepare_write(cx))?;
        let result = if self.write_switched || self.control.read.load(Ordering::Acquire) {
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            // A raw stream must not receive an outer TLS alert.
            Pin::new(&mut self.tls.inner.get_mut().0.raw).poll_shutdown(cx)
        } else {
            Pin::new(&mut self.tls).poll_shutdown(cx)
        };
        if matches!(result, Poll::Ready(Ok(()))) {
            self.closed = true;
        }
        result
    }
}
