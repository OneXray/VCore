//! sing-mux first-16-write padding. Incremental parsing retains at most a
//! four-byte header; padding is discarded through a fixed scratch buffer.
use super::*;
use bytes::Buf;

pub(super) struct Padding {
    raw: BoxStream,
    read_frames: u8,
    header: [u8; 4],
    header_used: usize,
    data_left: usize,
    padding_left: usize,
    write_frames: u8,
    queued: Bytes,
}
impl Padding {
    pub(super) fn new(raw: BoxStream) -> Self {
        Self {
            raw,
            read_frames: 0,
            header: [0; 4],
            header_used: 0,
            data_left: 0,
            padding_left: 0,
            write_frames: 0,
            queued: Bytes::new(),
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.queued.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let count = ready!(Pin::new(&mut self.raw).poll_write(cx, &self.queued))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.queued.advance(count);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncRead for Padding {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if this.data_left > 0 {
                let mut scratch = [0; 4096];
                let count = this.data_left.min(out.remaining()).min(scratch.len());
                let mut part = ReadBuf::new(&mut scratch[..count]);
                ready!(Pin::new(&mut this.raw).poll_read(cx, &mut part))?;
                let count = part.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                out.put_slice(part.filled());
                this.data_left -= count;
                return Poll::Ready(Ok(()));
            }
            if this.padding_left > 0 {
                let mut scratch = [0; 1024];
                let size = this.padding_left.min(scratch.len());
                let mut buf = ReadBuf::new(&mut scratch[..size]);
                ready!(Pin::new(&mut this.raw).poll_read(cx, &mut buf))?;
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.padding_left -= buf.filled().len();
                continue;
            }
            if this.read_frames == 16 {
                return Pin::new(&mut this.raw).poll_read(cx, out);
            }
            let mut buf = ReadBuf::new(&mut this.header[this.header_used..]);
            ready!(Pin::new(&mut this.raw).poll_read(cx, &mut buf))?;
            let count = buf.filled().len();
            if count == 0 {
                return Poll::Ready(if this.header_used == 0 {
                    Ok(())
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
            }
            this.header_used += count;
            if this.header_used == 4 {
                this.data_left = u16::from_be_bytes([this.header[0], this.header[1]]) as usize;
                this.padding_left = u16::from_be_bytes([this.header[2], this.header[3]]) as usize;
                this.header_used = 0;
                this.read_frames += 1;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Padding {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        if self.write_frames == 16 {
            return Pin::new(&mut self.raw).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let size = buf.len().min(16384);
        let padding = rand::random_range(256_usize..768);
        let mut wire = Vec::with_capacity(4 + size + padding);
        wire.extend_from_slice(&(size as u16).to_be_bytes());
        wire.extend_from_slice(&(padding as u16).to_be_bytes());
        wire.extend_from_slice(&buf[..size]);
        wire.resize(4 + size + padding, 0);
        self.queued = wire.into();
        self.write_frames += 1;
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}
