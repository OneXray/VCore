//! Independent smux v1 client framing. One owned reader/writer pair, bounded
//! physical write queue and per-stream receive queues; no detached workers.
use super::*;
use bytes::Buf;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc, oneshot},
};
use tokio_util::sync::PollSender;

const CHUNK: usize = crate::limits::SING_MUX_CHUNK;
struct Frame {
    cmd: u8,
    id: u32,
    data: Bytes,
    done: oneshot::Sender<io::Result<()>>,
}
struct Entry {
    receive: mpsc::Sender<Bytes>,
    close: CancellationToken,
    remote_fin: Arc<AtomicBool>,
}
struct State {
    closed: bool,
    next: u32,
    streams: HashMap<u32, Entry>,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
}
#[derive(Clone)]
pub(super) struct Client {
    shared: Arc<Shared>,
    write: mpsc::Sender<Frame>,
}
impl Client {
    pub(super) async fn open(&self) -> io::Result<BoxStream> {
        let permit = self
            .write
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| io::ErrorKind::ConnectionAborted)?;
        let (tx, receive) = mpsc::channel(crate::limits::SMUX_RECEIVE_QUEUE);
        let close = CancellationToken::new();
        let remote_fin = Arc::new(AtomicBool::new(false));
        let (id, done) = {
            let mut state = self.shared.state.lock().unwrap();
            if state.closed {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            state.next = state
                .next
                .checked_add(2)
                .ok_or(io::ErrorKind::ConnectionAborted)?;
            let id = state.next;
            state.streams.insert(
                id,
                Entry {
                    receive: tx,
                    close: close.clone(),
                    remote_fin: remote_fin.clone(),
                },
            );
            let (tx, rx) = oneshot::channel();
            permit.send(Frame {
                cmd: 0,
                id,
                data: Bytes::new(),
                done: tx,
            });
            (id, rx)
        };
        let stream = Stream {
            id,
            shared: self.shared.clone(),
            write: PollSender::new(self.write.clone()),
            receive,
            close: close.clone(),
            cancelled: Box::pin(close.cancelled_owned()),
            remote_fin,
            pending: None,
            data: Bytes::new(),
        };
        // Cancellation drops the newly registered logical stream and queues FIN.
        done.await.map_err(|_| io::ErrorKind::ConnectionAborted)??;
        Ok(Box::new(stream))
    }
}
struct Lifetime(Arc<Shared>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.closed = true;
        for (_, entry) in state.streams.drain() {
            entry.close.cancel();
        }
    }
}
pub(super) fn new(raw: BoxStream) -> (Client, impl Future<Output = ()> + Send) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            closed: false,
            next: 1,
            streams: HashMap::new(),
        }),
        changed: Notify::new(),
    });
    let lifetime = Lifetime(shared.clone());
    let (write, mut frames) = mpsc::channel::<Frame>(crate::limits::SING_MUX_COMMAND_QUEUE);
    let client = Client {
        shared: shared.clone(),
        write,
    };
    let (mut reader, mut writer) = tokio::io::split(raw);
    let read_shared = shared.clone();
    let read = async move {
        loop {
            let mut header = [0; 8];
            reader.read_exact(&mut header).await?;
            let cmd = header[1];
            let length = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
            let id = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if header[0] != 1 || !matches!(cmd, 1..=3) || (cmd != 2 && length != 0) {
                return Err::<(), _>(io::Error::from(io::ErrorKind::InvalidData));
            }
            if cmd == 1 {
                if let Some(entry) = read_shared.state.lock().unwrap().streams.remove(&id) {
                    entry.remote_fin.store(true, Ordering::Release);
                }
                continue;
            }
            if cmd == 3 || length == 0 {
                tokio::task::yield_now().await;
                continue;
            }
            let mut data = vec![0; length];
            reader.read_exact(&mut data).await?;
            let target = read_shared
                .state
                .lock()
                .unwrap()
                .streams
                .get(&id)
                .map(|e| (e.receive.clone(), e.close.clone()));
            if let Some((receive, close)) = target {
                tokio::select! {biased;()=close.cancelled()=>{},_=receive.send(data.into())=>{}}
            }
        }
    };
    let write = async move {
        let mut processed = 0;
        loop {
            // A canceled stream always has a FIN path even if the data queue is
            // full. No unbounded "control queue" and no try_send/drop fallback.
            let closing = {
                let mut state = shared.state.lock().unwrap();
                let id = state
                    .streams
                    .iter()
                    .find(|(_, e)| e.close.is_cancelled())
                    .map(|(id, _)| *id);
                id.and_then(|id| state.streams.remove(&id).map(|_| id))
            };
            if let Some(id) = closing {
                send(&mut writer, 1, id, &[]).await?;
            } else {
                let frame = tokio::select! {
                    ()=shared.changed.notified()=>continue,
                    frame=frames.recv()=>{let Some(frame)=frame else {return Ok::<(),io::Error>(());};frame}
                };
                let alive = shared
                    .state
                    .lock()
                    .unwrap()
                    .streams
                    .get(&frame.id)
                    .is_some_and(|e| !e.close.is_cancelled());
                if !alive {
                    let _ = frame.done.send(Err(io::ErrorKind::BrokenPipe.into()));
                    continue;
                }
                let result = send(&mut writer, frame.cmd, frame.id, &frame.data).await;
                let failed = result.is_err();
                let _ = frame.done.send(result);
                if failed {
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
            }
            processed += 1;
            if processed == crate::limits::IO_POLL_BUDGET {
                processed = 0;
                tokio::task::yield_now().await;
            }
        }
    };
    let driver = async move {
        let _lifetime = lifetime;
        tokio::select! {
            _=read=>{},
            _=write=>{}
        }
    };
    (client, driver)
}
async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    cmd: u8,
    id: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut header = [0; 8];
    header[0] = 1;
    header[1] = cmd;
    header[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    header[4..8].copy_from_slice(&id.to_le_bytes());
    writer.write_all(&header).await?;
    writer.write_all(data).await?;
    writer.flush().await
}
struct Stream {
    id: u32,
    shared: Arc<Shared>,
    write: PollSender<Frame>,
    receive: mpsc::Receiver<Bytes>,
    close: CancellationToken,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    remote_fin: Arc<AtomicBool>,
    pending: Option<oneshot::Receiver<io::Result<()>>>,
    data: Bytes,
}
impl Stream {
    fn stop(&mut self) {
        self.close.cancel();
        self.shared.changed.notify_one();
        self.pending.take();
        self.write.abort_send();
        self.receive.close();
        self.data = Bytes::new();
    }
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(pending) = &mut self.pending {
            ready!(Pin::new(pending).poll(cx)).map_err(|_| io::ErrorKind::BrokenPipe)??;
            self.pending = None;
        }
        Poll::Ready(Ok(()))
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.stop();
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 || self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        if self.data.is_empty() {
            match ready!(self.receive.poll_recv(cx)) {
                Some(data) => self.data = data,
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = out.remaining().min(self.data.len());
        out.put_slice(&self.data[..n]);
        self.data.advance(n);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.flush_pending(cx))?;
        if self.remote_fin.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.write.poll_reserve(cx)).map_err(|_| io::ErrorKind::BrokenPipe)?;
        let size = buf.len().min(CHUNK);
        let (tx, rx) = oneshot::channel();
        let id = self.id;
        self.write
            .send_item(Frame {
                cmd: 2,
                id,
                data: Bytes::copy_from_slice(&buf[..size]),
                done: tx,
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.pending = Some(rx);
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_pending(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stop();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn malformed_smux_headers_close_the_owned_driver_before_reading_a_body() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "XHTTP-UNIT",
            "malformed_smux_headers_close_the_owned_driver_before_reading_a_body",
        );
        for (version, command, length) in [(2, 2, 0), (1, 0, 0), (1, 4, 0), (1, 1, 1), (1, 3, 1)] {
            tokio::time::timeout(Duration::from_secs(1), async {
                let (raw, mut peer) = tokio::io::duplex(64);
                let (client, driver) = new(Box::new(raw));
                let task = tokio::spawn(driver);
                let mut logical = client.open().await.unwrap();
                let mut syn = [0; 8];
                peer.read_exact(&mut syn).await.unwrap();
                assert_eq!(syn, [1, 0, 0, 0, 3, 0, 0, 0]);
                // No body is supplied: malformed control framing must terminate
                // immediately rather than waiting for attacker-controlled data.
                peer.write_all(&[version, command, length, 0, 3, 0, 0, 0])
                    .await
                    .unwrap();
                task.await.unwrap();
                assert_eq!(logical.read(&mut [0]).await.unwrap(), 0);
                assert!(logical.write_all(b"closed").await.is_err());
                assert!(client.open().await.is_err());
            })
            .await
            .unwrap();
        }
    }
}
