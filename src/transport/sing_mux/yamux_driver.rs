//! The upstream library is caller-driven. VCore owns its one driver and the
//! bounded open-command queue; it never delegates detached task ownership.
use super::*;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

pub(super) const STREAMS: usize = crate::limits::YAMUX_CONNECTION_ADMISSIONS;
type Reply = oneshot::Sender<io::Result<BoxStream>>;
#[derive(Clone)]
pub(super) struct Client {
    open: mpsc::Sender<Reply>,
}
impl Client {
    pub(super) async fn open(&self) -> io::Result<BoxStream> {
        let (tx, rx) = oneshot::channel();
        self.open
            .send(tx)
            .await
            .map_err(|_| io::ErrorKind::ConnectionAborted)?;
        rx.await.map_err(|_| io::ErrorKind::ConnectionAborted)?
    }
}
pub(super) fn new(raw: BoxStream) -> (Client, impl Future<Output = ()> + Send) {
    let (open, mut commands) = mpsc::channel::<Reply>(crate::limits::SING_MUX_COMMAND_QUEUE);
    let mut config = yamux::Config::default();
    config
        .set_max_num_streams(STREAMS)
        .set_max_connection_receive_window(Some(crate::limits::YAMUX_CONNECTION_WINDOW))
        .set_read_after_close(false)
        .set_split_send_size(crate::limits::SING_MUX_CHUNK);
    let mut connection = yamux::Connection::new(raw.compat(), config, yamux::Mode::Client);
    let driver = async move {
        let mut pending: Option<Reply> = None;
        futures_util::future::poll_fn(|cx| {
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                if pending.is_none()
                    && let Poll::Ready(command) = commands.poll_recv(cx)
                {
                    let Some(command) = command else {
                        return Poll::Ready(());
                    };
                    pending = Some(command);
                }
                if pending.as_ref().is_some_and(Reply::is_closed) {
                    pending = None;
                    continue;
                }
                if pending.is_some()
                    && let Poll::Ready(result) = connection.poll_new_outbound(cx)
                {
                    let result = result
                        .map(|stream| Box::new(stream.compat()) as BoxStream)
                        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted));
                    let _ = pending.take().unwrap().send(result);
                    continue;
                }
                // Poll even with a pending open; this is also the write driver
                // for all existing streams, so open backpressure cannot stall it.
                match connection.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        drop(stream);
                        continue;
                    }
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await;
    };
    (Client { open }, driver)
}
