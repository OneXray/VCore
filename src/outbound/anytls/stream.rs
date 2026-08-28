use std::{
    future::Future as _,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::{CancellationToken, PollSender};

use super::{
    frame::MAX_FRAME_PAYLOAD,
    session::{Session, WriterCommand},
};

#[derive(Debug, Clone)]
pub(crate) struct StreamFailure {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl StreamFailure {
    pub(crate) fn new(kind: io::ErrorKind, message: impl Into<Arc<str>>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn from_io(error: &io::Error) -> Self {
        Self::new(error.kind(), Arc::<str>::from(error.to_string()))
    }

    fn to_io(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum StreamEvent {
    Data(Bytes),
    Finished,
    Failed(StreamFailure),
}

#[derive(Debug)]
pub(crate) struct StreamShared {
    remote_finished: AtomicBool,
    local_finished: AtomicBool,
    failure: Mutex<Option<StreamFailure>>,
    local_cancellation: CancellationToken,
}

impl StreamShared {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            remote_finished: AtomicBool::new(false),
            local_finished: AtomicBool::new(false),
            failure: Mutex::new(None),
            local_cancellation: CancellationToken::new(),
        })
    }

    pub(crate) fn mark_remote_finished(&self) {
        self.remote_finished.store(true, Ordering::Release);
    }

    pub(crate) fn remote_finished(&self) -> bool {
        self.remote_finished.load(Ordering::Acquire)
    }

    pub(crate) fn mark_local_finished(&self) {
        self.local_finished.store(true, Ordering::Release);
        self.local_cancellation.cancel();
    }

    pub(crate) fn local_finished(&self) -> bool {
        self.local_finished.load(Ordering::Acquire)
    }

    pub(crate) fn local_cancellation(&self) -> CancellationToken {
        self.local_cancellation.clone()
    }

    pub(crate) fn fail(&self, failure: StreamFailure) {
        self.remote_finished.store(true, Ordering::Release);
        let mut slot = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(failure);
        }
    }

    fn failure(&self) -> Option<StreamFailure> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

pub struct AnyTlsStream {
    session: Arc<Session>,
    stream_id: u32,
    incoming: mpsc::Receiver<StreamEvent>,
    current: Bytes,
    writer: PollSender<WriterCommand>,
    shared: Arc<StreamShared>,
    max_write_chunk: usize,
    pending_write: Option<oneshot::Receiver<io::Result<()>>>,
    pending_flush: Option<oneshot::Receiver<io::Result<()>>>,
    pending_shutdown: Option<oneshot::Receiver<io::Result<()>>>,
    read_finished: bool,
    close_queued: bool,
    closed: bool,
}

impl std::fmt::Debug for AnyTlsStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsStream")
            .field("stream_id", &self.stream_id)
            .field("remote_finished", &self.shared.remote_finished())
            .field("close_queued", &self.close_queued)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl AnyTlsStream {
    pub(crate) fn new(
        session: Arc<Session>,
        stream_id: u32,
        incoming: mpsc::Receiver<StreamEvent>,
        shared: Arc<StreamShared>,
        max_write_chunk: usize,
    ) -> Self {
        let writer = PollSender::new(session.writer());
        Self {
            session,
            stream_id,
            incoming,
            current: Bytes::new(),
            writer,
            shared,
            max_write_chunk: max_write_chunk.clamp(1, MAX_FRAME_PAYLOAD),
            pending_write: None,
            pending_flush: None,
            pending_shutdown: None,
            read_finished: false,
            close_queued: false,
            closed: false,
        }
    }

    fn poll_pending_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(completion) = &mut self.pending_write else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(completion).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Ok(()))) => {
                self.pending_write = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Err(error))) => {
                self.pending_write = None;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(_)) => {
                self.pending_write = None;
                Poll::Ready(Err(closed_pipe("AnyTLS writer stopped")))
            }
        }
    }

    fn poll_control(
        completion: &mut Option<oneshot::Receiver<io::Result<()>>>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(completion_receiver) = completion else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(completion_receiver).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                *completion = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                *completion = None;
                Poll::Ready(Err(closed_pipe("AnyTLS writer stopped")))
            }
        }
    }

    fn poll_reserve_writer(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writer
            .poll_reserve(context)
            .map_err(|_| closed_pipe("AnyTLS writer is closed"))
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_finished || self.closed || self.shared.local_finished() {
            self.current = Bytes::new();
            self.read_finished = true;
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.current.is_empty() {
                let length = self.current.len().min(output.remaining());
                output.put_slice(&self.current.split_to(length));
                return Poll::Ready(Ok(()));
            }
            match self.incoming.poll_recv(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(StreamEvent::Data(data))) => self.current = data,
                Poll::Ready(Some(StreamEvent::Finished)) => {
                    self.shared.mark_remote_finished();
                    self.read_finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::Failed(failure))) => {
                    self.shared.fail(failure.clone());
                    return Poll::Ready(Err(failure.to_io()));
                }
                Poll::Ready(None) => {
                    if let Some(failure) = self.shared.failure() {
                        return Poll::Ready(Err(failure.to_io()));
                    }
                    return Poll::Ready(Err(closed_pipe(
                        "AnyTLS session ended without a FIN frame",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.close_queued || self.shared.remote_finished() {
            return Poll::Ready(Err(closed_pipe("AnyTLS stream is closed")));
        }
        if self.pending_write.is_some() {
            match self.poll_pending_write(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_reserve_writer(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        let length = input.len().min(self.max_write_chunk);
        let (done, completion) = oneshot::channel();
        let command = WriterCommand::Data {
            stream_id: self.stream_id,
            payload: Bytes::copy_from_slice(&input[..length]),
            done,
        };
        if self.writer.send_item(command).is_err() {
            return Poll::Ready(Err(closed_pipe("AnyTLS writer is closed")));
        }
        self.pending_write = Some(completion);
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.poll_pending_write(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if self.pending_flush.is_some() {
            return Self::poll_control(&mut self.pending_flush, context);
        }
        if self.closed || self.close_queued {
            return Poll::Ready(Ok(()));
        }
        match self.poll_reserve_writer(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let (done, completion) = oneshot::channel();
        if self
            .writer
            .send_item(WriterCommand::Flush { done })
            .is_err()
        {
            return Poll::Ready(Err(closed_pipe("AnyTLS writer is closed")));
        }
        self.pending_flush = Some(completion);
        Self::poll_control(&mut self.pending_flush, context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.pending_write.is_some() {
            match self.poll_pending_write(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if self.pending_flush.is_some() {
            match Self::poll_control(&mut self.pending_flush, context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if self.pending_shutdown.is_some() {
            return match Self::poll_control(&mut self.pending_shutdown, context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    self.closed = result.is_ok();
                    Poll::Ready(result)
                }
            };
        }
        match self.poll_reserve_writer(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let (done, completion) = oneshot::channel();
        let command = WriterCommand::CloseStream {
            stream_id: self.stream_id,
            send_fin: !self.shared.remote_finished(),
            done: Some(done),
        };
        if self.writer.send_item(command).is_err() {
            return Poll::Ready(Err(closed_pipe("AnyTLS writer is closed")));
        }
        self.close_queued = true;
        self.pending_shutdown = Some(completion);
        match Self::poll_control(&mut self.pending_shutdown, context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.closed = result.is_ok();
                Poll::Ready(result)
            }
        }
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if self.closed || self.close_queued {
            return;
        }
        let command = WriterCommand::CloseStream {
            stream_id: self.stream_id,
            send_fin: !self.shared.remote_finished(),
            done: None,
        };
        let sent = self
            .writer
            .get_ref()
            .is_some_and(|writer| writer.try_send(command).is_ok());
        if !sent {
            self.session.abandon_stream(self.stream_id);
        }
        self.close_queued = true;
    }
}

fn closed_pipe(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message)
}
