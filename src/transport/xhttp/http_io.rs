//! Bounded HTTP exchanges over caller-owned IO; no socket or resolver ownership.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

use super::{BoxStream, ConnectionGuard, DriverOwner, connection_closed};

const BODY_QUEUE: usize = crate::limits::XHTTP_BODY_QUEUE;
const BODY_CHUNK: usize = crate::limits::XHTTP_BODY_CHUNK;
type H1Request = (
    Request<UploadBody>,
    oneshot::Sender<io::Result<Response<Incoming>>>,
);
pub(super) type ResponseFuture =
    Pin<Box<dyn Future<Output = io::Result<Response<Download>>> + Send>>;

#[derive(Clone, Debug)]
pub(super) enum Sender {
    H2(h2::client::SendRequest<Bytes>),
    H1(mpsc::Sender<H1Request>),
    H3(super::h3_driver::Sender),
}

impl Sender {
    pub(super) async fn send_request(
        &mut self,
        request: Request<()>,
        end: bool,
    ) -> io::Result<(ResponseFuture, Upload)> {
        match self {
            Self::H2(sender) => {
                let (response, upload) =
                    sender.send_request(request, end).map_err(super::io_other)?;
                Ok((
                    Box::pin(async move {
                        response
                            .await
                            .map(|r| r.map(Download::H2))
                            .map_err(super::io_other)
                    }),
                    Upload::H2(upload),
                ))
            }
            Self::H1(sender) => {
                let request = http1_request(request)?;
                let (send, receive) = mpsc::channel(BODY_QUEUE);
                let (reply, response) = oneshot::channel();
                let upload = if end {
                    drop(send);
                    H1Upload::closed()
                } else {
                    H1Upload::new(send)
                };
                sender
                    .send((
                        request.map(|_| UploadBody {
                            receive,
                            empty: end,
                        }),
                        reply,
                    ))
                    .await
                    .map_err(|_| connection_closed())?;
                Ok((
                    Box::pin(async move {
                        response
                            .await
                            .map_err(|_| connection_closed())?
                            .map(|r| r.map(Download::H1))
                    }),
                    Upload::H1(upload),
                ))
            }
            Self::H3(sender) => {
                let request = sender
                    .requests
                    .send_request(request)
                    .await
                    .map_err(super::h3_driver::failure)?;
                let (mut send, mut receive) = request.split();
                let cancel = sender.runtime.cancel.child_token();
                let (upload, mut data) = mpsc::channel::<Bytes>(BODY_QUEUE);
                if end {
                    send.finish().await.map_err(super::h3_driver::failure)?;
                } else {
                    let cancellation = cancel.clone();
                    sender.runtime.spawn_owned(async move {
                        let transmit = async {
                            while let Some(data) = data.recv().await {
                                send.send_data(data).await?;
                            }
                            send.finish().await
                        };
                        let completed = tokio::select! {biased;
                            () = cancellation.cancelled() => false,
                            result = transmit => result.is_ok(),
                        };
                        if !completed {
                            send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                        }
                    })?;
                }
                Ok((
                    Box::pin(async move {
                        let response = receive
                            .recv_response()
                            .await
                            .map_err(super::h3_driver::failure)?;
                        Ok(response.map(|_| Download::H3(H3Download(receive))))
                    }),
                    Upload::H3(H3Upload {
                        channel: H1Upload::new(upload),
                        cancel,
                    }),
                ))
            }
        }
    }
}

pub(super) async fn http1(
    io: BoxStream,
    owner: &DriverOwner,
) -> io::Result<(Sender, ConnectionGuard)> {
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(super::request::MAX_REQUEST_HEADERS)
        .max_buf_size(super::request::MAX_REQUEST_BYTES)
        .writev(false)
        .handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(h1_failure)?;
    let (commands, mut requests) = mpsc::channel::<H1Request>(BODY_QUEUE);
    // Dispatch eagerly, so an upload is not dependent on the caller polling reads.
    // Both futures belong to the same cancellation/join barrier as the physical IO.
    let guard = owner.spawn(async move {
        let dispatch = async move {
            while let Some((request, reply)) = requests.recv().await {
                if reply.is_closed() {
                    continue;
                }
                let result = match sender.ready().await {
                    Ok(()) => sender.send_request(request).await,
                    Err(error) => {
                        let _ = reply.send(Err(h1_failure(error)));
                        break;
                    }
                };
                let _ = reply.send(result.map_err(h1_failure));
            }
        };
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => {},
            () = dispatch => {
                // Dropping the last request sender does not end a response body.
                // The logical stream/owner still controls the connection lifetime.
                let _ = connection.await;
            }
        }
    })?;
    Ok((Sender::H1(commands), guard))
}

fn h1_failure(_: hyper::Error) -> io::Error {
    io::Error::other("XHTTP HTTP/1 exchange failed")
}

fn http1_request(mut request: Request<()>) -> io::Result<Request<()>> {
    let host = request
        .uri()
        .authority()
        .ok_or_else(super::request::invalid_request)?
        .as_str()
        .to_owned();
    request
        .headers_mut()
        .insert(http::header::HOST, super::request::header_value(&host)?);
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .ok_or_else(super::request::invalid_request)?
        .as_str()
        .parse()
        .map_err(|_| super::request::invalid_request())?;
    *request.version_mut() = http::Version::HTTP_11;
    Ok(request)
}

pub(super) struct UploadBody {
    receive: mpsc::Receiver<Bytes>,
    empty: bool,
}
impl Body for UploadBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.receive
            .poll_recv(cx)
            .map(|bytes| bytes.map(|data| Ok(Frame::data(data))))
    }
    fn is_end_stream(&self) -> bool {
        self.receive.is_closed() && self.receive.is_empty()
    }
    fn size_hint(&self) -> SizeHint {
        if self.empty {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}

pub(super) enum Upload {
    H2(h2::SendStream<Bytes>),
    H1(H1Upload),
    H3(H3Upload),
}
pub(super) struct H3Upload {
    channel: H1Upload,
    cancel: tokio_util::sync::CancellationToken,
}
impl Drop for H3Upload {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
pub(super) struct H1Upload {
    poll: PollSender<Bytes>,
    direct: Option<mpsc::Sender<Bytes>>,
    reserved: bool,
}
impl H1Upload {
    fn new(sender: mpsc::Sender<Bytes>) -> Self {
        Self {
            poll: PollSender::new(sender.clone()),
            direct: Some(sender),
            reserved: false,
        }
    }
    fn closed() -> Self {
        let (sender, _) = mpsc::channel(1);
        let mut value = Self::new(sender);
        value.close();
        value
    }
    fn close(&mut self) {
        self.poll.abort_send();
        self.poll.close();
        self.direct = None;
        self.reserved = false;
    }
}
impl Upload {
    pub(super) fn reserve_capacity(&mut self, count: usize) {
        if let Self::H2(stream) = self {
            stream.reserve_capacity(count);
        }
    }
    pub(super) fn capacity(&self) -> usize {
        match self {
            Self::H2(stream) => stream.capacity(),
            Self::H1(stream)
            | Self::H3(H3Upload {
                channel: stream, ..
            }) => {
                if stream.reserved {
                    BODY_CHUNK
                } else {
                    0
                }
            }
        }
    }
    pub(super) fn poll_capacity(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<usize>>> {
        match self {
            Self::H2(stream) => stream
                .poll_capacity(cx)
                .map(|r| r.map(|r| r.map_err(super::io_other))),
            Self::H1(stream)
            | Self::H3(H3Upload {
                channel: stream, ..
            }) => {
                if stream.direct.is_none() {
                    return Poll::Ready(None);
                }
                match std::task::ready!(stream.poll.poll_reserve(cx)) {
                    Ok(()) => {
                        stream.reserved = true;
                        Poll::Ready(Some(Ok(BODY_CHUNK)))
                    }
                    Err(_) => Poll::Ready(Some(Err(connection_closed()))),
                }
            }
        }
    }
    pub(super) fn send_data(&mut self, data: Bytes, end: bool) -> io::Result<()> {
        match self {
            Self::H2(stream) => stream.send_data(data, end).map_err(super::io_other),
            Self::H1(stream)
            | Self::H3(H3Upload {
                channel: stream, ..
            }) => {
                if !data.is_empty() {
                    if data.len() > crate::limits::XHTTP_PACKET_BATCH_BYTES {
                        return Err(super::request::invalid_request());
                    }
                    if stream.reserved {
                        stream.reserved = false;
                        stream
                            .poll
                            .send_item(data)
                            .map_err(|_| connection_closed())?;
                    } else {
                        stream
                            .direct
                            .as_ref()
                            .ok_or_else(connection_closed)?
                            .try_send(data)
                            .map_err(|_| connection_closed())?;
                    }
                }
                if end {
                    stream.close();
                }
                Ok(())
            }
        }
    }
}

pub(super) enum Download {
    H2(h2::RecvStream),
    H1(Incoming),
    H3(H3Download),
}
pub(super) struct H3Download(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>);
// Drop releases Quinn's receive stream, including a pending read future. Do not
// call h3-quinn's explicit stop_sending here: version 0.0.10 temporarily moves
// its stream into that future while polling and the method assumes it is idle.
impl Download {
    pub(super) fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> {
        match self {
            Self::H3(stream) => stream.0.poll_recv_data(cx).map(|result| match result {
                Ok(Some(mut data)) => Some(Ok(data.copy_to_bytes(data.remaining()))),
                Ok(None) => None,
                Err(error) => Some(Err(super::h3_driver::failure(error))),
            }),
            Self::H2(stream) => stream
                .poll_data(cx)
                .map(|r| r.map(|r| r.map_err(super::io_other))),
            Self::H1(stream) => {
                for _ in 0..16 {
                    match std::task::ready!(Pin::new(&mut *stream).poll_frame(cx)) {
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                return Poll::Ready(Some(Ok(data)));
                            }
                        }
                        Some(Err(error)) => return Poll::Ready(Some(Err(h1_failure(error)))),
                        None => return Poll::Ready(None),
                    }
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    pub(super) fn release_capacity(&mut self, bytes: usize) -> io::Result<()> {
        match self {
            Self::H2(stream) => stream
                .flow_control()
                .release_capacity(bytes)
                .map_err(super::io_other),
            Self::H1(_) | Self::H3(_) => Ok(()),
        }
    }
}
