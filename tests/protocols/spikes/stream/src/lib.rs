//! N0-B only: wrapping caller-owned streams using unmodified public libraries.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
pub use vcore::dispatch::BoxStream;

mod ws;
pub use ws::websocket;

pub const CHUNK: usize = 16 * 1024;
pub const LIMIT: usize = 64 * 1024;

mod grpc;
pub use grpc::{Driver, grpc};

pub async fn tls(
    stream: BoxStream,
    config: Arc<rustls::ClientConfig>,
    server_name: &str,
    deadline: Instant,
) -> io::Result<BoxStream> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let stream = tokio::time::timeout_at(
        deadline,
        tokio_rustls::TlsConnector::from(config).connect_with(name, stream, |connection| {
            connection.set_buffer_limit(Some(64 * 1024));
        }),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    Ok(Box::new(Tls {
        stream,
        closing: None,
    }))
}

// Tokio's default shutdown also shuts down the TCP underlay. Mihomo's TLS
// CloseWrite instead emits close_notify, bounds its flush by five seconds, and
// leaves the read direction and the underlay available. Public rustls APIs only.
struct Tls {
    stream: tokio_rustls::client::TlsStream<BoxStream>,
    closing: Option<Pin<Box<Sleep>>>,
}

impl AsyncRead for Tls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing.is_none() {
            self.stream.get_mut().1.send_close_notify();
            self.closing = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
        }
        if let Poll::Ready(result) = Pin::new(&mut self.stream).poll_flush(cx) {
            return Poll::Ready(result);
        }
        if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Poll::Pending
    }
}
