use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::{dispatch::BoxStream, session::Destination};

const VLESS_VERSION: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp,
    Mux,
}

impl VlessCommand {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Mux => 3,
        }
    }
}

pub fn encode_request_header(
    uuid: Uuid,
    command: VlessCommand,
    destination: Option<&Destination>,
) -> io::Result<Bytes> {
    if (command == VlessCommand::Tcp) != destination.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS TCP requires a destination and mux must omit it",
        ));
    }

    let mut output = BytesMut::with_capacity(64);
    output.put_u8(VLESS_VERSION);
    output.extend_from_slice(uuid.as_bytes());
    output.put_u8(0); // protobuf addons length; Vision is outside the current XHTTP scope
    output.put_u8(command.wire_value());
    if let Some(destination) = destination {
        encode_destination(destination, &mut output)?;
    }
    Ok(output.freeze())
}

pub async fn read_response_header<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != VLESS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected VLESS response version",
        ));
    }
    if header[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VLESS response addons are unsupported when flow is empty",
        ));
    }
    Ok(())
}

/// A VLESS TCP stream that emits the request header before the first operation
/// and consumes the response header immediately before the first payload read.
///
/// VLESS servers are allowed to delay their response header until target data
/// is available. Keeping both handshakes lazy avoids waiting for that response
/// before the caller has had a chance to send its first request payload.
pub struct VlessStream {
    inner: BoxStream,
    request_header: Bytes,
    request_header_written: usize,
    response_header: [u8; 2],
    response_header_read: usize,
    response_header_done: bool,
}

impl VlessStream {
    #[must_use]
    pub const fn new(inner: BoxStream, request_header: Bytes) -> Self {
        Self {
            inner,
            request_header,
            request_header_written: 0,
            response_header: [0; 2],
            response_header_read: 0,
            response_header_done: false,
        }
    }

    fn poll_request_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.request_header_written < self.request_header.len() {
            let written = match Pin::new(&mut *self.inner)
                .poll_write(cx, &self.request_header[self.request_header_written..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(written)) => written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            };
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.request_header_written += written;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_header_done {
            return Poll::Ready(Ok(()));
        }

        while self.response_header_read < self.response_header.len() {
            let mut buffer = ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            match Pin::new(&mut *self.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                Poll::Ready(Ok(())) => self.response_header_read += buffer.filled().len(),
            }
        }

        if self.response_header[0] != VLESS_VERSION {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected VLESS response version",
            )));
        }
        if self.response_header[1] != 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS response addons are unsupported when flow is empty",
            )));
        }

        self.response_header_done = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_request_header(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        match self.poll_response_header(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.poll_request_header(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.poll_request_header(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.poll_request_header(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

fn encode_destination(destination: &Destination, output: &mut BytesMut) -> io::Result<()> {
    output.put_u16(destination.port());
    match destination {
        Destination::Ip(address) if address.is_ipv4() => {
            output.put_u8(1);
            let std::net::IpAddr::V4(ip) = address.ip() else {
                unreachable!("is_ipv4 checked")
            };
            output.extend_from_slice(&ip.octets());
        }
        Destination::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "VLESS domain is too long")
            })?;
            output.put_u8(2);
            output.put_u8(length);
            output.extend_from_slice(host.as_bytes());
        }
        Destination::Ip(address) => {
            output.put_u8(3);
            let std::net::IpAddr::V6(ip) = address.ip() else {
                unreachable!("non-IPv4 address is IPv6")
            };
            output.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    fn uuid() -> Uuid {
        Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap()
    }

    #[test]
    fn tcp_header_matches_vless_wire_format() {
        let destination = Destination::domain("example.com", 443).unwrap();
        let header = encode_request_header(uuid(), VlessCommand::Tcp, Some(&destination)).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(uuid().as_bytes());
        expected.extend_from_slice(&[
            0, // addons
            1, // TCP
            0x01, 0xbb, // port 443
            2, 11, // domain + length
        ]);
        expected.extend_from_slice(b"example.com");
        assert_eq!(header.as_ref(), expected);
    }

    #[test]
    fn xudp_starts_with_a_destinationless_mux_header() {
        let header = encode_request_header(uuid(), VlessCommand::Mux, None).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(uuid().as_bytes());
        expected.extend_from_slice(&[0, 3]);
        assert_eq!(header.as_ref(), expected);
    }

    #[tokio::test]
    async fn rejects_response_addons_when_flow_is_empty() {
        let mut stream = std::io::Cursor::new([0, 3, 1, 2, 3]);
        let error = read_response_header(&mut stream).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn lazy_stream_does_not_wait_for_response_before_request_payload() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let destination = Destination::domain("example.com", 80).unwrap();
            let header =
                encode_request_header(uuid(), VlessCommand::Tcp, Some(&destination)).unwrap();
            let header_for_server = header.clone();
            let (client, mut server) = tokio::io::duplex(256);
            let mut stream = VlessStream::new(Box::new(client), header);

            let server_task = async move {
                let mut received_header = vec![0_u8; header_for_server.len()];
                server.read_exact(&mut received_header).await.unwrap();
                assert_eq!(received_header, header_for_server);

                let mut request = [0_u8; 4];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                server.write_all(&[0, 0]).await.unwrap();
                server.write_all(b"pong").await.unwrap();
            };
            let client_task = async move {
                stream.write_all(b"ping").await.unwrap();
                stream.flush().await.unwrap();
                let mut response = [0_u8; 4];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"pong");
            };

            tokio::join!(server_task, client_task);
        })
        .await
        .expect("lazy VLESS exchange timed out");
    }
}
