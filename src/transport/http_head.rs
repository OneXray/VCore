//! Bounded response headers shared by stream handshakes; leftover bytes are
//! preserved verbatim for the framing layer. No body buffering or diagnostics.
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const HTTP_HEAD_BYTES: usize = 16 * 1024;
pub const HTTP_HEADER_COUNT: usize = 100;

pub(super) async fn read_response(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<(http::Response<()>, Vec<u8>)> {
    let mut wire = Vec::new();
    loop {
        if let Some(end) = wire
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .map(|start| start + 4)
        {
            if end > HTTP_HEAD_BYTES {
                return Err(invalid());
            }
            let mut headers = [httparse::EMPTY_HEADER; HTTP_HEADER_COUNT];
            let mut parsed = httparse::Response::new(&mut headers);
            match parsed.parse(&wire[..end]).map_err(|_| invalid())? {
                httparse::Status::Complete(length) if length == end => {}
                _ => return Err(invalid()),
            }
            let version = match parsed.version {
                Some(0) => http::Version::HTTP_10,
                Some(1) => http::Version::HTTP_11,
                _ => return Err(invalid()),
            };
            let mut response = http::Response::builder()
                .version(version)
                .status(parsed.code.ok_or_else(invalid)?);
            for header in parsed.headers.iter() {
                response = response.header(header.name, header.value);
            }
            let response = response.body(()).map_err(|_| invalid())?;
            return Ok((response, wire[end..].to_vec()));
        }
        if wire.len() >= HTTP_HEAD_BYTES {
            return Err(invalid());
        }
        let mut chunk = [0; 1024];
        let remaining = (HTTP_HEAD_BYTES - wire.len()).min(chunk.len());
        let count = stream.read(&mut chunk[..remaining]).await?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        wire.extend_from_slice(&chunk[..count]);
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid transport HTTP response",
    )
}
