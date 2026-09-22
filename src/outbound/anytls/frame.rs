use std::io;

use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt as _};

pub(crate) const HEADER_LENGTH: usize = 1 + 4 + 2;
pub(crate) const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Command {
    Waste = 0,
    Syn = 1,
    Push = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl Command {
    pub(crate) fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Waste),
            1 => Ok(Self::Syn),
            2 => Ok(Self::Push),
            3 => Ok(Self::Fin),
            4 => Ok(Self::Settings),
            5 => Ok(Self::Alert),
            6 => Ok(Self::UpdatePaddingScheme),
            7 => Ok(Self::SynAck),
            8 => Ok(Self::HeartRequest),
            9 => Ok(Self::HeartResponse),
            10 => Ok(Self::ServerSettings),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown AnyTLS frame command",
            )),
        }
    }

    pub(crate) const fn wire_value(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) command: Command,
    pub(crate) stream_id: u32,
    pub(crate) payload: Bytes,
}

impl Frame {
    pub(crate) fn empty(command: Command, stream_id: u32) -> Self {
        Self {
            command,
            stream_id,
            payload: Bytes::new(),
        }
    }

    pub(crate) fn with_payload(
        command: Command,
        stream_id: u32,
        payload: impl Into<Bytes>,
    ) -> io::Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS frame payload exceeds 65535 bytes",
            ));
        }
        Ok(Self {
            command,
            stream_id,
            payload,
        })
    }

    pub(crate) fn encoded_len(&self) -> usize {
        HEADER_LENGTH + self.payload.len()
    }

    pub(crate) fn encode_into(&self, output: &mut BytesMut) -> io::Result<()> {
        let payload_length = u16::try_from(self.payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS frame payload exceeds 65535 bytes",
            )
        })?;
        output.reserve(self.encoded_len());
        output.put_u8(self.command.wire_value());
        output.put_u32(self.stream_id);
        output.put_u16(payload_length);
        output.extend_from_slice(&self.payload);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encode(&self) -> io::Result<Bytes> {
        let mut output = BytesMut::with_capacity(self.encoded_len());
        self.encode_into(&mut output)?;
        Ok(output.freeze())
    }
}

pub(crate) fn encode_batch(frames: &[Frame]) -> io::Result<Bytes> {
    let capacity = frames.iter().try_fold(0_usize, |total, frame| {
        total.checked_add(frame.encoded_len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "AnyTLS frame batch overflow")
        })
    })?;
    let mut output = BytesMut::with_capacity(capacity);
    for frame in frames {
        frame.encode_into(&mut output)?;
    }
    Ok(output.freeze())
}

pub(crate) async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0_u8; HEADER_LENGTH];
    reader.read_exact(&mut header).await?;
    let command = Command::from_wire(header[0])?;
    let stream_id = u32::from_be_bytes(header[1..5].try_into().expect("fixed header slice"));
    let payload_length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    let payload = if payload_length == 0 {
        Bytes::new()
    } else {
        let mut payload = BytesMut::zeroed(payload_length);
        reader.read_exact(&mut payload).await?;
        payload.freeze()
    };
    Ok(Frame {
        command,
        stream_id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[test]
    fn encodes_big_endian_header() {
        let frame =
            Frame::with_payload(Command::Push, 0x0102_0304, Bytes::from_static(b"abc")).unwrap();
        assert_eq!(
            frame.encode().unwrap().as_ref(),
            &[2, 1, 2, 3, 4, 0, 3, b'a', b'b', b'c']
        );
    }

    #[test]
    fn rejects_oversized_payload() {
        assert!(Frame::with_payload(Command::Push, 1, vec![0_u8; MAX_FRAME_PAYLOAD + 1]).is_err());
    }

    #[tokio::test]
    async fn reads_fragmented_header_and_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let sending = tokio::spawn(async move {
            for byte in [7, 0, 0, 0, 9, 0, 2, b'o', b'k'] {
                writer.write_all(&[byte]).await.unwrap();
            }
        });
        let frame = read_frame(&mut reader).await.unwrap();
        sending.await.unwrap();
        assert_eq!(frame.command, Command::SynAck);
        assert_eq!(frame.stream_id, 9);
        assert_eq!(frame.payload.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn rejects_unknown_command_before_allocating_payload() {
        let mut input = std::io::Cursor::new([0xff, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(
            read_frame(&mut input).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
