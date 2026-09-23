//! Bounded HY2 wire framing, tested through a native server by the probe.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub fn tcp_request(address: &str) -> io::Result<Vec<u8>> {
    if address.is_empty() || address.len() > 2048 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut request = Vec::new();
    encode_varint(0x401, &mut request);
    encode_varint(address.len() as u64, &mut request);
    request.extend_from_slice(address.as_bytes());
    encode_varint(0, &mut request);
    Ok(request)
}

pub fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16384 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        assert!(value < 1 << 62);
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

pub async fn read_varint(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let mut value = u64::from(first & 0x3f);
    for _ in 1..(1 << (first >> 6)) {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

pub async fn tcp_response(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    let status = reader.read_u8().await?;
    let mut scratch = [0; 4096];
    for limit in [2048, 4096] {
        let length = read_varint(reader).await?;
        if length > limit {
            return Err(io::ErrorKind::InvalidData.into());
        }
        reader.read_exact(&mut scratch[..length as usize]).await?;
    }
    if status != 0 {
        return Err(io::ErrorKind::ConnectionRefused.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn exact_response_decoder_leaves_server_first_data_unconsumed() {
        let mut input = &[0, 0, 0, b'H', b'Y', b'2'][..];
        super::tcp_response(&mut input).await.unwrap();
        assert_eq!(input, b"HY2");
    }

    #[tokio::test]
    async fn response_rejects_truncation_oversized_fields_and_failure_status() {
        use std::io::ErrorKind;
        for (mut input, expected) in [
            (&[0, 0x40][..], ErrorKind::UnexpectedEof),
            (&[0, 0x48, 0x01][..], ErrorKind::InvalidData),
            (&[0, 0, 0x50, 0x01][..], ErrorKind::InvalidData),
            (&[1, 0, 0][..], ErrorKind::ConnectionRefused),
        ] {
            assert_eq!(
                super::tcp_response(&mut input).await.unwrap_err().kind(),
                expected
            );
        }
    }

    #[test]
    fn request_uses_hysteria_frame_type_and_bounded_address() {
        assert_eq!(super::tcp_request("x:1").unwrap(), b"\x44\x01\x03x:1\x00");
        assert!(super::tcp_request("").is_err());
        assert!(super::tcp_request(&"a".repeat(2049)).is_err());
    }
}
