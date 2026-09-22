//! Minimal XUDP framing for one UDP association over a VLESS mux command.

use std::io;

use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_UDP: u8 = 2;
const MAX_METADATA_LENGTH: usize = 512;

pub struct XudpTransport {
    stream: BoxStream,
    global_id: [u8; 8],
    max_response_payload_size: u16,
    first_write: bool,
    response_pending: bool,
    last_remote: Option<Destination>,
    receive_buffer: BytesMut,
    max_receive_buffer_size: usize,
    closed: bool,
}

impl std::fmt::Debug for XudpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XudpTransport")
            .field("max_response_payload_size", &self.max_response_payload_size)
            .field("first_write", &self.first_write)
            .field("response_pending", &self.response_pending)
            .field("last_remote", &self.last_remote)
            .field("receive_buffered", &self.receive_buffer.len())
            .field("max_receive_buffer_size", &self.max_receive_buffer_size)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl XudpTransport {
    #[must_use]
    pub fn new(stream: BoxStream, global_id: [u8; 8], max_response_payload_size: u16) -> Self {
        // One VLESS response header plus one maximum-size XUDP frame. The
        // checked construction keeps the bound explicit if any component is
        // widened in the future.
        let max_receive_buffer_size = 2_usize
            .checked_add(2)
            .and_then(|size| size.checked_add(MAX_METADATA_LENGTH))
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(usize::from(max_response_payload_size)))
            .expect("XUDP receive-buffer ceiling fits usize");
        Self {
            stream,
            global_id,
            max_response_payload_size,
            first_write: true,
            response_pending: true,
            last_remote: None,
            receive_buffer: BytesMut::with_capacity(max_receive_buffer_size),
            max_receive_buffer_size,
            closed: false,
        }
    }

    /// Incrementally fills the persistent receive buffer using only
    /// cancellation-safe `read` calls. Every successful partial read is
    /// committed before the next await, so dropping `receive()` from a
    /// `tokio::select!` cannot lose bytes or parser progress.
    async fn fill_receive_buffer(&mut self, required: usize) -> io::Result<()> {
        if required > self.max_receive_buffer_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XUDP receive frame exceeds the bounded buffer",
            ));
        }

        let mut scratch = [0_u8; 1024];
        while self.receive_buffer.len() < required {
            let missing = required - self.receive_buffer.len();
            let chunk = missing.min(scratch.len());
            let read = self.stream.read(&mut scratch[..chunk]).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XUDP stream ended in the middle of a frame",
                ));
            }
            self.receive_buffer.extend_from_slice(&scratch[..read]);
        }
        Ok(())
    }

    async fn read_vless_response(&mut self) -> io::Result<()> {
        if !self.response_pending {
            return Ok(());
        }
        self.fill_receive_buffer(2).await?;
        let header = &self.receive_buffer[..2];
        if header[0] != 0 {
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
        // This reader never reads beyond the requested parser boundary.
        self.receive_buffer.clear();
        self.response_pending = false;
        Ok(())
    }

    async fn read_frame(&mut self) -> io::Result<Datagram> {
        loop {
            self.fill_receive_buffer(2).await?;
            let metadata_length = usize::from(u16::from_be_bytes([
                self.receive_buffer[0],
                self.receive_buffer[1],
            ]));
            if !(4..=MAX_METADATA_LENGTH).contains(&metadata_length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid XUDP metadata length",
                ));
            }
            let metadata_end = 2_usize
                .checked_add(metadata_length)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XUDP frame overflow"))?;
            self.fill_receive_buffer(metadata_end).await?;
            let (status, option) = {
                let metadata = &self.receive_buffer[2..metadata_end];
                if metadata[0..2] != [0, 0] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected XUDP session id",
                    ));
                }
                let status = metadata[2];
                let option = metadata[3];
                if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown XUDP frame option",
                    ));
                }
                if option & OPTION_ERROR != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "XUDP peer closed the association with an error",
                    ));
                }
                match status {
                    STATUS_END => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "XUDP peer closed the association normally",
                        ));
                    }
                    STATUS_KEEP | STATUS_KEEP_ALIVE => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected XUDP frame status",
                        ));
                    }
                }
                (status, option)
            };
            if option & OPTION_DATA == 0 {
                self.receive_buffer.clear();
                continue;
            }

            // Xray consumes and discards data attached to a keepalive frame.
            // It is transport padding/liveness data, not an application UDP
            // datagram, and therefore has no meaningful remote destination.
            let remote = (status != STATUS_KEEP_ALIVE)
                .then(|| {
                    let metadata = &self.receive_buffer[2..metadata_end];
                    if metadata_length > 4 {
                        if metadata[4] != NETWORK_UDP {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected XUDP response network",
                            ));
                        }
                        let (destination, consumed) = decode_destination(&metadata[5..])?;
                        if 5 + consumed > metadata_length {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated XUDP response destination",
                            ));
                        }
                        Ok(destination)
                    } else {
                        self.last_remote.clone().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XUDP response omitted its destination before any request",
                            )
                        })
                    }
                })
                .transpose()?;

            let payload_length_end = metadata_end
                .checked_add(2)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XUDP frame overflow"))?;
            self.fill_receive_buffer(payload_length_end).await?;
            let payload_length = u16::from_be_bytes([
                self.receive_buffer[metadata_end],
                self.receive_buffer[metadata_end + 1],
            ]);
            if payload_length > self.max_response_payload_size {
                self.closed = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "XUDP response payload length {payload_length} exceeds ceiling {}",
                        self.max_response_payload_size
                    ),
                ));
            }
            let frame_end = payload_length_end
                .checked_add(usize::from(payload_length))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XUDP frame overflow"))?;
            self.fill_receive_buffer(frame_end).await?;

            if status == STATUS_KEEP_ALIVE {
                self.receive_buffer.clear();
                continue;
            }
            let payload =
                Bytes::copy_from_slice(&self.receive_buffer[payload_length_end..frame_end]);
            self.receive_buffer.clear();
            return Ok(Datagram {
                remote: remote.expect("non-keepalive XUDP data has a remote destination"),
                payload,
                sniffed_domain: None,
            });
        }
    }
}

#[async_trait::async_trait]
impl DatagramTransport for XudpTransport {
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closed {
            return Err(DispatchError::Other(
                "XUDP association is closed".to_owned(),
            ));
        }
        let frame = encode_data_frame(
            &datagram,
            self.first_write,
            if self.first_write {
                Some(self.global_id)
            } else {
                None
            },
        )
        .map_err(DispatchError::from)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(DispatchError::from)?;
        self.stream.flush().await.map_err(DispatchError::from)?;
        self.first_write = false;
        self.last_remote = Some(datagram.remote);
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closed {
            return Err(DispatchError::Other(
                "XUDP association is closed".to_owned(),
            ));
        }
        self.read_vless_response()
            .await
            .map_err(DispatchError::from)?;
        self.read_frame().await.map_err(DispatchError::from)
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        if self.closed {
            return Ok(());
        }
        self.stream
            .write_all(&[0, 4, 0, 0, STATUS_END, 0])
            .await
            .map_err(DispatchError::from)?;
        self.stream.shutdown().await.map_err(DispatchError::from)?;
        self.closed = true;
        Ok(())
    }
}

pub(crate) fn encode_data_frame(
    datagram: &Datagram,
    first: bool,
    global_id: Option<[u8; 8]>,
) -> io::Result<Bytes> {
    if datagram.payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP does not send empty datagrams",
        ));
    }
    let payload_length = u16::try_from(datagram.payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP datagram exceeds 65535 bytes",
        )
    })?;

    let mut destination = BytesMut::with_capacity(19);
    encode_destination(&datagram.remote, &mut destination)?;
    let global_id_length = global_id.map_or(0, |_| 8);
    let metadata_length = 2 + 1 + 1 + 1 + destination.len() + global_id_length;
    let metadata_length = u16::try_from(metadata_length).expect("XUDP metadata is bounded");

    let mut output =
        BytesMut::with_capacity(2 + usize::from(metadata_length) + 2 + datagram.payload.len());
    output.put_u16(metadata_length);
    output.put_u16(0); // session id; XUDP uses the VLESS mux session zero
    output.put_u8(if first { STATUS_NEW } else { STATUS_KEEP });
    output.put_u8(OPTION_DATA);
    output.put_u8(NETWORK_UDP);
    output.extend_from_slice(&destination);
    if let Some(global_id) = global_id {
        output.extend_from_slice(&global_id);
    }
    output.put_u16(payload_length);
    output.extend_from_slice(&datagram.payload);
    Ok(output.freeze())
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
                io::Error::new(io::ErrorKind::InvalidInput, "XUDP domain is too long")
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

fn decode_destination(input: &[u8]) -> io::Result<(Destination, usize)> {
    if input.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated XUDP destination",
        ));
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP destination port is zero",
        ));
    }
    match input[2] {
        1 => {
            let octets: [u8; 4] = input
                .get(3..7)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated IPv4 destination")
                })?
                .try_into()
                .expect("slice length checked");
            Ok((
                Destination::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(octets.into()),
                    port,
                )),
                7,
            ))
        }
        2 => {
            let length = usize::from(*input.get(3).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated domain destination")
            })?);
            let host = input.get(4..4 + length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated domain destination")
            })?;
            let host = std::str::from_utf8(host)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 domain"))?;
            Ok((Destination::domain(host, port)?, 4 + length))
        }
        3 => {
            let octets: [u8; 16] = input
                .get(3..19)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated IPv6 destination")
                })?
                .try_into()
                .expect("slice length checked");
            Ok((
                Destination::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(octets.into()),
                    port,
                )),
                19,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown XUDP address type",
        )),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[test]
    fn first_frame_matches_xray_mux_wire_format() {
        let datagram = Datagram {
            remote: "1.2.3.4:53".parse::<std::net::SocketAddr>().unwrap().into(),
            payload: Bytes::from_static(b"abc"),
            sniffed_domain: None,
        };
        let frame = encode_data_frame(&datagram, true, Some([0; 8])).unwrap();
        assert_eq!(
            frame.as_ref(),
            &[
                0, 20, // metadata length
                0, 0, // mux session id
                1, 1, 2, // new, data, UDP
                0, 53, 1, 1, 2, 3, 4, // port + IPv4
                0, 0, 0, 0, 0, 0, 0, 0, // global id
                0, 3, b'a', b'b', b'c',
            ]
        );
    }

    #[test]
    fn followup_frame_carries_each_datagrams_destination() {
        let datagram = Datagram {
            remote: Destination::domain("dns.example", 53).unwrap(),
            payload: Bytes::from_static(b"q"),
            sniffed_domain: None,
        };
        let frame = encode_data_frame(&datagram, false, None).unwrap();
        assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), 20);
        assert_eq!(&frame[2..7], &[0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
        assert!(frame.ends_with(&[0, 1, b'q']));
    }

    #[test]
    fn destination_codec_round_trips_all_address_families() {
        for destination in [
            Destination::from("192.0.2.1:80".parse::<std::net::SocketAddr>().unwrap()),
            Destination::from("[2001:db8::1]:443".parse::<std::net::SocketAddr>().unwrap()),
            Destination::domain("example.com", 53).unwrap(),
        ] {
            let mut encoded = BytesMut::new();
            encode_destination(&destination, &mut encoded).unwrap();
            let (decoded, consumed) = decode_destination(&encoded).unwrap();
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, destination);
        }
    }

    #[tokio::test]
    async fn normal_and_error_end_frames_are_distinguishable() {
        let normal = receive_frame_error(&[0, 4, 0, 0, STATUS_END, 0]).await;
        let failed = receive_frame_error(&[0, 4, 0, 0, STATUS_END, OPTION_ERROR]).await;

        assert!(
            normal
                .to_string()
                .contains("closed the association normally")
        );
        assert!(
            failed
                .to_string()
                .contains("closed the association with an error")
        );
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_payload_read() {
        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&response_data_prefix(u16::MAX))
            .await
            .unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1_452);
        let bounded_capacity = 2 + 2 + MAX_METADATA_LENGTH + 2 + 1_452;
        assert_eq!(transport.max_receive_buffer_size, bounded_capacity);
        assert_eq!(transport.receive_buffer.capacity(), bounded_capacity);

        transport.read_vless_response().await.unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.read_frame(),
        )
        .await
        .expect("oversized length must be rejected without waiting for payload bytes")
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("65535 exceeds ceiling 1452"));
        assert_eq!(transport.receive_buffer.len(), 2 + 12 + 2);
        assert_eq!(transport.receive_buffer.capacity(), bounded_capacity);
        assert!(transport.closed);
        assert!(
            transport
                .receive()
                .await
                .unwrap_err()
                .to_string()
                .contains("closed")
        );
    }

    #[tokio::test]
    async fn fragmented_receive_survives_cancellation_and_resumes() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut frame = response_data_prefix(3);
        frame.extend_from_slice(b"abc");

        // Stop in the middle of the two-byte metadata length. The first byte
        // has already crossed the stream boundary when receive is cancelled.
        server.write_all(&frame[..3]).await.unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1_452);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), transport.receive())
                .await
                .is_err()
        );
        assert!(!transport.response_pending);
        assert_eq!(transport.receive_buffer.as_ref(), &[0]);

        let remaining = frame[3..].to_vec();
        let writer = tokio::spawn(async move {
            for byte in remaining {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive())
            .await
            .expect("fragmented frame should complete")
            .unwrap();
        writer.await.unwrap();

        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(&datagram.payload[..], b"abc");
        assert!(transport.receive_buffer.is_empty());
        assert!(transport.receive_buffer.capacity() <= transport.max_receive_buffer_size);
    }

    #[tokio::test]
    async fn keepalive_data_is_consumed_without_becoming_an_udp_response() {
        let (client, mut server) = tokio::io::duplex(128);
        let mut wire = vec![
            0,
            0, // VLESS response header
            0,
            4, // metadata length
            0,
            0, // mux session id
            STATUS_KEEP_ALIVE,
            OPTION_DATA,
            0,
            4, // discarded payload length
        ];
        wire.extend_from_slice(b"ping");
        wire.extend_from_slice(&response_data_prefix(3)[2..]);
        wire.extend_from_slice(b"abc");
        server.write_all(&wire).await.unwrap();

        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1_452);
        let datagram = transport.receive().await.unwrap();

        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(&datagram.payload[..], b"abc");
        assert!(transport.receive_buffer.is_empty());
    }

    #[tokio::test]
    async fn full_wire_payload_remains_available_to_proxy_inbounds() {
        let (client, mut server) = tokio::io::duplex(66_000);
        let mut frame = response_data_prefix(u16::MAX);
        frame.resize(frame.len() + usize::from(u16::MAX), 0x5a);
        server.write_all(&frame).await.unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], u16::MAX);

        let datagram = transport.receive().await.unwrap();

        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(datagram.payload.len(), usize::from(u16::MAX));
        assert!(datagram.payload.iter().all(|byte| *byte == 0x5a));
    }

    fn response_data_prefix(payload_length: u16) -> Vec<u8> {
        let mut frame = vec![
            0,
            0, // VLESS response header
            0,
            12, // metadata length
            0,
            0, // mux session id
            STATUS_KEEP,
            OPTION_DATA,
            NETWORK_UDP,
            0,
            53,
            1,
            1,
            2,
            3,
            4, // port + IPv4
        ];
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame
    }

    async fn receive_frame_error(frame: &[u8]) -> DispatchError {
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(&[0, 0]).await.unwrap();
        server.write_all(frame).await.unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], u16::MAX);
        transport.receive().await.unwrap_err()
    }
}
