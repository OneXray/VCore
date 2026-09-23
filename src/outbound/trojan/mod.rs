//! Trojan client wire primitives. The TLS/transport and physical socket remain
//! caller-owned; this module never resolves or opens a network endpoint.
//! Wire reference: https://trojan-gfw.github.io/trojan/protocol

use std::io;

use bytes::Bytes;
use sha2::{Digest, Sha224};

use crate::{session::Destination, socks5::encode_address};

mod datagram;
pub use datagram::{MAX_DATAGRAM_PAYLOAD, TrojanDatagram};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    Tcp,
    Udp,
}

/// A node's precomputed authentication token. Debug never exposes it.
#[derive(Clone)]
pub struct TrojanAuth([u8; 56]);

impl std::fmt::Debug for TrojanAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanAuth").finish_non_exhaustive()
    }
}

impl TrojanAuth {
    pub fn new(password: &str) -> io::Result<Self> {
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Trojan password",
            ));
        }
        let digest = Sha224::digest(password.as_bytes());
        let mut token = [0; 56];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (pair, byte) in token.as_chunks_mut::<2>().0.iter_mut().zip(digest) {
            pair[0] = HEX[usize::from(byte >> 4)];
            pair[1] = HEX[usize::from(byte & 15)];
        }
        Ok(Self(token))
    }

    pub fn request(&self, command: TrojanCommand, peer: &Destination) -> io::Result<Bytes> {
        if peer.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero Trojan destination port",
            ));
        }
        let mut output = Vec::with_capacity(61 + 259);
        output.extend_from_slice(&self.0);
        output.extend_from_slice(b"\r\n");
        output.push(match command {
            TrojanCommand::Tcp => 1,
            TrojanCommand::Udp => 3,
        });
        encode_address(peer, &mut output)?;
        output.extend_from_slice(b"\r\n");
        Ok(output.into())
    }
}
