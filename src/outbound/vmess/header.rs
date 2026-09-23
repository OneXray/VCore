use super::{
    BodyCipher, BodyOptions,
    crypto::{aead_key, error, kdf, open, random, seal},
};
use crate::{outbound::address::encode_port_first, session::Destination};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use bytes::BytesMut;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct VmessIdentity([u8; 16]);
impl std::fmt::Debug for VmessIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessIdentity").finish_non_exhaustive()
    }
}
impl VmessIdentity {
    pub fn new(uuid: uuid::Uuid) -> Self {
        let mut digest = Md5::new();
        digest.update(uuid.as_bytes());
        digest.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        Self(digest.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

pub struct ClientHandshake {
    request: Vec<u8>,
    pub(super) key: [u8; 16],
    pub(super) iv: [u8; 16],
    pub(super) response_key: [u8; 16],
    pub(super) response_iv: [u8; 16],
    response_tag: u8,
    pub(super) options: BodyOptions,
    pub(super) command: Command,
}
impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshake").finish_non_exhaustive()
    }
}

impl ClientHandshake {
    pub fn new(
        identity: &VmessIdentity,
        command: Command,
        peer: &Destination,
        options: BodyOptions,
    ) -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("VMess clock before epoch"))?
            .as_secs();
        let mut entropy = [0; 61];
        random(&mut entropy)?;
        Self::with_entropy(identity, command, peer, options, timestamp, entropy)
    }

    /// Synthetic-clock hook for owned native-peer rejection tests only.
    #[cfg(feature = "interop-test")]
    pub fn with_test_timestamp(
        identity: &VmessIdentity,
        command: Command,
        peer: &Destination,
        options: BodyOptions,
        timestamp: u64,
    ) -> io::Result<Self> {
        let mut entropy = [0; 61];
        random(&mut entropy)?;
        Self::with_entropy(identity, command, peer, options, timestamp, entropy)
    }

    fn with_entropy(
        identity: &VmessIdentity,
        command: Command,
        peer: &Destination,
        options: BodyOptions,
        timestamp: u64,
        entropy: [u8; 61],
    ) -> io::Result<Self> {
        if peer.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero VMess destination port",
            ));
        }
        let key: [u8; 16] = entropy[..16].try_into().unwrap();
        let iv: [u8; 16] = entropy[16..32].try_into().unwrap();
        let response_tag = entropy[32];
        let padding_length = entropy[33] as usize & 15;
        let mut plain = BytesMut::with_capacity(320);
        plain.extend_from_slice(&[1]);
        plain.extend_from_slice(&iv);
        plain.extend_from_slice(&key);
        plain.extend_from_slice(&[
            response_tag,
            options.wire(command),
            (padding_length as u8) << 4 | options.cipher.wire(),
            0,
            match command {
                Command::Tcp => 1,
                Command::Udp => 2,
                Command::Mux => 3,
            },
        ]);
        if command != Command::Mux {
            encode_port_first(peer, &mut plain)?;
        }
        plain.extend_from_slice(&entropy[34..34 + padding_length]);
        let checksum = plain.iter().fold(0x811c9dc5u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
        });
        plain.extend_from_slice(&checksum.to_be_bytes());

        let mut auth_id = [0; 16];
        auth_id[..8].copy_from_slice(&timestamp.to_be_bytes());
        auth_id[8..12].copy_from_slice(&entropy[49..53]);
        let checksum = crc32fast::hash(&auth_id[..12]);
        auth_id[12..].copy_from_slice(&checksum.to_be_bytes());
        let auth_key = kdf(&identity.0, &[b"AES Auth ID Encryption"]);
        let block = aes::Aes128::new_from_slice(&auth_key[..16]).expect("AES key size");
        block.encrypt_block((&mut auth_id).into());
        let nonce = &entropy[53..61];
        let mut length = (plain.len() as u16).to_be_bytes().to_vec();
        let mut payload = plain.to_vec();
        for (data, key_salt, iv_salt) in [
            (
                &mut length,
                b"VMess Header AEAD Key_Length".as_slice(),
                b"VMess Header AEAD Nonce_Length".as_slice(),
            ),
            (
                &mut payload,
                b"VMess Header AEAD Key".as_slice(),
                b"VMess Header AEAD Nonce".as_slice(),
            ),
        ] {
            let key = kdf(&identity.0, &[key_salt, &auth_id, nonce]);
            let iv = kdf(&identity.0, &[iv_salt, &auth_id, nonce]);
            seal(
                &aead_key(BodyCipher::Aes128Gcm, key[..16].try_into().unwrap()),
                iv[..12].try_into().unwrap(),
                &auth_id,
                data,
            )?;
        }
        let request = [&auth_id[..], &length, nonce, &payload].concat();
        Ok(Self {
            request,
            key,
            iv,
            response_key: Sha256::digest(key)[..16].try_into().unwrap(),
            response_iv: Sha256::digest(iv)[..16].try_into().unwrap(),
            response_tag,
            options,
            command,
        })
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn response_length(&self, wire: &[u8; 18]) -> io::Result<usize> {
        let mut data = *wire;
        let plain = self.open_response(
            b"AEAD Resp Header Len Key",
            b"AEAD Resp Header Len IV",
            &mut data,
        )?;
        let length = usize::from(u16::from_be_bytes(plain.try_into().map_err(|_| error())?));
        if !(4..=259).contains(&length) {
            return Err(error());
        }
        Ok(length + 16)
    }

    pub fn authenticate_response(&self, wire: &mut [u8]) -> io::Result<()> {
        if !(20..=275).contains(&wire.len()) {
            return Err(error());
        }
        let plain = self.open_response(b"AEAD Resp Header Key", b"AEAD Resp Header IV", wire)?;
        if plain[0] != self.response_tag || plain.len() != 4 + usize::from(plain[3]) {
            return Err(error());
        }
        // Authenticated server commands never change the configured cipher,
        // identity, upstream or destination. Legacy account changes are ignored.
        Ok(())
    }

    fn open_response<'a>(
        &self,
        key_salt: &[u8],
        iv_salt: &[u8],
        data: &'a mut [u8],
    ) -> io::Result<&'a mut [u8]> {
        let key = kdf(&self.response_key, &[key_salt]);
        let iv = kdf(&self.response_iv, &[iv_salt]);
        open(
            &aead_key(BodyCipher::Aes128Gcm, key[..16].try_into().unwrap()),
            iv[..12].try_into().unwrap(),
            &[],
            data,
        )
    }
}
