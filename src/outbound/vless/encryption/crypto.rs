use boring::{
    aead::{AeadCtx, Algorithm},
    derive::Deriver,
    pkey::{Id, PKey, Private, Public},
    symm::{Cipher, Crypter, Mode},
};
use std::io;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) enum Suite {
    Aes,
    ChaCha,
}

impl Suite {
    pub(super) fn for_cpu() -> Self {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Self::Aes;
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            return Self::Aes;
        }
        Self::ChaCha
    }
}

pub(super) fn failure() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "VLESS Encryption authentication failed",
    )
}

pub(super) struct Aead {
    context: AeadCtx,
    nonce: [u8; 12],
}
impl Aead {
    pub(super) fn new(context: &[u8], material: &[u8], suite: Suite) -> io::Result<Self> {
        let key = Zeroizing::new(vcore_blake3_raw::derive_key(context, material));
        let algorithm = match suite {
            Suite::Aes => Algorithm::aes_256_gcm(),
            Suite::ChaCha => Algorithm::chacha20_poly1305(),
        };
        Ok(Self {
            context: AeadCtx::new_default_tag(&algorithm, key.as_ref()).map_err(|_| failure())?,
            nonce: [0; 12],
        })
    }
    pub(super) fn exhausted(&self) -> bool {
        self.nonce == [255; 12]
    }
    fn next_nonce(&mut self, explicit: Option<[u8; 12]>) -> [u8; 12] {
        if let Some(nonce) = explicit {
            return nonce;
        }
        for byte in self.nonce.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        self.nonce
    }
    pub(super) fn seal(
        &mut self,
        plain: &[u8],
        aad: &[u8],
        nonce: Option<[u8; 12]>,
    ) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce(nonce);
        let mut sealed = plain.to_vec();
        let mut tag = [0; 16];
        self.context
            .seal_in_place_mut(&nonce, &mut sealed, &mut tag, aad)
            .map_err(|_| failure())?;
        sealed.extend_from_slice(&tag);
        Ok(sealed)
    }
    pub(super) fn open(
        &mut self,
        sealed: &[u8],
        aad: &[u8],
        nonce: Option<[u8; 12]>,
    ) -> io::Result<Vec<u8>> {
        let size = sealed.len().checked_sub(16).ok_or_else(failure)?;
        let nonce = self.next_nonce(nonce);
        let mut plain = Zeroizing::new(sealed[..size].to_vec());
        self.context
            .open_in_place_mut(&nonce, &mut plain, &sealed[size..], aad)
            .map_err(|_| failure())?;
        Ok(std::mem::take(&mut *plain))
    }
}

pub(super) struct Ctr(Crypter);
impl Ctr {
    pub(super) fn new(material: &[u8], iv: &[u8; 16]) -> io::Result<Self> {
        let key = Zeroizing::new(blake3::derive_key("VLESS", material));
        Ok(Self(
            Crypter::new(Cipher::aes_256_ctr(), Mode::Encrypt, key.as_ref(), Some(iv))
                .map_err(|_| failure())?,
        ))
    }
    pub(super) fn apply(&mut self, data: &mut [u8]) -> io::Result<()> {
        let mut output = Zeroizing::new(vec![0; data.len() + 16]);
        let count = self.0.update(data, &mut output).map_err(|_| failure())?;
        if count != data.len() {
            return Err(failure());
        }
        data.copy_from_slice(&output[..count]);
        Ok(())
    }
}

pub(super) fn x_public(raw: &[u8]) -> io::Result<PKey<Public>> {
    if raw.len() != 32 {
        return Err(failure());
    }
    // RFC 8410 SubjectPublicKeyInfo, id-X25519 with absent parameters.
    let mut der = [0; 44];
    der[..12].copy_from_slice(&[0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0]);
    der[12..].copy_from_slice(raw);
    PKey::public_key_from_der(&der).map_err(|_| failure())
}

pub(super) fn x_generate() -> io::Result<(PKey<Private>, [u8; 32])> {
    let private = PKey::generate(Id::X25519).map_err(|_| failure())?;
    let mut public = [0; 32];
    if private
        .raw_public_key(&mut public)
        .map_err(|_| failure())?
        .len()
        != 32
    {
        return Err(failure());
    }
    Ok((private, public))
}

pub(super) fn x_shared(private: &PKey<Private>, raw: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let peer = x_public(raw)?;
    let mut derive = Deriver::new(private).map_err(|_| failure())?;
    derive.set_peer(&peer).map_err(|_| failure())?;
    let mut shared = Zeroizing::new([0; 32]);
    // Native EVP derives reject low-order/all-zero shared secrets.
    if derive.derive(shared.as_mut()).map_err(|_| failure())? != 32 {
        return Err(failure());
    }
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        let s = value.as_str().unwrap().as_bytes();
        s.chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../tests/protocols/encryption-crypto.json"
        ))
        .unwrap()
    }
    #[test]
    fn derived_aead_matches_independent_go_ciphertexts() {
        for v in vectors()["records"].as_array().unwrap() {
            let suite = if v["cipher"] == "aes256gcm" {
                Suite::Aes
            } else {
                Suite::ChaCha
            };
            let mut aead = Aead::new(&bytes(&v["context"]), &bytes(&v["key"]), suite).unwrap();
            assert_eq!(
                aead.seal(
                    &bytes(&v["plaintext"]),
                    &bytes(&v["aad"]),
                    Some(bytes(&v["nonce"]).try_into().unwrap())
                )
                .unwrap(),
                bytes(&v["ciphertext"])
            );
        }
    }
    #[test]
    fn opens_go_records_and_rejects_changes_to_aad_nonce_or_tag() {
        for v in vectors()["records"].as_array().unwrap() {
            let suite = if v["cipher"] == "aes256gcm" {
                Suite::Aes
            } else {
                Suite::ChaCha
            };
            let nonce: [u8; 12] = bytes(&v["nonce"]).try_into().unwrap();
            let make = || Aead::new(&bytes(&v["context"]), &bytes(&v["key"]), suite).unwrap();
            assert_eq!(
                make()
                    .open(&bytes(&v["ciphertext"]), &bytes(&v["aad"]), Some(nonce))
                    .unwrap(),
                bytes(&v["plaintext"])
            );
            let mut aad = bytes(&v["aad"]);
            aad[0] ^= 1;
            assert!(
                make()
                    .open(&bytes(&v["ciphertext"]), &aad, Some(nonce))
                    .is_err()
            );
            let mut wrong_nonce = nonce;
            wrong_nonce[0] ^= 1;
            assert!(
                make()
                    .open(
                        &bytes(&v["ciphertext"]),
                        &bytes(&v["aad"]),
                        Some(wrong_nonce)
                    )
                    .is_err()
            );
            let mut sealed = bytes(&v["ciphertext"]);
            *sealed.last_mut().unwrap() ^= 1;
            assert!(
                make()
                    .open(&sealed, &bytes(&v["aad"]), Some(nonce))
                    .is_err()
            );
        }
    }
    #[test]
    fn automatic_nonce_increments_before_encryption() {
        let fixtures = vectors();
        for records in fixtures["records"].as_array().unwrap().chunks_exact(3) {
            let first = &records[0];
            let suite = if first["cipher"] == "aes256gcm" {
                Suite::Aes
            } else {
                Suite::ChaCha
            };
            let mut aead =
                Aead::new(&bytes(&first["context"]), &bytes(&first["key"]), suite).unwrap();
            for v in &records[..2] {
                assert_eq!(
                    aead.seal(&bytes(&v["plaintext"]), &bytes(&v["aad"]), None)
                        .unwrap(),
                    bytes(&v["ciphertext"])
                );
            }
        }
    }
    #[test]
    fn ctr_matches_go_across_arbitrary_fragment_boundaries() {
        let v = vectors();
        for chunk in [1, 3, 16, 37] {
            let mut ctr = Ctr::new(
                &bytes(&v["ctr_key"]),
                &bytes(&v["ctr_context"]).try_into().unwrap(),
            )
            .unwrap();
            let mut input = bytes(&v["ctr_plaintext"]);
            for piece in input.chunks_mut(chunk) {
                ctr.apply(piece).unwrap();
            }
            assert_eq!(input, bytes(&v["ctr_ciphertext"]));
        }
    }
    #[test]
    fn x25519_matches_go_and_rejects_low_order_peers() {
        let v = vectors();
        let mut der = Zeroizing::new(vec![
            0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 4, 0x22, 4, 0x20,
        ]);
        der.extend_from_slice(&bytes(&v["x25519_private"]));
        let private = PKey::private_key_from_pkcs8(&der).unwrap();
        assert_eq!(
            x_shared(&private, &bytes(&v["x25519_peer"]))
                .unwrap()
                .as_ref(),
            bytes(&v["x25519_shared"])
        );
        let mut public = [0; 32];
        private.raw_public_key(&mut public).unwrap();
        assert_eq!(public.as_slice(), bytes(&v["x25519_public"]));
        for low in [vec![0; 32], {
            let mut k = vec![0; 32];
            k[0] = 1;
            k
        }] {
            assert!(x_shared(&private, &low).is_err());
        }
    }
    #[test]
    fn native_mlkem_decapsulates_go_and_rejects_invalid_encodings() {
        use boring::mlkem::{Algorithm as Kem, MlKemPrivateKey, MlKemPublicKey};
        let v = vectors();
        let key =
            MlKemPrivateKey::from_seed(Kem::MlKem768, &bytes(&v["mlkem_seed"]).try_into().unwrap())
                .unwrap();
        assert_eq!(
            key.decapsulate(&bytes(&v["mlkem_ciphertext"]))
                .unwrap()
                .as_slice(),
            bytes(&v["mlkem_shared"])
        );
        assert!(key.decapsulate(&[0; 1087]).is_err());
        assert!(MlKemPublicKey::from_slice(Kem::MlKem768, &[255; 1184]).is_err());
        let peer = MlKemPublicKey::from_slice(Kem::MlKem768, &bytes(&v["mlkem_public"])).unwrap();
        let (ciphertext, shared) = peer.encapsulate().unwrap();
        assert_eq!(key.decapsulate(&ciphertext).unwrap(), shared);
        let mut tampered = bytes(&v["mlkem_ciphertext"]);
        tampered[0] ^= 1;
        assert_ne!(
            key.decapsulate(&tampered).unwrap().as_slice(),
            bytes(&v["mlkem_shared"])
        );
    }
}
