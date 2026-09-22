use hpke::{Deserializable, Kem as _, Serializable};
use rand::SeedableRng;
use rustls::Error;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::{
    enums::{HpkeAead, HpkeKdf, HpkeKem},
    handshake::HpkeSymmetricCipherSuite,
};
type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm128;
type Sender = hpke::aead::AeadCtxS<Aead, Kdf, Kem>;
type Receiver = hpke::aead::AeadCtxR<Aead, Kdf, Kem>;
#[derive(Debug)]
struct Adapter;
static ADAPTER: Adapter = Adapter;
struct SendContext(Sender);
struct RecvContext(Receiver);
impl std::fmt::Debug for SendContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE send context")
    }
}
impl std::fmt::Debug for RecvContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE receive context")
    }
}
fn err(_: hpke::HpkeError) -> Error {
    Error::General("HPKE operation failed".into())
}
impl HpkeSealer for SendContext {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(plaintext, aad).map_err(err)
    }
}
impl HpkeOpener for RecvContext {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(ciphertext, aad).map_err(err)
    }
}
impl Hpke for Adapter {
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            },
        }
    }
    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (sk, pk) = Kem::gen_keypair(&mut rand::rngs::StdRng::from_os_rng());
        Ok((
            HpkePublicKey(pk.to_bytes().to_vec()),
            sk.to_bytes().to_vec().into(),
        ))
    }
    fn setup_sealer(
        &self,
        info: &[u8],
        key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&key.0).map_err(err)?;
        let (enc, ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &hpke::OpModeS::Base,
            &pk,
            info,
            &mut rand::rngs::StdRng::from_os_rng(),
        )
        .map_err(err)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(SendContext(ctx)),
        ))
    }
    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(key.secret_bytes()).map_err(err)?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc.0).map_err(err)?;
        let ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&hpke::OpModeR::Base, &sk, &enc, info)
            .map_err(err)?;
        Ok(Box::new(RecvContext(ctx)))
    }
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut ctx) = self.setup_sealer(info, key)?;
        Ok((enc, ctx.seal(aad, plaintext)?))
    }
    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.setup_opener(enc, info, key)?.open(aad, ciphertext)
    }
}
fn ech_list(key: &HpkePublicKey) -> Vec<u8> {
    let mut content = vec![7, 0, 32, 0, 32]; // config_id, X25519 KEM, public-key length
    content.extend_from_slice(&key.0);
    content.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 14]); // AES128/HKDF256, max_name_length, name length
    content.extend_from_slice(b"public.invalid");
    content.extend_from_slice(&[0, 0]); // no config extensions
    let mut list = Vec::new();
    list.extend_from_slice(&((content.len() + 4) as u16).to_be_bytes());
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(content.len() as u16).to_be_bytes());
    list.extend_from_slice(&content);
    list
}
#[test]
fn hpke_public_trait_roundtrip_and_auth_failure() {
    let (pk, sk) = ADAPTER.generate_key_pair().unwrap();
    let (enc, cipher) = ADAPTER
        .seal(b"test info", b"aad", b"synthetic message", &pk)
        .unwrap();
    assert_eq!(
        ADAPTER
            .open(&enc, b"test info", b"aad", &cipher, &sk)
            .unwrap(),
        b"synthetic message"
    );
    assert!(
        ADAPTER
            .open(&enc, b"test info", b"wrong aad", &cipher, &sk)
            .is_err()
    );
    let (enc, mut sender) = ADAPTER.setup_sealer(b"stateful", &pk).unwrap();
    let mut receiver = ADAPTER.setup_opener(&enc, b"stateful", &sk).unwrap();
    for message in [b"one".as_slice(), b"two"] {
        let cipher = sender.seal(b"aad", message).unwrap();
        assert_eq!(receiver.open(b"aad", &cipher).unwrap(), message);
    }
}
#[test]
fn ring_client_emits_ech_with_external_rust_hpke() {
    let (pk, _) = ADAPTER.generate_key_pair().unwrap();
    let list = ech_list(&pk);
    let ech = rustls::client::EchConfig::new(list.into(), &[&ADAPTER]).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_ech(ech.into())
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        "private.invalid".try_into().unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    assert!(
        super::extensions(&hello)
            .iter()
            .any(|(kind, data)| *kind == 0xfe0d && !data.is_empty())
    );
    assert!(
        !hello
            .windows(b"private.invalid".len())
            .any(|w| w == b"private.invalid")
    );
    assert_eq!(client.ech_status(), rustls::client::EchStatus::Offered);
    println!(
        "ring TLS emitted ECH 0xfe0d through external hpke::Hpke implementation; status=Offered, not Accepted"
    );
}
