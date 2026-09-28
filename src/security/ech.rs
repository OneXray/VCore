//! Adapter for official Rust HPKE through rustls's public provider seam. The
//! wire enum paths are publicly exported but internal to rustls: keep them here.
use hpke::{Deserializable, Kem as _, Serializable, aead::Aead};
use rand::SeedableRng;
use rustls::internal::msgs::{
    enums::{HpkeAead, HpkeKdf, HpkeKem},
    handshake::HpkeSymmetricCipherSuite,
};
use rustls::{
    Error,
    crypto::hpke::{
        EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
    },
};
use std::marker::PhantomData;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;

static AES128: Adapter<hpke::aead::AesGcm128> = Adapter(PhantomData);
static AES256: Adapter<hpke::aead::AesGcm256> = Adapter(PhantomData);
static CHACHA: Adapter<hpke::aead::ChaCha20Poly1305> = Adapter(PhantomData);
pub(super) static SUITES: &[&dyn Hpke] = &[&AES128, &AES256, &CHACHA];

struct Adapter<A>(PhantomData<A>);
struct Sender<A: Aead>(hpke::aead::AeadCtxS<A, Kdf, Kem>);
struct Receiver<A: Aead>(hpke::aead::AeadCtxR<A, Kdf, Kem>);
impl<A> std::fmt::Debug for Adapter<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE adapter")
    }
}
impl<A: Aead> std::fmt::Debug for Sender<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE sender")
    }
}
impl<A: Aead> std::fmt::Debug for Receiver<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE receiver")
    }
}
fn error(_: hpke::HpkeError) -> Error {
    Error::General("HPKE operation failed".into())
}
fn rng() -> Result<rand::rngs::StdRng, Error> {
    rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|_| Error::General("HPKE randomness unavailable".into()))
}
impl<A: Aead + Send + Sync + 'static> HpkeSealer for Sender<A> {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(plaintext, aad).map_err(error)
    }
}
impl<A: Aead + Send + Sync + 'static> HpkeOpener for Receiver<A> {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(ciphertext, aad).map_err(error)
    }
}
impl<A: Aead + Send + Sync + 'static> Hpke for Adapter<A> {
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::from(A::AEAD_ID),
            },
        }
    }
    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (sk, pk) = Kem::gen_keypair_with_rng(&mut rng()?);
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
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&key.0).map_err(error)?;
        let (enc, ctx) = hpke::setup_sender_with_rng::<A, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &pk,
            info,
            &mut rng()?,
        )
        .map_err(error)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(Sender(ctx)),
        ))
    }
    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(key.secret_bytes()).map_err(error)?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc.0).map_err(error)?;
        let ctx = hpke::setup_receiver::<A, Kdf, Kem>(&hpke::OpModeR::Base, &sk, &enc, info)
            .map_err(error)?;
        Ok(Box::new(Receiver(ctx)))
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
