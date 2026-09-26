use super::{
    cache::{Cache, Ticket},
    config::{Appearance, Settings},
    crypto::{self, Aead, Ctr, Suite, failure},
    records::Records,
};
use crate::dispatch::BoxStream;
use crate::security::vision::{SpliceControl, SpliceStats};
use boring::{
    mlkem::{Algorithm, MlKemPrivateKey, MlKemPublicKey},
    pkey::{PKey, Private},
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Instant, sleep, timeout_at},
};
use zeroize::Zeroizing;

/// One owned flight. The initial bytes can be consumed exactly once by an
/// outer transport's early-data interface; finish sends only the remainder.
pub(crate) struct Handshake {
    hello: Vec<u8>,
    fragments: Vec<usize>,
    gaps: Vec<Duration>,
    iv: [u8; 16],
    nfs_key: Zeroizing<[u8; 32]>,
    exchange: Exchange,
    suite: Suite,
    random_headers: bool,
    cache: Arc<Cache>,
    cache_enabled: bool,
    vision: Option<(SpliceControl, Arc<SpliceStats>)>,
}

enum Exchange {
    Full {
        nfs: Aead,
        public: Vec<u8>,
        kem: MlKemPrivateKey,
        x: PKey<Private>,
    },
    Resume {
        ticket: Arc<Ticket>,
        context: Vec<u8>,
    },
}

impl Handshake {
    pub(super) fn start(settings: &Settings, cache: Arc<Cache>, suite: Suite) -> io::Result<Self> {
        let ticket = cache.lookup()?.filter(|_| settings.resume);
        let iv = rand::random::<[u8; 16]>();
        let mut hello = iv.to_vec();
        let mut last_ctr: Option<Ctr> = None;
        let mut nfs_key = Zeroizing::new([0; 32]);
        for (index, key) in settings.keys.iter().enumerate() {
            let mut relay = if key.len() == 32 {
                let (private, public) = crypto::x_generate()?;
                nfs_key = crypto::x_shared(&private, key)?;
                public.to_vec()
            } else {
                let peer =
                    MlKemPublicKey::from_slice(Algorithm::MlKem768, key).map_err(|_| failure())?;
                let (ciphertext, shared) = peer.encapsulate().map_err(|_| failure())?;
                nfs_key = Zeroizing::new(shared);
                ciphertext
            };
            if settings.appearance != Appearance::Native {
                Ctr::new(key, &iv)?.apply(&mut relay)?;
            }
            if let Some(previous) = last_ctr.as_mut() {
                previous.apply(&mut relay[..32])?;
            }
            hello.extend_from_slice(&relay);
            if let Some(next) = settings.keys.get(index + 1) {
                let mut next_hash = *blake3::hash(next).as_bytes();
                let mut ctr = Ctr::new(nfs_key.as_ref(), &iv)?;
                ctr.apply(&mut next_hash)?;
                hello.extend_from_slice(&next_hash);
                last_ctr = Some(ctr);
            }
        }
        let mut nfs = Aead::new(&iv, nfs_key.as_ref(), suite)?;
        if let Some(ticket) = ticket {
            hello.extend_from_slice(&nfs.seal(&32u16.to_be_bytes(), &[], None)?);
            let context = nfs.seal(ticket.bytes.as_ref(), &[], None)?;
            hello.extend_from_slice(&context);
            return Ok(Self {
                fragments: vec![hello.len()],
                hello,
                gaps: Vec::new(),
                iv,
                nfs_key,
                exchange: Exchange::Resume { ticket, context },
                suite,
                random_headers: settings.appearance == Appearance::Random,
                cache,
                cache_enabled: true,
                vision: None,
            });
        }
        let (kem_public, kem) =
            MlKemPrivateKey::generate(Algorithm::MlKem768).map_err(|_| failure())?;
        let (x, x_public) = crypto::x_generate()?;
        let mut public = kem_public.as_bytes().to_vec();
        public.extend_from_slice(&x_public);
        hello.extend_from_slice(&nfs.seal(&1232u16.to_be_bytes(), &[], None)?);
        hello.extend_from_slice(&nfs.seal(&public, &[], None)?);
        let (mut fragments, gaps) = settings.padding();
        let padding_size: usize = fragments.iter().sum();
        fragments[0] += hello.len();
        hello.extend_from_slice(&nfs.seal(
            &((padding_size - 18) as u16).to_be_bytes(),
            &[],
            None,
        )?);
        hello.extend_from_slice(&nfs.seal(&vec![0; padding_size - 34], &[], None)?);
        Ok(Self {
            hello,
            fragments,
            gaps,
            iv,
            nfs_key,
            exchange: Exchange::Full {
                nfs,
                public,
                kem,
                x,
            },
            suite,
            random_headers: settings.appearance == Appearance::Random,
            cache,
            cache_enabled: settings.resume,
            vision: None,
        })
    }

    pub(crate) fn with_vision(mut self, vision: Option<(SpliceControl, Arc<SpliceStats>)>) -> Self {
        self.vision = vision;
        self
    }

    pub(crate) fn prefix(&self) -> &[u8] {
        &self.hello[..self.fragments[0]]
    }

    pub(crate) async fn finish(
        self,
        raw: BoxStream,
        prefix_sent: bool,
        deadline: Instant,
    ) -> io::Result<BoxStream> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VLESS Encryption establishment timed out",
            ));
        }
        let cancellation = self.cache.cancellation.clone();
        let mut raw: BoxStream = Box::new(crate::outbound::owned_stream::OwnedStream::new(
            raw,
            cancellation.child_token(),
        ));
        let operation = async move {
            if let Exchange::Resume { ticket, context } = &self.exchange {
                let mut united = Zeroizing::new([0; 96]);
                united[..64].copy_from_slice(ticket.pfs.as_ref());
                united[64..].copy_from_slice(self.nfs_key.as_ref());
                let tx = Aead::new(context, united.as_ref(), self.suite)?;
                let tx_ctr = self
                    .random_headers
                    .then(|| Ctr::new(united.as_ref(), &self.iv))
                    .transpose()?;
                let prefix = if prefix_sent {
                    Vec::new()
                } else {
                    self.prefix().to_vec()
                };
                return Ok(Box::new(
                    Records::resumed(
                        raw,
                        united,
                        self.suite,
                        tx,
                        tx_ctr,
                        self.random_headers,
                        prefix,
                        self.cache.clone(),
                        ticket.clone(),
                    )
                    .with_vision(self.vision),
                ) as BoxStream);
            }
            let mut offset = 0;
            for (index, length) in self.fragments.iter().copied().enumerate() {
                if length != 0 && !(index == 0 && prefix_sent) {
                    raw.write_all(&self.hello[offset..offset + length]).await?;
                    raw.flush().await?;
                }
                offset += length;
                if let Some(gap) = self.gaps.get(index).filter(|gap| !gap.is_zero()) {
                    sleep(*gap).await;
                }
            }
            let mut server = [0; 1136];
            raw.read_exact(&mut server).await?;
            let Exchange::Full {
                mut nfs,
                public: client_public,
                kem: private_kem,
                x: private_x,
            } = self.exchange
            else {
                unreachable!()
            };
            let public = nfs.open(&server, &[], Some([255; 12]))?;
            let kem = Zeroizing::new(
                private_kem
                    .decapsulate(&public[..1088])
                    .map_err(|_| failure())?,
            );
            let x = crypto::x_shared(&private_x, &public[1088..])?;
            let mut united = Zeroizing::new([0; 96]);
            united[..32].copy_from_slice(kem.as_ref());
            united[32..64].copy_from_slice(x.as_ref());
            united[64..].copy_from_slice(self.nfs_key.as_ref());
            let tx = Aead::new(&client_public, united.as_ref(), self.suite)?;
            let mut rx = Aead::new(&public, united.as_ref(), self.suite)?;
            let mut ticket = [0; 32];
            raw.read_exact(&mut ticket).await?;
            let ticket = Zeroizing::new(rx.open(&ticket, &[], None)?);
            let mut length = [0; 18];
            raw.read_exact(&mut length).await?;
            let size = rx.open(&length, &[], None)?;
            let padding_size = usize::from(u16::from_be_bytes([size[0], size[1]]));
            if padding_size < 16 {
                return Err(failure());
            }
            let seconds = u16::from_be_bytes([ticket[0], ticket[1]]);
            let cached = if self.cache_enabled && seconds != 0 {
                let mut pfs = Zeroizing::new([0; 64]);
                pfs.copy_from_slice(&united[..64]);
                let cached = Arc::new(Ticket {
                    pfs,
                    bytes: Zeroizing::new(ticket.as_slice().try_into().map_err(|_| failure())?),
                    expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
                });
                self.cache.publish(cached.clone())?;
                Some(cached)
            } else {
                None
            };
            let (tx_ctr, rx_ctr) = if self.random_headers {
                let server_iv: &[u8; 16] = ticket.as_slice().try_into().map_err(|_| failure())?;
                (
                    Some(Ctr::new(united.as_ref(), &self.iv)?),
                    Some(Ctr::new(united.as_ref(), server_iv)?),
                )
            } else {
                (None, None)
            };
            Ok(Box::new(
                Records::new(
                    raw,
                    united,
                    self.suite,
                    tx,
                    rx,
                    tx_ctr,
                    rx_ctr,
                    padding_size,
                    self.cache,
                    cached,
                )
                .with_vision(self.vision),
            ) as BoxStream)
        };
        timeout_at(deadline, async {
            tokio::select! { biased;
                _ = cancellation.cancelled() => Err(super::cache::closed()),
                result = operation => result,
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "VLESS Encryption establishment timed out",
            )
        })?
    }
}
