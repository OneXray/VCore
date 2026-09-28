//! Certificate policy is per immutable TLS client. Handshake signatures are mandatory
//! even when a pin replaces WebPKI trust or chain verification is disabled.
use std::{io, sync::Arc};

use rustls::{
    CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};

use super::{SecurityContext, tls::TlsCertificatePolicy};

pub(super) struct CertificateVerifier {
    policy: TlsCertificatePolicy,
    verification_name: Option<ServerName<'static>>,
    provider: Arc<CryptoProvider>,
    default: Arc<WebPkiServerVerifier>,
}

impl std::fmt::Debug for CertificateVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateVerifier")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl CertificateVerifier {
    pub(super) fn new(context: &SecurityContext, policy: TlsCertificatePolicy) -> io::Result<Self> {
        let verification_name = policy
            .verification_name
            .clone()
            .map(ServerName::try_from)
            .transpose()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS verification name")
            })?;
        let default = WebPkiServerVerifier::builder_with_provider(
            context.tls_roots.clone(),
            context.provider.clone(),
        )
        .build()
        .map_err(|_| io::Error::other("failed to construct certificate verifier"))?;
        Ok(Self {
            policy,
            verification_name,
            provider: context.provider.clone(),
            default,
        })
    }
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let server_name = self.verification_name.as_ref().unwrap_or(server_name);
        if let Some(pin) = self.policy.fingerprint {
            if Sha256::digest(end_entity.as_ref()).as_slice() == pin {
                // Like mihomo, an exact leaf pin is the trust decision. The
                // TLS signature still proves possession of this leaf's key.
                return Ok(ServerCertVerified::assertion());
            }
            for (index, certificate) in intermediates.iter().enumerate() {
                if Sha256::digest(certificate.as_ref()).as_slice() != pin {
                    continue;
                }
                let mut roots = RootCertStore::empty();
                roots
                    .add(certificate.clone())
                    .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
                let verifier = WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    self.provider.clone(),
                )
                .build()
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
                return verifier.verify_server_cert(
                    end_entity,
                    &intermediates[..index],
                    server_name,
                    ocsp,
                    now,
                );
            }
            // Explicit skip-cert-verify never overrides a configured pin.
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Mihomo's explicit name verifier, like pin verification, takes
        // precedence over skip-cert-verify. It never changes the SNI.
        if self.policy.skip_cert_verify && self.verification_name.is_none() {
            return Ok(ServerCertVerified::assertion());
        }
        self.default
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
