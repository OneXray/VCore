//! Certificate policy is per AnyTLS node. Handshake signatures are mandatory
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

use super::SecurityContext;
use crate::config::AnyTlsCertificatePolicy;

#[derive(Debug)]
pub(super) struct AnyTlsVerifier {
    policy: AnyTlsCertificatePolicy,
    provider: Arc<CryptoProvider>,
    default: Arc<WebPkiServerVerifier>,
}

impl AnyTlsVerifier {
    pub(super) fn new(
        context: &SecurityContext,
        policy: AnyTlsCertificatePolicy,
    ) -> io::Result<Self> {
        let default = WebPkiServerVerifier::builder_with_provider(
            context.tls_roots.clone(),
            context.provider.clone(),
        )
        .build()
        .map_err(|_| io::Error::other("failed to construct AnyTLS certificate verifier"))?;
        Ok(Self {
            policy,
            provider: context.provider.clone(),
            default,
        })
    }
}

impl ServerCertVerifier for AnyTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
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
        if self.policy.skip_cert_verify {
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
