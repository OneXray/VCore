use super::*;
use crate::config::AnyTlsCertificatePolicy;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::{
    RootCertStore, ServerConfig, SignatureAlgorithm, SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
};
use sha2::{Digest, Sha256};
use std::{sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::LazyConfigAcceptor;

struct Chain {
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn ca(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
}

fn chain(expired: bool) -> Chain {
    let root =
        CertifiedIssuer::self_signed(ca("fixture root"), KeyPair::generate().unwrap()).unwrap();
    let intermediate = CertifiedIssuer::signed_by(
        ca("fixture intermediate"),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["fixture.invalid".into()]).unwrap();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(if expired { 2021 } else { 2090 }, 1, 1);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&key, &intermediate).unwrap();
    Chain {
        certificates: vec![
            leaf.der().clone(),
            intermediate.der().clone(),
            root.der().clone(),
        ],
        key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    }
}

fn pin(chain: &Chain, index: usize) -> [u8; 32] {
    Sha256::digest(chain.certificates[index].as_ref()).into()
}

fn trusted(chain: &Chain) -> SecurityContext {
    let mut roots = RootCertStore::empty();
    roots.add(chain.certificates[2].clone()).unwrap();
    SecurityContext {
        provider: Arc::new(rustls::crypto::ring::default_provider()),
        tls_roots: Arc::new(roots),
    }
}

fn client(
    context: &SecurityContext,
    name: &str,
    policy: AnyTlsCertificatePolicy,
) -> StandardTlsClient {
    StandardTlsClient::for_anytls(context, name, &policy, 4, DEFAULT_TLS_BUFFER_LIMIT).unwrap()
}

#[derive(Debug)]
struct BrokenKey(Arc<dyn SigningKey>);
#[derive(Debug)]
struct BrokenSigner(Box<dyn Signer>);
impl SigningKey for BrokenKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(BrokenSigner(signer)) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}
impl Signer for BrokenSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;
        *signature.last_mut().unwrap() ^= 1;
        Ok(signature)
    }
    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

fn server(
    chain: &Chain,
    version: &'static rustls::SupportedProtocolVersion,
    broken_signature: bool,
) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut key =
        CertifiedKey::from_der(chain.certificates.clone(), chain.key.clone_key(), &provider)
            .unwrap();
    if broken_signature {
        key.key = Arc::new(BrokenKey(key.key));
    }
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key))),
    )
}

#[derive(Default, Debug)]
struct Seen {
    alpn: Vec<Vec<u8>>,
    name: Option<String>,
    resumed: bool,
}

async fn handshake(client: &StandardTlsClient, server: Arc<ServerConfig>) -> (bool, Seen) {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let observed = seen.clone();
    let server = async move {
        let start = LazyConfigAcceptor::new(Default::default(), server_io).await?;
        {
            let hello = start.client_hello();
            let mut seen = observed.lock().unwrap();
            seen.alpn = hello
                .alpn()
                .into_iter()
                .flatten()
                .map(<[u8]>::to_vec)
                .collect();
            seen.name = hello.server_name().map(str::to_owned);
        }
        let mut stream = start.into_stream(server).await?;
        observed.lock().unwrap().resumed =
            stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
        stream.write_all(&[42]).await?;
        stream.shutdown().await
    };
    let client = async {
        let mut stream = client.connect(Box::new(client_io)).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        assert_eq!(response, [42]);
        Ok::<_, io::Error>(())
    };
    let (result, _) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    (
        result.is_ok(),
        Arc::try_unwrap(seen).unwrap().into_inner().unwrap(),
    )
}

#[tokio::test]
async fn webpki_rejects_untrusted_wrong_name_and_expired_unless_explicitly_skipped() {
    for expired in [false, true] {
        let chain = chain(expired);
        let server = server(&chain, &TLS13, false);
        for (context, name, expected) in [
            (trusted(&chain), "fixture.invalid", !expired),
            (trusted(&chain), "wrong.invalid", false),
            (SecurityContext::new(), "fixture.invalid", false),
        ] {
            assert_eq!(
                handshake(&client(&context, name, Default::default()), server.clone())
                    .await
                    .0,
                expected
            );
            let insecure = AnyTlsCertificatePolicy {
                skip_cert_verify: true,
                ..Default::default()
            };
            assert!(
                handshake(&client(&context, name, insecure), server.clone())
                    .await
                    .0
            );
        }
    }
}

#[tokio::test]
async fn leaf_pin_is_trust_but_nonleaf_pin_checks_chain_name_and_expiry() {
    for expired in [false, true] {
        let chain = chain(expired);
        let server = server(&chain, &TLS13, false);
        for index in 0..3 {
            for name in ["fixture.invalid", "wrong.invalid"] {
                for skip in [false, true] {
                    let policy = AnyTlsCertificatePolicy {
                        fingerprint: Some(pin(&chain, index)),
                        skip_cert_verify: skip,
                        ..Default::default()
                    };
                    let expected = index == 0 || (!expired && name == "fixture.invalid");
                    assert_eq!(
                        handshake(
                            &client(&SecurityContext::new(), name, policy),
                            server.clone()
                        )
                        .await
                        .0,
                        expected,
                        "index={index}, skip={skip}, expired={expired}"
                    );
                }
            }
        }
        let policy = AnyTlsCertificatePolicy {
            fingerprint: Some([0; 32]),
            skip_cert_verify: true,
            ..Default::default()
        };
        assert!(
            !handshake(
                &client(&SecurityContext::new(), "fixture.invalid", policy),
                server.clone()
            )
            .await
            .0
        );
        // A pinned unrelated certificate appended to the chain cannot bless
        // a leaf it did not issue, even with skip-cert-verify also enabled.
        let other = chain_for_unrelated();
        let mut unrelated = Chain {
            certificates: chain.certificates.clone(),
            key: chain.key.clone_key(),
        };
        unrelated.certificates.push(other.certificates[2].clone());
        let policy = AnyTlsCertificatePolicy {
            fingerprint: Some(pin(&other, 2)),
            skip_cert_verify: true,
            ..Default::default()
        };
        assert!(
            !handshake(
                &client(&SecurityContext::new(), "fixture.invalid", policy),
                super_server(&unrelated)
            )
            .await
            .0
        );
    }
}

// Separate names avoid shadowing helpers in the table-driven test above.
fn chain_for_unrelated() -> Chain {
    chain(false)
}
fn super_server(chain: &Chain) -> Arc<ServerConfig> {
    server(chain, &TLS13, false)
}

#[tokio::test]
async fn ticket_storage_obeys_exact_node_budget_and_consumes_each_ticket_once() {
    use crate::security::resumption::NodeSessionStore;
    use rustls::client::ClientSessionStore;
    let chain = chain(false);
    let context = trusted(&chain);
    let name = ServerName::try_from("fixture.invalid").unwrap().to_owned();
    for version in [&TLS12, &TLS13] {
        for capacity in [0, 1, 4] {
            let store = Arc::new(NodeSessionStore::new(name.clone(), capacity));
            let mut client = client(&context, "fixture.invalid", Default::default());
            let mut config = client.connector.config().as_ref().clone();
            config.resumption = Resumption::store(store.clone());
            client.connector = TlsConnector::from(Arc::new(config));
            let mut server = server(&chain, version, false);
            Arc::get_mut(&mut server).unwrap().send_tls13_tickets = 8;
            assert!(handshake(&client, server.clone()).await.0);
            let expected = if version == &TLS12 {
                usize::from(capacity > 0)
            } else {
                capacity
            };
            assert_eq!(store.stored_sessions(), expected);
            let wrong = ServerName::try_from("wrong.invalid").unwrap();
            assert!(store.take_tls13_ticket(&wrong).is_none());
            assert!(store.tls12_session(&wrong).is_none());
            if version == &TLS13 {
                for _ in 0..expected {
                    assert!(store.take_tls13_ticket(&name).is_some());
                }
                assert!(store.take_tls13_ticket(&name).is_none());
            } else {
                assert_eq!(
                    handshake(&client, server.clone()).await.1.resumed,
                    capacity > 0
                );
                store.remove_tls12_session(&name);
            }
            assert_eq!(store.stored_sessions(), 0);
        }
    }
}

#[tokio::test]
async fn every_certificate_policy_verifies_tls12_and_tls13_handshake_signatures() {
    let chain = chain(false);
    for version in [&TLS12, &TLS13] {
        for fingerprint in [None, Some(pin(&chain, 0)), Some(pin(&chain, 1))] {
            let policy = AnyTlsCertificatePolicy {
                skip_cert_verify: true,
                fingerprint,
                ..Default::default()
            };
            let client = client(&SecurityContext::new(), "fixture.invalid", policy);
            assert!(handshake(&client, server(&chain, version, false)).await.0);
            assert!(!handshake(&client, server(&chain, version, true)).await.0);
        }
    }
}

#[tokio::test]
async fn vless_keeps_webpki_tls13_and_required_h2_after_anytls_connections() {
    let chain = chain(false);
    let mut endpoint = server(&chain, &TLS13, false);
    Arc::get_mut(&mut endpoint).unwrap().alpn_protocols = vec![b"h2".to_vec()];
    let insecure = client(
        &SecurityContext::new(),
        "fixture.invalid",
        AnyTlsCertificatePolicy {
            skip_cert_verify: true,
            alpn: vec![b"h2".to_vec()],
            ..Default::default()
        },
    );
    assert!(handshake(&insecure, endpoint.clone()).await.0);
    for (context, expected) in [(SecurityContext::new(), false), (trusted(&chain), true)] {
        let vless = StandardTlsClient::new(
            &context,
            "fixture.invalid",
            StandardTlsProfile::VlessXhttp,
            4,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
        .unwrap();
        let (ok, seen) = handshake(&vless, endpoint.clone()).await;
        assert_eq!(ok, expected);
        assert_eq!(seen.alpn, [b"h2".to_vec()]);
        assert!(!seen.resumed);
        if expected {
            assert!(handshake(&vless, endpoint.clone()).await.1.resumed);
        }
        assert!(!handshake(&vless, server(&chain, &TLS13, false)).await.0);
        let mut tls12 = server(&chain, &TLS12, false);
        Arc::get_mut(&mut tls12).unwrap().alpn_protocols = vec![b"h2".to_vec()];
        assert!(!handshake(&vless, tls12).await.0);
    }
}

#[tokio::test]
async fn alpn_and_tls_resumption_are_isolated_between_node_policies() {
    let chain = chain(false);
    let server = server(&chain, &TLS13, false);
    let context = trusted(&chain);
    let alpn = vec![b"custom".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];
    let policy = AnyTlsCertificatePolicy {
        alpn: alpn.clone(),
        fingerprint: Some(pin(&chain, 2)),
        ..Default::default()
    };
    let first = client(&context, "fixture.invalid", policy.clone());
    let (ok, seen) = handshake(&first, server.clone()).await;
    assert!(ok);
    assert!(!seen.resumed);
    assert_eq!(seen.alpn, alpn);
    assert_eq!(seen.name.as_deref(), Some("fixture.invalid"));
    let (ok, seen) = handshake(&first, server.clone()).await;
    assert!(ok);
    assert!(seen.resumed);
    let (ok, seen) = handshake(
        &client(&context, "fixture.invalid", Default::default()),
        server.clone(),
    )
    .await;
    assert!(ok);
    assert!(!seen.resumed);
    assert!(seen.alpn.is_empty());
    assert!(
        !handshake(
            &client(&context, "wrong.invalid", policy.clone()),
            server.clone()
        )
        .await
        .0
    );
    let wrong = AnyTlsCertificatePolicy {
        fingerprint: Some([0; 32]),
        skip_cert_verify: true,
        ..policy
    };
    assert!(
        !handshake(&client(&context, "fixture.invalid", wrong), server.clone())
            .await
            .0
    );
    assert!(
        !handshake(
            &client(
                &SecurityContext::new(),
                "fixture.invalid",
                Default::default()
            ),
            server
        )
        .await
        .0
    );
}
