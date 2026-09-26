//! N7 prerequisite probes against the exact production TLS dependency revision.
//! Only bounded in-memory ClientHello capture: no peer, socket, or production
//! configuration is created. A passing boundary probe is not interoperability.
#![cfg(all(feature = "tls-fingerprint", feature = "outbound-vless"))]

use boring::ssl::{
    ClientFingerprint, ErrorCode, FingerprintConnector, RealityClientConfig, Ssl, SslConnector,
    SslMethod, SslStream,
};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};
use tokio::io::AsyncReadExt;

const X25519: u16 = 29;
const X25519_MLKEM768: u16 = 4588;
const HELLO_LIMIT: usize = 65_536;

#[derive(Default)]
struct Capture(Vec<u8>);

impl Read for Capture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for Capture {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > HELLO_LIMIT.saturating_sub(self.0.len()) {
            return Err(io::Error::other("ClientHello capture limit exceeded"));
        }
        self.0.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn client(reality: bool) -> Ssl {
    client_with_hybrid(reality, false)
}

fn client_with_hybrid(reality: bool, hybrid: bool) -> Ssl {
    let builder = SslConnector::builder(SslMethod::tls()).unwrap();
    let connector = FingerprintConnector::new(builder, ClientFingerprint::Chrome133).unwrap();
    let mut ssl = connector
        .configure(b"\x02h2")
        .unwrap()
        .into_ssl("n7-capability.invalid")
        .unwrap();
    if reality {
        // RFC 7748 public test vector. No real identity or secret is recorded.
        let public = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let config = RealityClientConfig::new(public, &[], [26, 7, 11]).unwrap();
        let config = if hybrid {
            config.require_x25519mlkem768()
        } else {
            config
        };
        ssl.set_reality_client(&config).unwrap();
    }
    ssl
}

fn capture(ssl: Ssl) -> (ErrorCode, Vec<u8>) {
    let mut stream = SslStream::new(ssl, Capture::default()).unwrap();
    let code = stream.connect().unwrap_err().code();
    (code, stream.get_ref().0.clone())
}

fn word(bytes: &[u8], at: usize) -> usize {
    u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()).into()
}

fn key_shares(records: &[u8]) -> Vec<(u16, usize)> {
    let mut hello = Vec::new();
    let mut at = 0;
    while at < records.len() {
        assert_eq!(records[at], 22, "expected handshake record");
        let size = word(records, at + 3);
        assert!(size <= 16_384);
        hello.extend_from_slice(&records[at + 5..at + 5 + size]);
        at += 5 + size;
    }
    assert_eq!(hello[0], 1, "expected ClientHello");
    assert_eq!(
        hello.len(),
        4 + u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize
    );
    let mut at = 39 + usize::from(hello[38]);
    at += 2 + word(&hello, at);
    at += 1 + usize::from(hello[at]);
    let end = at + 2 + word(&hello, at);
    assert_eq!(end, hello.len());
    at += 2;
    let mut shares = None;
    while at < end {
        let kind = word(&hello, at);
        let next = at + 4 + word(&hello, at + 2);
        assert!(next <= end);
        if kind == 51 {
            assert!(shares.is_none(), "duplicate key_share extension");
            assert_eq!(at + 6 + word(&hello, at + 4), next);
            let mut item = at + 6;
            let mut found = Vec::new();
            while item < next {
                let group = word(&hello, item) as u16;
                let size = word(&hello, item + 2);
                item += 4 + size;
                assert!(item <= next);
                // GREASE is not a negotiated cryptographic group.
                if group & 0x0f0f != 0x0a0a {
                    found.push((group, size));
                }
            }
            shares = Some(found);
        }
        at = next;
    }
    shares.expect("missing key_share extension")
}

#[test]
fn ordinary_chrome133_offers_a_real_hybrid_key_share() {
    let (code, wire) = capture(client(false));
    assert_eq!(code, ErrorCode::WANT_READ);
    let shares = key_shares(&wire);
    assert_eq!(shares, [(X25519_MLKEM768, 1216), (X25519, 32)]);
    println!("ordinary TLS: group/length={shares:?}; peer acceptance NOT RUN");
}

#[test]
fn current_classic_reality_removes_the_hybrid_share() {
    let (code, wire) = capture(client(true));
    assert_eq!(code, ErrorCode::WANT_READ);
    let shares = key_shares(&wire);
    assert_eq!(shares, [(X25519, 32)]);
    println!("classic REALITY: group/length={shares:?}; explicit hybrid remains opt-in");
}

#[test]
fn current_reality_rejects_public_key_share_override_before_io() {
    let mut ssl = client(true);
    ssl.set_curves_list("X25519MLKEM768:X25519").unwrap();
    let shares = [X25519_MLKEM768, X25519];
    // Public BoringSSL setter. The SSL lives throughout the call; the setter
    // copies the supplied group array. No private native state is accessed.
    unsafe {
        assert_eq!(
            boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len()),
            1
        );
    }
    let (code, wire) = capture(ssl);
    assert_eq!(code, ErrorCode::SSL);
    assert!(wire.is_empty());
    println!("REALITY + reintroduced hybrid share: native rejection, emitted bytes=0");
}

/// The original prerequisite failure remains in the N7 progress record.
/// Exercise the new opt-in API without weakening the classic default.
#[test]
fn n7_requires_hybrid_reality_in_the_actual_client_hello() {
    let (code, wire) = capture(client_with_hybrid(true, true));
    assert_eq!(code, ErrorCode::WANT_READ);
    assert!(
        key_shares(&wire).contains(&(X25519_MLKEM768, 1216)),
        "explicit hybrid REALITY must retain the required X25519MLKEM768 share"
    );
}

#[tokio::test]
async fn public_hybrid_reality_emits_required_shares_on_both_transport_legs() {
    use serde_json::json;
    use vcore::{
        config::{Config, ProxyProtocol},
        security::SecurityClient,
    };

    for profile in ["none", "chrome"] {
        let yaml = serde_json::to_vec(&json!({
            "socks-port": 1080,
            "proxies": [{
                "name": "edge", "type": "vless", "server": "example.invalid", "port": 443,
                "uuid": "07070707-0707-0707-0707-070707070707", "tls": true,
                "client-fingerprint": profile,
                "reality-opts": {
                    "public-key": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
                    "support-x25519mlkem768": true
                },
                "network": "xhttp",
                "xhttp-opts": {"mode": "stream-up", "download-settings": {}}
            }],
            "rules": ["MATCH,edge"]
        }))
        .unwrap();
        let config = Config::parse_yaml(&yaml).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            panic!()
        };
        for security in [&node.security, &node.download().unwrap().security] {
            let client = SecurityClient::from_security(security).unwrap();
            let (io, mut peer) = tokio::io::duplex(HELLO_LIMIT);
            let handshake = tokio::spawn(async move { client.connect(Box::new(io)).await });
            let mut header = [0u8; 5];
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                peer.read_exact(&mut header),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(header[0], 22);
            let size = word(&header, 3);
            assert!(size <= 16_384);
            let mut wire = header.to_vec();
            wire.resize(5 + size, 0);
            peer.read_exact(&mut wire[5..]).await.unwrap();
            let shares = key_shares(&wire);
            handshake.abort();
            assert!(matches!(handshake.await, Err(error) if error.is_cancelled()));
            let expected = if profile == "chrome" {
                vec![(X25519_MLKEM768, 1216), (X25519, 32)]
            } else {
                vec![(X25519_MLKEM768, 1216)]
            };
            assert_eq!(shares, expected, "public {profile} REALITY");
            assert_eq!(
                peer.read(&mut header).await.unwrap(),
                0,
                "cancel releases supplied IO"
            );
        }
    }
}
