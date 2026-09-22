#![allow(dead_code, unused_imports)]
use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
};
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
};
mod ech;

#[derive(Debug)]
struct UnimplementedHybrid;
impl SupportedKxGroup for UnimplementedHybrid {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Err(rustls::Error::General(
            "sentinel, not a cryptographic implementation".into(),
        ))
    }
    fn supports_reality(&self) -> bool {
        true
    }
}
static HYBRID_SENTINEL: UnimplementedHybrid = UnimplementedHybrid;

fn reality_config(
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<ClientConfig, rustls::Error> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = groups;
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_reality(rustls::client::RealityClientConfig::new([7; 32], &[], [1, 2, 3]).unwrap())
        .map(|builder| builder.with_no_client_auth())
}

fn tls_pair() -> (ClientConnection, ServerConnection) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let mut client =
        ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
    for _ in 0..10 {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        if !buf.is_empty() {
            server.read_tls(&mut Cursor::new(buf)).unwrap();
            server.process_new_packets().unwrap();
        }
        let mut buf = Vec::new();
        server.write_tls(&mut buf).unwrap();
        if !buf.is_empty() {
            client.read_tls(&mut Cursor::new(buf)).unwrap();
            client.process_new_packets().unwrap();
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !server.wants_write()
            && !client.wants_write()
        {
            return (client, server);
        }
    }
    panic!("in-memory handshake did not complete");
}

fn extensions(hello: &[u8]) -> Vec<(u16, &[u8])> {
    assert_eq!(hello[0], 22);
    assert_eq!(hello[5], 1);
    let mut pos = 9 + 2 + 32;
    pos += 1 + usize::from(hello[pos]);
    let ciphers = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + ciphers;
    pos += 1 + usize::from(hello[pos]);
    let length = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let end = pos + length;
    let mut result = Vec::new();
    while pos < end {
        let kind = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let n = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        result.push((kind, &hello[pos + 4..pos + 4 + n]));
        pos += 4 + n;
    }
    result
}

// This signature is intentionally checked without constructing a fake TlsStream.
pub fn public_stream_parts<IO>(
    stream: tokio_rustls::client::TlsStream<IO>,
) -> (IO, ClientConnection) {
    stream.into_inner()
}

#[cfg(feature = "missing-session-hook")]
pub async fn compile_missing_session_hook(
    connector: &tokio_rustls::TlsConnector,
    stream: tokio::io::DuplexStream,
) {
    let _ = connector
        .connect_with_session_id_generator(
            "localhost".try_into().unwrap(),
            stream,
            Some(|_: &[u8]| [0u8; 32]),
            |_| {},
        )
        .await;
}

#[test]
fn reality_rejects_only_hybrid_group_despite_capability_flag() {
    let error = reality_config(vec![&HYBRID_SENTINEL]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not support REALITY X25519 key reuse")
    );
    println!("hybrid-only builder rejected: {error}");
}

#[test]
fn reality_ignores_preferred_hybrid_and_emits_classic_keyshare() {
    let config = reality_config(vec![
        &HYBRID_SENTINEL,
        rustls::crypto::ring::kx_group::X25519,
    ])
    .unwrap();
    let mut connection =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).unwrap();
    let extensions = extensions(&hello);
    let key_share = extensions.iter().find(|(kind, _)| *kind == 51).unwrap().1;
    assert_eq!(u16::from_be_bytes([key_share[0], key_share[1]]), 36);
    assert_eq!(u16::from_be_bytes([key_share[2], key_share[3]]), 29);
    assert_eq!(u16::from_be_bytes([key_share[4], key_share[5]]), 32);
    println!("REALITY key_share: one entry, group=0x001d, public_key_bytes=32; no 0x11ec share");
}

#[test]
fn public_reader_retains_unconsumed_application_plaintext() {
    let (mut client, mut server) = tls_pair();
    server.writer().write_all(b"marker-payload").unwrap();
    let mut encrypted = Vec::new();
    server.write_tls(&mut encrypted).unwrap();
    client.read_tls(&mut Cursor::new(encrypted)).unwrap();
    client.process_new_packets().unwrap();
    let mut marker = [0; 7];
    client.reader().read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"marker-");
    let mut remainder = [0; 7];
    client.reader().read_exact(&mut remainder).unwrap();
    assert_eq!(&remainder, b"payload");
}

#[test]
fn unrestricted_record_read_consumes_raw_tail_and_errors() {
    let (mut client, mut server) = tls_pair();
    server.writer().write_all(b"direct-marker").unwrap();
    let mut encrypted = Vec::new();
    server.write_tls(&mut encrypted).unwrap();
    // A syntactically framed, but non-outer-TLS raw record after the direct marker.
    let tail = [
        23, 3, 3, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    encrypted.extend_from_slice(&tail);
    let mut source = Cursor::new(encrypted);
    let read = client.read_tls(&mut source).unwrap();
    assert_eq!(read, source.get_ref().len());
    let err = client.process_new_packets().unwrap_err();
    assert_eq!(err, rustls::Error::DecryptError);
    println!("unrestricted input consumed direct tail, process_new_packets={err:?}");
}

#[test]
fn one_record_owned_input_preserves_raw_tail_without_private_access() {
    let (mut client, mut server) = tls_pair();
    server.writer().write_all(b"direct-marker").unwrap();
    let mut encrypted = Vec::new();
    server.write_tls(&mut encrypted).unwrap();
    let outer_record_len = encrypted.len();
    encrypted.extend_from_slice(b"raw-following-bytes");
    let mut source = Cursor::new(encrypted);
    client
        .read_tls(&mut (&mut source).take(outer_record_len as u64))
        .unwrap();
    client.process_new_packets().unwrap();
    let mut marker = [0; 13];
    client.reader().read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"direct-marker");
    let mut raw = Vec::new();
    source.read_to_end(&mut raw).unwrap();
    assert_eq!(raw, b"raw-following-bytes");
}
