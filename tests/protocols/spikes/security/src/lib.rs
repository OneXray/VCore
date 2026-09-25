#![allow(dead_code, unused_imports)]
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
};
mod ech;

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
