//! Dependency gate only: a published native hook is not a ShadowTLS transport.
//! No socket, peer, YAML capability, or runtime is created by this test.
#![cfg(all(feature = "outbound-vless", feature = "tls-fingerprint"))]

use boring::{
    hash::hmac_sha1,
    ssl::{ErrorCode, SslConnector, SslMethod, SslStream, SslVersion},
};
use std::io::{self, Read, Write};

#[derive(Default)]
struct Capture(Vec<u8>);
impl Read for Capture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}
impl Write for Capture {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > 65_536usize.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn published_shadow_hook_authenticates_the_actual_hello_without_retry_resealing() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        builder.set_max_proto_version(Some(version)).unwrap();
        let mut config = builder.build().configure().unwrap();
        let password = b"synthetic-dependency-gate-password";
        config.set_shadow_tls_v3_client(password).unwrap();
        let ssl = config.into_ssl("shadow-capability.invalid").unwrap();
        let mut stream = SslStream::new(ssl, Capture::default()).unwrap();
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        let wire = stream.get_ref().0.clone();
        assert_eq!(wire[0], 22);
        let size = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let mut hello = wire[5..5 + size].to_vec();
        assert_eq!(hello[0], 1);
        assert_eq!(hello[38], 32);
        let mac: [u8; 4] = hello[67..71].try_into().unwrap();
        hello[67..71].fill(0);
        assert_eq!(mac, hmac_sha1(password, &hello).unwrap()[..4]);
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        assert_eq!(stream.get_ref().0, wire);
    }
}
