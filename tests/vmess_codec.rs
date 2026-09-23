#![cfg(feature = "outbound-vmess")]

use vcore::{
    outbound::vmess::{
        BodyCipher, BodyOptions, ClientHandshake, Command, VmessIdentity, VmessStream,
    },
    session::Destination,
};

#[test]
fn vmess_aead_requests_are_fresh_bounded_and_redacted() {
    let identity = VmessIdentity::new(uuid::Uuid::from_bytes([7; 16]));
    let target = Destination::domain("fixture.invalid", 443).unwrap();
    let options = BodyOptions::new(BodyCipher::None, false, false).unwrap();
    let first = ClientHandshake::new(&identity, Command::Tcp, &target, options).unwrap();
    let second = ClientHandshake::new(&identity, Command::Tcp, &target, options).unwrap();
    assert_ne!(first.request(), second.request());
    assert!((99..=384).contains(&first.request().len()));
    assert!(!format!("{identity:?}").contains("07070707"));
    assert!(!format!("{first:?}").contains("fixture.invalid"));
    assert!(first.response_length(&[0; 18]).is_err());
    assert!(BodyOptions::new(BodyCipher::None, true, false).is_err());
    assert!(BodyOptions::new(BodyCipher::None, false, true).is_err());
}

#[tokio::test]
async fn vmess_response_authentication_cannot_be_skipped_by_none_cipher() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let identity = VmessIdentity::new(uuid::Uuid::from_bytes([7; 16]));
    let target = Destination::domain("fixture.invalid", 443).unwrap();
    let handshake = ClientHandshake::new(
        &identity,
        Command::Tcp,
        &target,
        BodyOptions::new(BodyCipher::None, false, false).unwrap(),
    )
    .unwrap();
    let (client, mut peer) = tokio::io::duplex(1024);
    let mut stream = VmessStream::new(
        Box::new(client),
        handshake,
        tokio::time::Instant::now() + std::time::Duration::from_secs(1),
    );
    peer.write_all(&[0; 18]).await.unwrap();
    let mut data = [0; 1];
    assert_eq!(
        stream.read(&mut data).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(stream.write_all(b"after-failure").await.is_err());
}
