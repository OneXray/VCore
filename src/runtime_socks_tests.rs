use super::*;
use crate::dialer::SystemResolver;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

fn yaml(port: u16, controller: SocketAddr, http: Option<u16>) -> String {
    format!(
        "socks-port: {port}\nipv6: false\nexternal-controller: {controller}\nsecret: fixture-token\n{}\nproxies:\n  - {{name: node, type: socks5, server: 127.0.0.1, port: 9, udp: true}}\nproxy-groups:\n  - {{name: local, type: select, proxies: [DIRECT, REJECT]}}\nrules: ['MATCH,local']\n",
        http.map_or(String::new(), |port| format!("port: {port}"))
    )
}

async fn prepared(yaml: &str) -> PreparedCore {
    PreparedCore::prepare(yaml.as_bytes(), &SystemResolver, ResourceLimits::default())
        .await
        .unwrap()
}

async fn query(address: SocketAddr, route: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("GET {route} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-token\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[tokio::test]
async fn pure_socks5_controller_and_repeated_stop_release_all_resources() {
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_address = socks.local_addr().unwrap();
    let controller = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let controller_address = controller.local_addr().unwrap();
    let config = yaml(socks_address.port(), controller_address, None);
    drop((socks, controller));
    for _ in 0..3 {
        let prepared = prepared(&config).await;
        assert!(prepared.traffic_stats().is_none());
        let running = prepared.start_local(Dialer::default()).await.unwrap();
        assert!(
            query(controller_address, "/group")
                .await
                .contains("\"name\":\"local\"")
        );
        assert!(
            query(controller_address, "/traffic")
                .await
                .starts_with("HTTP/1.1 404")
        );
        let mut control = TcpStream::connect(socks_address).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut response = [0; 12];
        timeout(Duration::from_secs(2), control.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..5], &[5, 0, 5, 0, 0]);
        timeout(Duration::from_secs(2), running.stop())
            .await
            .unwrap()
            .unwrap();
        drop(TcpListener::bind(socks_address).await.unwrap());
        drop(UdpSocket::bind(socks_address).await.unwrap());
        drop(TcpListener::bind(controller_address).await.unwrap());
    }
}

#[cfg(feature = "inbound-http")]
#[tokio::test]
async fn http_socks5_controller_start_is_atomic_including_udp_and_tcp_conflicts() {
    let socks = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socks_address = socks.local_addr().unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http.local_addr().unwrap();
    let controller = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let controller_address = controller.local_addr().unwrap();
    let config = yaml(
        socks_address.port(),
        controller_address,
        Some(http_address.port()),
    );
    drop((http, controller));
    let error = prepared(&config)
        .await
        .start_local(Dialer::default())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    for address in [socks_address, http_address, controller_address] {
        drop(TcpListener::bind(address).await.unwrap());
    }
    drop(socks);
    let conflict = yaml(
        socks_address.port(),
        controller_address,
        Some(socks_address.port()),
    );
    let error = prepared(&conflict)
        .await
        .start_local(Dialer::default())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    let running = prepared(&config)
        .await
        .start_local(Dialer::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), running.stop())
        .await
        .unwrap()
        .unwrap();
    for address in [socks_address, http_address, controller_address] {
        drop(TcpListener::bind(address).await.unwrap());
    }
    drop(UdpSocket::bind(socks_address).await.unwrap());
}
