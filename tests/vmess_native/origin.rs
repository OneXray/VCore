//! Client-only control for origins owned by the isolated-container harness.
use super::*;

pub fn fixture() -> serde_json::Value {
    let path = std::env::var("VCORE_VMESS_AB_INPUT").expect("isolated origin fixture required");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(value["isolation"], "containers");
    value
}

pub struct TcpOrigin {
    control: tokio::net::TcpStream,
    pub target: Destination,
}

impl TcpOrigin {
    pub async fn new(mode: u8) -> Self {
        let fixture = fixture();
        let mut control =
            tokio::net::TcpStream::connect(fixture["origin_control"].as_str().unwrap())
                .await
                .unwrap();
        control.set_nodelay(true).unwrap();
        control.write_u8(mode).await.unwrap();
        let port = control.read_u16().await.unwrap();
        let ip: std::net::IpAddr = fixture["origin_ipv4"].as_str().unwrap().parse().unwrap();
        assert!(!ip.is_loopback() && !ip.is_unspecified());
        Self {
            control,
            target: SocketAddr::new(ip, port).into(),
        }
    }

    pub async fn accepted(&mut self) {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), self.control.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'A'
        );
    }

    pub async fn completed(&mut self) {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), self.control.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'D'
        );
    }

    pub async fn not_accepted(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(350), self.control.read_u8())
                .await
                .is_err(),
            "rejected authentication reached origin"
        );
    }
}
