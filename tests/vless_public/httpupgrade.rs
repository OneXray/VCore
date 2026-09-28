//! Shared public consumers; every protocol peer and origin is container-owned.
use super::*;
use vcore::resources::observation::ResourceProbe;

fn save(value: Value) {
    std::fs::write(
        std::env::var("VCORE_HTTPUPGRADE_OBSERVATIONS").unwrap(),
        value.to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "isolated HTTPUpgrade peer and origin required"]
fn tcp() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("HTTPUPGRADE-PUBLIC", "tcp");
    let probe = ResourceProbe::default();
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    for (ipv6, domain) in [(false, false), (true, false), (false, true)] {
        bulk(port, &f, ipv6, domain);
    }
    echo(port, &f);
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    save(
        json!({"families":["ipv4","ipv6","domain"],"tcp_bytes_each_family_each_direction":10*1024*1024,"server_first":true,"client_first":true,"stop_idle":true}),
    );
}

fn no_udp(association: &mut Association, payload: &[u8]) {
    association
        .client
        .send_to(&association.packet(payload), association.relay)
        .unwrap();
    association
        .client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    assert!(
        matches!(association.client.recv_from(&mut [0;64]), Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut))
    );
    association.origin.quiet();
    association.client.set_read_timeout(Some(TIMEOUT)).unwrap();
}

#[test]
#[ignore = "isolated HTTPUpgrade UDP peer and origin required"]
fn udp() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("HTTPUPGRADE-PUBLIC", "udp");
    let vmess = f["node"]["type"] == "vmess";
    let native = f["peer_kind"] == "XR";
    let codec = if vmess {
        f["node"]["packet-encoding"].as_str().unwrap()
    } else {
        "trojan"
    };
    let probe = ResourceProbe::default();
    let port = free_port();
    let mut dns_origin = Origin::new(&f, 17, false);
    let mut yaml = config(f["node"].clone(), port);
    dns(&mut yaml, &dns_origin, "DIRECT");
    let core = probe.scope_sync(|| Core::start(&yaml));
    let mut live = Vec::new();
    let mut rows = Vec::new();
    for (family, ipv6, domain) in [
        ("ipv4", false, false),
        ("ipv6", true, false),
        ("domain", false, true),
    ] {
        if !f["families"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == family)
        {
            continue;
        }
        if vmess || native {
            let mut empty = Association::new(&f, port, ipv6, domain);
            no_udp(&mut empty, b"");
            live.push(empty);
        }
        let mut association = Association::new(&f, port, ipv6, domain);
        let cap = if vmess {
            15000
                - if codec == "packetaddr" {
                    if ipv6 || domain { 19 } else { 7 }
                } else {
                    0
                }
        } else if native {
            8166 // Native reply's 8192 total-frame budget minus this domain header.
        } else {
            8192
        };
        let mut sizes = vec![1, 64, 512, 1200, cap];
        if !vmess && !native {
            sizes.insert(0, 0);
        }
        for &size in &sizes {
            for sequence in 0..100_u8 {
                association.exchange(&vec![sequence; size]);
            }
        }
        if native {
            // Upload fits VCore, but exceeds the native reply frame. The
            // incomplete reply must not become a successful shortened UDP.
            let mut overflow = Association::new(&f, port, ipv6, domain);
            let payload = vec![7; cap + 1];
            overflow
                .client
                .send_to(&overflow.packet(&payload), overflow.relay)
                .unwrap();
            overflow.origin.udp(&payload);
            overflow
                .client
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            assert!(
                matches!(overflow.client.recv_from(&mut [0;20000]),Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut))
            );
            no_udp(&mut association, &vec![7; 8193]);
            live.push(overflow);
        } else {
            no_udp(&mut association, &vec![7; cap + 1]);
        }
        rows.push(json!({"family":family,"sizes":sizes,"packets":sizes.len()*100}));
        live.push(association);
    }
    if codec == "packetaddr" {
        let mut header = [0; 4];
        dns_origin.observer.read_exact(&mut header).unwrap();
        let mut question = vec![0; u16::from_be_bytes([header[0], header[1]]) as usize];
        dns_origin.observer.read_exact(&mut question).unwrap();
        assert_eq!(&question[12..], b"\x0dvcore-fixture\x04test\0\0\x01\0\x01");
    }
    echo(port, &f);
    let before = Instant::now();
    core.stop();
    assert!(before.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    for association in &mut live {
        association.origin.quiet();
    }
    save(
        json!({"udp":rows,"zero_no_delivery":vmess || native,"oversize_rejected":true,"tcp_sibling":true,"stop_idle":true}),
    );
}

#[test]
#[ignore = "isolated HTTPUpgrade peer and origin required"]
fn echo_and_stop() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("HTTPUPGRADE-PUBLIC", "echo_and_stop");
    let probe = ResourceProbe::default();
    let port = free_port();
    let core = probe.scope_sync(|| Core::start(&config(f["node"].clone(), port)));
    echo(port, &f);
    let (mut client, mut origin) = runtime::live(port, &f);
    runtime::exchange(&mut client, b"before-stop");
    let start = Instant::now();
    core.stop();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    runtime::assert_closed(&mut client);
    origin.marker(b'D');
    origin.quiet();
    save(json!({"authenticated_echo":true,"live_stream_cancelled":true,"stop_idle":true}));
}

#[test]
#[ignore = "isolated HTTPUpgrade negative fixture required"]
fn rejected() {
    let f = fixture();
    initialize(&f);
    let _case = RecordedCase::new("HTTPUPGRADE-PUBLIC", "rejected");
    let probe = ResourceProbe::default();
    probe.scope_sync(|| denied(f["node"].clone(), &f));
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    save(json!({"origin_connected":false,"received_business_bytes":0,"stop_idle":true}));
}

#[tokio::test]
#[ignore = "isolated HTTPUpgrade peer and official close reference required"]
async fn close() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vcore::{
        config::{Config, ProxyProtocol},
        dialer::{Dialer, ResolvedEndpoint},
        outbound::{
            EstablishContext, OutboundConnector, UpstreamPath, trojan::TrojanOutbound,
            vmess::VmessOutbound,
        },
        session::{InboundKind, StreamSession},
    };
    let f = fixture();
    let _case = RecordedCase::new("HTTPUPGRADE-PUBLIC", "close");
    let parsed =
        Config::parse_yaml(config(f["node"].clone(), 1080).to_string().as_bytes()).unwrap();
    let proxy = &parsed.proxies[0];
    let probe = ResourceProbe::default();
    let mut origin = Origin::new(&f, 11, false);
    let tail = probe.scope(async {
        let path = UpstreamPath::direct(ResolvedEndpoint {
            logical_host: proxy.address().into(), port: proxy.port(),
            addresses: vec![SocketAddr::new(proxy.address().parse().unwrap(), proxy.port())],
        }, Dialer::default());
        let outbound: Arc<dyn OutboundConnector> = match &proxy.protocol {
            ProxyProtocol::Vmess(c) => Arc::new(VmessOutbound::new_with_path(c,path).unwrap()),
            ProxyProtocol::Trojan(c) => Arc::new(TrojanOutbound::new_with_path(c,path).unwrap()),
            _ => unreachable!(),
        };
        let mut io = outbound.connect_stream(StreamSession {
            inbound: InboundKind::InternalMeasure, source:"127.0.0.1:1".parse().unwrap(),
            destination: origin.target.into(), sniffed_domain:None,
        }, &EstablishContext::default()).await.unwrap().io;
        let tail = tokio::time::timeout(TIMEOUT, async {
            let mut hello=[0;5]; io.read_exact(&mut hello).await.unwrap(); assert_eq!(&hello,b"hello");
            io.write_all(b"ping").await.unwrap(); io.flush().await.unwrap();
            let mut echo=[0;4]; io.read_exact(&mut echo).await.unwrap(); assert_eq!(&echo,b"ping");
            io.shutdown().await.unwrap();
            let mut tail=Vec::new();
            let terminal=io.read_to_end(&mut tail).await;
            assert!(terminal.is_ok() || matches!(terminal,Err(ref e) if matches!(e.kind(),io::ErrorKind::ConnectionReset|io::ErrorKind::UnexpectedEof|io::ErrorKind::BrokenPipe)));
            tail
        }).await.expect("close did not terminate");
        drop(io);
        tokio::time::timeout(Duration::from_secs(5),outbound.shutdown()).await.unwrap();
        tail
    }).await;
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    origin.marker(b'A');
    origin.marker(b'D');
    let hex: String = tail.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(f["close_reference"]["terminated"], true);
    assert_eq!(hex, f["close_reference"]["tail_hex"].as_str().unwrap());
    save(json!({"tail_hex":hex,"terminated":true,"stop_idle":true}));
}
