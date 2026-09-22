//! Test-only socket ownership. No production dialer or third-party hooks.
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    ops::Deref,
};

fn bind_one(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    Ok(socket.into())
}

/// Reserve the same UDP port in both families for the socket's whole lifetime.
/// On Darwin, an automatically allocated IPv6 dual-stack port can otherwise
/// alias an already bound IPv4 endpoint. Neither socket enables address reuse.
pub(super) struct GuardedUdpSocket {
    socket: UdpSocket,
    _other_family: UdpSocket,
}

impl GuardedUdpSocket {
    pub(super) fn bind(address: impl ToSocketAddrs) -> io::Result<Self> {
        let address = address
            .to_socket_addrs()?
            .next()
            .filter(|address| {
                address.ip().is_loopback()
                    || address.ip() == super::origin_address(address.is_ipv6()).ip()
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fixture must use loopback or owned bridge",
                )
            })?;
        for _ in 0..32 {
            let socket = bind_one(address)?;
            let other_ip = if address.is_ipv4() {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
            let other = SocketAddr::new(other_ip, socket.local_addr()?.port());
            match bind_one(other) {
                Ok(guard) => {
                    return Ok(Self {
                        socket,
                        _other_family: guard,
                    });
                }
                Err(error) if address.port() == 0 && error.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => return Err(error),
            }
            // Only port reservation retries; no traffic has started.
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "could not reserve a dual-family fixture UDP port",
        ))
    }
}

impl Deref for GuardedUdpSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

pub(super) fn report_udp_sockets() {
    #[cfg(target_os = "macos")]
    {
        // Only this test process and the peer PIDs supplied by its owner.
        // Do not inspect unrelated services or read packet/config contents.
        let Ok(peers) = std::env::var("VCORE_MIHOMO_PEER_PIDS") else {
            return;
        };
        if peers.split(',').any(|pid| pid.parse::<u32>().is_err()) {
            return;
        }
        let pids = format!("{},{}", std::process::id(), peers);
        let Ok(mut child) = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pids, "-iUDP"])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return;
        };
        let deadline = std::time::Instant::now() + super::IO_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
        }
    }
}

#[test]
fn fixture_ports_block_both_families_and_release_together() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let fixture = GuardedUdpSocket::bind(address).unwrap();
        let port = fixture.local_addr().unwrap().port();
        for address in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ] {
            assert_eq!(
                bind_one(address).unwrap_err().kind(),
                io::ErrorKind::AddrInUse
            );
        }
        let dual = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        dual.set_only_v6(false).unwrap();
        assert_eq!(
            dual.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrInUse
        );
        drop(fixture);
        drop(bind_one(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).unwrap());
        drop(bind_one(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).unwrap());
    }
}

#[test]
fn fixture_socket_preserves_real_udp_source_and_payload() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let sender = GuardedUdpSocket::bind(address).unwrap();
        let receiver = GuardedUdpSocket::bind(address).unwrap();
        receiver.set_read_timeout(Some(super::IO_TIMEOUT)).unwrap();
        sender
            .send_to(b"guarded-fixture", receiver.local_addr().unwrap())
            .unwrap();
        let mut bytes = [0; 32];
        let (length, source) = receiver.recv_from(&mut bytes).unwrap();
        assert_eq!(source, sender.local_addr().unwrap());
        assert_eq!(&bytes[..length], b"guarded-fixture");
    }
}
