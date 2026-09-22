use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, copy_bidirectional_with_sizes},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval_at, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Socks5InboundConfig,
    dispatch::{DispatchError, Dispatcher},
    inbound::listen::{bind_proxy_tcp, bind_udp},
    session::{
        Datagram, DatagramSession, Destination, InboundKind, SOCKS5_UDP_PACKET_LIMIT, StreamSession,
    },
    socks5::{COMMAND_CONNECT, encode_udp_packet},
};

use super::{
    association::{Associations, CLEANUP_INTERVAL, Lease},
    handshake,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_BUFFER_SIZE: usize = 4 * 1024;

pub struct Socks5Server {
    listeners: Vec<TcpListener>,
    sockets: Vec<Arc<UdpSocket>>,
    config: Socks5InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
}

impl Socks5Server {
    pub fn bind(config: Socks5InboundConfig, dispatcher: Arc<dyn Dispatcher>) -> io::Result<Self> {
        if config.access.allow_lan && config.auth.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared proxy requires authentication",
            ));
        }
        let listeners = bind_proxy_tcp(config.port, config.access)?;
        // UDP must bind every successfully acquired TCP family. Failure drops
        // all sockets, before either protocol can accept application traffic.
        let sockets = listeners
            .iter()
            .map(|listener| bind_udp(listener.local_addr()?).map(Arc::new))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            listeners,
            sockets,
            config,
            dispatcher,
        })
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.listeners.iter().map(TcpListener::local_addr).collect()
    }

    async fn accept(&self) -> io::Result<(usize, TcpStream, SocketAddr)> {
        let (index, accepted) = match self.listeners.as_slice() {
            [one] => (0, one.accept().await),
            [v4, v6] => {
                tokio::select! { result = v4.accept() => (0, result), result = v6.accept() => (1, result) }
            }
            _ => unreachable!("one or two listener families"),
        };
        accepted.map(|(stream, peer)| (index, stream, peer))
    }

    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let registry = Arc::new(Associations::default());
        let mut receivers = JoinSet::new();
        for socket in &self.sockets {
            let socket = socket.clone();
            let registry = registry.clone();
            let child = cancellation.clone();
            receivers.spawn(async move {
                // A sentinel byte rejects oversized packets, including OS
                // truncation, without allocating from a client length field.
                let mut buffer = vec![0; SOCKS5_UDP_PACKET_LIMIT + 1];
                loop {
                    tokio::select! {
                        biased;
                        () = child.cancelled() => return Ok::<_, io::Error>(()),
                        received = socket.recv_from(&mut buffer) => {
                            let (length, source) = received?;
                            registry.enqueue(source, &buffer[..length], Instant::now());
                        }
                    }
                }
            });
        }
        let mut connections = JoinSet::new();
        let mut cleanup = interval_at(Instant::now() + CLEANUP_INTERVAL, CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break Ok(()),
                ended = receivers.join_next() => break match ended {
                    Some(Ok(Err(error))) => Err(error),
                    _ => Err(io::Error::other("SOCKS5 UDP receiver stopped")),
                },
                joined = connections.join_next(), if !connections.is_empty() => { let _ = joined; },
                _ = cleanup.tick() => registry.cleanup(Instant::now()),
                accepted = self.accept() => {
                    let (index, stream, peer) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let socket = self.sockets[index].clone();
                    let dispatcher = self.dispatcher.clone();
                    let config = self.config.clone();
                    let registry = registry.clone();
                    let child = cancellation.clone();
                    connections.spawn(async move {
                        tokio::select! {
                            biased;
                            () = child.cancelled() => {},
                            _ = handle_connection(stream, peer, socket, config, dispatcher, registry, child.clone()) => {},
                        }
                    });
                }
            }
        };
        cancellation.cancel();
        while connections.join_next().await.is_some() {}
        while receivers.join_next().await.is_some() {}
        result
    }
}

async fn timed<F, T>(future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    timeout(IO_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 operation timed out"))?
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    socket: Arc<UdpSocket>,
    config: Socks5InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
    registry: Arc<Associations>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let (command, destination) = timeout(
        HANDSHAKE_TIMEOUT,
        handshake::negotiate(&mut stream, config.auth.as_ref()),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))??;
    if !config.access.ipv6 && matches!(&destination, Destination::Ip(address) if address.is_ipv6())
    {
        timed(handshake::reply(&mut stream, 8, None)).await?;
        return Ok(());
    }
    if command == COMMAND_CONNECT {
        let session = StreamSession {
            inbound: InboundKind::Socks5,
            source: peer,
            destination,
            sniffed_domain: None,
        };
        let connected = timeout(IO_TIMEOUT, dispatcher.connect_tcp(session))
            .await
            .unwrap_or(Err(DispatchError::TimedOut));
        match connected {
            Ok(mut upstream) => {
                timed(handshake::reply(&mut stream, 0, None)).await?;
                copy_bidirectional_with_sizes(
                    &mut stream,
                    &mut upstream,
                    RELAY_BUFFER_SIZE,
                    RELAY_BUFFER_SIZE,
                )
                .await?;
            }
            Err(error) => {
                timed(handshake::reply(
                    &mut stream,
                    handshake::status(&error),
                    None,
                ))
                .await?;
            }
        }
        return Ok(());
    }
    let requested = match destination {
        Destination::Ip(address) if address.ip().is_unspecified() || address.ip() == peer.ip() => {
            address
        }
        _ => {
            timed(handshake::reply(&mut stream, 2, None)).await?;
            return Ok(());
        }
    };
    let (lease, receiver) = match registry.register(peer, requested.port(), &cancellation) {
        Ok(value) => value,
        Err(_) => {
            timed(handshake::reply(&mut stream, 2, None)).await?;
            return Ok(());
        }
    };
    // The accepted socket's concrete local IP is reachable even when the
    // listener was bound to a wildcard. TCP and UDP share this exact port.
    let relay = stream.local_addr()?;
    timed(handshake::reply(&mut stream, 0, Some(relay))).await?;
    tokio::select! {
        biased;
        () = lease.cancellation.cancelled() => {},
        _ = read_control(&mut stream) => {},
        _ = relay_datagrams(&lease, receiver, socket, dispatcher, registry) => {},
    }
    // Dropping the lease revokes authorization before the control socket.
    Ok(())
}

async fn read_control(stream: &mut TcpStream) -> io::Result<()> {
    let mut buffer = [0; 1024];
    while stream.read(&mut buffer).await? != 0 {}
    Ok(())
}

async fn relay_datagrams(
    lease: &Lease,
    mut receiver: mpsc::Receiver<Datagram>,
    socket: Arc<UdpSocket>,
    dispatcher: Arc<dyn Dispatcher>,
    registry: Arc<Associations>,
) -> io::Result<()> {
    let Some(first) = receiver.recv().await else {
        return Ok(());
    };
    let source = *lease.source.lock().unwrap();
    let session = DatagramSession::new(InboundKind::Socks5, source);
    let response_limit = usize::from(session.max_response_payload_size());
    let mut transport = timeout(IO_TIMEOUT, dispatcher.open_datagram(session))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 UDP open timed out"))?
        .map_err(|_| io::Error::other("SOCKS5 UDP open failed"))?;
    timeout(IO_TIMEOUT, transport.send(first))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| io::Error::other("SOCKS5 UDP send failed"))?;
    loop {
        tokio::select! {
            datagram = receiver.recv() => {
                let Some(datagram) = datagram else { return Ok(()); };
                timeout(IO_TIMEOUT, transport.send(datagram)).await.map_err(|_| io::ErrorKind::TimedOut)?
                    .map_err(|_| io::Error::other("SOCKS5 UDP send failed"))?;
            }
            response = transport.receive() => {
                let response = response.map_err(|_| io::Error::other("SOCKS5 UDP receive failed"))?;
                if response.payload.len() > response_limit { continue; }
                let Ok(packet) = encode_udp_packet(&response.remote, &response.payload, SOCKS5_UDP_PACKET_LIMIT) else { continue; };
                timed(async {
                    loop {
                        socket.writable().await?;
                        match registry.try_reply(lease, &socket, &packet) {
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                            result => return result,
                        }
                    }
                }).await?;
            }
        }
    }
}
