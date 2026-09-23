//! Single-connection, bounded public DatagramTransport to AsyncUdpSocket adapter.

use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::task::AtomicWaker;
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use vcore::{
    dispatch::{DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};

pub const PACKET_LIMIT: usize = 1400;
pub const QUEUE_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub sent: usize,
    pub received: usize,
    pub rejected_source: usize,
    pub dropped_full: usize,
    pub peak_outgoing: usize,
    pub peak_incoming: usize,
}

#[derive(Default)]
struct State {
    incoming: VecDeque<Bytes>,
    outgoing: VecDeque<Bytes>,
    closed: bool,
    error: Option<io::ErrorKind>,
    stats: Stats,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Notify,
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl Shared {
    fn finish(&self, error: Option<io::ErrorKind>) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.error = state.error.or(error);
        state.incoming.clear();
        state.outgoing.clear();
        drop(state);
        self.reader.wake();
        self.writer.wake();
    }
}

/// One QUIC connection to one logical peer; no implicit socket creation or DNS.
pub struct DatagramSocket {
    peer: SocketAddr,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for DatagramSocket {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("ControlledDatagramSocket")
            .finish_non_exhaustive()
    }
}

impl DatagramSocket {
    pub fn stats(&self) -> Stats {
        self.shared.state.lock().unwrap().stats
    }
}

pub struct DatagramDriver {
    shared: Arc<Shared>,
    cancel: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl DatagramDriver {
    pub async fn stop(mut self) -> io::Result<()> {
        self.cancel.cancel();
        // Keep the handle in self while awaiting: dropping stop() still aborts it.
        let result = self
            .task
            .as_mut()
            .unwrap()
            .await
            .map_err(|_| io::ErrorKind::Other)?;
        self.task.take();
        result
    }
}

impl Drop for DatagramDriver {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.shared.finish(None);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub fn attach(
    transport: Box<dyn DatagramTransport>,
    peer: SocketAddr,
) -> (Arc<DatagramSocket>, DatagramDriver) {
    attach_mapped(transport, peer, peer)
}

/// Keep one logical QUIC peer while this transport owns exactly one physical
/// endpoint. Each hop uses a fresh VCore transport; no direct socket creation.
pub fn attach_mapped(
    mut transport: Box<dyn DatagramTransport>,
    logical_peer: SocketAddr,
    physical_peer: SocketAddr,
) -> (Arc<DatagramSocket>, DatagramDriver) {
    let shared = Arc::new(Shared::default());
    let socket = Arc::new(DatagramSocket {
        peer: logical_peer,
        shared: shared.clone(),
    });
    let cancel = CancellationToken::new();
    let task_shared = shared.clone();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let result = drive(&mut *transport, physical_peer, &task_shared, &task_cancel).await;
        task_shared.finish(result.as_ref().err().map(io::Error::kind));
        // A transport close must not hold the test's synchronous stop indefinitely.
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(1), transport.close()).await;
        drop(transport);
        result?;
        closed
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map_err(dispatch_error)
    });
    (
        socket,
        DatagramDriver {
            shared,
            cancel,
            task: Some(task),
        },
    )
}

async fn drive(
    transport: &mut dyn DatagramTransport,
    peer: SocketAddr,
    shared: &Shared,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let mut has_sent = false;
    loop {
        let can_receive = shared.state.lock().unwrap().incoming.len() < QUEUE_LIMIT;
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = shared.changed.notified() => {},
            received = transport.receive(), if has_sent && can_receive => {
                let datagram = received.map_err(dispatch_error)?;
                let mut state = shared.state.lock().unwrap();
                if datagram.remote != Destination::Ip(peer) || datagram.payload.len() > PACKET_LIMIT {
                    state.stats.rejected_source += 1;
                } else if state.incoming.len() == QUEUE_LIMIT {
                    state.stats.dropped_full += 1;
                } else {
                    state.incoming.push_back(datagram.payload);
                    state.stats.received += 1;
                    state.stats.peak_incoming = state.stats.peak_incoming.max(state.incoming.len());
                    drop(state);
                    shared.reader.wake();
                }
            }
        }
        let payload = shared.state.lock().unwrap().outgoing.pop_front();
        if let Some(payload) = payload {
            shared.writer.wake();
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                sent = transport.send(Datagram { remote: Destination::Ip(peer), payload, sniffed_domain: None }) => sent.map_err(dispatch_error)?,
            }
            has_sent = true;
            let mut state = shared.state.lock().unwrap();
            state.stats.sent += 1;
            if !state.outgoing.is_empty() {
                shared.changed.notify_one();
            }
        }
    }
}

fn dispatch_error(error: DispatchError) -> io::Error {
    match error {
        DispatchError::NotAllowed => io::ErrorKind::PermissionDenied,
        DispatchError::TimedOut => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::ConnectionAborted,
    }
    .into()
}

struct PacketPoller(Arc<Shared>);

impl std::fmt::Debug for PacketPoller {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("PacketPoller")
    }
}

impl UdpPoller for PacketPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.writer.register(cx.waker());
        let state = self.0.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        if state.outgoing.len() < QUEUE_LIMIT {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncUdpSocket for DatagramSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PacketPoller(self.shared.clone()))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.peer
            || transmit.contents.len() > PACKET_LIMIT
            || transmit.segment_size.is_some()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into());
        }
        if state.outgoing.len() == QUEUE_LIMIT {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state
            .outgoing
            .push_back(Bytes::copy_from_slice(transmit.contents));
        state.stats.peak_outgoing = state.stats.peak_outgoing.max(state.outgoing.len());
        drop(state);
        self.shared.changed.notify_one();
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.shared.reader.register(cx.waker());
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        let Some(payload) = state.incoming.front() else {
            return Poll::Pending;
        };
        if buffers.is_empty() || meta.is_empty() || buffers[0].len() < payload.len() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        buffers[0][..payload.len()].copy_from_slice(payload);
        meta[0] = quinn::udp::RecvMeta {
            addr: self.peer,
            len: payload.len(),
            stride: payload.len(),
            ecn: None,
            dst_ip: None,
        };
        state.incoming.pop_front();
        // Resume the single transport owner when the consumer frees capacity.
        self.shared.changed.notify_one();
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Logical socket metadata only. VCore's public datagram transport owns
        // physical sockets and intentionally does not expose their bound ports.
        Ok(if self.peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap())
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use quinn::AsyncUdpSocket;
    use std::{future::poll_fn, io::IoSliceMut, time::Duration};
    use vcore::{
        dialer::Dialer,
        outbound::{DatagramRequest, DirectOutbound, EstablishContext, OutboundConnector},
        session::{DatagramSession, InboundKind},
    };

    #[tokio::test]
    async fn mapped_peer_sends_to_one_physical_port_and_reports_the_logical_peer() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let logical = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let physical = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let logical_peer = logical.local_addr().unwrap();
            let physical_peer = physical.local_addr().unwrap();
            let transport = DirectOutbound::new(Dialer::default())
                .open_datagram(
                    DatagramRequest::new(DatagramSession::new(InboundKind::Socks5, logical_peer))
                        .with_max_response_payload_size(1400),
                    &EstablishContext::default(),
                )
                .await
                .unwrap();
            let (socket, driver) = super::attach_mapped(transport, logical_peer, physical_peer);
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: logical_peer,
                    ecn: None,
                    contents: b"mapped",
                    segment_size: None,
                    src_ip: None,
                })
                .unwrap();
            let mut payload = [0; 1400];
            let (len, source) = physical.recv_from(&mut payload).await.unwrap();
            assert_eq!(&payload[..len], b"mapped");
            logical
                .send_to(b"not-the-physical-peer", source)
                .await
                .unwrap();
            while socket.stats().rejected_source == 0 {
                tokio::task::yield_now().await;
            }
            physical.send_to(b"mapped-reply", source).await.unwrap();
            let mut buffers = [IoSliceMut::new(&mut payload)];
            let mut meta = [quinn::udp::RecvMeta::default()];
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                .await
                .unwrap();
            assert_eq!(meta[0].addr, logical_peer);
            assert_eq!(&buffers[0][..meta[0].len], b"mapped-reply");
            driver.stop().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn incoming_queue_backpressures_without_discarding_a_controlled_burst() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = echo.local_addr().unwrap();
            let transport = DirectOutbound::new(Dialer::default())
                .open_datagram(
                    DatagramRequest::new(DatagramSession::new(InboundKind::Socks5, peer))
                        .with_max_response_payload_size(1400),
                    &EstablishContext::default(),
                )
                .await
                .unwrap();
            let (socket, driver) = super::attach(transport, peer);
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: b"ready",
                    segment_size: None,
                    src_ip: None,
                })
                .unwrap();
            let mut payload = [0; 1400];
            let (_, source) = echo.recv_from(&mut payload).await.unwrap();
            for sequence in 0..40_u8 {
                echo.send_to(&[sequence], source).await.unwrap();
            }
            // Deliberately pause the reader until the bounded queue saturates.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(socket.stats().peak_incoming, super::QUEUE_LIMIT);
            assert_eq!(socket.stats().dropped_full, 0);
            for expected in 0..40_u8 {
                let mut buffers = [IoSliceMut::new(&mut payload)];
                let mut meta = [quinn::udp::RecvMeta::default()];
                poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                    .await
                    .unwrap();
                assert_eq!(&buffers[0][..meta[0].len], &[expected]);
            }
            driver.stop().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn controlled_direct_datagrams_roundtrip_and_stop() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = echo.local_addr().unwrap();
            let transport = DirectOutbound::new(Dialer::default())
                .open_datagram(
                    DatagramRequest::new(DatagramSession::new(
                        InboundKind::Socks5,
                        "127.0.0.1:0".parse().unwrap(),
                    ))
                    .with_max_response_payload_size(1400),
                    &EstablishContext::default(),
                )
                .await
                .unwrap();
            let (socket, driver) = super::attach(transport, peer);
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: b"N0-controlled-datagram",
                    segment_size: None,
                    src_ip: None,
                })
                .unwrap();
            let mut payload = [0; 1400];
            let (len, source) = echo.recv_from(&mut payload).await.unwrap();
            assert_eq!(&payload[..len], b"N0-controlled-datagram");
            let foreign = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            foreign.send_to(b"wrong-source", source).await.unwrap();
            while socket.stats().rejected_source == 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                socket
                    .try_send(&quinn::udp::Transmit {
                        destination: foreign.local_addr().unwrap(),
                        ecn: None,
                        contents: b"wrong-target",
                        segment_size: None,
                        src_ip: None,
                    })
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
            assert_eq!(
                socket
                    .try_send(&quinn::udp::Transmit {
                        destination: peer,
                        ecn: None,
                        contents: &[0; super::PACKET_LIMIT + 1],
                        segment_size: None,
                        src_ip: None,
                    })
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
            echo.send_to(b"N0-reply", source).await.unwrap();
            let mut buffers = [IoSliceMut::new(&mut payload)];
            let mut meta = [quinn::udp::RecvMeta::default()];
            assert_eq!(
                poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(meta[0].addr, peer);
            assert_eq!(&buffers[0][..meta[0].len], b"N0-reply");
            // The current-thread driver cannot consume these until we yield.
            let transmit = quinn::udp::Transmit {
                destination: peer,
                ecn: None,
                contents: b"bounded",
                segment_size: None,
                src_ip: None,
            };
            for _ in 0..super::QUEUE_LIMIT {
                socket.try_send(&transmit).unwrap();
            }
            assert_eq!(
                socket.try_send(&transmit).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let mut writable = socket.clone().create_io_poller();
            let waker = futures_util::task::noop_waker();
            assert!(
                writable
                    .as_mut()
                    .poll_writable(&mut std::task::Context::from_waker(&waker))
                    .is_pending()
            );
            poll_fn(|cx| writable.as_mut().poll_writable(cx))
                .await
                .unwrap();
            assert_eq!(socket.stats().peak_outgoing, super::QUEUE_LIMIT);
            driver.stop().await.unwrap();
            assert!(
                socket
                    .try_send(&quinn::udp::Transmit {
                        destination: peer,
                        ecn: None,
                        contents: b"after-stop",
                        segment_size: None,
                        src_ip: None
                    })
                    .is_err()
            );
        })
        .await
        .unwrap();
    }
}
