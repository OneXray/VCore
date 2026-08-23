use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(all(windows, feature = "ffi"))]
use std::{
    num::NonZeroU32,
    os::windows::io::{AsRawSocket, RawSocket},
};

use async_trait::async_trait;
#[cfg(all(windows, feature = "ffi"))]
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpSocket, UdpSocket},
    sync::Notify,
    time::timeout,
};
#[cfg(all(windows, feature = "ffi"))]
use windows::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR,
    WSAGetLastError, setsockopt,
};

use crate::limits::{DNS_WORKER_STACK_BYTES, MAX_DNS_WORKERS};

const MAX_RESOLVED_ADDRESSES: usize = 8;

static DNS_WORKER_POOL: OnceLock<DnsWorkerPool> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub logical_host: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
}

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

#[derive(Debug)]
struct DnsWorker {
    requests: SyncSender<DnsRequest>,
    busy: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DnsWorkerPool {
    workers: Mutex<Vec<DnsWorker>>,
    available: Arc<Notify>,
}

#[derive(Debug)]
struct DnsWorkerLease {
    requests: SyncSender<DnsRequest>,
    busy: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DnsRequest {
    host: String,
    port: u16,
    response: tokio::sync::oneshot::Sender<io::Result<Vec<SocketAddr>>>,
}

impl DnsWorker {
    fn spawn(slot: usize, available: Arc<Notify>) -> io::Result<Self> {
        let (requests, receiver) = sync_channel::<DnsRequest>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = busy.clone();
        thread::Builder::new()
            .name(format!("vcore-bootstrap-dns-{slot}"))
            .stack_size(DNS_WORKER_STACK_BYTES)
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let result = std::panic::catch_unwind(|| {
                        (request.host.as_str(), request.port)
                            .to_socket_addrs()
                            .map(take_resolved_addresses)
                    })
                    .unwrap_or_else(|_| Err(io::Error::other("bootstrap DNS worker panicked")));
                    worker_busy.store(false, Ordering::Release);
                    available.notify_one();
                    let _ = request.response.send(result);
                }
            })?;
        Ok(Self { requests, busy })
    }

    fn try_claim(&self) -> Option<DnsWorkerLease> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }

        Some(DnsWorkerLease {
            requests: self.requests.clone(),
            busy: self.busy.clone(),
        })
    }
}

impl DnsWorkerPool {
    async fn claim_worker(&self) -> io::Result<DnsWorkerLease> {
        loop {
            // Register before inspecting worker state so a completion between
            // the scan and await cannot be lost.
            let notified = self.available.notified();
            {
                let mut workers = self
                    .workers
                    .lock()
                    .map_err(|_| io::Error::other("bootstrap DNS worker pool lock is poisoned"))?;

                // Always scan from slot zero so sequential lookups reuse the
                // first worker. A new thread is created only when every
                // existing slot is still occupied by getaddrinfo.
                if let Some(lease) = workers.iter().find_map(DnsWorker::try_claim) {
                    return Ok(lease);
                }
                if workers.len() < MAX_DNS_WORKERS {
                    let worker = DnsWorker::spawn(workers.len(), Arc::clone(&self.available))?;
                    let lease = worker.try_claim().ok_or_else(|| {
                        io::Error::other("new bootstrap DNS worker is unexpectedly busy")
                    })?;
                    workers.push(worker);
                    return Ok(lease);
                }
            }
            notified.await;
        }
    }

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let worker = self.claim_worker().await?;

        let (response, receiver) = tokio::sync::oneshot::channel();
        if worker
            .requests
            .try_send(DnsRequest {
                host: host.to_owned(),
                port,
                response,
            })
            .is_err()
        {
            worker.busy.store(false, Ordering::Release);
            self.available.notify_one();
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "bootstrap DNS worker is unavailable",
            ));
        }
        receiver.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "bootstrap DNS worker stopped before replying",
            )
        })?
    }

    #[cfg(test)]
    fn worker_count(&self) -> usize {
        self.workers.lock().unwrap().len()
    }
}

impl Default for DnsWorkerPool {
    fn default() -> Self {
        Self {
            workers: Mutex::new(Vec::new()),
            available: Arc::new(Notify::new()),
        }
    }
}

fn take_resolved_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addresses.into_iter().take(MAX_RESOLVED_ADDRESSES).collect()
}

fn dns_worker_pool() -> &'static DnsWorkerPool {
    DNS_WORKER_POOL.get_or_init(DnsWorkerPool::default)
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server port is zero",
            ));
        }
        let mut addresses = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            dns_worker_pool().resolve(host, port).await?
        };
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "server did not resolve to an address",
            ));
        }
        Ok(ResolvedEndpoint {
            logical_host: host.to_owned(),
            port,
            addresses,
        })
    }
}

/// Platform hook invoked after socket creation and before connect.
pub trait SocketProtector: Send + Sync {
    fn protect(&self, socket: i32) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy)]
struct SourceBinding {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

#[cfg(all(windows, feature = "ffi"))]
#[derive(Debug, Clone, Copy)]
struct InterfaceBinding {
    ipv4: Option<(Ipv4Addr, NonZeroU32)>,
    ipv6: Option<(Ipv6Addr, NonZeroU32)>,
}

#[derive(Clone)]
pub struct Dialer {
    protector: Option<Arc<dyn SocketProtector>>,
    source_binding: Option<SourceBinding>,
    #[cfg(all(windows, feature = "ffi"))]
    interface_binding: Option<InterfaceBinding>,
    connect_timeout: Duration,
}

impl std::fmt::Debug for Dialer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("Dialer");
        debug
            .field("has_protector", &self.protector.is_some())
            .field("source_binding", &self.source_binding);
        #[cfg(all(windows, feature = "ffi"))]
        debug.field("interface_binding", &self.interface_binding);
        debug
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl Default for Dialer {
    fn default() -> Self {
        Self {
            protector: None,
            source_binding: None,
            #[cfg(all(windows, feature = "ffi"))]
            interface_binding: None,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl Dialer {
    #[must_use]
    pub fn with_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.protector = Some(protector);
        self
    }

    #[must_use]
    pub const fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_binding = Some(match source_ip {
            IpAddr::V4(ipv4) => SourceBinding {
                ipv4: Some(ipv4),
                ipv6: None,
            },
            IpAddr::V6(ipv6) => SourceBinding {
                ipv4: None,
                ipv6: Some(ipv6),
            },
        });
        #[cfg(all(windows, feature = "ffi"))]
        {
            self.interface_binding = None;
        }
        self
    }

    #[cfg(all(windows, feature = "ffi"))]
    #[must_use]
    pub(crate) const fn with_windows_interface(
        mut self,
        ipv4: Option<(Ipv4Addr, NonZeroU32)>,
        ipv6: Option<(Ipv6Addr, NonZeroU32)>,
    ) -> Self {
        self.source_binding = None;
        self.interface_binding = Some(InterfaceBinding { ipv4, ipv6 });
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub async fn connect(&self, endpoint: &ResolvedEndpoint) -> io::Result<tokio::net::TcpStream> {
        let mut last_error = None;
        for address in &endpoint.addresses {
            match self.connect_one(*address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "endpoint has no addresses")
        }))
    }

    /// Connects a direct TCP socket while applying the same platform protect
    /// hook and timeout used for the proxy-server dial path.
    pub async fn connect_address(&self, address: SocketAddr) -> io::Result<tokio::net::TcpStream> {
        self.connect_one(address).await
    }

    /// Creates a direct UDP socket for one address family and applies the
    /// platform protect hook before the socket is exposed to the caller.
    pub async fn bind_udp(&self, ipv6: bool) -> io::Result<UdpSocket> {
        let bind_address = self.source_address(ipv6)?.unwrap_or_else(|| {
            if ipv6 {
                SocketAddr::from(([0_u16; 8], 0))
            } else {
                SocketAddr::from(([0_u8; 4], 0))
            }
        });
        #[cfg(all(windows, feature = "ffi"))]
        let socket = {
            let socket = Socket::new(
                if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            self.apply_interface_binding(socket.as_raw_socket(), ipv6)?;
            socket.bind(&bind_address.into())?;
            socket.set_nonblocking(true)?;
            UdpSocket::from_std(socket.into())?
        };
        #[cfg(not(all(windows, feature = "ffi")))]
        let socket = UdpSocket::bind(bind_address).await?;
        #[cfg(unix)]
        if let Some(protector) = &self.protector {
            protector.protect(socket.as_raw_fd())?;
        }
        #[cfg(not(unix))]
        if self.protector.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "socket protection is only supported on Unix platforms",
            ));
        }
        Ok(socket)
    }

    fn source_address(&self, ipv6: bool) -> io::Result<Option<SocketAddr>> {
        #[cfg(all(windows, feature = "ffi"))]
        if let Some(binding) = self.interface_binding {
            let source_ip = if ipv6 {
                binding.ipv6.map(|(ip, _)| IpAddr::V6(ip))
            } else {
                binding.ipv4.map(|(ip, _)| IpAddr::V4(ip))
            };
            return source_ip.map(|ip| SocketAddr::new(ip, 0)).map_or_else(
                || {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "no physical interface is bound for the destination address family",
                    ))
                },
                |address| Ok(Some(address)),
            );
        }
        let Some(binding) = self.source_binding else {
            return Ok(None);
        };
        let source_ip = if ipv6 {
            binding.ipv6.map(IpAddr::V6)
        } else {
            binding.ipv4.map(IpAddr::V4)
        };
        source_ip.map(|ip| SocketAddr::new(ip, 0)).map_or_else(
            || {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no source IP is bound for the destination address family",
                ))
            },
            |address| Ok(Some(address)),
        )
    }

    #[cfg(all(windows, feature = "ffi"))]
    fn apply_interface_binding(&self, socket: RawSocket, ipv6: bool) -> io::Result<()> {
        let Some(binding) = self.interface_binding else {
            return Ok(());
        };
        let index = if ipv6 {
            binding.ipv6.map(|(_, index)| index)
        } else {
            binding.ipv4.map(|(_, index)| index)
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no interface index is bound for the destination address family",
            )
        })?;
        let value = interface_option_value(index, ipv6);
        let (level, option) = if ipv6 {
            (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP.0, IP_UNICAST_IF)
        };
        let socket = usize::try_from(socket)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Windows socket"))?;
        // SAFETY: `socket` is live for the call and `value` is the required DWORD.
        if unsafe { setsockopt(SOCKET(socket), level, option, Some(&value)) } == SOCKET_ERROR {
            // SAFETY: this immediately reads the calling thread's WinSock error.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
        }
        Ok(())
    }

    async fn connect_one(&self, address: SocketAddr) -> io::Result<tokio::net::TcpStream> {
        let ipv6 = address.is_ipv6();
        let socket = if ipv6 {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        #[cfg(unix)]
        if let Some(protector) = &self.protector {
            protector.protect(socket.as_raw_fd())?;
        }
        #[cfg(not(unix))]
        if self.protector.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "socket protection is only supported on Unix platforms",
            ));
        }
        #[cfg(all(windows, feature = "ffi"))]
        self.apply_interface_binding(socket.as_raw_socket(), ipv6)?;
        if let Some(source_address) = self.source_address(ipv6)? {
            socket.bind(source_address)?;
        }
        let stream = timeout(self.connect_timeout, socket.connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

#[cfg(all(windows, feature = "ffi"))]
fn interface_option_value(index: NonZeroU32, ipv6: bool) -> [u8; 4] {
    if ipv6 {
        index.get().to_ne_bytes()
    } else {
        index.get().to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::atomic::AtomicUsize;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::atomic::Ordering,
    };

    use tokio::net::TcpListener;

    use super::*;

    #[cfg(unix)]
    struct CountingProtector(AtomicUsize);

    #[cfg(unix)]
    impl SocketProtector for CountingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[cfg(unix)]
    struct RejectingProtector;

    #[cfg(unix)]
    impl SocketProtector for RejectingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "protect rejected",
            ))
        }
    }

    #[tokio::test]
    async fn source_ip_binds_tcp_and_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let dialer = Dialer::default().with_source_ip(source);

        let stream = dialer
            .connect_address(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), source);
        assert_eq!(peer.ip(), source);

        let udp = dialer.bind_udp(false).await.unwrap();
        assert_eq!(udp.local_addr().unwrap().ip(), source);
    }

    #[tokio::test]
    async fn source_ip_rejects_another_address_family() {
        let dialer = Dialer::default().with_source_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let error = dialer
            .connect_address(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            dialer.bind_udp(true).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(all(windows, feature = "ffi"))]
    #[tokio::test]
    async fn interface_binding_rejects_missing_address_family() {
        let ipv4_only = Dialer::default().with_windows_interface(
            Some((Ipv4Addr::LOCALHOST, NonZeroU32::new(10).unwrap())),
            None,
        );
        assert_eq!(
            ipv4_only.bind_udp(true).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(all(windows, feature = "ffi"))]
    #[test]
    fn windows_interface_index_uses_win_sock_byte_order() {
        let index = NonZeroU32::new(0x0102_0304).unwrap();
        assert_eq!(interface_option_value(index, false), [1, 2, 3, 4]);
        assert_eq!(
            interface_option_value(index, true),
            0x0102_0304_u32.to_ne_bytes()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn protector_runs_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let protector = Arc::new(CountingProtector(AtomicUsize::new(0)));
        let dialer = Dialer::default().with_protector(protector.clone());
        let endpoint = ResolvedEndpoint {
            logical_host: "localhost".to_owned(),
            port: address.port(),
            addresses: vec![address],
        };

        let _stream = dialer.connect(&endpoint).await.unwrap();
        assert_eq!(protector.0.load(Ordering::Relaxed), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn protect_failure_prevents_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dialer = Dialer::default().with_protector(Arc::new(RejectingProtector));
        let endpoint = ResolvedEndpoint {
            logical_host: "localhost".to_owned(),
            port: address.port(),
            addresses: vec![address],
        };

        let error = dialer.connect(&endpoint).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn literal_addresses_do_not_require_dns() {
        let endpoint = SystemResolver.resolve("127.0.0.1", 443).await.unwrap();
        assert_eq!(endpoint.addresses, ["127.0.0.1:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn hostnames_use_the_runtime_shared_dns_worker_pool() {
        for _ in 0..2 {
            let endpoint = SystemResolver.resolve("localhost", 443).await.unwrap();
            assert!(!endpoint.addresses.is_empty());
            assert!(endpoint.addresses.len() <= MAX_RESOLVED_ADDRESSES);
            assert!(
                endpoint
                    .addresses
                    .iter()
                    .all(|address| address.port() == 443)
            );
        }
        assert!(std::ptr::eq(dns_worker_pool(), dns_worker_pool()));
    }

    #[tokio::test]
    async fn worker_pool_resolves_localhost_concurrently() {
        let pool = Arc::new(DnsWorkerPool::default());
        let barrier = Arc::new(tokio::sync::Barrier::new(MAX_DNS_WORKERS));
        let mut tasks = Vec::new();

        for _ in 0..MAX_DNS_WORKERS {
            let pool = pool.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                pool.resolve("localhost", 443).await
            }));
        }

        for task in tasks {
            let addresses = task.await.unwrap().unwrap();
            assert!(!addresses.is_empty());
            assert!(addresses.len() <= MAX_RESOLVED_ADDRESSES);
            assert!(addresses.iter().all(|address| address.port() == 443));
        }
        assert!((1..=MAX_DNS_WORKERS).contains(&pool.worker_count()));
    }

    #[tokio::test]
    async fn sequential_lookups_lazily_reuse_the_first_worker() {
        let pool = DnsWorkerPool::default();
        assert_eq!(pool.worker_count(), 0);

        for _ in 0..3 {
            let addresses = pool.resolve("localhost", 443).await.unwrap();
            assert!(!addresses.is_empty());
        }

        assert_eq!(pool.worker_count(), 1);
    }

    #[tokio::test]
    async fn worker_pool_waits_instead_of_rejecting_after_four_claimed_slots() {
        let pool = Arc::new(DnsWorkerPool::default());
        let mut leases = Vec::new();
        for _ in 0..MAX_DNS_WORKERS {
            leases.push(pool.claim_worker().await.unwrap());
        }
        assert_eq!(pool.worker_count(), MAX_DNS_WORKERS);

        let waiting_pool = Arc::clone(&pool);
        let mut waiting = tokio::spawn(async move { waiting_pool.claim_worker().await });
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err(),
            "worker request unexpectedly bypassed occupied slots"
        );

        let released = leases.pop().unwrap();
        released.busy.store(false, Ordering::Release);
        pool.available.notify_one();
        let acquired = timeout(Duration::from_secs(1), waiting)
            .await
            .expect("waiting worker was not notified")
            .unwrap()
            .unwrap();
        acquired.busy.store(false, Ordering::Release);

        for lease in leases {
            lease.busy.store(false, Ordering::Release);
        }
    }

    #[test]
    fn resolved_address_collection_enforces_the_limit() {
        let addresses = (1..=MAX_RESOLVED_ADDRESSES + 3)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port as u16)));
        let addresses = take_resolved_addresses(addresses);

        assert_eq!(addresses.len(), MAX_RESOLVED_ADDRESSES);
        assert_eq!(
            addresses.last().unwrap().port(),
            MAX_RESOLVED_ADDRESSES as u16
        );
    }
}
