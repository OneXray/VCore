use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_util::future::select_all;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf},
    sync::Notify,
    task::JoinHandle,
};

use crate::{
    config::{Network, ProxyId, RuleAction},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    dns::{
        MAX_MESSAGE_SIZE,
        runtime::{DnsWireResponse, RuntimeDns},
    },
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

use super::{GeoMatcher, RoutingContext, RuleEvaluation, RuleSet};

const TCP_DNS_DUPLEX_CAPACITY: usize = 8 * 1024;

#[async_trait]
trait RoutingDns: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError>;
    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError>;
    async fn domain_hint(&self, address: IpAddr) -> Option<String>;
}

#[async_trait]
impl RoutingDns for RuntimeDns {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
        RuntimeDns::resolve(self, host)
            .await
            .map_err(runtime_dns_error)
    }

    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
        RuntimeDns::exchange_retained(self, query)
            .await
            .map_err(runtime_dns_error)
    }

    async fn domain_hint(&self, address: IpAddr) -> Option<String> {
        RuntimeDns::domain_hint(self, address).await
    }
}

fn runtime_dns_error(error: impl std::fmt::Display) -> DispatchError {
    DispatchError::Other(format!("runtime DNS: {error}"))
}

/// Runtime proxy registry. Configuration validation converts every
/// user-facing tag into a checked [`ProxyId`].
#[derive(Clone)]
pub struct ProxyDispatchers {
    slots: Vec<Arc<dyn Dispatcher>>,
}

impl std::fmt::Debug for ProxyDispatchers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyDispatchers")
            .field("len", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl ProxyDispatchers {
    pub fn new(proxies: Vec<Arc<dyn Dispatcher>>) -> Result<Self, DispatchError> {
        if proxies.is_empty() {
            return Err(DispatchError::Other(
                "proxy registry must contain at least one entry".to_owned(),
            ));
        }
        Ok(Self { slots: proxies })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn get(&self, id: ProxyId) -> Result<&Arc<dyn Dispatcher>, DispatchError> {
        self.slots
            .get(id.index())
            .ok_or_else(|| DispatchError::Other(format!("unknown proxy id {}", id.index())))
    }
}

/// Ordered VCore router backed by named proxy nodes, built-in DIRECT, and
/// fail-closed REJECT actions.
///
/// The outer session observer records returned transport lifetimes without
/// admitting or rejecting work. This layer creates at most one transport per
/// proxy id and one direct transport for each association and chooses between
/// them independently for every datagram.
pub struct RoutingDispatcher {
    proxies: ProxyDispatchers,
    direct: Arc<dyn Dispatcher>,
    dns: Option<Arc<dyn RoutingDns>>,
    rules: Arc<RuleSet>,
    geo_matcher: Arc<dyn GeoMatcher>,
}

impl RoutingDispatcher {
    #[must_use]
    pub fn new(
        proxies: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self {
            proxies,
            direct,
            dns: dns.map(|dns| dns as Arc<dyn RoutingDns>),
            rules: Arc::new(rules),
            geo_matcher,
        }
    }

    #[cfg(test)]
    fn with_dns_service(
        proxy: Arc<dyn Dispatcher>,
        direct: Arc<dyn Dispatcher>,
        dns: Option<Arc<dyn RoutingDns>>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self {
            proxies: ProxyDispatchers::new(vec![proxy])
                .expect("test proxy registry contains one entry"),
            direct,
            dns,
            rules: Arc::new(rules),
            geo_matcher,
        }
    }

    async fn route(
        &self,
        network: Network,
        inbound: InboundKind,
        destination: &Destination,
        sniffed_domain: Option<&str>,
    ) -> Result<RouteDecision, DispatchError> {
        let accepts_domain_hint = inbound == InboundKind::Tun && self.rules.uses_domain_routing();
        let sniffed_domain = accepts_domain_hint.then_some(sniffed_domain).flatten();
        let dns_domain_hint = match (accepts_domain_hint, destination, &self.dns, sniffed_domain) {
            (true, Destination::Ip(address), Some(dns), None) => {
                dns.domain_hint(address.ip()).await
            }
            _ => None,
        };
        let domain_hint = sniffed_domain.or(dns_domain_hint.as_deref());
        let mut context = RoutingContext::with_domain_hint(network, destination, domain_hint)
            .map_err(|_| DispatchError::HostUnreachable)?;

        let mut resolved = None;
        let evaluation = match self
            .rules
            .evaluate_with_geo(&context, self.geo_matcher.as_ref())
        {
            RuleEvaluation::NeedsIpResolution { rule_index } => {
                let addresses = match (destination, &self.dns) {
                    (Destination::Domain { host, .. }, Some(dns)) => dns
                        .resolve(context.domain().unwrap_or(host))
                        .await
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                resolved = Some(addresses);
                self.rules.evaluate_with_resolved_ips(
                    &mut context,
                    self.geo_matcher.as_ref(),
                    rule_index,
                    resolved.as_deref().unwrap_or_default(),
                )
            }
            evaluation => evaluation,
        };

        let RuleEvaluation::Matched(rule_match) = evaluation else {
            return Err(DispatchError::Other(
                "routing rules produced no final action".to_owned(),
            ));
        };

        let mut routed_destination = match destination {
            Destination::Domain { port, .. } => Destination::Domain {
                host: context
                    .domain()
                    .expect("domain destination has a normalized routing domain")
                    .to_owned(),
                port: *port,
            },
            Destination::Ip(_) => destination.clone(),
        };
        if let Some(address) = context.pinned_ip() {
            routed_destination =
                Destination::Ip(std::net::SocketAddr::new(address, destination.port()));
        } else if rule_match.action == RuleAction::Direct
            && let Destination::Domain { host, port } = destination
        {
            let addresses = if let Some(addresses) = resolved.as_deref() {
                addresses
            } else {
                resolved = Some(match &self.dns {
                    Some(dns) => dns
                        .resolve(context.domain().unwrap_or(host))
                        .await
                        .unwrap_or_default(),
                    None => Vec::new(),
                });
                resolved.as_deref().unwrap_or_default()
            };
            let address = preferred_address(addresses).ok_or(DispatchError::HostUnreachable)?;
            routed_destination = Destination::Ip(std::net::SocketAddr::new(address, *port));
        }

        Ok(RouteDecision {
            action: rule_match.action,
            destination: routed_destination,
        })
    }

    fn dns_tcp_stream(&self, dns: Arc<dyn RoutingDns>) -> BoxStream {
        let (client, mut server) = tokio::io::duplex(TCP_DNS_DUPLEX_CAPACITY);
        let relay = tokio::spawn(async move {
            let mut query = vec![0_u8; MAX_MESSAGE_SIZE];
            let mut length = [0_u8; 2];
            loop {
                if server.read_exact(&mut length).await.is_err() {
                    break;
                }
                let length = usize::from(u16::from_be_bytes(length));
                if length == 0 || length > MAX_MESSAGE_SIZE {
                    break;
                }
                if server.read_exact(&mut query[..length]).await.is_err() {
                    break;
                }
                let Ok(response) = dns.exchange(&query[..length]).await else {
                    break;
                };
                if response.wire().is_empty() || response.wire().len() > MAX_MESSAGE_SIZE {
                    break;
                }
                let Ok(response_len) = u16::try_from(response.wire().len()) else {
                    break;
                };
                if server.write_all(&response_len.to_be_bytes()).await.is_err()
                    || server.write_all(response.wire()).await.is_err()
                {
                    break;
                }
            }
            let _ = server.shutdown().await;
        });
        Box::new(DnsTcpStream {
            inner: client,
            relay,
        })
    }
}

/// Couples the local TCP DNS relay task to the stream returned to the inbound.
/// Dropping a cancelled TUN session aborts an in-flight upstream query instead
/// of leaving it detached in the runtime until its nameserver timeout expires.
struct DnsTcpStream {
    inner: DuplexStream,
    relay: JoinHandle<()>,
}

impl AsyncRead for DnsTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for DnsTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Drop for DnsTcpStream {
    fn drop(&mut self) {
        self.relay.abort();
    }
}

struct RouteDecision {
    action: RuleAction,
    destination: Destination,
}

fn log_route_decision(network: Network, decision: &RouteDecision) {
    let destination_port = decision.destination.port();
    match decision.action {
        RuleAction::Proxy(id) => tracing::debug!(
            ?network,
            action = "proxy",
            proxy_index = id.index(),
            destination_port,
            "routing decision"
        ),
        RuleAction::Direct => tracing::debug!(
            ?network,
            action = "direct",
            destination_port,
            "routing decision"
        ),
        RuleAction::Reject => tracing::debug!(
            ?network,
            action = "reject",
            destination_port,
            "routing decision"
        ),
    }
}

fn preferred_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.iter().copied().find(IpAddr::is_ipv6))
}

#[async_trait]
impl Dispatcher for RoutingDispatcher {
    async fn connect_tcp(&self, mut session: StreamSession) -> Result<BoxStream, DispatchError> {
        if session.inbound == InboundKind::Tun
            && session.destination.port() == 53
            && let Some(dns) = &self.dns
        {
            return Ok(self.dns_tcp_stream(dns.clone()));
        }

        let decision = self
            .route(
                Network::Tcp,
                session.inbound,
                &session.destination,
                session.sniffed_domain.as_deref(),
            )
            .await?;
        log_route_decision(Network::Tcp, &decision);
        session.destination = decision.destination;
        session.sniffed_domain = None;
        match decision.action {
            RuleAction::Proxy(id) => self.proxies.get(id)?.connect_tcp(session).await,
            RuleAction::Direct => self.direct.connect_tcp(session).await,
            RuleAction::Reject => Err(DispatchError::NotAllowed),
        }
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(RoutedDatagramTransport {
            router: self.clone_parts(),
            session,
            proxy_transports: HashMap::new(),
            direct_transport: None,
            logged_route_actions: HashSet::new(),
            receive_wakeup: Arc::new(Notify::new()),
        }))
    }
}

impl RoutingDispatcher {
    fn clone_parts(&self) -> Self {
        Self {
            proxies: self.proxies.clone(),
            direct: self.direct.clone(),
            dns: self.dns.clone(),
            rules: self.rules.clone(),
            geo_matcher: self.geo_matcher.clone(),
        }
    }
}

struct RoutedDatagramTransport {
    router: RoutingDispatcher,
    session: DatagramSession,
    proxy_transports: HashMap<ProxyId, Box<dyn DatagramTransport>>,
    direct_transport: Option<Box<dyn DatagramTransport>>,
    logged_route_actions: HashSet<LoggedRouteAction>,
    receive_wakeup: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LoggedRouteAction {
    Proxy(ProxyId),
    Direct,
    Reject,
}

impl From<RuleAction> for LoggedRouteAction {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Proxy(id) => Self::Proxy(id),
            RuleAction::Direct => Self::Direct,
            RuleAction::Reject => Self::Reject,
        }
    }
}

impl RoutedDatagramTransport {
    fn should_log_route_action(&mut self, action: RuleAction) -> bool {
        self.logged_route_actions.insert(action.into())
    }

    async fn send_proxy(&mut self, id: ProxyId, datagram: Datagram) -> Result<(), DispatchError> {
        if !self.proxy_transports.contains_key(&id) {
            let transport = self
                .router
                .proxies
                .get(id)?
                .open_datagram(self.session.clone())
                .await?;
            self.proxy_transports.insert(id, transport);
            self.receive_wakeup.notify_one();
        }
        self.proxy_transports
            .get_mut(&id)
            .expect("proxy transport was inserted")
            .send(datagram)
            .await
    }

    async fn send_direct(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.direct_transport.is_none() {
            self.direct_transport = Some(
                self.router
                    .direct
                    .open_datagram(self.session.clone())
                    .await?,
            );
            self.receive_wakeup.notify_one();
        }
        self.direct_transport
            .as_mut()
            .expect("direct transport initialized")
            .send(datagram)
            .await
    }

    async fn receive_inner(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            let mut receives = self
                .proxy_transports
                .values_mut()
                .map(|transport| transport.receive())
                .collect::<Vec<_>>();
            if let Some(direct) = self.direct_transport.as_mut() {
                receives.push(direct.receive());
            }
            if receives.is_empty() {
                self.receive_wakeup.notified().await;
                continue;
            }
            tokio::select! {
                _ = self.receive_wakeup.notified() => {}
                (result, _, _) = select_all(receives) => return result,
            }
        }
    }
}

#[async_trait]
impl DatagramTransport for RoutedDatagramTransport {
    async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
        let decision = self
            .router
            .route(
                Network::Udp,
                self.session.inbound,
                &datagram.remote,
                datagram.sniffed_domain.as_deref(),
            )
            .await?;
        if self.should_log_route_action(decision.action) {
            log_route_decision(Network::Udp, &decision);
        }
        datagram.remote = decision.destination;
        datagram.sniffed_domain = None;
        match decision.action {
            RuleAction::Proxy(id) => self.send_proxy(id, datagram).await,
            RuleAction::Direct => self.send_direct(datagram).await,
            // UDP REJECT applies only to this datagram. The association stays
            // alive so a later destination can select another action.
            RuleAction::Reject => Ok(()),
        }
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.receive_inner().await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        let mut first_error = None;
        for proxy in self.proxy_transports.values_mut() {
            if let Err(error) = proxy.close().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(direct) = &mut self.direct_transport
            && let Err(error) = direct.close().await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        self.proxy_transports.clear();
        self.direct_transport = None;
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{
        config::{IpCidr, PortRange, RuleKind, RuleSpec},
        routing::EmptyGeoMatcher,
    };

    #[derive(Default)]
    struct RecordingDispatcher {
        tcp_sessions: Mutex<Vec<StreamSession>>,
        datagrams: Arc<Mutex<Vec<Datagram>>>,
        udp_opens: AtomicUsize,
    }

    #[async_trait]
    impl Dispatcher for RecordingDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_sessions.lock().unwrap().push(session);
            let (client, _server) = tokio::io::duplex(64);
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_opens.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(RecordingDatagrams {
                sent: self.datagrams.clone(),
                responses: VecDeque::new(),
            }))
        }
    }

    struct RecordingDatagrams {
        sent: Arc<Mutex<Vec<Datagram>>>,
        responses: VecDeque<Datagram>,
    }

    #[async_trait]
    impl DatagramTransport for RecordingDatagrams {
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            self.sent.lock().unwrap().push(datagram.clone());
            self.responses.push_back(datagram);
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if let Some(response) = self.responses.pop_front() {
                return Ok(response);
            }
            std::future::pending().await
        }
    }

    struct MockDns {
        addresses: Vec<IpAddr>,
        hint: Option<(IpAddr, String)>,
        resolved_hosts: Mutex<Vec<String>>,
        resolve_calls: AtomicUsize,
        exchange_calls: AtomicUsize,
        hint_calls: AtomicUsize,
    }

    impl MockDns {
        fn new(addresses: Vec<IpAddr>) -> Self {
            Self {
                addresses,
                hint: None,
                resolved_hosts: Mutex::new(Vec::new()),
                resolve_calls: AtomicUsize::new(0),
                exchange_calls: AtomicUsize::new(0),
                hint_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl RoutingDns for MockDns {
        async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            self.resolve_calls.fetch_add(1, Ordering::Relaxed);
            self.resolved_hosts.lock().unwrap().push(host.to_owned());
            Ok(self.addresses.clone())
        }

        async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            self.exchange_calls.fetch_add(1, Ordering::Relaxed);
            Ok(DnsWireResponse::test_untracked(query.to_vec()))
        }

        async fn domain_hint(&self, address: IpAddr) -> Option<String> {
            self.hint_calls.fetch_add(1, Ordering::Relaxed);
            self.hint
                .as_ref()
                .filter(|(expected, _)| *expected == address)
                .map(|(_, domain)| domain.clone())
        }
    }

    struct BlockingDns {
        exchange_started: Notify,
        exchange_cancelled: Arc<AtomicBool>,
    }

    struct ExchangeGuard(Arc<AtomicBool>);

    impl Drop for ExchangeGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[async_trait]
    impl RoutingDns for BlockingDns {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            Ok(Vec::new())
        }

        async fn exchange(&self, _query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            let _guard = ExchangeGuard(self.exchange_cancelled.clone());
            self.exchange_started.notify_one();
            std::future::pending().await
        }

        async fn domain_hint(&self, _address: IpAddr) -> Option<String> {
            None
        }
    }

    #[derive(Default)]
    struct WireDns {
        query_types: Mutex<Vec<u16>>,
    }

    #[async_trait]
    impl RoutingDns for WireDns {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            Ok(Vec::new())
        }

        async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            let classified = crate::dns::classify_query(query)
                .map_err(|error| DispatchError::Other(error.to_string()))?;
            self.query_types
                .lock()
                .unwrap()
                .push(classified.question.query_type);
            crate::dns::synthesize_empty_response(&classified, 0)
                .map(DnsWireResponse::test_untracked)
                .map_err(|error| DispatchError::Other(error.to_string()))
        }

        async fn domain_hint(&self, _address: IpAddr) -> Option<String> {
            None
        }
    }

    fn rule(kind: RuleKind, action: RuleAction) -> RuleSpec {
        RuleSpec {
            kind,
            action,
            no_resolve: false,
        }
    }

    fn dispatcher(
        proxy: Arc<RecordingDispatcher>,
        direct: Arc<RecordingDispatcher>,
        dns: Option<Arc<dyn RoutingDns>>,
        rules: Vec<RuleSpec>,
    ) -> RoutingDispatcher {
        RoutingDispatcher::with_dns_service(
            proxy,
            direct,
            dns,
            RuleSet::compile(rules).unwrap(),
            Arc::new(EmptyGeoMatcher),
        )
    }

    fn dispatcher_with_proxies(
        proxies: Vec<Arc<RecordingDispatcher>>,
        direct: Arc<RecordingDispatcher>,
        rules: Vec<RuleSpec>,
    ) -> RoutingDispatcher {
        let proxies = ProxyDispatchers::new(
            proxies
                .into_iter()
                .map(|proxy| proxy as Arc<dyn Dispatcher>)
                .collect(),
        )
        .unwrap();
        RoutingDispatcher::new(
            proxies,
            direct,
            None,
            RuleSet::compile(rules).unwrap(),
            Arc::new(EmptyGeoMatcher),
        )
    }

    #[test]
    fn proxy_registry_accepts_ids_beyond_u8() {
        let proxies = (0..300)
            .map(|_| Arc::new(RecordingDispatcher::default()) as Arc<dyn Dispatcher>)
            .collect();
        let registry = ProxyDispatchers::new(proxies).unwrap();

        assert_eq!(registry.len(), 300);
        assert!(registry.get(ProxyId::new(299).unwrap()).is_ok());
        assert!(registry.get(ProxyId::new(300).unwrap()).is_err());
    }

    fn stream(destination: SocketAddr, inbound: InboundKind) -> StreamSession {
        StreamSession {
            inbound,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::Ip(destination),
            sniffed_domain: None,
        }
    }

    fn association(inbound: InboundKind) -> DatagramSession {
        DatagramSession::new(inbound, "127.0.0.1:10000".parse().unwrap())
    }

    fn datagram(destination: SocketAddr, payload: &'static [u8]) -> Datagram {
        Datagram {
            remote: Destination::Ip(destination),
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }

    fn wire_query(id: u16, query_type: u16) -> Vec<u8> {
        let mut query = crate::dns::build_query(id, "example.com", crate::dns::QueryType::A)
            .expect("test query is valid");
        let query_type_offset = query.len() - 4;
        query[query_type_offset..query_type_offset + 2].copy_from_slice(&query_type.to_be_bytes());
        query
    }

    #[tokio::test]
    async fn tcp_selects_proxy_direct_and_reject() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 80, end: 80 }]),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 25, end: 25 }]),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );

        router
            .connect_tcp(stream("192.0.2.1:80".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:443".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        assert!(matches!(
            router
                .connect_tcp(stream("192.0.2.1:25".parse().unwrap(), InboundKind::Http,))
                .await,
            Err(DispatchError::NotAllowed)
        ));

        assert_eq!(direct.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sniffed_domain_routes_tun_tcp_without_replacing_original_ip() {
        let destination: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "stale.example".to_owned()));
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(Arc::new(dns)),
            vec![
                rule(
                    RuleKind::Domain("stale.example".to_owned()),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::DomainSuffix("example.com".to_owned()),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );

        router
            .connect_tcp(StreamSession {
                inbound: InboundKind::Tun,
                source: "192.0.2.10:10000".parse().unwrap(),
                destination: Destination::Ip(destination),
                sniffed_domain: Some("api.Example.COM".to_owned()),
            })
            .await
            .unwrap();

        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        let sessions = direct.tcp_sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].destination, Destination::Ip(destination));
        assert_eq!(sessions[0].sniffed_domain, None);
    }

    #[tokio::test]
    async fn sniffed_domain_routes_tun_udp_without_replacing_original_ip() {
        let destination: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "stale.example".to_owned()));
        let dns = Arc::new(dns);
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::Domain("stale.example".to_owned()),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::DomainSuffix("example.com".to_owned()),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );
        let mut transport = router
            .open_datagram(DatagramSession::new(
                InboundKind::Tun,
                "192.0.2.10:10000".parse().unwrap(),
            ))
            .await
            .unwrap();
        transport
            .send(Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"quic"),
                sniffed_domain: Some(Arc::from("api.Example.COM")),
            })
            .await
            .unwrap();

        assert!(proxy.datagrams.lock().unwrap().is_empty());
        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 0);
        let datagrams = direct.datagrams.lock().unwrap();
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].remote, Destination::Ip(destination));
        assert_eq!(datagrams[0].sniffed_domain, None);
        assert_eq!(&datagrams[0].payload[..], b"quic");
    }

    #[tokio::test]
    async fn dns_and_sniffed_domain_hints_are_consumed_only_by_tun() {
        let destination: SocketAddr = "198.51.100.8:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "hint.example".to_owned()));
        let dns = Arc::new(dns);
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::Domain("hint.example".to_owned()),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );

        router
            .connect_tcp(StreamSession {
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::Ip(destination),
                sniffed_domain: Some("hint.example".to_owned()),
            })
            .await
            .unwrap();
        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 0);
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        assert!(direct.tcp_sessions.lock().unwrap().is_empty());

        router
            .connect_tcp(stream(destination, InboundKind::Tun))
            .await
            .unwrap();
        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 1);
        assert_eq!(direct.tcp_sessions.lock().unwrap().len(), 1);

        let mut http_udp = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        http_udp.send(datagram(destination, b"http")).await.unwrap();
        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 1);

        let mut tun_udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        tun_udp.send(datagram(destination, b"tun")).await.unwrap();
        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 2);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
        assert_eq!(direct.datagrams.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tun_without_domain_rules_does_not_query_dns_hints() {
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "unused.example".to_owned()));
        let dns = Arc::new(dns);
        let router = dispatcher(
            proxy.clone(),
            direct,
            Some(dns.clone()),
            vec![rule(
                RuleKind::Match,
                RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
            )],
        );

        router
            .connect_tcp(stream(destination, InboundKind::Tun))
            .await
            .unwrap();
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        udp.send(datagram(destination, b"tun")).await.unwrap();

        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 0);
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tcp_rules_select_dynamic_proxy_ids() {
        let proxies = (0..4)
            .map(|_| Arc::new(RecordingDispatcher::default()))
            .collect::<Vec<_>>();
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher_with_proxies(
            proxies.clone(),
            direct,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 80, end: 80 }]),
                    RuleAction::Proxy(ProxyId::new(3).unwrap()),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 81, end: 81 }]),
                    RuleAction::Proxy(ProxyId::new(2).unwrap()),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 82, end: 82 }]),
                    RuleAction::Proxy(ProxyId::new(1).unwrap()),
                ),
                rule(RuleKind::Match, RuleAction::Proxy(ProxyId::new(0).unwrap())),
            ],
        );

        router
            .connect_tcp(stream("192.0.2.1:80".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:81".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:82".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:443".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();

        for proxy in proxies {
            assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn one_udp_association_lazily_opens_dynamic_proxy_ids_once() {
        let proxies = (0..4)
            .map(|_| Arc::new(RecordingDispatcher::default()))
            .collect::<Vec<_>>();
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher_with_proxies(
            proxies.clone(),
            direct,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 53, end: 53 }]),
                    RuleAction::Proxy(ProxyId::new(3).unwrap()),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange {
                        start: 123,
                        end: 123,
                    }]),
                    RuleAction::Proxy(ProxyId::new(2).unwrap()),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange {
                        start: 500,
                        end: 500,
                    }]),
                    RuleAction::Proxy(ProxyId::new(1).unwrap()),
                ),
                rule(RuleKind::Match, RuleAction::Proxy(ProxyId::new(0).unwrap())),
            ],
        );
        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        for (port, payload) in [
            (53, b"three".as_slice()),
            (123, b"two".as_slice()),
            (500, b"one".as_slice()),
            (443, b"zero".as_slice()),
            (53, b"three-again".as_slice()),
            (123, b"two-again".as_slice()),
            (500, b"one-again".as_slice()),
            (443, b"zero-again".as_slice()),
        ] {
            transport
                .send(datagram(
                    format!("192.0.2.1:{port}").parse().unwrap(),
                    payload,
                ))
                .await
                .unwrap();
        }

        for proxy in &proxies {
            assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
            assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);
        }

        let mut responses = Vec::new();
        for _ in 0..8 {
            let response =
                tokio::time::timeout(std::time::Duration::from_millis(100), transport.receive())
                    .await
                    .expect("all dynamically opened proxy transports remain receivable")
                    .unwrap();
            responses.push(response.payload);
        }
        responses.sort();
        assert_eq!(
            responses,
            [
                Bytes::from_static(b"one"),
                Bytes::from_static(b"one-again"),
                Bytes::from_static(b"three"),
                Bytes::from_static(b"three-again"),
                Bytes::from_static(b"two"),
                Bytes::from_static(b"two-again"),
                Bytes::from_static(b"zero"),
                Bytes::from_static(b"zero-again"),
            ]
        );
    }

    #[tokio::test]
    async fn normalized_domain_is_reused_by_runtime_dns_and_outbound() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(vec![IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 7,
        ))]));
        let router = dispatcher(
            proxy,
            direct.clone(),
            Some(dns.clone()),
            vec![rule(RuleKind::Match, RuleAction::Direct)],
        );
        router
            .connect_tcp(StreamSession {
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::domain("例子.中国", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(
            *dns.resolved_hosts.lock().unwrap(),
            vec!["xn--fsqu00a.xn--fiqs8s"]
        );
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip("203.0.113.7:443".parse().unwrap())
        );

        let proxy = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            Arc::new(RecordingDispatcher::default()),
            None,
            vec![rule(
                RuleKind::Match,
                RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
            )],
        );
        router
            .connect_tcp(StreamSession {
                inbound: InboundKind::Http,
                source: "127.0.0.1:10001".parse().unwrap(),
                destination: Destination::domain("例子.中国", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(
            proxy.tcp_sessions.lock().unwrap()[0].destination,
            Destination::domain("xn--fsqu00a.xn--fiqs8s", 443).unwrap()
        );
    }

    #[tokio::test]
    async fn one_udp_association_lazily_uses_both_actions() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        prefix_len: 8,
                    }),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );
        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        transport
            .send(datagram("10.0.0.1:1234".parse().unwrap(), b"direct"))
            .await
            .unwrap();
        transport
            .send(datagram("192.0.2.1:1234".parse().unwrap(), b"proxy"))
            .await
            .unwrap();
        transport
            .send(datagram("10.0.0.2:1234".parse().unwrap(), b"direct2"))
            .await
            .unwrap();

        assert_eq!(direct.datagrams.lock().unwrap().len(), 2);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
        assert_eq!(direct.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn udp_associations_share_the_immutable_rule_set() {
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            Arc::new(RecordingDispatcher::default()),
            None,
            vec![rule(
                RuleKind::Match,
                RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
            )],
        );
        let association_router = router.clone_parts();

        assert!(Arc::ptr_eq(&router.rules, &association_router.rules));
    }

    #[tokio::test]
    async fn udp_reject_drops_only_the_current_datagram() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 9, end: 9 }]),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );
        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        transport
            .send(datagram("192.0.2.1:9".parse().unwrap(), b"drop"))
            .await
            .unwrap();
        transport
            .send(datagram("192.0.2.1:443".parse().unwrap(), b"keep"))
            .await
            .unwrap();

        assert!(direct.datagrams.lock().unwrap().is_empty());
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tcp_dns_hijack_is_tun_only_while_udp_uses_normal_routing() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(Vec::new()));
        let router = dispatcher(
            proxy.clone(),
            direct,
            Some(dns.clone()),
            vec![rule(
                RuleKind::Match,
                RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
            )],
        );

        let mut tun_udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        tun_udp
            .send(datagram("1.1.1.1:53".parse().unwrap(), b"udp-query"))
            .await
            .unwrap();
        let response = tun_udp.receive().await.unwrap();
        assert_eq!(&response.payload[..], b"udp-query");
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);

        let mut socks_udp = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        socks_udp
            .send(datagram("1.1.1.1:53".parse().unwrap(), b"normal"))
            .await
            .unwrap();
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);

        let mut tun_tcp = router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
            .await
            .unwrap();
        for query in [b"first".as_slice(), b"second".as_slice()] {
            tun_tcp.write_u16(query.len() as u16).await.unwrap();
            tun_tcp.write_all(query).await.unwrap();
            assert_eq!(tun_tcp.read_u16().await.unwrap() as usize, query.len());
            let mut response = vec![0_u8; query.len()];
            tun_tcp.read_exact(&mut response).await.unwrap();
            assert_eq!(response, query);
        }

        router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(dns.exchange_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn tun_dns_tcp_accepts_partial_and_pipelined_mixed_qtype_frames() {
        let dns = Arc::new(WireDns::default());
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            Arc::new(RecordingDispatcher::default()),
            Some(dns.clone()),
            vec![rule(
                RuleKind::Match,
                RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
            )],
        );
        let mut stream = router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
            .await
            .unwrap();
        let queries = [
            wire_query(0x1001, 1),
            wire_query(0x1002, 65),
            wire_query(0x1003, 28),
            wire_query(0x1004, 16),
        ];

        let first_length = u16::try_from(queries[0].len()).unwrap().to_be_bytes();
        stream.write_all(&first_length[..1]).await.unwrap();
        stream.write_all(&first_length[1..]).await.unwrap();
        let split = queries[0].len() / 2;
        stream.write_all(&queries[0][..split]).await.unwrap();
        stream.write_all(&queries[0][split..]).await.unwrap();
        for query in &queries[1..] {
            stream.write_u16(query.len() as u16).await.unwrap();
            stream.write_all(query).await.unwrap();
        }

        for query in &queries {
            let response_length = stream.read_u16().await.unwrap() as usize;
            let mut response = vec![0_u8; response_length];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &query[..2]);
            assert_ne!(response[2] & 0x80, 0);
        }
        assert_eq!(*dns.query_types.lock().unwrap(), vec![1, 65, 28, 16]);
    }

    #[tokio::test]
    async fn dropping_a_tun_dns_tcp_stream_cancels_its_relay_query() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let exchange_cancelled = Arc::new(AtomicBool::new(false));
        let dns = Arc::new(BlockingDns {
            exchange_started: Notify::new(),
            exchange_cancelled: exchange_cancelled.clone(),
        });
        let router = dispatcher(
            proxy,
            direct,
            Some(dns.clone()),
            vec![rule(
                RuleKind::Match,
                RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
            )],
        );

        let mut stream = router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
            .await
            .unwrap();
        stream.write_u16(5).await.unwrap();
        stream.write_all(b"query").await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            dns.exchange_started.notified(),
        )
        .await
        .expect("DNS relay never entered the exchange");

        drop(stream);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !exchange_cancelled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the caller stream did not abort the DNS relay");
    }

    #[tokio::test]
    async fn lazy_resolution_preserves_rule_priority_and_pins_the_match() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let selected = IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>().unwrap());
        let dns = Arc::new(MockDns::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            selected,
        ]));
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V6("2001:db8::".parse().unwrap()),
                        prefix_len: 32,
                    }),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        prefix_len: 8,
                    }),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );

        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        transport
            .send(Datagram {
                remote: Destination::domain("example.com", 443).unwrap(),
                payload: Bytes::from_static(b"payload"),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.datagrams.lock().unwrap().is_empty());
        let sent = direct.datagrams.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].remote,
            Destination::Ip(SocketAddr::new(selected, 443))
        );
    }

    #[tokio::test]
    async fn lazy_resolution_is_visible_to_later_no_resolve_rule() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let resolved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let dns = Arc::new(MockDns::new(vec![resolved]));
        let mut later_no_resolve = rule(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Direct,
        );
        later_no_resolve.no_resolve = true;
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                        prefix_len: 24,
                    }),
                    RuleAction::Reject,
                ),
                later_no_resolve,
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );

        router
            .connect_tcp(StreamSession {
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::domain("example.com", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip(SocketAddr::new(resolved, 443))
        );
    }

    #[tokio::test]
    async fn lazy_resolution_does_not_revisit_prior_no_resolve_rule() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let selected = IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>().unwrap());
        let dns = Arc::new(MockDns::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            selected,
        ]));
        let mut earlier_no_resolve = rule(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Reject,
        );
        earlier_no_resolve.no_resolve = true;
        let mut later_no_resolve = rule(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V6("2001:db8::".parse().unwrap()),
                prefix_len: 32,
            }),
            RuleAction::Direct,
        );
        later_no_resolve.no_resolve = true;
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                earlier_no_resolve,
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                        prefix_len: 24,
                    }),
                    RuleAction::Reject,
                ),
                later_no_resolve,
                rule(
                    RuleKind::Match,
                    RuleAction::Proxy(crate::config::ProxyId::new(0).unwrap()),
                ),
            ],
        );

        router
            .connect_tcp(StreamSession {
                inbound: InboundKind::Http,
                source: "127.0.0.1:10001".parse().unwrap(),
                destination: Destination::domain("example.com", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip(SocketAddr::new(selected, 443))
        );
    }
}
