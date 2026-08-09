#![cfg_attr(not(feature = "ffi"), allow(dead_code))]

use std::{future::Future, io, sync::Arc, time::Duration};

#[cfg(feature = "inbound-http")]
use std::net::SocketAddr;

use futures_util::future::{join_all, select_all};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[cfg(all(unix, feature = "tun"))]
use crate::{platform::TunIo, tun_runtime::TunRuntime};
#[cfg(not(all(unix, feature = "tun")))]
type TunRuntime = ();
#[cfg(all(unix, feature = "tun"))]
use crate::traffic::TrafficController;
#[cfg(not(all(unix, feature = "tun")))]
type TrafficController = ();

#[cfg(feature = "ffi")]
use crate::config::MeasureConfig;
#[cfg(test)]
use crate::config::ProxyId;
#[cfg(feature = "inbound-http")]
use crate::inbound::http::{HttpBasicAuth, HttpServer, HttpServerConfig};
use crate::{
    ResourceLimits,
    config::{Config, InboundConfig, ProxyConfig, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint, Resolver},
    dispatch::{Dispatcher, observe_handshakes_with_stats, observe_sessions_with_stats},
    dns::runtime::RuntimeDns,
    geodata::{
        GeoDataManager, GeoDataRegistration, GeoRequirements, service::GeoDataUpdateService,
    },
    outbound::{ConnectorDispatcher, DirectOutbound, OutboundConnector, UpstreamPath},
    resources::RuntimeResourceStats,
    routing::{GeoMatcher, ProxyDispatchers, RoutingDispatcher, RuleSet},
    traffic::TunTrafficStats,
};

#[cfg(feature = "outbound-socks5")]
use crate::outbound::Socks5Outbound;
#[cfg(feature = "outbound-anytls")]
use crate::outbound::{AnyTlsOutbound, server_destination};
#[cfg(feature = "outbound-vless")]
use crate::outbound::{VlessOutbound, VlessResourceLimits};
#[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
use crate::security::{SecurityContext, TLS_RESUMPTION_SESSION_BUDGET};
#[cfg(feature = "outbound-anytls")]
use crate::security::{StandardTlsClient, StandardTlsProfile};

/// Parsed configuration plus the bootstrap-resolved physical proxy roots.
#[derive(Debug)]
pub(crate) struct PreparedCore {
    config: Config,
    endpoints: Vec<PreparedProxyEndpoints>,
    limits: ResourceLimits,
    rules: RuleSet,
    geodata_manager: Arc<GeoDataManager>,
    geodata_registration: GeoDataRegistration,
    traffic_stats: Option<Arc<TunTrafficStats>>,
}

/// A node-only outbound graph prepared for one built-in latency probe.
///
/// Unlike `PreparedCore`, this type never registers GeoData, compiles rules,
/// builds DNS, or starts an inbound. Each value owns independent connector and
/// security state and is dropped when its measurement item completes.
#[cfg(feature = "ffi")]
pub(crate) struct PreparedMeasurement {
    config: MeasureConfig,
    endpoints: Vec<PreparedProxyEndpoints>,
    limits: ResourceLimits,
}

/// Bootstrap-resolved physical destinations for one proxy graph node.
///
/// Nodes with a `dialer-proxy` keep both entries empty because their logical
/// server names are resolved by the parent connector. Physical roots retain a
/// primary endpoint and, when XHTTP download settings are present, a second
/// endpoint for the independent download leg.
#[derive(Debug, Clone, Default)]
struct PreparedProxyEndpoints {
    upload: Option<ResolvedEndpoint>,
    download: Option<ResolvedEndpoint>,
}

#[cfg(feature = "ffi")]
pub(crate) struct MeasurementRuntime {
    dispatcher: Arc<dyn Dispatcher>,
    proxy_graph: BuiltProxyGraph,
}

#[cfg(feature = "ffi")]
impl MeasurementRuntime {
    #[must_use]
    pub(crate) fn dispatcher(&self) -> Arc<dyn Dispatcher> {
        self.dispatcher.clone()
    }

    pub(crate) async fn shutdown(self) {
        self.proxy_graph.begin_shutdown();
        self.proxy_graph.shutdown().await;
    }
}

#[cfg(feature = "ffi")]
impl Drop for MeasurementRuntime {
    fn drop(&mut self) {
        self.proxy_graph.begin_shutdown();
    }
}

struct BuiltRuntimeParts {
    dispatcher: Arc<dyn Dispatcher>,
    dns: Option<Arc<RuntimeDns>>,
    geodata_updater: Option<GeoDataUpdateService>,
    proxy_graph: BuiltProxyGraph,
}

struct BuiltProxyGraph {
    nodes: Vec<Arc<dyn OutboundConnector>>,
    lifecycle_order: Vec<Arc<dyn OutboundConnector>>,
}

impl BuiltProxyGraph {
    fn get(&self, index: usize) -> Option<&Arc<dyn OutboundConnector>> {
        self.nodes.get(index)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn connectors(&self) -> &[Arc<dyn OutboundConnector>] {
        &self.nodes
    }

    fn begin_shutdown(&self) {
        for connector in self.lifecycle_order.iter().rev() {
            connector.begin_shutdown();
        }
    }

    async fn shutdown(&self) {
        for connector in self.lifecycle_order.iter().rev() {
            connector.shutdown().await;
        }
    }
}

impl Drop for BuiltProxyGraph {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

impl PreparedCore {
    #[cfg(test)]
    async fn prepare(
        yaml: &[u8],
        resolver: &dyn Resolver,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        let config = Config::parse_yaml(yaml)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let directory = tempfile::tempdir()?;
        let manager = GeoDataManager::open(directory.path(), Duration::from_secs(24 * 60 * 60))
            .map_err(io::Error::other)?;
        Self::prepare_config(config, manager, resolver, limits).await
    }

    /// Completes bootstrap preparation for a configuration that has already
    /// passed strict schema validation. The Invoke layer uses this split to
    /// claim runtime-local resources, notably the unique TUN lease, before a
    /// potentially blocking DNS lookup.
    pub(crate) async fn prepare_config(
        mut config: Config,
        geodata_manager: Arc<GeoDataManager>,
        resolver: &dyn Resolver,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let (rules, geodata_registration) = prepare_routing(&mut config, &geodata_manager)?;
        let endpoints = prepare_proxy_endpoints(&config.proxies, resolver).await?;
        let traffic_stats = config
            .tun
            .enable
            .then(|| Arc::new(TunTrafficStats::default()));
        Ok(Self {
            config,
            endpoints,
            limits,
            rules,
            geodata_manager,
            geodata_registration,
            traffic_stats,
        })
    }

    /// Performs every configuration-owned validation step without resolving
    /// the proxy, opening GeoData files, or retaining a matcher.
    pub(crate) fn validate_config(mut config: Config) -> io::Result<()> {
        GeoRequirements::collect(&config.rules, &config.dns.nameserver_policies)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        RuleSet::compile(std::mem::take(&mut config.rules))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(())
    }

    #[must_use]
    #[cfg(test)]
    fn proxy(&self, id: ProxyId) -> &ProxyConfig {
        &self.config.proxies[id.index()]
    }

    #[must_use]
    #[cfg(test)]
    fn endpoint(&self, id: ProxyId) -> Option<&ResolvedEndpoint> {
        self.endpoints
            .get(id.index())
            .and_then(|endpoints| endpoints.upload.as_ref())
    }

    #[must_use]
    #[cfg(test)]
    fn download_endpoint(&self, id: ProxyId) -> Option<&ResolvedEndpoint> {
        self.endpoints
            .get(id.index())
            .and_then(|endpoints| endpoints.download.as_ref())
    }

    #[must_use]
    pub(crate) fn has_tun(&self) -> bool {
        self.config
            .inbounds
            .iter()
            .any(|inbound| matches!(inbound, InboundConfig::Tun(_)))
    }

    #[must_use]
    pub(crate) fn traffic_stats(&self) -> Option<Arc<TunTrafficStats>> {
        self.traffic_stats.clone()
    }

    fn dns_redir_host_entries(&self) -> usize {
        if self.has_tun() && self.rules.uses_domain_routing() {
            self.limits.dns_redir_host_entries
        } else {
            0
        }
    }

    fn domain_sniffer_config(&self) -> Option<Arc<crate::config::SnifferConfig>> {
        (self.has_tun() && self.config.sniffer.enable && self.rules.uses_domain_routing())
            .then(|| Arc::new(self.config.sniffer.clone()))
    }

    fn build_dispatcher(&self, dialer: Dialer) -> io::Result<BuiltRuntimeParts> {
        let handshake_stats = RuntimeResourceStats::new("runtime_handshake_observation");
        let proxy_graph = self.build_proxy_graph(dialer.clone())?;
        let geodata_proxy = proxy_graph
            .get(self.config.default_proxy.index())
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "default proxy is missing from the runtime graph",
                )
            })?;
        let geodata_dispatcher: Arc<dyn Dispatcher> =
            Arc::new(ConnectorDispatcher::new(geodata_proxy));
        let proxies = self.wrap_proxy_dispatchers(proxy_graph.connectors(), &handshake_stats)?;
        let direct_raw: Arc<dyn Dispatcher> = Arc::new(DirectOutbound::new(dialer));
        let direct = observe_handshakes_with_stats(direct_raw, handshake_stats.clone());
        let rules = self.rules.clone();
        let redir_host_entries = self.dns_redir_host_entries();
        let geo_matcher: Arc<dyn GeoMatcher> = self.geodata_registration.matcher();
        let dns = self.config.dns.enable.then(|| {
            Arc::new(RuntimeDns::new_routed_proxies_with_cache_limits(
                &self.config.dns,
                proxies.clone(),
                direct.clone(),
                rules.clone(),
                geo_matcher.clone(),
                self.limits.dns_address_cache_entries,
                redir_host_entries,
            ))
        });
        let router: Arc<dyn Dispatcher> = Arc::new(RoutingDispatcher::new(
            proxies,
            direct,
            dns.clone(),
            rules,
            geo_matcher,
        ));
        let session_stats = RuntimeResourceStats::new("runtime_session_observation");
        Ok(BuiltRuntimeParts {
            dispatcher: observe_sessions_with_stats(router, session_stats),
            dns,
            geodata_updater: {
                let report = self.geodata_registration.initial_report();
                let required = report.geosite.required || report.geoip.required;
                self.config
                    .geodata_update
                    .as_ref()
                    .filter(|update| update.auto_update && required)
                    .map(|update| {
                        GeoDataUpdateService::new(
                            self.geodata_manager.clone(),
                            geodata_dispatcher,
                            self.geodata_registration.updater_lease(),
                            update.urls.clone(),
                        )
                    })
            },
            proxy_graph,
        })
    }

    fn build_proxy_graph(&self, dialer: Dialer) -> io::Result<BuiltProxyGraph> {
        build_proxy_graph(&self.config.proxies, &self.endpoints, self.limits, dialer)
    }

    fn wrap_proxy_dispatchers(
        &self,
        connectors: &[Arc<dyn OutboundConnector>],
        handshake_stats: &RuntimeResourceStats,
    ) -> io::Result<ProxyDispatchers> {
        let mut dispatchers = Vec::with_capacity(connectors.len());
        for (proxy, connector) in self.config.proxies.iter().zip(connectors) {
            let mut dispatcher: Arc<dyn Dispatcher> = Arc::new(
                ConnectorDispatcher::with_udp_capability(connector.clone(), proxy.udp),
            );
            dispatcher = observe_handshakes_with_stats(dispatcher, handshake_stats.clone());
            dispatchers.push(dispatcher);
        }
        ProxyDispatchers::new(dispatchers)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    /// Starts configured local proxy listeners. TUN is started separately once
    /// a platform descriptor and netstack are available.
    pub(crate) async fn start_local(self, dialer: Dialer) -> io::Result<RunningCore> {
        let BuiltRuntimeParts {
            dispatcher,
            geodata_updater,
            proxy_graph,
            ..
        } = self.build_dispatcher(dialer)?;
        RunningCore::start_components(
            &self.config.inbounds,
            dispatcher,
            None,
            None,
            None,
            geodata_updater,
            self.geodata_registration,
            proxy_graph,
        )
        .await
    }

    /// Starts the configured TUN listener and any loopback HTTP listener in the
    /// same cancellation domain.
    #[cfg(all(unix, feature = "tun"))]
    pub(crate) async fn start_tun(self, tun: TunIo, dialer: Dialer) -> io::Result<RunningCore> {
        let tun_count = self
            .config
            .inbounds
            .iter()
            .filter(|inbound| matches!(inbound, InboundConfig::Tun(_)))
            .count();
        if tun_count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("start_tun requires exactly one TUN listener, found {tun_count}"),
            ));
        }
        let BuiltRuntimeParts {
            dispatcher,
            dns,
            geodata_updater,
            proxy_graph,
        } = self.build_dispatcher(dialer)?;
        let sniffer = self.domain_sniffer_config();
        let traffic_stats = self
            .traffic_stats()
            .unwrap_or_else(|| Arc::new(TunTrafficStats::default()));
        let traffic_controller = match &self.config.external_controller {
            Some(config) => Some(TrafficController::bind(config, traffic_stats.clone()).await?),
            None => None,
        };
        let tun_runtime = TunRuntime::new_with_stats(
            tun,
            self.limits,
            dispatcher.clone(),
            dns,
            true,
            sniffer,
            traffic_stats.clone(),
        )?;
        RunningCore::start_components(
            &self.config.inbounds,
            dispatcher,
            Some(tun_runtime),
            Some(traffic_stats),
            traffic_controller,
            geodata_updater,
            self.geodata_registration,
            proxy_graph,
        )
        .await
    }
}

#[cfg(feature = "ffi")]
impl PreparedMeasurement {
    pub(crate) async fn prepare_config(
        config: MeasureConfig,
        resolver: &dyn Resolver,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let endpoints = prepare_proxy_endpoints(&config.proxies, resolver).await?;
        Ok(Self {
            config,
            endpoints,
            limits,
        })
    }

    pub(crate) fn into_runtime(self, dialer: Dialer) -> io::Result<MeasurementRuntime> {
        let proxy_graph =
            build_proxy_graph(&self.config.proxies, &self.endpoints, self.limits, dialer)?;
        let connector = proxy_graph
            .get(self.config.default_proxy.index())
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "default proxy is missing from the measurement graph",
                )
            })?;
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(ConnectorDispatcher::new(connector));
        let handshake_stats = RuntimeResourceStats::new("measurement_handshake_observation");
        let dispatcher = observe_handshakes_with_stats(dispatcher, handshake_stats);
        let session_stats = RuntimeResourceStats::new("measurement_session_observation");
        Ok(MeasurementRuntime {
            dispatcher: observe_sessions_with_stats(dispatcher, session_stats),
            proxy_graph,
        })
    }
}

fn build_proxy_graph(
    proxies: &[ProxyConfig],
    endpoints: &[PreparedProxyEndpoints],
    limits: ResourceLimits,
    dialer: Dialer,
) -> io::Result<BuiltProxyGraph> {
    if endpoints.len() != proxies.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy endpoint registry length does not match the proxy graph",
        ));
    }
    #[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
    let (security_client_count, standard_tls_count) = security_counts(proxies);
    #[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
    let security_context = (security_client_count != 0).then(SecurityContext::new);
    #[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
    let resumption_sessions = standard_tls_resumption_sessions(standard_tls_count);

    // Every node has at most one parent (`dialer-proxy`). Walk each unresolved
    // parent chain once, then construct it root-first while unwinding. The
    // state vector both detects cycles and keeps a long chain O(n).
    const UNVISITED: u8 = 0;
    const VISITING: u8 = 1;
    const BUILT: u8 = 2;
    let mut states = vec![UNVISITED; proxies.len()];
    let mut nodes: Vec<Option<Arc<dyn OutboundConnector>>> = std::iter::repeat_with(|| None)
        .take(proxies.len())
        .collect();
    let mut lifecycle_order = Vec::with_capacity(proxies.len());
    for start in 0..proxies.len() {
        if states[start] == BUILT {
            continue;
        }
        let mut path = Vec::new();
        let mut current = start;
        loop {
            match states.get(current).copied() {
                Some(BUILT) => break,
                Some(VISITING) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "proxy graph is cyclic",
                    ));
                }
                Some(UNVISITED) => {
                    states[current] = VISITING;
                    path.push(current);
                }
                Some(_) => unreachable!("proxy graph state is internal"),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "proxy graph references an unknown parent",
                    ));
                }
            }
            let Some(parent) = proxies[current].dialer_proxy else {
                break;
            };
            current = parent.index();
        }

        while let Some(index) = path.pop() {
            let proxy = &proxies[index];
            let upstream = match proxy.dialer_proxy {
                Some(id) => {
                    let upstream = nodes
                        .get(id.index())
                        .and_then(Option::as_ref)
                        .cloned()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("proxy `{}` references an unresolved parent", proxy.tag),
                            )
                        })?;
                    UpstreamPath::proxy(upstream)
                }
                None => UpstreamPath::direct(
                    endpoints
                        .get(index)
                        .and_then(|endpoints| endpoints.upload.as_ref())
                        .cloned()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "physical proxy root `{}` has no prepared endpoint",
                                    proxy.tag
                                ),
                            )
                        })?,
                    dialer.clone(),
                ),
            };
            let connector: Arc<dyn OutboundConnector> = match &proxy.protocol {
                ProxyProtocol::Vless(config) => {
                    #[cfg(feature = "outbound-vless")]
                    {
                        let download_upstream = config.xhttp.download.as_ref().map(|_| {
                            match proxy.dialer_proxy {
                                Some(_) => Ok(upstream.clone()),
                                None => endpoints
                                    .get(index)
                                    .and_then(|endpoints| endpoints.download.as_ref())
                                    .cloned()
                                    .map(|endpoint| {
                                        UpstreamPath::direct(endpoint, dialer.clone())
                                    })
                                    .ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidInput,
                                            format!(
                                                "physical VLESS root `{}` has no prepared download endpoint",
                                                proxy.tag
                                            ),
                                        )
                                    }),
                            }
                        }).transpose()?;
                        Arc::new(VlessOutbound::new_with_shared_security(
                            config,
                            upstream,
                            download_upstream,
                            security_context
                                .as_ref()
                                .expect("VLESS graph has shared security material"),
                            resumption_sessions,
                            VlessResourceLimits::new(
                                limits.tls_buffer_limit,
                                limits.xhttp_send_buffer_size,
                                limits.xhttp_upload_chunk_size,
                            ),
                        )?)
                    }
                    #[cfg(not(feature = "outbound-vless"))]
                    {
                        let _ = (config, upstream);
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "VLESS outbound support is disabled at build time",
                        ));
                    }
                }
                ProxyProtocol::Socks5(config) => {
                    #[cfg(feature = "outbound-socks5")]
                    {
                        Arc::new(Socks5Outbound::new_with_path(config, upstream)?)
                    }
                    #[cfg(not(feature = "outbound-socks5"))]
                    {
                        let _ = (config, upstream);
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "SOCKS5 outbound support is disabled at build time",
                        ));
                    }
                }
                ProxyProtocol::AnyTls(config) => {
                    #[cfg(feature = "outbound-anytls")]
                    {
                        let tls = StandardTlsClient::new(
                            security_context
                                .as_ref()
                                .expect("AnyTLS graph has shared security material"),
                            &config.server_name,
                            StandardTlsProfile::AnyTls,
                            resumption_sessions,
                            limits.tls_buffer_limit,
                        )?;
                        Arc::new(AnyTlsOutbound::new(
                            server_destination(&config.address, config.port)?,
                            upstream,
                            &config.password,
                            Arc::new(tls),
                            limits.tcp_buffer_per_direction,
                        )?)
                    }
                    #[cfg(not(feature = "outbound-anytls"))]
                    {
                        let _ = (config, upstream);
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "AnyTLS outbound support is disabled at build time",
                        ));
                    }
                }
            };
            lifecycle_order.push(connector.clone());
            nodes[index] = Some(connector);
            states[index] = BUILT;
        }
    }
    Ok(BuiltProxyGraph {
        nodes: nodes
            .into_iter()
            .map(|node| node.expect("every validated proxy graph node was built"))
            .collect(),
        lifecycle_order,
    })
}

async fn prepare_proxy_endpoints(
    proxies: &[ProxyConfig],
    resolver: &dyn Resolver,
) -> io::Result<Vec<PreparedProxyEndpoints>> {
    let lookups = proxies
        .iter()
        .enumerate()
        .filter(|(_, proxy)| proxy.dialer_proxy.is_none())
        .map(|(index, proxy)| async move {
            let upload_address = proxy.address();
            let upload_port = proxy.port();
            let download = match &proxy.protocol {
                ProxyProtocol::Vless(config) => config.xhttp.download.as_deref(),
                ProxyProtocol::Socks5(_) | ProxyProtocol::AnyTls(_) => None,
            };

            let (upload, download) = match download {
                Some(download)
                    if download.address != upload_address || download.port != upload_port =>
                {
                    let (upload, download) = tokio::join!(
                        resolver.resolve(upload_address, upload_port),
                        resolver.resolve(&download.address, download.port),
                    );
                    (upload?, Some(download?))
                }
                Some(_) => {
                    let upload = resolver.resolve(upload_address, upload_port).await?;
                    (upload.clone(), Some(upload))
                }
                None => (resolver.resolve(upload_address, upload_port).await?, None),
            };
            Ok::<_, io::Error>((
                index,
                PreparedProxyEndpoints {
                    upload: Some(upload),
                    download,
                },
            ))
        });
    let resolved = tokio::time::timeout(Duration::from_secs(10), join_all(lookups))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bootstrap DNS timed out"))?;
    let mut endpoints = vec![PreparedProxyEndpoints::default(); proxies.len()];
    for endpoint in resolved {
        let (index, endpoint) = endpoint?;
        endpoints[index] = endpoint;
    }
    Ok(endpoints)
}

#[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
fn security_counts(proxies: &[ProxyConfig]) -> (usize, usize) {
    proxies.iter().fold(
        (0, 0),
        |(client_count, standard_count), proxy| match &proxy.protocol {
            ProxyProtocol::Vless(config) => {
                let download = config.xhttp.download.as_deref();
                (
                    client_count + 1 + usize::from(download.is_some()),
                    standard_count
                        + usize::from(matches!(
                            &config.security,
                            crate::config::SecurityConfig::Tls(_)
                        ))
                        + download.map_or(0, |download| {
                            usize::from(matches!(
                                &download.security,
                                crate::config::SecurityConfig::Tls(_)
                            ))
                        }),
                )
            }
            ProxyProtocol::AnyTls(_) => (client_count + 1, standard_count + 1),
            ProxyProtocol::Socks5(_) => (client_count, standard_count),
        },
    )
}

#[cfg(any(feature = "outbound-anytls", feature = "outbound-vless"))]
fn standard_tls_resumption_sessions(standard_tls_count: usize) -> usize {
    if standard_tls_count == 0 || standard_tls_count > TLS_RESUMPTION_SESSION_BUDGET {
        0
    } else {
        TLS_RESUMPTION_SESSION_BUDGET / standard_tls_count
    }
}

fn prepare_routing(
    config: &mut Config,
    geodata_manager: &Arc<GeoDataManager>,
) -> io::Result<(RuleSet, GeoDataRegistration)> {
    let requirements = GeoRequirements::collect(&config.rules, &config.dns.nameserver_policies)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let geodata_registration = geodata_manager
        .register(requirements)
        .map_err(io::Error::other)?;
    // GeoData must inspect the normalized rule specifications first. Once that
    // borrowing load is complete, move the rules directly into the compiled
    // set so PreparedCore does not retain a second owned rule graph.
    let rules = RuleSet::compile(std::mem::take(&mut config.rules))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok((rules, geodata_registration))
}

pub(crate) struct RunningCore {
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    traffic_stats: Option<Arc<TunTrafficStats>>,
    proxy_graph: BuiltProxyGraph,
    _geodata_registration: GeoDataRegistration,
}

impl std::fmt::Debug for RunningCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningCore")
            .field("task_count", &self.tasks.len())
            .field("has_traffic_stats", &self.traffic_stats.is_some())
            .finish_non_exhaustive()
    }
}

impl RunningCore {
    // Runtime construction keeps ownership transfers explicit; grouping these
    // independent components into another one-use container would only hide
    // the shutdown responsibilities enforced below.
    #[allow(clippy::too_many_arguments)]
    async fn start_components(
        inbounds: &[InboundConfig],
        dispatcher: Arc<dyn Dispatcher>,
        tun_runtime: Option<TunRuntime>,
        traffic_stats: Option<Arc<TunTrafficStats>>,
        traffic_controller: Option<TrafficController>,
        geodata_updater: Option<GeoDataUpdateService>,
        geodata_registration: GeoDataRegistration,
        proxy_graph: BuiltProxyGraph,
    ) -> io::Result<Self> {
        let cancellation = CancellationToken::new();
        let mut tasks = Vec::with_capacity(
            inbounds.len()
                + usize::from(tun_runtime.is_some())
                + usize::from(traffic_controller.is_some())
                + usize::from(geodata_updater.is_some()),
        );
        #[cfg(not(feature = "inbound-http"))]
        let _ = &dispatcher;

        for inbound in inbounds {
            match inbound {
                InboundConfig::Http(config) => {
                    #[cfg(not(feature = "inbound-http"))]
                    {
                        let _ = config;
                        cancellation.cancel();
                        abort_and_join(&mut tasks).await;
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "HTTP listener support is disabled at build time",
                        ));
                    }
                    #[cfg(feature = "inbound-http")]
                    {
                        let address = SocketAddr::new(config.listen, config.port);
                        let authentication =
                            HttpBasicAuth::new(config.username.clone(), config.password.clone())?;
                        let server = match HttpServer::bind(
                            HttpServerConfig::loopback(address, authentication)?,
                            dispatcher.clone(),
                        )
                        .await
                        {
                            Ok(server) => server,
                            Err(error) => {
                                cancellation.cancel();
                                abort_and_join(&mut tasks).await;
                                return Err(error);
                            }
                        };
                        let child = cancellation.clone();
                        tasks.push(tokio::spawn(server.serve(child)));
                    }
                }
                InboundConfig::Tun(_) => {
                    if tun_runtime.is_none() {
                        cancellation.cancel();
                        abort_and_join(&mut tasks).await;
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "TUN listener requires start_tun with a platform descriptor",
                        ));
                    }
                }
            }
        }

        #[cfg(all(unix, feature = "tun"))]
        if let Some(tun_runtime) = tun_runtime {
            let child = cancellation.clone();
            tasks.push(tokio::spawn(tun_runtime.run(child)));
        }

        #[cfg(all(unix, feature = "tun"))]
        if let Some(traffic_controller) = traffic_controller {
            let child = cancellation.clone();
            tasks.push(tokio::spawn(traffic_controller.serve(child)));
        }

        if let Some(geodata_updater) = geodata_updater {
            let child = cancellation.clone();
            tasks.push(tokio::spawn(geodata_updater.run(child)));
        }

        Ok(Self {
            cancellation,
            tasks,
            traffic_stats,
            proxy_graph,
            _geodata_registration: geodata_registration,
        })
    }

    pub(crate) async fn stop(self) -> io::Result<()> {
        self.run_until_shutdown(std::future::ready(Ok(()))).await
    }

    /// Runs until the host requests shutdown or any long-lived component
    /// exits. A component that ends before shutdown is always treated as a
    /// core failure, even when it returned `Ok(())`.
    pub(crate) async fn run_until_shutdown<F>(mut self, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = io::Result<()>>,
    {
        tokio::pin!(shutdown);
        let (completed, shutdown_error) = tokio::select! {
            biased;
            result = &mut shutdown => (None, result.err()),
            completed = wait_first_task(&mut self.tasks), if !self.tasks.is_empty() => (completed, None),
        };
        self.proxy_graph.begin_shutdown();
        self.cancellation.cancel();
        let mut first_error = shutdown_error.or_else(|| completed.map(component_completion_error));
        for task in self.tasks.drain(..) {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(error) if first_error.is_none() => {
                    first_error = Some(io::Error::other(error));
                }
                _ => {}
            }
        }
        self.proxy_graph.shutdown().await;
        first_error.map_or(Ok(()), Err)
    }
}

async fn wait_first_task(
    tasks: &mut Vec<JoinHandle<io::Result<()>>>,
) -> Option<Result<io::Result<()>, tokio::task::JoinError>> {
    if tasks.is_empty() {
        return None;
    }
    let (result, index, remaining) = select_all(tasks.iter_mut()).await;
    drop(remaining);
    drop(tasks.swap_remove(index));
    Some(result)
}

fn component_completion_error(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Error {
    match result {
        Ok(Ok(())) => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "VCore runtime component stopped unexpectedly",
        ),
        Ok(Err(error)) => error,
        Err(error) => io::Error::other(error),
    }
}

impl Drop for RunningCore {
    fn drop(&mut self) {
        self.proxy_graph.begin_shutdown();
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn abort_and_join(tasks: &mut Vec<JoinHandle<io::Result<()>>>) {
    for task in tasks.iter() {
        task.abort();
    }
    for task in tasks.drain(..) {
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[cfg(all(unix, feature = "tun"))]
    use std::net::Ipv4Addr;

    #[cfg(all(unix, feature = "tun"))]
    use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram};

    use async_trait::async_trait;
    use tempfile::tempdir;
    #[cfg(all(unix, feature = "tun"))]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    #[cfg(all(unix, feature = "tun"))]
    use crate::config::TunInboundConfig;
    use crate::dialer::ResolvedEndpoint;

    struct FixedResolver;

    #[async_trait]
    impl Resolver for FixedResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            Ok(ResolvedEndpoint {
                logical_host: host.to_owned(),
                port,
                addresses: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)],
            })
        }
    }

    #[derive(Default)]
    struct RecordingResolver {
        hosts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Resolver for RecordingResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            self.hosts.lock().unwrap().push(host.to_owned());
            Ok(ResolvedEndpoint {
                logical_host: host.to_owned(),
                port,
                addresses: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)],
            })
        }
    }

    #[derive(Default)]
    struct ConcurrentResolver {
        active: AtomicUsize,
        peak: AtomicUsize,
    }

    #[async_trait]
    impl Resolver for ConcurrentResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.peak.fetch_max(active, Ordering::AcqRel);
            tokio::time::sleep(Duration::from_millis(25)).await;
            self.active.fetch_sub(1, Ordering::AcqRel);
            Ok(ResolvedEndpoint {
                logical_host: host.to_owned(),
                port,
                addresses: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)],
            })
        }
    }

    const CONFIG: &str = r#"port: 18080
authentication:
  - measure:secret
proxies:
  - name: proxy
    type: vless
    server: server.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      path: /x
      mode: packet-up
rules:
  - MATCH,proxy
"#;

    fn config_with_rules(rules: &str) -> String {
        CONFIG.replacen("rules:\n  - MATCH,proxy\n", rules, 1)
    }

    fn config_with_download(fields: &str) -> String {
        CONFIG.replace(
            "      mode: packet-up\n",
            &format!("      mode: packet-up\n      download-settings:\n{fields}\n"),
        )
    }

    #[tokio::test]
    async fn prepare_resolves_the_sole_outbound() {
        let prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let id = ProxyId::new(0).unwrap();
        assert_eq!(prepared.proxy(id).tag, "proxy");
        assert!(matches!(
            prepared.proxy(id).protocol,
            ProxyProtocol::Vless(_)
        ));
        assert_eq!(prepared.endpoint(id).unwrap().logical_host, "server.test");
        assert!(!prepared.has_tun());
        assert!(
            prepared.config.rules.is_empty(),
            "normalized rules must be moved out of the retained config"
        );
        assert_eq!(prepared.rules.len(), 1);
        assert_eq!(
            prepared.rules.rule(0).map(|rule| rule.action),
            Some(crate::config::RuleAction::Proxy(id)),
            "moving the normalized rules must preserve the compiled default route"
        );
    }

    #[tokio::test]
    async fn prepare_reuses_one_resolution_for_an_identical_download_server() {
        let resolver = RecordingResolver::default();
        let yaml = CONFIG.replace(
            "      mode: packet-up\n",
            "      mode: packet-up\n      download-settings: {}\n",
        );
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        assert_eq!(*resolver.hosts.lock().unwrap(), ["server.test".to_owned()]);

        let id = ProxyId::new(0).unwrap();
        let upload = prepared.endpoint(id).unwrap();
        let download = prepared.download_endpoint(id).unwrap();
        assert_eq!(upload, download);
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn prepare_resolves_distinct_download_server_concurrently() {
        let resolver = ConcurrentResolver::default();
        let yaml = config_with_download("        server: download.test\n        port: 8443");
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        assert_eq!(resolver.peak.load(Ordering::Acquire), 2);

        let id = ProxyId::new(0).unwrap();
        assert_eq!(prepared.endpoint(id).unwrap().logical_host, "server.test");
        let download = prepared.download_endpoint(id).unwrap();
        assert_eq!(download.logical_host, "download.test");
        assert_eq!(download.port, 8443);
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            1
        );
    }

    #[test]
    fn security_budget_counts_every_vless_transport_leg() {
        let yaml = config_with_download("        server: download.test\n        port: 8443");
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(security_counts(&config.proxies), (2, 2));
        assert_eq!(standard_tls_resumption_sessions(2), 2);
    }

    #[tokio::test]
    async fn production_redir_host_store_requires_tun_and_domain_rules() {
        let domain_rules = r#"
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - MATCH,proxy
"#;
        let tun = r#"
tun:
  enable: true
  mtu: 1500
"#;

        let no_tun = PreparedCore::prepare(
            config_with_rules(domain_rules).as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(no_tun.dns_redir_host_entries(), 0);

        let no_domain_rules = PreparedCore::prepare(
            format!("{CONFIG}{tun}").as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(no_domain_rules.dns_redir_host_entries(), 0);

        let enabled = PreparedCore::prepare(
            format!("{}{tun}", config_with_rules(domain_rules)).as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            enabled.dns_redir_host_entries(),
            ResourceLimits::default().dns_redir_host_entries
        );
        assert!(
            enabled.domain_sniffer_config().is_none(),
            "redir-host remains available when the optional sniffer is omitted"
        );
    }

    #[tokio::test]
    async fn production_domain_sniffer_requires_tun_enable_and_domain_rules() {
        let domain_rules = r#"
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - MATCH,proxy
"#;
        let tun = r#"
tun:
  enable: true
  mtu: 1500
"#;
        let sniffer = r#"
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [8080]
    TLS:
      ports: ["8443-8444"]
"#;

        let no_tun = PreparedCore::prepare(
            format!("{}{sniffer}", config_with_rules(domain_rules)).as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(no_tun.domain_sniffer_config().is_none());

        let no_domain_rules = PreparedCore::prepare(
            format!("{CONFIG}{tun}{sniffer}").as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(no_domain_rules.domain_sniffer_config().is_none());

        let disabled = PreparedCore::prepare(
            format!(
                "{}{tun}sniffer:\n  enable: false\n  sniff:\n    HTTP: {{}}\n",
                config_with_rules(domain_rules)
            )
            .as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(disabled.domain_sniffer_config().is_none());
        assert_eq!(
            disabled.dns_redir_host_entries(),
            ResourceLimits::default().dns_redir_host_entries,
            "sniffer disablement must not remove DNS routing hints"
        );

        let enabled = PreparedCore::prepare(
            format!("{}{tun}{sniffer}", config_with_rules(domain_rules)).as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let normalized = enabled
            .domain_sniffer_config()
            .expect("all three production sniffer gates are enabled");
        assert!(normalized.matches_http_port(8080));
        assert!(!normalized.matches_http_port(80));
        assert!(normalized.matches_tls_port(8444));
        assert!(!normalized.matches_tls_port(443));
    }

    #[test]
    fn nameserver_policy_validation_does_not_require_geosite_asset() {
        let yaml = format!(
            r#"{CONFIG}
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#proxy"]
  nameserver-policy:
    "geosite:private,cn,apple":
      - "tcp://223.5.5.5:53#DIRECT"
"#
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        PreparedCore::validate_config(config).unwrap();
    }

    #[cfg(feature = "outbound-vless")]
    #[tokio::test]
    async fn geodata_updater_requires_enabled_config_and_actual_demand() {
        fn configured(auto_update: bool, geodata_rule: bool) -> String {
            let fields = format!(
                r#"geox-url:
  geoip: https://downloads.example.test/custom-geoip.dat
  geosite: https://downloads.example.test/custom-geosite.dat
geo-auto-update: {auto_update}
geo-update-interval: 24
"#
            );
            if geodata_rule {
                config_with_rules("rules:\n  - GEOSITE,cn,proxy\n  - MATCH,proxy\n").replacen(
                    "port: 18080\n",
                    &format!("{fields}port: 18080\n"),
                    1,
                )
            } else {
                CONFIG.replacen("port: 18080\n", &format!("{fields}port: 18080\n"), 1)
            }
        }

        async fn updater_for(yaml: &str) -> Option<GeoDataUpdateService> {
            PreparedCore::prepare(yaml.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap()
                .build_dispatcher(Dialer::default())
                .unwrap()
                .geodata_updater
        }

        let missing_config_with_demand =
            config_with_rules("rules:\n  - GEOIP,cn,proxy\n  - MATCH,proxy\n");
        assert!(updater_for(&missing_config_with_demand).await.is_none());
        assert!(updater_for(&configured(false, true)).await.is_none());
        assert!(updater_for(&configured(true, false)).await.is_none());

        let updater = updater_for(&configured(true, true))
            .await
            .expect("enabled explicit GeoData config plus demand starts the updater");
        assert_eq!(
            updater.urls().geoip,
            "https://downloads.example.test/custom-geoip.dat"
        );
        assert_eq!(
            updater.urls().geosite,
            "https://downloads.example.test/custom-geosite.dat"
        );
    }

    #[cfg(feature = "outbound-vless")]
    #[tokio::test]
    async fn a_manager_rejects_a_second_prepared_configuration() {
        fn configured(auto_update: bool, rule: &str, source: &str) -> String {
            let fields = format!(
                r#"geox-url:
  geoip: https://{source}/geoip.dat
  geosite: https://{source}/geosite.dat
geo-auto-update: {auto_update}
geo-update-interval: 24
"#
            );
            config_with_rules(&format!("rules:\n  - {rule},proxy\n  - MATCH,proxy\n")).replacen(
                "port: 18080\n",
                &format!("{fields}port: 18080\n"),
                1,
            )
        }

        let directory = tempdir().unwrap();
        let manager =
            GeoDataManager::open(directory.path(), Duration::from_secs(24 * 60 * 60)).unwrap();
        let _active = PreparedCore::prepare_config(
            Config::parse_yaml(
                configured(true, "GEOSITE,enabled", "enabled.example.test").as_bytes(),
            )
            .unwrap(),
            manager.clone(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let second = PreparedCore::prepare_config(
            Config::parse_yaml(
                configured(false, "GEOIP,disabled", "disabled.example.test").as_bytes(),
            )
            .unwrap(),
            manager.clone(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap_err();

        assert!(second.to_string().contains("active registration"));
    }

    fn two_socks_config(chained: bool) -> String {
        let dialer = if chained {
            "    dialer-proxy: node-b\n"
        } else {
            ""
        };
        format!(
            r#"port: 18080
authentication:
  - measure:secret
proxies:
  - name: node-a
    type: socks5
{dialer}    server: a.test
    port: 1080
  - name: node-b
    type: socks5
    server: b.test
    port: 1081
rules:
  - MATCH,node-a
"#
        )
    }

    #[tokio::test]
    async fn prepare_resolves_both_independent_proxy_roots() {
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(
            two_socks_config(false).as_bytes(),
            &resolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let mut hosts = resolver.hosts.lock().unwrap().clone();
        hosts.sort();
        assert_eq!(hosts, ["a.test".to_owned(), "b.test".to_owned()]);
        assert!(prepared.endpoint(ProxyId::new(0).unwrap()).is_some());
        assert!(prepared.endpoint(ProxyId::new(1).unwrap()).is_some());
    }

    #[cfg(feature = "outbound-socks5")]
    #[tokio::test]
    async fn prepare_resolves_only_the_physical_chain_root() {
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(
            two_socks_config(true).as_bytes(),
            &resolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(*resolver.hosts.lock().unwrap(), ["b.test".to_owned()]);
        assert!(prepared.endpoint(ProxyId::new(0).unwrap()).is_none());
        assert!(prepared.endpoint(ProxyId::new(1).unwrap()).is_some());
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            2
        );
    }

    #[cfg(all(feature = "outbound-socks5", feature = "outbound-vless"))]
    #[tokio::test]
    async fn split_vless_behind_dialer_proxy_does_not_resolve_either_child_leg() {
        let yaml = r#"port: 18080
authentication:
  - measure:secret
proxies:
  - name: vless-child
    type: vless
    server: upload-child.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: upload-child.test
    alpn: [h2]
    dialer-proxy: socks-root
    xhttp-opts:
      host: upload-child.test
      path: /upload
      mode: packet-up
      download-settings:
        server: download-child.test
        port: 8443
  - name: socks-root
    type: socks5
    server: socks-root.test
    port: 1080
rules:
  - MATCH,vless-child
"#;
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        assert_eq!(
            *resolver.hosts.lock().unwrap(),
            ["socks-root.test".to_owned()]
        );
        let child = ProxyId::new(0).unwrap();
        assert!(prepared.endpoint(child).is_none());
        assert!(prepared.download_endpoint(child).is_none());
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            2
        );
    }

    #[cfg(all(
        feature = "outbound-anytls",
        feature = "outbound-socks5",
        feature = "outbound-vless"
    ))]
    #[tokio::test]
    async fn proxy_graph_builds_protocol_combinations_and_long_chains() {
        assert_eq!(standard_tls_resumption_sessions(1), 4);
        assert_eq!(standard_tls_resumption_sessions(2), 2);
        assert_eq!(standard_tls_resumption_sessions(3), 1);
        assert_eq!(standard_tls_resumption_sessions(4), 1);
        assert_eq!(standard_tls_resumption_sessions(5), 0);
        assert_eq!(standard_tls_resumption_sessions(64), 0);

        fn vless(tag: &str) -> ProxyConfig {
            let mut proxy = Config::parse_yaml(CONFIG.as_bytes())
                .unwrap()
                .proxies
                .into_iter()
                .next()
                .unwrap();
            proxy.tag = tag.to_owned();
            proxy
        }

        fn socks5(tag: &str) -> ProxyConfig {
            ProxyConfig {
                tag: tag.to_owned(),
                dialer_proxy: None,
                udp: false,
                protocol: ProxyProtocol::Socks5(crate::config::Socks5OutboundConfig {
                    address: "127.0.0.1".to_owned(),
                    port: 1080,
                    username: None,
                    password: None,
                }),
            }
        }

        fn anytls(tag: &str) -> ProxyConfig {
            ProxyConfig {
                tag: tag.to_owned(),
                dialer_proxy: None,
                udp: true,
                protocol: ProxyProtocol::AnyTls(crate::config::AnyTlsOutboundConfig {
                    address: "127.0.0.1".to_owned(),
                    port: 443,
                    password: "secret".to_owned(),
                    server_name: "example.com".to_owned(),
                }),
            }
        }

        let mut mixed_security = vec![vless("tls")];
        for index in 0..8 {
            let mut reality = vless(&format!("reality-{index}"));
            let ProxyProtocol::Vless(config) = &mut reality.protocol else {
                unreachable!("vless test helper always creates VLESS")
            };
            config.security =
                crate::config::SecurityConfig::Reality(crate::config::RealityConfig {
                    server_name: "example.com".to_owned(),
                    public_key: [7; 32],
                    short_id: vec![1, 2, 3, 4],
                });
            mixed_security.push(reality);
        }
        mixed_security.push(anytls("anytls"));
        let (security_client_count, standard_tls_count) = security_counts(&mixed_security);
        assert_eq!(security_client_count, 10);
        assert_eq!(standard_tls_count, 2);
        assert_eq!(standard_tls_resumption_sessions(standard_tls_count), 2);

        async fn build(proxies: Vec<ProxyConfig>) -> usize {
            let mut config = Config::parse_yaml(CONFIG.as_bytes()).unwrap();
            config.proxies = proxies;
            let directory = tempdir().unwrap();
            let geodata_manager =
                GeoDataManager::open(directory.path(), Duration::from_secs(24 * 60 * 60)).unwrap();
            let prepared = PreparedCore::prepare_config(
                config,
                geodata_manager,
                &FixedResolver,
                ResourceLimits::tun(),
            )
            .await
            .unwrap();
            prepared.build_proxy_graph(Dialer::default()).unwrap().len()
        }

        assert_eq!(build(vec![vless("selected")]).await, 1);
        assert_eq!(build(vec![socks5("selected")]).await, 1);
        assert_eq!(build(vec![anytls("selected")]).await, 1);

        for (mut selected, upstream) in [
            (vless("selected"), vless("upstream")),
            (vless("selected"), socks5("upstream")),
            (vless("selected"), anytls("upstream")),
            (socks5("selected"), vless("upstream")),
            (socks5("selected"), socks5("upstream")),
            (socks5("selected"), anytls("upstream")),
            (anytls("selected"), vless("upstream")),
            (anytls("selected"), socks5("upstream")),
            (anytls("selected"), anytls("upstream")),
        ] {
            // `selected -> upstream` means selected.dialer-proxy references
            // the second node; the wire path reaches upstream first.
            selected.dialer_proxy = ProxyId::new(1);
            assert_eq!(build(vec![selected, upstream]).await, 2);
        }

        let mut chain = (0..6)
            .map(|index| socks5(&format!("node-{index}")))
            .collect::<Vec<_>>();
        for (index, proxy) in chain.iter_mut().take(5).enumerate() {
            proxy.dialer_proxy = ProxyId::new(index + 1);
        }
        assert_eq!(build(chain).await, 6);
    }

    #[cfg(all(unix, feature = "tun"))]
    #[tokio::test]
    async fn start_tun_requires_exactly_one_tun_listener() {
        let prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let (tun, _peer) = test_tun();
        let error = prepared
            .start_tun(tun, Dialer::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        prepared.config.inbounds.extend([
            InboundConfig::Tun(TunInboundConfig {
                tag: "tun-a".to_owned(),
                mtu: 1_500,
            }),
            InboundConfig::Tun(TunInboundConfig {
                tag: "tun-b".to_owned(),
                mtu: 1_500,
            }),
        ]);
        let (tun, _peer) = test_tun();
        let error = prepared
            .start_tun(tun, Dialer::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        prepared
            .config
            .inbounds
            .push(InboundConfig::Tun(TunInboundConfig {
                tag: "tun".to_owned(),
                mtu: 1_500,
            }));
        let (tun, _peer) = test_tun();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();
        running.stop().await.unwrap();
    }

    #[cfg(all(unix, feature = "tun"))]
    #[tokio::test]
    async fn current_tun_enables_local_icmp_echo() {
        let prepared = PreparedCore::prepare(
            CURRENT_TUN_CONFIG.as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let reply = tun_echo_reply(prepared)
            .await
            .expect("TUN did not answer ICMP echo");
        assert_eq!(reply[0], 0x45);
        assert_eq!(reply[8], 64);
        assert_eq!(reply[9], 1);
        assert_eq!(&reply[12..16], &[198, 51, 100, 20]);
        assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
        assert_eq!(reply[20], 0);
        assert_eq!(&reply[24..], &[0x12, 0x34, 0x56, 0x78, b'o', b'd', b'd']);
    }

    #[cfg(all(unix, feature = "tun"))]
    #[tokio::test]
    async fn tun_controller_shares_lifecycle_and_reports_raw_ip_bytes() {
        let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let controller_address = reservation.local_addr().unwrap();
        drop(reservation);
        let yaml = CURRENT_TUN_CONFIG.replacen(
            "tun:\n",
            &format!("external-controller: \"{controller_address}\"\nsecret: test-token\ntun:\n"),
            1,
        );
        let prepared =
            PreparedCore::prepare(yaml.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let stats = prepared
            .traffic_stats()
            .expect("TUN preparation allocates one statistics object");
        let (tun, peer) = test_tun();
        peer.set_nonblocking(true).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();

        let request = icmpv4_echo_request();
        peer.send(&request).await.unwrap();
        let mut reply = vec![0_u8; 1_500];
        let reply_length = tokio::time::timeout(Duration::from_millis(100), peer.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();

        let mut controller = tokio::net::TcpStream::connect(controller_address)
            .await
            .unwrap();
        controller
            .write_all(
                b"GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        controller.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let snapshot = serde_json::from_str::<serde_json::Value>(body).unwrap();
        assert_eq!(snapshot["upTotal"].as_u64(), Some(request.len() as u64));
        assert_eq!(snapshot["downTotal"].as_u64(), Some(reply_length as u64));
        assert_eq!(stats.snapshot().up_total, request.len() as u64);
        assert_eq!(stats.snapshot().down_total, reply_length as u64);

        running.stop().await.unwrap();
        let reconnect = tokio::time::timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect(controller_address),
        )
        .await
        .unwrap();
        assert!(reconnect.is_err());
    }

    #[cfg(all(unix, feature = "tun"))]
    const CURRENT_TUN_CONFIG: &str = r#"tun:
  enable: true
proxies:
  - name: proxy
    type: vless
    server: server.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      path: /x
      mode: packet-up
rules:
  - MATCH,proxy
"#;

    #[cfg(all(unix, feature = "tun"))]
    async fn tun_echo_reply(prepared: PreparedCore) -> Option<Vec<u8>> {
        let (tun, peer) = test_tun();
        peer.set_nonblocking(true).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();
        peer.send(&icmpv4_echo_request()).await.unwrap();

        let mut reply = vec![0_u8; 1_500];
        let received =
            tokio::time::timeout(Duration::from_millis(100), peer.recv(&mut reply)).await;
        running.stop().await.unwrap();
        match received {
            Ok(Ok(length)) => {
                reply.truncate(length);
                Some(reply)
            }
            Ok(Err(error)) => panic!("TUN peer receive failed: {error}"),
            Err(_) => None,
        }
    }

    #[cfg(all(unix, feature = "tun"))]
    fn icmpv4_echo_request() -> Vec<u8> {
        let mut message = vec![8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, b'o', b'd', b'd'];
        let checksum = test_checksum(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut packet = vec![0_u8; 20 + message.len()];
        packet[0] = 0x45;
        let packet_len = u16::try_from(packet.len()).unwrap();
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 32;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        packet[20..].copy_from_slice(&message);
        let checksum = test_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[cfg(all(unix, feature = "tun"))]
    fn test_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u32::from(*byte) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).unwrap()
    }

    #[cfg(all(unix, feature = "tun"))]
    fn test_tun() -> (TunIo, UnixDatagram) {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = crate::platform::TunFd::duplicate(host.as_raw_fd()).unwrap();
        (TunIo::new(fd, crate::TunFraming::RawIp).unwrap(), peer)
    }
}
