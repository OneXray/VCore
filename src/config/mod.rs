//! Strict parsing for the current VCore YAML configuration.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_yaml_ng::Value as YamlValue;
use url::{Host, Url};
use uuid::Uuid;

use crate::{Result, VCoreError};

#[cfg(feature = "ffi")]
mod measure;

#[cfg(feature = "ffi")]
pub(crate) use measure::MeasureConfig;

pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_RULES: usize = 1_024;
pub const MAX_RULE_BYTES: usize = 1_024;
pub const MAX_RULES_TOTAL_BYTES: usize = 128 * 1024;
pub const MAX_DNS_NAMESERVERS: usize = 4;
pub const MAX_DNS_NAMESERVER_POLICIES: usize = 16;
pub const MAX_DNS_POLICY_GEOSITE_CODES: usize = 16;
pub const MAX_SNIFFER_PORT_ITEMS: usize = 64;
pub const MAX_GEOX_URL_BYTES: usize = 4_096;
pub const MAX_CONTROLLER_SECRET_BYTES: usize = 255;
pub const MAX_ANYTLS_PASSWORD_BYTES: usize = 1_024;
pub const GEO_UPDATE_INTERVAL_HOURS: u64 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub proxies: Vec<ProxyConfig>,
    pub default_proxy: ProxyId,
    pub geodata_update: Option<GeoDataUpdateConfig>,
    pub external_controller: Option<ExternalControllerConfig>,
    pub inbounds: Vec<InboundConfig>,
    pub http_port: Option<u16>,
    pub tun: TunConfig,
    pub sniffer: SnifferConfig,
    pub dns: DnsConfig,
    pub rules: Vec<RuleSpec>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExternalControllerConfig {
    pub listen: SocketAddr,
    pub secret: Option<String>,
}

impl std::fmt::Debug for ExternalControllerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalControllerConfig")
            .field("listen", &self.listen)
            .field("authenticated", &self.secret.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataUpdateConfig {
    pub urls: GeoDataUrls,
    pub auto_update: bool,
    pub interval_hours: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataUrls {
    pub geoip: String,
    pub geosite: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunConfig {
    pub enable: bool,
    pub mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnifferConfig {
    pub enable: bool,
    pub http_ports: Box<[PortRange]>,
    pub tls_ports: Box<[PortRange]>,
    pub quic_ports: Box<[PortRange]>,
}

impl SnifferConfig {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enable: false,
            http_ports: Box::new([]),
            tls_ports: Box::new([]),
            quic_ports: Box::new([]),
        }
    }

    #[must_use]
    pub fn matches_http_port(&self, port: u16) -> bool {
        port_ranges_contain(&self.http_ports, port)
    }

    #[must_use]
    pub fn matches_tls_port(&self, port: u16) -> bool {
        port_ranges_contain(&self.tls_ports, port)
    }

    #[must_use]
    pub fn matches_quic_port(&self, port: u16) -> bool {
        port_ranges_contain(&self.quic_ports, port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub enable: bool,
    pub ipv6: bool,
    pub nameservers: Vec<DnsNameserver>,
    pub nameserver_policies: Vec<DnsNameserverPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsNameserver {
    pub transport: DnsTransport,
    pub address: IpAddr,
    pub port: u16,
    pub route: DnsRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameserverPolicy {
    pub geosite_codes: Box<[String]>,
    pub nameservers: Box<[DnsNameserver]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRoute {
    Direct,
    Rules,
    Proxy(ProxyId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSpec {
    pub kind: RuleKind,
    pub action: RuleAction,
    pub no_resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    GeoSite(String),
    GeoIp(String),
    IpCidr(IpCidr),
    DstPorts(Vec<PortRange>),
    Network(Network),
    Match,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Proxy(ProxyId),
    Direct,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProxyId(usize);

impl ProxyId {
    #[must_use]
    pub const fn new(index: usize) -> Option<Self> {
        Some(Self(index))
    }

    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    fn from_index(index: usize) -> Self {
        Self(index)
    }
}

type ProxyIdsByTag = HashMap<String, ProxyId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    pub network: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub tag: String,
    pub dialer_proxy: Option<ProxyId>,
    pub udp: bool,
    pub protocol: ProxyProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocol {
    Vless(VlessOutboundConfig),
    Socks5(Socks5OutboundConfig),
    AnyTls(AnyTlsOutboundConfig),
}

impl ProxyConfig {
    #[must_use]
    pub fn address(&self) -> &str {
        match &self.protocol {
            ProxyProtocol::Vless(config) => &config.address,
            ProxyProtocol::Socks5(config) => &config.address,
            ProxyProtocol::AnyTls(config) => &config.address,
        }
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        match &self.protocol {
            ProxyProtocol::Vless(config) => config.port,
            ProxyProtocol::Socks5(config) => config.port,
            ProxyProtocol::AnyTls(config) => config.port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessOutboundConfig {
    pub address: String,
    pub port: u16,
    pub id: Uuid,
    pub encryption: VlessEncryption,
    pub flow: String,
    pub security: SecurityConfig,
    pub xhttp: XHttpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5OutboundConfig {
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AnyTlsOutboundConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub server_name: String,
}

impl std::fmt::Debug for AnyTlsOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsOutboundConfig")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessEncryption {
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityConfig {
    Tls(TlsConfig),
    Reality(RealityConfig),
}

impl SecurityConfig {
    #[must_use]
    pub fn server_name(&self) -> &str {
        match self {
            Self::Tls(config) => &config.server_name,
            Self::Reality(config) => &config.server_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpConfig {
    pub path: String,
    pub host: String,
    pub mode: XHttpMode,
    pub download: Option<Box<XHttpDownloadConfig>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpDownloadConfig {
    pub address: String,
    pub port: u16,
    pub security: SecurityConfig,
    pub path: String,
    pub host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMode {
    PacketUp,
    StreamOne,
    StreamUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundConfig {
    Tun(TunInboundConfig),
    Http(HttpInboundConfig),
}

impl InboundConfig {
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Tun(config) => &config.tag,
            Self::Http(config) => &config.tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunInboundConfig {
    pub tag: String,
    pub mtu: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HttpInboundConfig {
    pub tag: String,
    pub listen: IpAddr,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for HttpInboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpInboundConfig")
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVCoreConfig {
    #[serde(
        rename = "geox-url",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    geox_url: Option<RawGeoDataUrls>,
    #[serde(
        rename = "geo-auto-update",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    geo_auto_update: Option<bool>,
    #[serde(
        rename = "geo-update-interval",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    geo_update_interval: Option<u64>,
    #[serde(
        rename = "external-controller",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    external_controller: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    secret: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    port: Option<u16>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    authentication: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    tun: Option<RawTunConfig>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sniffer: Option<RawSnifferConfig>,
    proxies: Vec<RawOutbound>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    dns: Option<RawDnsConfig>,
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGeoDataUrls {
    geoip: String,
    geosite: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunConfig {
    enable: bool,
    #[serde(default = "default_mtu")]
    mtu: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnifferConfig {
    enable: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sniff: Option<RawSniffConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSniffConfig {
    #[serde(
        rename = "HTTP",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    http: Option<Option<RawSniffProtocolConfig>>,
    #[serde(
        rename = "TLS",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    tls: Option<Option<RawSniffProtocolConfig>>,
    #[serde(
        rename = "QUIC",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    quic: Option<Option<RawSniffProtocolConfig>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSniffProtocolConfig {
    #[serde(default, deserialize_with = "deserialize_present_option")]
    ports: Option<Vec<RawSnifferPort>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSnifferPort {
    Integer(u64),
    String(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsConfig {
    enable: bool,
    #[serde(default = "default_true")]
    ipv6: bool,
    #[serde(default)]
    nameserver: Vec<String>,
    #[serde(
        rename = "nameserver-policy",
        default,
        deserialize_with = "deserialize_dns_nameserver_policies"
    )]
    nameserver_policies: Vec<RawDnsNameserverPolicy>,
}

#[derive(Debug)]
struct RawDnsNameserverPolicy {
    selector: String,
    nameservers: Vec<String>,
}

fn deserialize_dns_nameserver_policies<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<RawDnsNameserverPolicy>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedPoliciesVisitor;

    impl<'de> Visitor<'de> for OrderedPoliciesVisitor {
        type Value = Vec<RawDnsNameserverPolicy>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an ordered nameserver-policy mapping")
        }

        fn visit_map<A>(
            self,
            mut mapping: A,
        ) -> std::result::Result<Vec<RawDnsNameserverPolicy>, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut policies = Vec::with_capacity(mapping.size_hint().unwrap_or(0));
            while let Some((selector, nameservers)) = mapping.next_entry::<String, Vec<String>>()? {
                policies.push(RawDnsNameserverPolicy {
                    selector,
                    nameservers,
                });
            }
            Ok(policies)
        }
    }

    deserializer.deserialize_map(OrderedPoliciesVisitor)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
// This enum exists only while deserializing a configuration. Keeping the
// protocol fields inline avoids extra heap allocations in the startup path.
#[allow(clippy::large_enum_variant)]
enum RawOutbound {
    #[serde(rename = "vless")]
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        #[serde(default)]
        udp: bool,
        tls: bool,
        network: String,
        #[serde(default)]
        encryption: String,
        #[serde(default)]
        flow: String,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        servername: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        alpn: Option<Vec<String>>,
        #[serde(
            rename = "dialer-proxy",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        dialer_proxy: Option<String>,
        #[serde(
            rename = "reality-opts",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        reality_opts: Option<RawRealitySettings>,
        #[serde(
            rename = "xhttp-opts",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        xhttp_opts: Option<RawXHttpSettings>,
    },
    #[serde(rename = "socks5")]
    Socks5 {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        udp: bool,
        #[serde(default)]
        tls: bool,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        username: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        password: Option<String>,
        #[serde(
            rename = "dialer-proxy",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        dialer_proxy: Option<String>,
    },
    #[serde(rename = "anytls")]
    AnyTls {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        udp: bool,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        sni: Option<String>,
        #[serde(
            rename = "dialer-proxy",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        dialer_proxy: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawXHttpSettings {
    #[serde(default, deserialize_with = "deserialize_present_option")]
    host: Option<String>,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default = "default_xhttp_mode")]
    mode: String,
    #[serde(
        rename = "download-settings",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    download_settings: Option<RawXHttpDownloadSettings>,
}

impl Default for RawXHttpSettings {
    fn default() -> Self {
        Self {
            host: None,
            path: default_path(),
            mode: default_xhttp_mode(),
            download_settings: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawXHttpDownloadSettings {
    #[serde(default, deserialize_with = "deserialize_present_option")]
    server: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    port: Option<u16>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    tls: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    servername: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(
        rename = "reality-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    reality_opts: Option<RawRealitySettings>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    path: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRealitySettings {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "short-id", default)]
    short_id: String,
}

#[derive(Debug)]
struct PendingProxyConfig {
    tag: String,
    dialer_proxy: Option<String>,
    udp: bool,
    protocol: ProxyProtocol,
}

fn default_mtu() -> u16 {
    1_500
}

fn default_true() -> bool {
    true
}

fn default_path() -> String {
    "/".to_owned()
}

fn default_xhttp_mode() -> String {
    "auto".to_owned()
}

fn deserialize_present_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl Config {
    pub fn parse_yaml(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_CONFIG_BYTES {
            return invalid(format!(
                "configuration exceeds the {MAX_CONFIG_BYTES}-byte limit"
            ));
        }
        let input = std::str::from_utf8(input)
            .map_err(|_| VCoreError::InvalidConfig("configuration is not UTF-8".to_owned()))?;

        reject_yaml_anchors_and_aliases(input)?;
        let yaml: YamlValue = serde_yaml_ng::from_str(input)
            .map_err(|error| VCoreError::InvalidConfig(error.to_string()))?;
        validate_json_compatible_yaml(&yaml)?;
        // Deserialize from the YAML value directly. Mapping order is part of
        // nameserver-policy semantics and would be lost by the intermediate
        // serde_json map representation.
        let raw: RawVCoreConfig = serde_yaml_ng::from_value(yaml)
            .map_err(|error| VCoreError::InvalidConfig(error.to_string()))?;
        raw.normalize()
    }
}

impl RawVCoreConfig {
    fn normalize(self) -> Result<Config> {
        let geodata_update = normalize_geodata_update(
            self.geox_url,
            self.geo_auto_update,
            self.geo_update_interval,
        )?;

        if let Some(port) = self.port {
            validate_port(port, "port")?;
        }
        let http_authentication = normalize_http_authentication(self.port, self.authentication)?;

        let tun = self.tun.map_or(
            TunConfig {
                enable: false,
                mtu: default_mtu(),
            },
            |tun| TunConfig {
                enable: tun.enable,
                mtu: tun.mtu,
            },
        );
        if tun.mtu != default_mtu() {
            return invalid("TUN only supports mtu: 1500");
        }
        let external_controller =
            normalize_external_controller(self.external_controller, self.secret, tun.enable)?;
        if self.port.is_none() && !tun.enable {
            return invalid("configuration requires port or tun.enable: true");
        }
        let sniffer = self.sniffer.map_or_else(
            || Ok(SnifferConfig::disabled()),
            RawSnifferConfig::normalize,
        )?;

        if self.proxies.is_empty() {
            return invalid("proxies must contain at least 1 entry");
        }
        let (proxies, proxy_ids) = normalize_proxy_graph(self.proxies)?;
        let default_proxy = derive_default_proxy_from_rules(&self.rules, &proxy_ids)?;

        let dns = self
            .dns
            .map_or_else(DnsConfig::disabled, |dns| dns.normalize(&proxy_ids))?;
        let rules = normalize_rules(self.rules, &proxy_ids)?;
        drop(proxy_ids);

        let mut inbounds = Vec::with_capacity(2);
        if let (Some(port), Some((username, password))) = (self.port, http_authentication) {
            let listen = IpAddr::V4(Ipv4Addr::LOCALHOST);
            inbounds.push(InboundConfig::Http(HttpInboundConfig {
                tag: "http-in".to_owned(),
                listen,
                port,
                username,
                password,
            }));
        }
        if tun.enable {
            inbounds.push(InboundConfig::Tun(TunInboundConfig {
                tag: "tun-in".to_owned(),
                mtu: tun.mtu,
            }));
        }

        Ok(Config {
            proxies,
            default_proxy,
            geodata_update,
            external_controller,
            inbounds,
            http_port: self.port,
            tun,
            sniffer,
            dns,
            rules,
        })
    }
}

fn normalize_external_controller(
    listen: Option<String>,
    secret: Option<String>,
    tun_enabled: bool,
) -> Result<Option<ExternalControllerConfig>> {
    let Some(listen) = listen else {
        if secret.is_some() {
            return invalid("secret requires external-controller");
        }
        return Ok(None);
    };
    if !tun_enabled {
        return invalid("external-controller requires tun.enable: true");
    }
    let listen = listen.parse::<SocketAddr>().map_err(|_| {
        VCoreError::InvalidConfig(
            "external-controller must be an IP socket address with an explicit port".to_owned(),
        )
    })?;
    if !listen.ip().is_loopback() {
        return invalid("external-controller must listen on a loopback address");
    }
    if listen.port() == 0 {
        return invalid("external-controller port must be between 1 and 65535");
    }
    if let Some(secret) = &secret
        && !(1..=MAX_CONTROLLER_SECRET_BYTES).contains(&secret.len())
    {
        return invalid(format!(
            "secret must contain between 1 and {MAX_CONTROLLER_SECRET_BYTES} UTF-8 bytes"
        ));
    }
    Ok(Some(ExternalControllerConfig { listen, secret }))
}

fn normalize_geodata_update(
    urls: Option<RawGeoDataUrls>,
    auto_update: Option<bool>,
    interval_hours: Option<u64>,
) -> Result<Option<GeoDataUpdateConfig>> {
    match (urls, auto_update, interval_hours) {
        (None, None, None) => Ok(None),
        (Some(urls), Some(auto_update), Some(interval_hours)) => {
            if interval_hours != GEO_UPDATE_INTERVAL_HOURS {
                return invalid(format!(
                    "geo-update-interval must be {GEO_UPDATE_INTERVAL_HOURS}"
                ));
            }
            Ok(Some(GeoDataUpdateConfig {
                urls: GeoDataUrls {
                    geoip: normalize_geox_url(urls.geoip, "geox-url.geoip")?,
                    geosite: normalize_geox_url(urls.geosite, "geox-url.geosite")?,
                },
                auto_update,
                interval_hours,
            }))
        }
        _ => invalid(
            "geox-url, geo-auto-update, and geo-update-interval must be configured together",
        ),
    }
}

fn normalize_geox_url(raw: String, field: &str) -> Result<String> {
    if raw.len() > MAX_GEOX_URL_BYTES {
        return invalid(format!(
            "{field} exceeds the {MAX_GEOX_URL_BYTES}-byte limit"
        ));
    }
    let url = Url::parse(&raw)
        .map_err(|error| VCoreError::InvalidConfig(format!("{field} is invalid: {error}")))?;
    if url.scheme() != "https" {
        return invalid(format!("{field} must use HTTPS"));
    }
    let authority = raw
        .split_once("://")
        .map(|(_, suffix)| suffix)
        .and_then(|suffix| suffix.split(['/', '?', '#']).next())
        .unwrap_or_default();
    if !url.username().is_empty() || url.password().is_some() || authority.contains('@') {
        return invalid(format!("{field} must not contain credentials"));
    }
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return invalid(format!("{field} must contain a domain host"));
    }
    if url.fragment().is_some() {
        return invalid(format!("{field} must not contain a fragment"));
    }
    Ok(raw)
}

impl RawSnifferConfig {
    fn normalize(self) -> Result<SnifferConfig> {
        let sniff = self.sniff.unwrap_or_default();
        let http = normalize_sniffer_protocol(sniff.http, 80, "HTTP")?;
        let tls = normalize_sniffer_protocol(sniff.tls, 443, "TLS")?;
        let quic = normalize_sniffer_protocol(sniff.quic, 443, "QUIC")?;

        if self.enable && http.is_none() && tls.is_none() && quic.is_none() {
            return invalid(
                "sniffer.enable: true requires at least one HTTP, TLS, or QUIC sniffer",
            );
        }

        let http_ports = http.unwrap_or_default();
        let tls_ports = tls.unwrap_or_default();
        let quic_ports = quic.unwrap_or_default();
        if port_ranges_overlap(&http_ports, &tls_ports) {
            return invalid("sniffer HTTP and TLS port ranges must not overlap");
        }

        Ok(SnifferConfig {
            enable: self.enable,
            http_ports,
            tls_ports,
            quic_ports,
        })
    }
}

fn normalize_sniffer_protocol(
    raw: Option<Option<RawSniffProtocolConfig>>,
    default_port: u16,
    protocol: &str,
) -> Result<Option<Box<[PortRange]>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.unwrap_or_default();
    let ranges = match raw.ports {
        None => vec![PortRange {
            start: default_port,
            end: default_port,
        }],
        Some(items) => {
            if items.is_empty() {
                return invalid(format!("sniffer.sniff.{protocol}.ports must not be empty"));
            }
            if items.len() > MAX_SNIFFER_PORT_ITEMS {
                return invalid(format!(
                    "sniffer.sniff.{protocol}.ports exceeds the {MAX_SNIFFER_PORT_ITEMS}-item limit"
                ));
            }
            items
                .into_iter()
                .map(|item| parse_sniffer_port(item, protocol))
                .collect::<Result<Vec<_>>>()?
        }
    };
    Ok(Some(merge_port_ranges(ranges).into_boxed_slice()))
}

fn parse_sniffer_port(item: RawSnifferPort, protocol: &str) -> Result<PortRange> {
    match item {
        RawSnifferPort::Integer(port) => {
            let port = parse_sniffer_port_number(port, protocol)?;
            Ok(PortRange {
                start: port,
                end: port,
            })
        }
        RawSnifferPort::String(value) => {
            if let Some((start, end)) = value.split_once('-') {
                if start.is_empty() || end.is_empty() || end.contains('-') {
                    return invalid(format!(
                        "sniffer.sniff.{protocol}.ports contains invalid range `{value}`"
                    ));
                }
                let start = parse_sniffer_port_string(start, protocol)?;
                let end = parse_sniffer_port_string(end, protocol)?;
                if start > end {
                    return invalid(format!(
                        "sniffer.sniff.{protocol}.ports range start must not exceed its end"
                    ));
                }
                Ok(PortRange { start, end })
            } else {
                let port = parse_sniffer_port_string(&value, protocol)?;
                Ok(PortRange {
                    start: port,
                    end: port,
                })
            }
        }
    }
}

fn parse_sniffer_port_string(value: &str, protocol: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid(format!(
            "sniffer.sniff.{protocol}.ports contains invalid port `{value}`"
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        VCoreError::InvalidConfig(format!(
            "sniffer.sniff.{protocol}.ports contains invalid port `{value}`"
        ))
    })?;
    parse_sniffer_port_number(parsed, protocol)
}

fn parse_sniffer_port_number(value: u64, protocol: &str) -> Result<u16> {
    u16::try_from(value)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            VCoreError::InvalidConfig(format!(
                "sniffer.sniff.{protocol}.ports values must be between 1 and 65535"
            ))
        })
}

fn merge_port_ranges(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end.saturating_add(1)
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn port_ranges_overlap(left: &[PortRange], right: &[PortRange]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while let (Some(left), Some(right)) = (left.get(left_index), right.get(right_index)) {
        if left.end < right.start {
            left_index += 1;
        } else if right.end < left.start {
            right_index += 1;
        } else {
            return true;
        }
    }
    false
}

fn port_ranges_contain(ranges: &[PortRange], port: u16) -> bool {
    ranges
        .binary_search_by(|range| {
            if port < range.start {
                std::cmp::Ordering::Greater
            } else if port > range.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn normalize_http_authentication(
    port: Option<u16>,
    authentication: Option<Vec<String>>,
) -> Result<Option<(String, String)>> {
    match (port, authentication) {
        (None, None) => Ok(None),
        (None, Some(_)) => invalid("authentication requires port"),
        (Some(_), None) => invalid("port requires authentication"),
        (Some(_), Some(entries)) => {
            let [credential] = entries.as_slice() else {
                return invalid("authentication must contain exactly one user:password entry");
            };
            let (username, password) = credential.split_once(':').ok_or_else(|| {
                VCoreError::InvalidConfig("authentication entry must use user:password".to_owned())
            })?;
            for (name, value) in [("user", username), ("password", password)] {
                if !(1..=u8::MAX as usize).contains(&value.len()) {
                    return invalid(format!(
                        "authentication {name} must contain between 1 and 255 UTF-8 bytes"
                    ));
                }
            }
            Ok(Some((username.to_owned(), password.to_owned())))
        }
    }
}

fn validate_proxy_graph(
    proxies: &[PendingProxyConfig],
    dialer_proxies: &[Option<ProxyId>],
) -> Result<()> {
    let mut states = vec![0_u8; proxies.len()];
    let mut path = Vec::new();
    for (start, starting_proxy) in proxies.iter().enumerate() {
        if states[start] != 0 {
            continue;
        }
        path.clear();
        let mut current = Some(ProxyId::from_index(start));
        while let Some(proxy) = current {
            let index = proxy.index();
            match states[index] {
                0 => {
                    states[index] = 1;
                    path.push(index);
                    current = dialer_proxies[index];
                }
                1 => {
                    return invalid(format!(
                        "proxy `{}` has a circular dialer-proxy dependency",
                        starting_proxy.tag
                    ));
                }
                2 => break,
                _ => unreachable!("proxy graph state is internal"),
            }
        }
        for &index in &path {
            states[index] = 2;
        }
    }
    Ok(())
}

fn normalize_proxy_graph(
    raw_proxies: Vec<RawOutbound>,
) -> Result<(Vec<ProxyConfig>, ProxyIdsByTag)> {
    if raw_proxies.is_empty() {
        return invalid("proxies must contain at least 1 entry");
    }
    let pending = raw_proxies
        .into_iter()
        .map(RawOutbound::normalize)
        .collect::<Result<Vec<_>>>()?;
    let mut proxy_ids = ProxyIdsByTag::with_capacity(pending.len());
    for (index, proxy) in pending.iter().enumerate() {
        if proxy_ids
            .insert(proxy.tag.clone(), ProxyId::from_index(index))
            .is_some()
        {
            return invalid(format!("duplicate proxy name `{}`", proxy.tag));
        }
    }
    let dialer_proxies = pending
        .iter()
        .map(|proxy| {
            proxy
                .dialer_proxy
                .as_deref()
                .map(|tag| {
                    proxy_ids.get(tag).copied().ok_or_else(|| {
                        VCoreError::InvalidConfig(format!(
                            "proxy `{}` dialer-proxy `{tag}` does not reference a configured proxy name",
                            proxy.tag
                        ))
                    })
                })
                .transpose()
        })
        .collect::<Result<Vec<_>>>()?;
    validate_proxy_graph(&pending, &dialer_proxies)?;

    let proxies = pending
        .into_iter()
        .zip(dialer_proxies)
        .map(|(proxy, dialer_proxy)| ProxyConfig {
            tag: proxy.tag,
            dialer_proxy,
            udp: proxy.udp,
            protocol: proxy.protocol,
        })
        .collect();
    Ok((proxies, proxy_ids))
}

impl RawOutbound {
    fn normalize(self) -> Result<PendingProxyConfig> {
        let (tag, dialer_proxy, udp, protocol) = match self {
            Self::Vless {
                name,
                server,
                port,
                uuid,
                udp,
                tls,
                network,
                encryption,
                flow,
                servername,
                alpn,
                dialer_proxy,
                reality_opts,
                xhttp_opts,
            } => (
                name,
                dialer_proxy,
                udp,
                ProxyProtocol::Vless(normalize_vless(
                    server,
                    port,
                    uuid,
                    tls,
                    network,
                    encryption,
                    flow,
                    servername,
                    alpn,
                    reality_opts,
                    xhttp_opts,
                )?),
            ),
            Self::Socks5 {
                name,
                server,
                port,
                udp,
                tls,
                username,
                password,
                dialer_proxy,
            } => (
                name,
                dialer_proxy,
                udp,
                ProxyProtocol::Socks5(normalize_socks5(server, port, tls, username, password)?),
            ),
            Self::AnyTls {
                name,
                server,
                port,
                password,
                udp,
                sni,
                dialer_proxy,
            } => (
                name,
                dialer_proxy,
                udp,
                ProxyProtocol::AnyTls(normalize_anytls(server, port, password, sni)?),
            ),
        };
        validate_proxy_tag(&tag)?;
        if let Some(dialer_proxy) = &dialer_proxy {
            validate_tag_syntax(dialer_proxy, "dialer-proxy")?;
        }
        Ok(PendingProxyConfig {
            tag,
            dialer_proxy,
            udp,
            protocol,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn normalize_vless(
    server: String,
    port: u16,
    uuid: String,
    tls: bool,
    network: String,
    encryption: String,
    flow: String,
    servername: Option<String>,
    alpn: Option<Vec<String>>,
    reality_opts: Option<RawRealitySettings>,
    xhttp_opts: Option<RawXHttpSettings>,
) -> Result<VlessOutboundConfig> {
    validate_host(&server, "VLESS server")?;
    validate_port(port, "VLESS")?;
    let id = parse_standard_uuid(&uuid)?;
    if !matches!(encryption.as_str(), "" | "none") {
        return invalid("VLESS encryption must be empty or `none`");
    }
    if !flow.is_empty() {
        return invalid("VLESS flow must be empty");
    }
    if !tls {
        return invalid("VLESS tls must be true");
    }
    if network != "xhttp" {
        return invalid("VLESS network must be `xhttp`");
    }
    if let Some(alpn) = alpn
        && alpn.as_slice() != ["h2"]
    {
        return invalid("VLESS alpn must be [h2] when configured");
    }
    let server_name_is_explicit = servername.is_some();
    let server_name = servername.unwrap_or_else(|| server.clone());
    validate_host(&server_name, "VLESS servername")?;
    let security = match reality_opts {
        Some(reality) => SecurityConfig::Reality(reality.normalize(server_name)?),
        None => SecurityConfig::Tls(TlsConfig { server_name }),
    };
    let xhttp = xhttp_opts.unwrap_or_default().normalize(
        &server,
        port,
        server_name_is_explicit.then_some(security.server_name()),
        security.server_name(),
        &security,
    )?;
    Ok(VlessOutboundConfig {
        address: server,
        port,
        id,
        encryption: VlessEncryption::None,
        flow,
        security,
        xhttp,
    })
}

impl RawRealitySettings {
    fn normalize(self, server_name: String) -> Result<RealityConfig> {
        let decoded = URL_SAFE_NO_PAD
            .decode(self.public_key.as_bytes())
            .map_err(|_| VCoreError::InvalidConfig("invalid REALITY public-key".to_owned()))?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|_| {
            VCoreError::InvalidConfig("invalid REALITY public-key length".to_owned())
        })?;
        if URL_SAFE_NO_PAD.encode(public_key) != self.public_key {
            return invalid("REALITY public-key must use canonical unpadded base64url");
        }

        if self.short_id.len() > 16 || !self.short_id.len().is_multiple_of(2) {
            return invalid("REALITY short-id must be at most 16 even-numbered hex characters");
        }
        let mut short_id = Vec::with_capacity(self.short_id.len() / 2);
        for pair in self.short_id.as_bytes().as_chunks::<2>().0 {
            let pair = std::str::from_utf8(pair).expect("hex input is UTF-8");
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| VCoreError::InvalidConfig("invalid REALITY short-id".to_owned()))?;
            short_id.push(byte);
        }

        Ok(RealityConfig {
            server_name,
            public_key,
            short_id,
        })
    }
}

fn normalize_socks5(
    server: String,
    port: u16,
    tls: bool,
    username: Option<String>,
    password: Option<String>,
) -> Result<Socks5OutboundConfig> {
    validate_host(&server, "SOCKS5 server")?;
    validate_port(port, "SOCKS5")?;
    if tls {
        return invalid("SOCKS5 tls must be false");
    }
    match (&username, &password) {
        (None, None) => {}
        (Some(username), Some(password)) => {
            for (name, value) in [("username", username), ("password", password)] {
                if !(1..=u8::MAX as usize).contains(&value.len()) {
                    return invalid(format!(
                        "SOCKS5 {name} must contain between 1 and 255 UTF-8 bytes"
                    ));
                }
            }
        }
        _ => {
            return invalid("SOCKS5 username and password must be provided together");
        }
    }
    Ok(Socks5OutboundConfig {
        address: server,
        port,
        username,
        password,
    })
}

fn normalize_anytls(
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
) -> Result<AnyTlsOutboundConfig> {
    validate_host(&server, "AnyTLS server")?;
    validate_port(port, "AnyTLS")?;
    if !(1..=MAX_ANYTLS_PASSWORD_BYTES).contains(&password.len()) {
        return invalid(format!(
            "AnyTLS password must contain between 1 and {MAX_ANYTLS_PASSWORD_BYTES} UTF-8 bytes"
        ));
    }
    let server_name = sni.unwrap_or_else(|| server.clone());
    validate_host(&server_name, "AnyTLS sni")?;
    Ok(AnyTlsOutboundConfig {
        address: server,
        port,
        password,
        server_name,
    })
}

impl RawXHttpSettings {
    fn normalize(
        self,
        default_address: &str,
        default_port: u16,
        default_explicit_server_name: Option<&str>,
        default_host: &str,
        security: &SecurityConfig,
    ) -> Result<XHttpConfig> {
        let Self {
            host,
            path,
            mode,
            download_settings,
        } = self;
        if path.is_empty()
            || path.len() > 2_048
            || !path.starts_with('/')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return invalid(
                "xhttp-opts.path must be a valid path/query starting with `/` and at most 2048 bytes",
            );
        }
        let download = download_settings
            .map(|settings| {
                settings.normalize(
                    default_address,
                    default_port,
                    default_explicit_server_name,
                    security,
                    &path,
                    host.as_deref(),
                )
            })
            .transpose()?
            .map(Box::new);
        let host = host.unwrap_or_else(|| {
            default_host.parse::<std::net::Ipv6Addr>().map_or_else(
                |_| default_host.to_owned(),
                |address| format!("[{address}]"),
            )
        });
        if host.is_empty() || host.len() > 253 || host.parse::<http::uri::Authority>().is_err() {
            return invalid("xhttp-opts.host must be a valid HTTP authority");
        }

        let mode = match mode.as_str() {
            "auto" if matches!(security, SecurityConfig::Reality(_)) && download.is_some() => {
                XHttpMode::StreamUp
            }
            "auto" if matches!(security, SecurityConfig::Reality(_)) => XHttpMode::StreamOne,
            "auto" | "packet-up" => XHttpMode::PacketUp,
            "stream-one" if download.is_none() => XHttpMode::StreamOne,
            "stream-one" => {
                return invalid("xhttp mode `stream-one` cannot be used with download-settings");
            }
            "stream-up" => XHttpMode::StreamUp,
            _ => return invalid("XHTTP mode must be auto, packet-up, stream-up, or stream-one"),
        };
        Ok(XHttpConfig {
            path,
            host,
            mode,
            download,
        })
    }
}

impl RawXHttpDownloadSettings {
    fn normalize(
        self,
        default_address: &str,
        default_port: u16,
        default_explicit_server_name: Option<&str>,
        default_security: &SecurityConfig,
        default_path: &str,
        default_explicit_host: Option<&str>,
    ) -> Result<XHttpDownloadConfig> {
        let Self {
            server,
            port,
            tls,
            servername,
            alpn,
            reality_opts,
            path,
            host,
        } = self;

        if tls == Some(false) {
            return invalid("xhttp-opts.download-settings.tls must be true when configured");
        }
        if let Some(alpn) = &alpn
            && alpn.as_slice() != ["h2"]
        {
            return invalid("xhttp-opts.download-settings.alpn must be [h2] when configured");
        }

        let address = server.unwrap_or_else(|| default_address.to_owned());
        validate_host(&address, "XHTTP download server")?;
        let port = port.unwrap_or(default_port);
        validate_port(port, "XHTTP download")?;

        let server_name = servername
            .or_else(|| default_explicit_server_name.map(str::to_owned))
            .unwrap_or_else(|| address.clone());
        validate_host(&server_name, "XHTTP download servername")?;
        let host = host
            .or_else(|| default_explicit_host.map(str::to_owned))
            .unwrap_or_else(|| {
                server_name
                    .parse::<std::net::Ipv6Addr>()
                    .map_or_else(|_| server_name.clone(), |address| format!("[{address}]"))
            });
        if host.is_empty() || host.len() > 253 || host.parse::<http::uri::Authority>().is_err() {
            return invalid("xhttp-opts.download-settings.host must be a valid HTTP authority");
        }
        let security = match reality_opts {
            Some(reality) => SecurityConfig::Reality(reality.normalize(server_name)?),
            None => {
                let mut security = default_security.clone();
                match &mut security {
                    SecurityConfig::Tls(config) => config.server_name = server_name,
                    SecurityConfig::Reality(config) => config.server_name = server_name,
                }
                security
            }
        };

        let path = path.unwrap_or_else(|| default_path.to_owned());
        if path.is_empty()
            || path.len() > 2_048
            || !path.starts_with('/')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return invalid(
                "xhttp-opts.download-settings.path must be a valid path/query starting with `/` and at most 2048 bytes",
            );
        }
        Ok(XHttpDownloadConfig {
            address,
            port,
            security,
            path,
            host,
        })
    }
}

impl DnsConfig {
    fn disabled() -> Result<Self> {
        Ok(Self {
            enable: false,
            ipv6: true,
            nameservers: Vec::new(),
            nameserver_policies: Vec::new(),
        })
    }
}

impl RawDnsConfig {
    fn normalize(self, proxy_ids: &ProxyIdsByTag) -> Result<DnsConfig> {
        if !self.enable {
            if !self.nameserver.is_empty() || !self.nameserver_policies.is_empty() {
                return invalid(
                    "dns.nameserver and dns.nameserver-policy must be empty when dns.enable is false",
                );
            }
            return Ok(DnsConfig {
                enable: false,
                ipv6: self.ipv6,
                nameservers: Vec::new(),
                nameserver_policies: Vec::new(),
            });
        }

        if self.nameserver.is_empty() || self.nameserver.len() > MAX_DNS_NAMESERVERS {
            return invalid(format!(
                "dns.nameserver must contain between 1 and {MAX_DNS_NAMESERVERS} entries when enabled"
            ));
        }
        let default_route = DnsRoute::Direct;
        let nameservers = self
            .nameserver
            .iter()
            .map(|nameserver| parse_dns_nameserver(nameserver, proxy_ids, default_route))
            .collect::<Result<Vec<_>>>()?;
        let nameserver_policies =
            normalize_dns_nameserver_policies(self.nameserver_policies, proxy_ids, default_route)?;

        Ok(DnsConfig {
            enable: true,
            ipv6: self.ipv6,
            nameservers,
            nameserver_policies,
        })
    }
}

fn normalize_dns_nameserver_policies(
    raw_policies: Vec<RawDnsNameserverPolicy>,
    proxy_ids: &ProxyIdsByTag,
    default_route: DnsRoute,
) -> Result<Vec<DnsNameserverPolicy>> {
    if raw_policies.len() > MAX_DNS_NAMESERVER_POLICIES {
        return invalid(format!(
            "dns.nameserver-policy exceeds the {MAX_DNS_NAMESERVER_POLICIES}-entry limit"
        ));
    }

    let mut normalized = Vec::with_capacity(raw_policies.len());
    let mut seen_codes = Vec::<String>::new();
    for raw_policy in raw_policies {
        let selector = raw_policy
            .selector
            .strip_prefix("geosite:")
            .ok_or_else(|| {
                VCoreError::InvalidConfig(format!(
                    "invalid dns.nameserver-policy selector `{}`; expected geosite:<code>[,<code>...]",
                    raw_policy.selector
                ))
            })?;
        if selector.is_empty() {
            return invalid("dns.nameserver-policy geosite selector must not be empty");
        }

        let mut geosite_codes = Vec::new();
        for raw_code in selector.split(',') {
            if raw_code.is_empty() || trim_ascii_whitespace(raw_code) != raw_code {
                return invalid(format!(
                    "invalid dns.nameserver-policy selector `{}`; GeoSite codes must be non-empty and contain no surrounding whitespace",
                    raw_policy.selector
                ));
            }
            let code = normalize_geo_code(raw_code, "dns.nameserver-policy GeoSite")?;
            if seen_codes.contains(&code) {
                return invalid(format!(
                    "dns.nameserver-policy contains duplicate GeoSite code `{code}`"
                ));
            }
            if seen_codes.len() == MAX_DNS_POLICY_GEOSITE_CODES {
                return invalid(format!(
                    "dns.nameserver-policy exceeds the {MAX_DNS_POLICY_GEOSITE_CODES}-code limit"
                ));
            }
            seen_codes.push(code.clone());
            geosite_codes.push(code);
        }

        if raw_policy.nameservers.is_empty() || raw_policy.nameservers.len() > MAX_DNS_NAMESERVERS {
            return invalid(format!(
                "dns.nameserver-policy `{}` must contain between 1 and {MAX_DNS_NAMESERVERS} nameservers",
                raw_policy.selector
            ));
        }
        let nameservers = raw_policy
            .nameservers
            .iter()
            .map(|nameserver| parse_dns_nameserver(nameserver, proxy_ids, default_route))
            .collect::<Result<Vec<_>>>()?;
        normalized.push(DnsNameserverPolicy {
            geosite_codes: geosite_codes.into_boxed_slice(),
            nameservers: nameservers.into_boxed_slice(),
        });
    }
    Ok(normalized)
}

fn parse_dns_nameserver(
    input: &str,
    proxy_ids: &ProxyIdsByTag,
    default_route: DnsRoute,
) -> Result<DnsNameserver> {
    let (endpoint, route) = match input.split_once('#') {
        Some((endpoint, fragment)) => (
            endpoint,
            parse_dns_route_fragment(input, fragment, proxy_ids)?,
        ),
        None => (input, default_route),
    };

    if let Ok(address) = endpoint.parse::<IpAddr>() {
        return Ok(DnsNameserver {
            transport: DnsTransport::Udp,
            address,
            port: 53,
            route,
        });
    }

    let (transport, endpoint) = if let Some(endpoint) = endpoint.strip_prefix("udp://") {
        (DnsTransport::Udp, endpoint)
    } else if let Some(endpoint) = endpoint.strip_prefix("tcp://") {
        (DnsTransport::Tcp, endpoint)
    } else {
        return invalid(format!(
            "invalid DNS nameserver `{input}`; expected IP, udp://IP[:port], or tcp://IP[:port], optionally followed by a route fragment"
        ));
    };

    let (address, port) = parse_dns_endpoint(endpoint).ok_or_else(|| {
        VCoreError::InvalidConfig(format!(
            "invalid DNS nameserver `{input}`; hostnames and URL paths are not supported"
        ))
    })?;
    validate_port(port, "DNS nameserver")?;
    Ok(DnsNameserver {
        transport,
        address,
        port,
        route,
    })
}

fn parse_dns_route_fragment(
    input: &str,
    fragment: &str,
    proxy_ids: &ProxyIdsByTag,
) -> Result<DnsRoute> {
    if fragment.is_empty() {
        return invalid(format!(
            "invalid DNS nameserver `{input}`; route fragment must not be empty"
        ));
    }
    if fragment.contains(['=', '&']) {
        return invalid(format!(
            "invalid DNS nameserver `{input}`; route fragment parameters and multiple tokens are not supported"
        ));
    }
    match fragment {
        "DIRECT" => Ok(DnsRoute::Direct),
        "RULES" => Ok(DnsRoute::Rules),
        fragment => proxy_ids
            .get(fragment)
            .copied()
            .map(DnsRoute::Proxy)
            .ok_or_else(|| {
                VCoreError::InvalidConfig(format!(
                    "invalid DNS nameserver `{input}`; route fragment must be exactly DIRECT, RULES, or a configured proxy name"
                ))
            }),
    }
}

fn parse_dns_endpoint(endpoint: &str) -> Option<(IpAddr, u16)> {
    if endpoint.is_empty()
        || endpoint.contains(['/', '?', '#', '@'])
        || endpoint.as_bytes().contains(&b'%')
    {
        return None;
    }
    if let Ok(address) = endpoint.parse::<IpAddr>() {
        return Some((address, 53));
    }
    if endpoint.starts_with('[') {
        let close = endpoint.find(']')?;
        let address = endpoint.get(1..close)?.parse::<Ipv6Addr>().ok()?;
        let suffix = endpoint.get(close + 1..)?;
        let port = if suffix.is_empty() {
            53
        } else {
            suffix.strip_prefix(':')?.parse::<u16>().ok()?
        };
        return Some((IpAddr::V6(address), port));
    }
    let endpoint = endpoint.parse::<SocketAddr>().ok()?;
    Some((endpoint.ip(), endpoint.port()))
}

fn derive_default_proxy_from_rules(rules: &[String], proxy_ids: &ProxyIdsByTag) -> Result<ProxyId> {
    let final_rule = rules.last().ok_or_else(|| {
        VCoreError::InvalidConfig(
            "rules must end with MATCH targeting an exact proxy name".to_owned(),
        )
    })?;
    let fields = final_rule
        .split(',')
        .map(trim_ascii_whitespace)
        .collect::<Vec<_>>();
    if fields.len() != 2 || !fields[0].eq_ignore_ascii_case("MATCH") {
        return invalid("rules must end with MATCH targeting an exact proxy name");
    }
    proxy_ids.get(fields[1]).copied().ok_or_else(|| {
        VCoreError::InvalidConfig(format!(
            "final MATCH target must be an exact configured proxy name; found `{}`",
            fields[1]
        ))
    })
}

fn normalize_rules(rules: Vec<String>, proxy_ids: &ProxyIdsByTag) -> Result<Vec<RuleSpec>> {
    if rules.is_empty() {
        return invalid("rules must not be empty");
    }
    if rules.len() > MAX_RULES {
        return invalid(format!("rules exceeds the {MAX_RULES}-entry limit"));
    }

    let mut total_bytes = 0_usize;
    let mut normalized = Vec::with_capacity(rules.len());
    for rule in rules {
        if rule.len() > MAX_RULE_BYTES {
            return invalid(format!(
                "rule exceeds the {MAX_RULE_BYTES}-byte per-entry limit"
            ));
        }
        total_bytes = total_bytes
            .checked_add(rule.len())
            .ok_or_else(|| VCoreError::InvalidConfig("rules byte length overflowed".to_owned()))?;
        if total_bytes > MAX_RULES_TOTAL_BYTES {
            return invalid(format!(
                "rules exceeds the {MAX_RULES_TOTAL_BYTES}-byte cumulative limit"
            ));
        }
        normalized.push(parse_rule(&rule, proxy_ids)?);
    }

    let match_count = normalized
        .iter()
        .filter(|rule| matches!(rule.kind, RuleKind::Match))
        .count();
    if match_count != 1
        || !matches!(
            normalized.last().map(|rule| &rule.kind),
            Some(RuleKind::Match)
        )
    {
        return invalid("explicit rules must contain exactly one MATCH as the final rule");
    }
    Ok(normalized)
}

fn parse_rule(input: &str, proxy_ids: &ProxyIdsByTag) -> Result<RuleSpec> {
    if input.is_empty() {
        return invalid("rule must not be empty");
    }
    let fields = input
        .split(',')
        .map(trim_ascii_whitespace)
        .collect::<Vec<_>>();
    let rule_type = fields
        .first()
        .filter(|field| !field.is_empty())
        .ok_or_else(|| VCoreError::InvalidConfig("rule type must not be empty".to_owned()))?
        .to_ascii_uppercase();

    match rule_type.as_str() {
        "MATCH" => {
            require_rule_field_count(&fields, 2, "MATCH")?;
            Ok(RuleSpec {
                kind: RuleKind::Match,
                action: parse_rule_action(fields[1], proxy_ids)?,
                no_resolve: false,
            })
        }
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "GEOSITE" | "DST-PORT" | "NETWORK" => {
            require_rule_field_count(&fields, 3, &rule_type)?;
            let kind = match rule_type.as_str() {
                "DOMAIN" => RuleKind::Domain(normalize_rule_domain(fields[1], "DOMAIN")?),
                "DOMAIN-SUFFIX" => {
                    RuleKind::DomainSuffix(normalize_rule_domain(fields[1], "DOMAIN-SUFFIX")?)
                }
                "DOMAIN-KEYWORD" => RuleKind::DomainKeyword(normalize_rule_keyword(fields[1])?),
                "GEOSITE" => RuleKind::GeoSite(normalize_geo_code(fields[1], "GEOSITE")?),
                "DST-PORT" => RuleKind::DstPorts(parse_port_ranges(fields[1])?),
                "NETWORK" => RuleKind::Network(parse_network(fields[1])?),
                _ => unreachable!("matched rule type"),
            };
            Ok(RuleSpec {
                kind,
                action: parse_rule_action(fields[2], proxy_ids)?,
                no_resolve: false,
            })
        }
        "GEOIP" | "IP-CIDR" | "IP-CIDR6" => {
            if fields.len() != 3 && fields.len() != 4 {
                return invalid(format!(
                    "{rule_type} rule must contain 3 fields, or 4 fields with no-resolve"
                ));
            }
            let kind = match rule_type.as_str() {
                "GEOIP" => RuleKind::GeoIp(normalize_geo_code(fields[1], "GEOIP")?),
                "IP-CIDR" => RuleKind::IpCidr(parse_ip_cidr(fields[1], false)?),
                "IP-CIDR6" => RuleKind::IpCidr(parse_ip_cidr(fields[1], true)?),
                _ => unreachable!("matched rule type"),
            };
            let no_resolve = if fields.len() == 4 {
                if fields[3] != "no-resolve" {
                    return invalid(format!(
                        "{rule_type} fourth field must be exactly `no-resolve`"
                    ));
                }
                true
            } else {
                false
            };
            Ok(RuleSpec {
                kind,
                action: parse_rule_action(fields[2], proxy_ids)?,
                no_resolve,
            })
        }
        _ => invalid(format!("unsupported rule type `{}`", fields[0])),
    }
}

fn trim_ascii_whitespace(input: &str) -> &str {
    input.trim_matches(|character: char| character.is_ascii_whitespace())
}

fn require_rule_field_count(fields: &[&str], expected: usize, rule_type: &str) -> Result<()> {
    if fields.len() != expected {
        return invalid(format!(
            "{rule_type} rule must contain exactly {expected} fields"
        ));
    }
    Ok(())
}

fn parse_rule_action(action: &str, proxy_ids: &ProxyIdsByTag) -> Result<RuleAction> {
    match action {
        "DIRECT" => Ok(RuleAction::Direct),
        "REJECT" => Ok(RuleAction::Reject),
        tag => proxy_ids
            .get(tag)
            .copied()
            .map(RuleAction::Proxy)
            .ok_or_else(|| {
                VCoreError::InvalidConfig(format!(
                    "rule target must be exactly DIRECT, REJECT, or a configured proxy name; found `{action}`"
                ))
            }),
    }
}

fn normalize_rule_domain(input: &str, rule_type: &str) -> Result<String> {
    let input = input.strip_suffix('.').unwrap_or(input);
    crate::routing::normalize_domain_name(input)
        .map_err(|_| VCoreError::InvalidConfig(format!("invalid {rule_type} domain")))
}

fn normalize_rule_keyword(input: &str) -> Result<String> {
    if input.is_empty()
        || input.len() > 253
        || !input.is_ascii()
        || input.bytes().any(|byte| byte.is_ascii_control())
    {
        return invalid("invalid DOMAIN-KEYWORD value");
    }
    Ok(input.to_ascii_lowercase())
}

fn normalize_geo_code(input: &str, rule_type: &str) -> Result<String> {
    let bytes = input.as_bytes();
    if !(1..=64).contains(&bytes.len())
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'+' | b'!' | b'-')
        })
    {
        return invalid(format!("invalid {rule_type} code"));
    }
    Ok(input.to_ascii_lowercase())
}

fn parse_ip_cidr(input: &str, require_v6: bool) -> Result<IpCidr> {
    let (address, prefix) = input
        .split_once('/')
        .ok_or_else(|| VCoreError::InvalidConfig("CIDR must include a prefix length".to_owned()))?;
    if prefix.contains('/') {
        return invalid("CIDR must contain exactly one `/`");
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| VCoreError::InvalidConfig(format!("invalid CIDR address `{address}`")))?;
    let prefix_len = prefix
        .parse::<u8>()
        .map_err(|_| VCoreError::InvalidConfig(format!("invalid CIDR prefix `{prefix}`")))?;

    let network = match (require_v6, address) {
        (false, IpAddr::V4(address)) if prefix_len <= 32 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_len))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        (true, IpAddr::V6(address)) if prefix_len <= 128 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix_len))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
        (false, IpAddr::V6(_)) => return invalid("IP-CIDR requires an IPv4 network"),
        (true, IpAddr::V4(_)) => return invalid("IP-CIDR6 requires an IPv6 network"),
        (false, IpAddr::V4(_)) => return invalid("IPv4 CIDR prefix must be between 0 and 32"),
        (true, IpAddr::V6(_)) => return invalid("IPv6 CIDR prefix must be between 0 and 128"),
    };
    Ok(IpCidr {
        network,
        prefix_len,
    })
}

fn parse_port_ranges(input: &str) -> Result<Vec<PortRange>> {
    if input.is_empty() {
        return invalid("DST-PORT value must not be empty");
    }
    input
        .split('/')
        .map(|item| {
            if item.is_empty() {
                return invalid("DST-PORT contains an empty port range");
            }
            let (start, end) = item.split_once('-').unwrap_or((item, item));
            if end.contains('-') {
                return invalid("DST-PORT range must contain at most one `-`");
            }
            let start = parse_destination_port(start)?;
            let end = parse_destination_port(end)?;
            if start > end {
                return invalid("DST-PORT range start must not exceed its end");
            }
            Ok(PortRange { start, end })
        })
        .collect()
}

fn parse_destination_port(input: &str) -> Result<u16> {
    let port = input
        .parse::<u16>()
        .map_err(|_| VCoreError::InvalidConfig(format!("invalid destination port `{input}`")))?;
    if port == 0 {
        return invalid("destination port must be between 1 and 65535");
    }
    Ok(port)
}

fn parse_network(input: &str) -> Result<Network> {
    if input.eq_ignore_ascii_case("tcp") {
        Ok(Network::Tcp)
    } else if input.eq_ignore_ascii_case("udp") {
        Ok(Network::Udp)
    } else {
        invalid("NETWORK value must be TCP or UDP")
    }
}

fn validate_tag_syntax(tag: &str, field: &str) -> Result<()> {
    let bytes = tag.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
    {
        return invalid(format!(
            "{field} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,63}}"
        ));
    }
    Ok(())
}

fn validate_proxy_tag(tag: &str) -> Result<()> {
    validate_tag_syntax(tag, "proxy name")?;
    if matches!(tag, "DIRECT" | "REJECT" | "RULES") {
        return invalid(format!("proxy name `{tag}` is reserved"));
    }
    Ok(())
}

fn validate_host(host: &str, field: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        return invalid(format!("invalid {field}"));
    }
    if IpAddr::from_str(host).is_ok() {
        return Ok(());
    }
    if !host.is_ascii()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return invalid(format!("invalid {field}"));
    }
    Ok(())
}

fn validate_port(port: u16, kind: &str) -> Result<()> {
    if port == 0 {
        return invalid(format!("{kind} port must be between 1 and 65535"));
    }
    Ok(())
}

fn parse_standard_uuid(input: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(input)
        .map_err(|_| VCoreError::InvalidConfig("invalid VLESS settings.id UUID".to_owned()))?;
    if id.hyphenated().to_string() != input.to_ascii_lowercase() {
        return invalid("VLESS settings.id must use standard hyphenated UUID form");
    }
    Ok(id)
}

fn validate_json_compatible_yaml(value: &YamlValue) -> Result<()> {
    match value {
        YamlValue::Null | YamlValue::Bool(_) | YamlValue::Number(_) | YamlValue::String(_) => {
            Ok(())
        }
        YamlValue::Sequence(values) => {
            for value in values {
                validate_json_compatible_yaml(value)?;
            }
            Ok(())
        }
        YamlValue::Mapping(mapping) => {
            for (key, value) in mapping {
                let YamlValue::String(key) = key else {
                    return invalid("YAML map keys must be strings");
                };
                if key == "<<" {
                    return invalid("YAML merge keys are not supported");
                }
                validate_json_compatible_yaml(value)?;
            }
            Ok(())
        }
        YamlValue::Tagged(_) => invalid("custom YAML tags are not supported"),
    }
}

/// Anchors and aliases disappear when `serde_yaml_ng` materializes a value, so
/// reject their node-property syntax before parsing. Quoted text and comments
/// are intentionally ignored by this small lexical pass.
fn reject_yaml_anchors_and_aliases(input: &str) -> Result<()> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut comment = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if comment {
            if byte == b'\n' {
                comment = false;
            }
            index += 1;
            continue;
        }
        if single_quoted {
            if byte == b'\'' {
                if bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                single_quoted = false;
            }
            index += 1;
            continue;
        }
        if double_quoted {
            if byte == b'\\' {
                index = (index + 2).min(bytes.len());
                continue;
            }
            if byte == b'"' {
                double_quoted = false;
            }
            index += 1;
            continue;
        }

        match byte {
            b'#' if index == 0 || bytes[index - 1].is_ascii_whitespace() => comment = true,
            b'\'' => single_quoted = true,
            b'"' => double_quoted = true,
            b'&' | b'*' if is_yaml_node_boundary(bytes, index) => {
                return invalid("YAML anchors and aliases are not supported");
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn is_yaml_node_boundary(bytes: &[u8], index: usize) -> bool {
    let previous_is_boundary = index == 0
        || bytes[index - 1].is_ascii_whitespace()
        || b"[{,:?-".contains(&bytes[index - 1]);
    let Some(next) = bytes.get(index + 1) else {
        return false;
    };
    previous_is_boundary
        && !next.is_ascii_whitespace()
        && !b"[]{}:,#".contains(next)
        && *next != b'\n'
        && *next != b'\r'
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(VCoreError::InvalidConfig(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_TLS: &str = r#"port: 1080
authentication:
  - measure:secret
tun:
  enable: true
  mtu: 1500
rules:
  - MATCH,proxy
proxies:
  - name: proxy
    type: vless
    server: 203.0.113.1
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    flow: ""
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      path: /x
      host: example.com
      mode: auto
"#;

    const CURRENT_PROXY: &str = r#"
proxies:
  - name: proxy
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    flow: ""
    servername: edge.example.com
    alpn: [h2]
    xhttp-opts:
      host: edge.example.com
      path: /onev
      mode: auto
"#;

    const SOCKS_PROXY_ENTRY: &str = r#"  - name: socks-hop
    type: socks5
    server: socks.example.com
    port: 1080
    udp: true
    username: user
    password: password
"#;

    const CURRENT_ANYTLS: &str = r#"port: 1080
authentication:
  - measure:secret
rules:
  - MATCH,anytls-node
proxies:
  - name: anytls-node
    type: anytls
    server: anytls.example.com
    port: 443
    password: private-anytls-password
"#;

    fn current_yaml(fields: &str) -> String {
        let default_rules = if fields
            .lines()
            .any(|line| line.trim_ascii_start() == "rules:")
        {
            ""
        } else {
            "rules:\n  - MATCH,proxy\n"
        };
        format!("{fields}\n{default_rules}{CURRENT_PROXY}")
    }

    fn with_sniffer(sniffer: &str) -> String {
        CURRENT_TLS.replacen("proxies:\n", &format!("sniffer:\n{sniffer}\nproxies:\n"), 1)
    }

    fn with_geodata(fields: &str) -> String {
        current_yaml(&format!(
            "{fields}\nport: 1080\nauthentication:\n  - measure:secret"
        ))
    }

    fn two_proxy_yaml(fields: &str) -> String {
        format!("{}{SOCKS_PROXY_ENTRY}", current_yaml(fields))
    }

    fn second_vless_entry() -> String {
        CURRENT_PROXY
            .strip_prefix("\nproxies:\n")
            .expect("CURRENT_PROXY starts with its collection key")
            .replace("name: proxy", "name: vless-two")
            .replace("edge.example.com", "second.example.com")
            .replace(
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
            )
    }

    fn socks_proxy_entries(count: usize, chained: bool) -> String {
        assert!(count > 0);
        let mut entries = String::new();
        for index in 0..count {
            entries.push_str(&format!("  - name: node-{index}\n    type: socks5\n"));
            if chained && index > 0 {
                entries.push_str(&format!("    dialer-proxy: node-{}\n", index - 1));
            }
            entries.push_str(&format!(
                "    server: node-{index}.example.com\n    port: 1080\n    udp: true\n"
            ));
        }
        entries
    }

    fn first_vless(config: &Config) -> &VlessOutboundConfig {
        let ProxyProtocol::Vless(vless) = &config.proxies[0].protocol else {
            panic!("expected VLESS proxy");
        };
        vless
    }

    fn first_xhttp_download(config: &Config) -> &XHttpDownloadConfig {
        first_vless(config)
            .xhttp
            .download
            .as_deref()
            .expect("expected XHTTP download settings")
    }

    fn reality_yaml() -> String {
        let key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        CURRENT_TLS.replace(
            "    servername: example.com\n",
            &format!(
                "    servername: example.com\n    reality-opts:\n      public-key: {key}\n      short-id: 01a2\n"
            ),
        )
    }

    fn with_xhttp_download(yaml: &str, fields: &str) -> String {
        let download = if fields.is_empty() {
            "      download-settings: {}\n".to_owned()
        } else {
            let fields = fields
                .lines()
                .map(|line| format!("        {line}\n"))
                .collect::<String>();
            format!("      download-settings:\n{fields}")
        };
        yaml.replacen(
            "      mode: auto\n",
            &format!("      mode: auto\n{download}"),
            1,
        )
    }

    #[test]
    fn parses_the_strict_tls_subset() {
        assert_eq!(ProxyId::new(0).unwrap().index(), 0);
        assert_eq!(ProxyId::new(1).unwrap().index(), 1);
        assert_eq!(
            ProxyId::new(usize::MAX).expect("ProxyId has no count-based ceiling"),
            ProxyId(usize::MAX)
        );
        let config = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.proxies[0].tag, "proxy");
        assert!(config.proxies[0].udp);
        assert_eq!(config.default_proxy, ProxyId::new(0).unwrap());
        assert_eq!(first_vless(&config).address, "203.0.113.1");
        assert!(matches!(
            &first_vless(&config).security,
            SecurityConfig::Tls(TlsConfig { server_name }) if server_name == "example.com"
        ));
        assert_eq!(first_vless(&config).xhttp.mode, XHttpMode::PacketUp);
        assert!(first_vless(&config).xhttp.download.is_none());
    }

    #[test]
    fn parses_the_complete_geodata_update_contract() {
        let config = Config::parse_yaml(
            with_geodata(
                r#"geox-url:
  geoip: https://geo.example.test/custom-geoip.dat?channel=stable
  geosite: https://geo.example.test/custom-geosite.dat
geo-auto-update: true
geo-update-interval: 24"#,
            )
            .as_bytes(),
        )
        .unwrap();
        let update = config
            .geodata_update
            .expect("complete GeoData fields normalize into an update config");
        assert!(update.auto_update);
        assert_eq!(update.interval_hours, GEO_UPDATE_INTERVAL_HOURS);
        assert_eq!(
            update.urls.geoip,
            "https://geo.example.test/custom-geoip.dat?channel=stable"
        );
        assert_eq!(
            update.urls.geosite,
            "https://geo.example.test/custom-geosite.dat"
        );

        let disabled = Config::parse_yaml(
            with_geodata(
                r#"geox-url:
  geoip: https://geo.example.test/geoip.dat
  geosite: https://geo.example.test/geosite.dat
geo-auto-update: false
geo-update-interval: 24"#,
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(
            !disabled
                .geodata_update
                .expect("disabled updater remains explicit configuration")
                .auto_update
        );
        assert!(
            Config::parse_yaml(CURRENT_TLS.as_bytes())
                .unwrap()
                .geodata_update
                .is_none()
        );
    }

    #[test]
    fn geodata_update_fields_are_all_present_or_all_absent() {
        let urls = "geox-url:\n  geoip: https://geo.example.test/geoip.dat\n  geosite: https://geo.example.test/geosite.dat";
        for fields in [
            urls.to_owned(),
            "geo-auto-update: true".to_owned(),
            "geo-update-interval: 24".to_owned(),
            format!("{urls}\ngeo-auto-update: true"),
            format!("{urls}\ngeo-update-interval: 24"),
            "geo-auto-update: true\ngeo-update-interval: 24".to_owned(),
        ] {
            let error = Config::parse_yaml(with_geodata(&fields).as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("must be configured together"),
                "{fields}: {error}"
            );
        }
    }

    #[test]
    fn validates_geodata_update_interval_and_url_shape() {
        let complete = |geoip: &str, geosite: &str, interval: &str| {
            with_geodata(&format!(
                "geox-url:\n  geoip: {geoip}\n  geosite: {geosite}\ngeo-auto-update: true\ngeo-update-interval: {interval}"
            ))
        };
        for yaml in [
            complete(
                "https://geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "23",
            ),
            complete(
                "https://geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24.0",
            ),
            complete(
                "http://geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://127.0.0.1/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://[::1]/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://user:password@geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://@geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://geo.example.test/geoip.dat#latest",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let prefix = "https://geo.example.test/";
        let maximum = format!("{prefix}{}", "g".repeat(MAX_GEOX_URL_BYTES - prefix.len()));
        assert_eq!(maximum.len(), MAX_GEOX_URL_BYTES);
        assert!(
            Config::parse_yaml(
                complete(&maximum, "https://geo.example.test/geosite.dat", "24").as_bytes()
            )
            .is_ok()
        );
        let oversized = format!("{maximum}x");
        let error = Config::parse_yaml(
            complete(&oversized, "https://geo.example.test/geosite.dat", "24").as_bytes(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("4096-byte limit"), "{error}");
    }

    #[test]
    fn rejects_incomplete_or_extended_geox_url_maps() {
        for fields in [
            r#"geox-url:
  geoip: https://geo.example.test/geoip.dat
geo-auto-update: true
geo-update-interval: 24"#,
            r#"geox-url:
  geosite: https://geo.example.test/geosite.dat
geo-auto-update: true
geo-update-interval: 24"#,
            r#"geox-url:
  geoip: https://geo.example.test/geoip.dat
  geosite: https://geo.example.test/geosite.dat
  mmdb: https://geo.example.test/country.mmdb
geo-auto-update: true
geo-update-interval: 24"#,
        ] {
            assert!(
                Config::parse_yaml(with_geodata(fields).as_bytes()).is_err(),
                "{fields}"
            );
        }
    }

    #[test]
    fn defaults_documented_fields() {
        let yaml = CURRENT_TLS
            .replace("    flow: \"\"\n", "")
            .replace("    encryption: none\n", "")
            .replace("    alpn: [h2]\n", "")
            .replace(
                "    xhttp-opts:\n      path: /x\n      host: example.com\n      mode: auto\n",
                "",
            );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(first_vless(&config).flow, "");
        assert_eq!(first_vless(&config).xhttp.path, "/");
        assert_eq!(first_vless(&config).xhttp.host, "example.com");
        assert_eq!(first_vless(&config).xhttp.mode, XHttpMode::PacketUp);
        assert!(matches!(
            config.inbounds[1],
            InboundConfig::Tun(TunInboundConfig { mtu: 1_500, .. })
        ));
        assert_eq!(config.sniffer, SnifferConfig::disabled());
    }

    #[test]
    fn parses_and_normalizes_the_strict_mihomo_style_sniffer_subset() {
        let config = Config::parse_yaml(
            with_sniffer(
                r#"  enable: true
  sniff:
    HTTP:
    TLS:
      ports: [443, "8443", "8444-8446", "8445-8447"]
    QUIC:"#,
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(config.sniffer.enable);
        assert_eq!(
            config.sniffer.http_ports.as_ref(),
            &[PortRange { start: 80, end: 80 }]
        );
        assert_eq!(
            config.sniffer.tls_ports.as_ref(),
            &[
                PortRange {
                    start: 443,
                    end: 443
                },
                PortRange {
                    start: 8_443,
                    end: 8_447
                }
            ]
        );
        assert!(config.sniffer.matches_http_port(80));
        assert!(!config.sniffer.matches_http_port(8080));
        assert!(config.sniffer.matches_tls_port(8445));
        assert!(!config.sniffer.matches_tls_port(8448));
        assert_eq!(
            config.sniffer.quic_ports.as_ref(),
            &[PortRange {
                start: 443,
                end: 443
            }]
        );
        assert!(config.sniffer.matches_quic_port(443));
        assert!(!config.sniffer.matches_quic_port(8443));

        let http_only =
            Config::parse_yaml(with_sniffer("  enable: true\n  sniff:\n    HTTP: {}").as_bytes())
                .unwrap();
        assert!(http_only.sniffer.enable);
        assert!(http_only.sniffer.matches_http_port(80));
        assert!(http_only.sniffer.tls_ports.is_empty());
        assert!(http_only.sniffer.quic_ports.is_empty());

        let quic_only =
            Config::parse_yaml(with_sniffer("  enable: true\n  sniff:\n    QUIC: {}").as_bytes())
                .unwrap();
        assert!(quic_only.sniffer.matches_quic_port(443));
        assert!(quic_only.sniffer.http_ports.is_empty());
        assert!(quic_only.sniffer.tls_ports.is_empty());

        let shared_port = Config::parse_yaml(
            with_sniffer(
                "  enable: true\n  sniff:\n    HTTP:\n      ports: [443]\n    TLS:\n      ports: [8443]\n    QUIC:\n      ports: [443, 8443]",
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(shared_port.sniffer.matches_http_port(443));
        assert!(shared_port.sniffer.matches_tls_port(8443));
        assert!(shared_port.sniffer.matches_quic_port(443));
        assert!(shared_port.sniffer.matches_quic_port(8443));
    }

    #[test]
    fn disabled_sniffer_may_omit_or_preconfigure_protocols() {
        let omitted = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert_eq!(omitted.sniffer, SnifferConfig::disabled());

        let configured = Config::parse_yaml(
            with_sniffer(
                r#"  enable: false
  sniff:
    HTTP:
      ports: ["8080-8081"]
    QUIC:
      ports: ["8443-8444"]"#,
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(!configured.sniffer.enable);
        assert_eq!(
            configured.sniffer.http_ports.as_ref(),
            &[PortRange {
                start: 8080,
                end: 8081
            }]
        );
        assert!(configured.sniffer.tls_ports.is_empty());
        assert_eq!(
            configured.sniffer.quic_ports.as_ref(),
            &[PortRange {
                start: 8443,
                end: 8444
            }]
        );
    }

    #[test]
    fn rejects_invalid_sniffer_shapes_ports_and_overlap() {
        let too_many_ports = (1..=MAX_SNIFFER_PORT_ITEMS + 1)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        for yaml in [
            with_sniffer("  enable: true"),
            with_sniffer("  enable: true\n  sniff: {}"),
            with_sniffer("  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: \"true\"\n  sniff:\n    HTTP: {}"),
            CURRENT_TLS.replacen("tun:\n", "sniffer:\ntun:\n", 1),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: []"),
            with_sniffer("  enable: true\n  sniff:\n    QUIC:\n      ports: []"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [0]"),
            with_sniffer("  enable: true\n  sniff:\n    QUIC:\n      ports: [0]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [65536]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"+80\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\" 80\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"80 \"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"８０\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"443-\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"444-443\"]"),
            with_sniffer("  enable: true\n  sniff:\n    QUIC:\n      ports: [\"444-443\"]"),
            with_sniffer(
                "  enable: true\n  sniff:\n    HTTP:\n      ports: [\"80-90\"]\n    TLS:\n      ports: [90]",
            ),
            with_sniffer(&format!(
                "  enable: true\n  sniff:\n    HTTP:\n      ports: [{too_many_ports}]"
            )),
            with_sniffer(&format!(
                "  enable: true\n  sniff:\n    QUIC:\n      ports: [{too_many_ports}]"
            )),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn brackets_an_ipv6_server_name_used_as_the_default_xhttp_host() {
        let yaml = CURRENT_TLS
            .replace("servername: example.com", "servername: '::1'")
            .replace("      host: example.com\n", "");
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(first_vless(&config).xhttp.host, "[::1]");
    }

    #[test]
    fn parses_and_decodes_reality() {
        let config = Config::parse_yaml(reality_yaml().as_bytes()).unwrap();
        let SecurityConfig::Reality(reality) = &first_vless(&config).security else {
            panic!("expected REALITY");
        };
        assert_eq!(reality.server_name, "example.com");
        assert_eq!(reality.public_key, [7_u8; 32]);
        assert_eq!(reality.short_id, [1, 0xa2]);
        assert_eq!(first_vless(&config).xhttp.mode, XHttpMode::StreamOne);
    }

    #[test]
    fn auto_mode_tracks_the_security_transport() {
        let tls = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert_eq!(first_vless(&tls).xhttp.mode, XHttpMode::PacketUp);
        let reality = Config::parse_yaml(reality_yaml().as_bytes()).unwrap();
        assert_eq!(first_vless(&reality).xhttp.mode, XHttpMode::StreamOne);
        let reality_with_download = with_xhttp_download(&reality_yaml(), "");
        let reality_with_download = Config::parse_yaml(reality_with_download.as_bytes()).unwrap();
        assert_eq!(
            first_vless(&reality_with_download).xhttp.mode,
            XHttpMode::StreamUp
        );
    }

    #[test]
    fn accepts_explicit_supported_xhttp_modes() {
        let packet_up = CURRENT_TLS.replace("mode: auto", "mode: packet-up");
        let packet_up = Config::parse_yaml(packet_up.as_bytes()).unwrap();
        assert_eq!(first_vless(&packet_up).xhttp.mode, XHttpMode::PacketUp);
        let stream_one = CURRENT_TLS.replace("mode: auto", "mode: stream-one");
        let stream_one = Config::parse_yaml(stream_one.as_bytes()).unwrap();
        assert_eq!(first_vless(&stream_one).xhttp.mode, XHttpMode::StreamOne);
        let stream_up = CURRENT_TLS.replace("mode: auto", "mode: stream-up");
        let stream_up = Config::parse_yaml(stream_up.as_bytes()).unwrap();
        assert_eq!(first_vless(&stream_up).xhttp.mode, XHttpMode::StreamUp);

        for (mode, expected) in [
            ("packet-up", XHttpMode::PacketUp),
            ("stream-up", XHttpMode::StreamUp),
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, "")
                .replace("mode: auto", &format!("mode: {mode}"));
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert_eq!(first_vless(&config).xhttp.mode, expected);
        }
    }

    #[test]
    fn normalizes_xhttp_download_security_inheritance_and_reality_override() {
        let tls_inherited = with_xhttp_download(CURRENT_TLS, "");
        let tls_inherited = Config::parse_yaml(tls_inherited.as_bytes()).unwrap();
        let download = first_xhttp_download(&tls_inherited);
        assert_eq!(download.address, "203.0.113.1");
        assert_eq!(download.port, 443);
        assert_eq!(download.path, "/x");
        assert_eq!(download.host, "example.com");
        assert!(matches!(
            &download.security,
            SecurityConfig::Tls(TlsConfig { server_name }) if server_name == "example.com"
        ));
        assert_eq!(first_vless(&tls_inherited).xhttp.mode, XHttpMode::PacketUp);

        let download_reality_key = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let tls_to_reality = with_xhttp_download(
            CURRENT_TLS,
            &format!(
                "server: download.example.com\nport: 8443\ntls: true\nservername: reality-download.example.com\nalpn: [h2]\npath: /down\nhost: cdn.example.com\nreality-opts:\n  public-key: {download_reality_key}\n  short-id: 02a3"
            ),
        );
        let tls_to_reality_without_explicit_tls = tls_to_reality.replace("        tls: true\n", "");
        let inherited_tls =
            Config::parse_yaml(tls_to_reality_without_explicit_tls.as_bytes()).unwrap();
        assert!(matches!(
            &first_xhttp_download(&inherited_tls).security,
            SecurityConfig::Reality(_)
        ));
        let tls_to_reality = Config::parse_yaml(tls_to_reality.as_bytes()).unwrap();
        let download = first_xhttp_download(&tls_to_reality);
        assert_eq!(download.address, "download.example.com");
        assert_eq!(download.port, 8_443);
        assert_eq!(download.path, "/down");
        assert_eq!(download.host, "cdn.example.com");
        let SecurityConfig::Reality(download_reality) = &download.security else {
            panic!("expected download REALITY");
        };
        assert_eq!(download_reality.server_name, "reality-download.example.com");
        assert_eq!(download_reality.public_key, [9_u8; 32]);
        assert_eq!(download_reality.short_id, [2, 0xa3]);
        assert_eq!(first_vless(&tls_to_reality).xhttp.mode, XHttpMode::PacketUp);

        let reality_inherited = with_xhttp_download(&reality_yaml(), "");
        let reality_inherited = Config::parse_yaml(reality_inherited.as_bytes()).unwrap();
        assert_eq!(
            &first_xhttp_download(&reality_inherited).security,
            &first_vless(&reality_inherited).security
        );
        assert_eq!(
            first_vless(&reality_inherited).xhttp.mode,
            XHttpMode::StreamUp
        );

        let reality_with_explicit_tls = with_xhttp_download(
            &reality_yaml(),
            "tls: true\nservername: tls-download.example.com",
        );
        let reality_with_explicit_tls =
            Config::parse_yaml(reality_with_explicit_tls.as_bytes()).unwrap();
        let SecurityConfig::Reality(download_reality) =
            &first_xhttp_download(&reality_with_explicit_tls).security
        else {
            panic!("explicit download tls must not clear inherited REALITY");
        };
        assert_eq!(download_reality.server_name, "tls-download.example.com");
        assert_eq!(
            first_vless(&reality_with_explicit_tls).xhttp.mode,
            XHttpMode::StreamUp
        );
    }

    #[test]
    fn xhttp_download_defaults_follow_raw_mihomo_fallback_order() {
        let implicit_outer = CURRENT_TLS
            .replace("    servername: example.com\n", "")
            .replace("      host: example.com\n", "");
        let implicit_outer =
            with_xhttp_download(&implicit_outer, "server: download.example.com\nport: 8443");
        let implicit_outer = Config::parse_yaml(implicit_outer.as_bytes()).unwrap();
        let download = first_xhttp_download(&implicit_outer);
        assert_eq!(download.address, "download.example.com");
        assert_eq!(download.port, 8_443);
        assert_eq!(download.security.server_name(), "download.example.com");
        assert_eq!(download.host, "download.example.com");

        let inherited_sni = CURRENT_TLS.replace("      host: example.com\n", "");
        let inherited_sni =
            with_xhttp_download(&inherited_sni, "server: download.example.com\nport: 8443");
        let inherited_sni = Config::parse_yaml(inherited_sni.as_bytes()).unwrap();
        let download = first_xhttp_download(&inherited_sni);
        assert_eq!(download.security.server_name(), "example.com");
        assert_eq!(download.host, "example.com");

        let inherited_host = CURRENT_TLS.replace("    servername: example.com\n", "");
        let inherited_host =
            with_xhttp_download(&inherited_host, "server: download.example.com\nport: 8443");
        let inherited_host = Config::parse_yaml(inherited_host.as_bytes()).unwrap();
        let download = first_xhttp_download(&inherited_host);
        assert_eq!(download.security.server_name(), "download.example.com");
        assert_eq!(download.host, "example.com");

        let ipv6_download = CURRENT_TLS
            .replace("    servername: example.com\n", "")
            .replace("      host: example.com\n", "");
        let ipv6_download =
            with_xhttp_download(&ipv6_download, "server: '2001:db8::10'\nport: 8443");
        let ipv6_download = Config::parse_yaml(ipv6_download.as_bytes()).unwrap();
        let download = first_xhttp_download(&ipv6_download);
        assert_eq!(download.security.server_name(), "2001:db8::10");
        assert_eq!(download.host, "[2001:db8::10]");
    }

    #[test]
    fn rejects_stream_one_with_xhttp_download_settings() {
        let yaml = with_xhttp_download(CURRENT_TLS, "").replace("mode: auto", "mode: stream-one");
        let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("stream-one")
                && error.to_string().contains("download-settings"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_or_null_xhttp_download_fields() {
        let download_null = CURRENT_TLS.replace(
            "      mode: auto\n",
            "      mode: auto\n      download-settings: null\n",
        );
        assert!(Config::parse_yaml(download_null.as_bytes()).is_err());

        for field in [
            "server",
            "port",
            "tls",
            "servername",
            "alpn",
            "reality-opts",
            "path",
            "host",
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, &format!("{field}: null"));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{field}");
        }

        for fields in [
            "tls: false",
            "alpn: []",
            "alpn: [h3]",
            "server: 'bad host'",
            "port: 0",
            "servername: 'bad host'",
            "path: 'bad-path'",
            "host: '[broken'",
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, fields);
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{fields}");
        }
    }

    #[test]
    fn rejects_unsupported_xhttp_download_fields_fail_closed() {
        for fields in [
            "shadow-tls-opts: {}",
            "restls-opts: {}",
            "jls-opts: {}",
            "ech-opts: {}",
            "headers: {}",
            "reuse-settings: {}",
            "skip-cert-verify: false",
            "name-cert-verify: example.com",
            "fingerprint: pinned",
            "certificate: cert.pem",
            "private-key: key.pem",
            "client-fingerprint: chrome",
            "mode: stream-up",
            "typo: true",
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, fields);
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "{fields}: {error}"
            );
        }

        for unsupported in [
            "    shadow-tls-opts: {}\n",
            "    restls-opts: {}\n",
            "    jls-opts: null\n",
        ] {
            let yaml = CURRENT_TLS.replace(
                "    xhttp-opts:\n",
                &format!("{unsupported}    xhttp-opts:\n"),
            );
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "{unsupported}: {error}"
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_at_every_depth() {
        for yaml in [
            CURRENT_TLS.replacen("port: 1080\n", "log: {}\nport: 1080\n", 1),
            CURRENT_TLS.replace("tun:\n", "tun:\n  typo: true\n"),
            with_sniffer("  enable: true\n  typo: true\n  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: true\n  override-destination: false\n  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: true\n  force-dns-mapping: true\n  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: true\n  parse-pure-ip: true\n  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: true\n  force-domain: [example.com]\n  sniff:\n    HTTP: {}"),
            with_sniffer(
                "  enable: true\n  skip-src-address: [192.0.2.1/32]\n  sniff:\n    HTTP: {}",
            ),
            with_sniffer(
                "  enable: true\n  skip-dst-address: [192.0.2.1/32]\n  sniff:\n    HTTP: {}",
            ),
            with_sniffer("  enable: true\n  skip-domain: [example.com]\n  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: true\n  sniffing: [http]"),
            with_sniffer("  enable: true\n  port-whitelist: [80]"),
            with_sniffer("  enable: true\n  sniff:\n    http: {}"),
            with_sniffer("  enable: true\n  sniff:\n    quic: {}"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      override-destination: false"),
            CURRENT_TLS.replace("  - name: proxy\n", "  - typo: true\n    name: proxy\n"),
            CURRENT_TLS.replace("    server: ", "    vnext: []\n    server: "),
            CURRENT_TLS.replace("    network: xhttp", "    typo: true\n    network: xhttp"),
            CURRENT_TLS.replace("      path: /x", "      typo: true\n      path: /x"),
            CURRENT_TLS.replace(
                "    servername: example.com",
                "    client-fingerprint: chrome\n    servername: example.com",
            ),
            reality_yaml().replace(
                "      public-key:",
                "      support-x25519mlkem768: true\n      public-key:",
            ),
        ] {
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }

    #[test]
    fn rejects_removed_xray_style_vless_shapes() {
        for yaml in [
            CURRENT_TLS.replace("    server: ", "    settings: {}\n    server: "),
            CURRENT_TLS.replace("    server: ", "    streamSettings: {}\n    server: "),
            CURRENT_TLS.replace("    type: vless", "    protocol: vless"),
            CURRENT_TLS.replace("  - name: proxy", "  - tag: proxy"),
            CURRENT_TLS.replace("    server: ", "    address: "),
            CURRENT_TLS.replace("    uuid: ", "    id: "),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_removed_version_and_default_proxy_fields() {
        for yaml in [
            CURRENT_TLS.replacen("port: 1080\n", "configVersion: 9\nport: 1080\n", 1),
            CURRENT_TLS.replacen("port: 1080\n", "default-proxy: proxy\nport: 1080\n", 1),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }

        let old = r#"inbounds: []
outbounds: []
"#;
        assert!(Config::parse_yaml(old.as_bytes()).is_err());
    }

    #[test]
    fn validates_listener_and_tun_constraints() {
        for yaml in [
            CURRENT_TLS.replace("mtu: 1500", "mtu: 1400"),
            CURRENT_TLS.replace(
                "port: 1080
authentication:
  - measure:secret",
                "port: 0
authentication:
  - measure:secret",
            ),
            CURRENT_TLS
                .replace("enable: true", "enable: false")
                .replace(
                    "port: 1080
authentication:
  - measure:secret\n",
                    "",
                ),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn parses_the_strict_mihomo_style_traffic_controller_subset() {
        let authenticated = Config::parse_yaml(
            current_yaml(
                r#"external-controller: "127.0.0.1:19090"
secret: "random token"
tun:
  enable: true"#,
            )
            .as_bytes(),
        )
        .unwrap();
        let controller = authenticated
            .external_controller
            .expect("configured controller");
        assert_eq!(controller.listen, "127.0.0.1:19090".parse().unwrap());
        assert_eq!(controller.secret.as_deref(), Some("random token"));

        let unauthenticated = Config::parse_yaml(
            current_yaml(
                r#"external-controller: "[::1]:19091"
tun:
  enable: true"#,
            )
            .as_bytes(),
        )
        .unwrap();
        let controller = unauthenticated
            .external_controller
            .expect("configured controller");
        assert_eq!(controller.listen, "[::1]:19091".parse().unwrap());
        assert!(controller.secret.is_none());

        let debug = format!(
            "{:?}",
            ExternalControllerConfig {
                listen: "127.0.0.1:19090".parse().unwrap(),
                secret: Some("private-token".to_owned()),
            }
        );
        assert!(debug.contains("authenticated: true"));
        assert!(!debug.contains("private-token"));
    }

    #[test]
    fn rejects_unsafe_or_misplaced_traffic_controller_config() {
        for (fields, expected) in [
            (
                "port: 1080\nauthentication:\n  - measure:secret\nsecret: token",
                "secret requires external-controller",
            ),
            (
                "port: 1080\nauthentication:\n  - measure:secret\nexternal-controller: \"127.0.0.1:19090\"",
                "external-controller requires tun.enable",
            ),
            (
                "external-controller: \"0.0.0.0:19090\"\ntun:\n  enable: true",
                "loopback",
            ),
            (
                "external-controller: \"127.0.0.1:0\"\ntun:\n  enable: true",
                "between 1 and 65535",
            ),
            (
                "external-controller: localhost:19090\ntun:\n  enable: true",
                "IP socket address",
            ),
            (
                "external-controller: \"127.0.0.1:19090\"\nsecret: \"\"\ntun:\n  enable: true",
                "between 1 and 255",
            ),
        ] {
            let error = Config::parse_yaml(current_yaml(fields).as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected error for {fields:?}: {error}"
            );
        }

        let oversized = current_yaml(&format!(
            "external-controller: \"127.0.0.1:19090\"\nsecret: \"{}\"\ntun:\n  enable: true",
            "s".repeat(MAX_CONTROLLER_SECRET_BYTES + 1)
        ));
        assert!(Config::parse_yaml(oversized.as_bytes()).is_err());
        assert!(
            Config::parse_yaml(
                current_yaml("external-controller: null\ntun:\n  enable: true").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn validates_strict_http_port_authentication_contract() {
        let yaml = current_yaml(
            r#"port: 1080
authentication:
  - "用户:密:码""#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let [InboundConfig::Http(http)] = config.inbounds.as_slice() else {
            panic!("HTTP-only config must normalize exactly one HTTP inbound");
        };
        assert_eq!(http.username, "用户");
        assert_eq!(http.password, "密:码");

        let max_user = "u".repeat(usize::from(u8::MAX));
        let max_password = "p".repeat(usize::from(u8::MAX));
        let max = current_yaml(&format!(
            "port: 1080\nauthentication:\n  - \"{max_user}:{max_password}\""
        ));
        assert!(Config::parse_yaml(max.as_bytes()).is_ok());

        for (fields, expected) in [
            ("port: 1080", "port requires authentication"),
            (
                "authentication:\n  - measure:secret\ntun:\n  enable: true",
                "authentication requires port",
            ),
            (
                "port: 1080\nauthentication: []",
                "authentication must contain exactly one",
            ),
            (
                "port: 1080\nauthentication:\n  - one:secret\n  - two:secret",
                "authentication must contain exactly one",
            ),
            (
                "port: 1080\nauthentication:\n  - missing-separator",
                "authentication entry must use user:password",
            ),
            (
                "port: 1080\nauthentication:\n  - \":secret\"",
                "authentication user must contain between 1 and 255",
            ),
            (
                "port: 1080\nauthentication:\n  - \"measure:\"",
                "authentication password must contain between 1 and 255",
            ),
        ] {
            let error = Config::parse_yaml(current_yaml(fields).as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected error for {fields:?}: {error}"
            );
        }

        for yaml in [
            current_yaml("port: 1080\nauthentication: null"),
            current_yaml("port: 1080\nauthentication: measure:secret"),
            current_yaml("mixed-port: 1080\ntun:\n  enable: true"),
            current_yaml(&format!(
                "port: 1080\nauthentication:\n  - \"{}:secret\"",
                "u".repeat(usize::from(u8::MAX) + 1)
            )),
            current_yaml(&format!(
                "port: 1080\nauthentication:\n  - \"measure:{}\"",
                "p".repeat(usize::from(u8::MAX) + 1)
            )),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn http_inbound_debug_redacts_credentials() {
        let inbound = HttpInboundConfig {
            tag: "http-in".to_owned(),
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 1080,
            username: "private-user".to_owned(),
            password: "private-password".to_owned(),
        };
        let debug = format!("{inbound:?}");
        assert!(debug.contains("HttpInboundConfig"));
        assert!(debug.contains("http-in"));
        assert!(debug.contains("1080"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
    }

    #[test]
    fn parses_the_strict_anytls_subset() {
        let config = Config::parse_yaml(CURRENT_ANYTLS.as_bytes()).unwrap();
        assert_eq!(config.default_proxy, ProxyId::new(0).unwrap());
        let proxy = &config.proxies[0];
        assert_eq!(proxy.tag, "anytls-node");
        assert!(!proxy.udp);
        assert_eq!(proxy.address(), "anytls.example.com");
        assert_eq!(proxy.port(), 443);
        let ProxyProtocol::AnyTls(anytls) = &proxy.protocol else {
            panic!("expected AnyTLS proxy");
        };
        assert_eq!(anytls.password, "private-anytls-password");
        assert_eq!(anytls.server_name, "anytls.example.com");
        let debug = format!("{anytls:?}");
        assert!(debug.contains("AnyTlsOutboundConfig"));
        assert!(debug.contains("anytls.example.com"));
        assert!(!debug.contains("private-anytls-password"));

        let explicit = CURRENT_ANYTLS.replace(
            "    password: private-anytls-password",
            "    password: private-anytls-password\n    udp: true\n    sni: front.example.com",
        );
        let config = Config::parse_yaml(explicit.as_bytes()).unwrap();
        assert!(config.proxies[0].udp);
        let ProxyProtocol::AnyTls(anytls) = &config.proxies[0].protocol else {
            panic!("expected AnyTLS proxy");
        };
        assert_eq!(anytls.server_name, "front.example.com");
    }

    #[test]
    fn supports_anytls_as_a_chain_head() {
        let yaml = CURRENT_ANYTLS
            .replacen("proxies:\n", &format!("proxies:\n{SOCKS_PROXY_ENTRY}"), 1)
            .replace(
                "    password: private-anytls-password",
                "    password: private-anytls-password\n    dialer-proxy: socks-hop",
            );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(config.default_proxy, ProxyId::new(1).unwrap());
        assert_eq!(
            config.proxies[1].dialer_proxy,
            ProxyId::new(0),
            "AnyTLS must participate in the same protocol-agnostic proxy graph"
        );
        assert!(matches!(
            config.proxies[1].protocol,
            ProxyProtocol::AnyTls(_)
        ));
    }

    #[test]
    fn validates_anytls_required_fields() {
        for yaml in [
            CURRENT_ANYTLS.replace("server: anytls.example.com", "server: 'bad host'"),
            CURRENT_ANYTLS.replace("port: 443", "port: 0"),
            CURRENT_ANYTLS.replace("    password: private-anytls-password\n", ""),
            CURRENT_ANYTLS.replace("password: private-anytls-password", "password: \"\""),
            CURRENT_ANYTLS.replace(
                "password: private-anytls-password",
                "password: private-anytls-password\n    sni: 'bad host'",
            ),
            CURRENT_ANYTLS.replace(
                "password: private-anytls-password",
                "password: private-anytls-password\n    sni: null",
            ),
            CURRENT_ANYTLS.replace(
                "password: private-anytls-password",
                &format!("password: {}", "p".repeat(MAX_ANYTLS_PASSWORD_BYTES + 1)),
            ),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn rejects_anytls_fields_outside_the_locked_subset() {
        for field in [
            "tls: true",
            "alpn: [h2]",
            "skip-cert-verify: false",
            "client-fingerprint: chrome",
            "fingerprint: example.com",
            "ech-opts: {}",
            "certificate: client.crt",
            "private-key: client.key",
            "idle-session-check-interval: 30",
            "idle-session-timeout: 30",
            "min-idle-session: 1",
            "disable-reuse: false",
        ] {
            let yaml = CURRENT_ANYTLS.replace(
                "    password: private-anytls-password",
                &format!("    password: private-anytls-password\n    {field}"),
            );
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn validates_simplified_vless_settings() {
        for yaml in [
            CURRENT_TLS.replace("server: 203.0.113.1", "server: 'bad host'"),
            CURRENT_TLS.replace("port: 443", "port: 0"),
            CURRENT_TLS.replace(
                "uuid: 00000000-0000-4000-8000-000000000001",
                "uuid: 00000000000040008000000000000001",
            ),
            CURRENT_TLS.replace("encryption: none", "encryption: auto"),
            CURRENT_TLS.replace("flow: \"\"", "flow: xtls-rprx-vision"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
        assert!(
            Config::parse_yaml(
                CURRENT_TLS
                    .replace("encryption: none", "encryption: \"\"")
                    .as_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn validates_flat_vless_transport_combinations() {
        for yaml in [
            CURRENT_TLS.replace("network: xhttp", "network: ws"),
            CURRENT_TLS.replace("tls: true", "tls: false"),
            CURRENT_TLS.replace(
                "    network: xhttp",
                "    security: tls\n    network: xhttp",
            ),
            CURRENT_TLS.replace("    xhttp-opts:\n", "    xhttp-opts: null\n"),
            CURRENT_TLS.replace(
                "    xhttp-opts:\n",
                "    reality-opts: null\n    xhttp-opts:\n",
            ),
            reality_yaml().replace("    reality-opts:\n", "    reality-opts: {}\n"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn validates_tls_and_xhttp_whitelists() {
        for yaml in [
            CURRENT_TLS.replace("alpn: [h2]", "alpn: [http/1.1]"),
            CURRENT_TLS.replace(
                "    alpn: [h2]",
                "    alpn: [h2]\n    skip-cert-verify: false",
            ),
            CURRENT_TLS.replace("    alpn: [h2]", "    alpn: [h2]\n    allowInsecure: true"),
            CURRENT_TLS.replace("path: /x", "path: '/bad path'"),
            CURRENT_TLS.replace("host: example.com", "host: '[broken'"),
            CURRENT_TLS.replace("host: example.com", "host: null"),
            CURRENT_TLS.replace("      path: /x", "      max-concurrency: 8\n      path: /x"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn validates_reality_key_and_short_id() {
        for yaml in [
            reality_yaml().replace(&URL_SAFE_NO_PAD.encode([7_u8; 32]), "not-base64url"),
            reality_yaml().replace("short-id: 01a2", "short-id: abc"),
            reality_yaml().replace("short-id: 01a2", "short-id: 0123456789abcdef00"),
            reality_yaml().replace("short-id: 01a2", "short-id: zz"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_non_json_yaml_features() {
        for yaml in [
            CURRENT_TLS.replacen("proxies:\n", "1: value\nproxies:\n", 1),
            CURRENT_TLS.replace("name: proxy", "name: !custom proxy"),
            CURRENT_TLS.replace("    xhttp-opts:\n", "    xhttp-opts: &defaults\n"),
            CURRENT_TLS.replace("    xhttp-opts:\n", "    xhttp-opts: *defaults\n"),
            CURRENT_TLS.replacen("proxies:\n", "<<: {}\nproxies:\n", 1),
            CURRENT_TLS.replacen("proxies:\n", "proxies: []\nproxies:\n", 1),
            format!("{CURRENT_TLS}\n---\n{CURRENT_TLS}"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }

        let quoted_anchor = CURRENT_TLS.replace("path: /x", "path: \"/&proxy\"");
        assert!(Config::parse_yaml(quoted_anchor.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_invalid_utf8_and_oversize_input() {
        assert!(Config::parse_yaml(&[0xff]).is_err());
        assert!(Config::parse_yaml(&vec![b'a'; MAX_CONFIG_BYTES + 1]).is_err());
    }

    #[test]
    fn parses_and_normalizes_current_config() {
        let yaml = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
tun:
  enable: true
  mtu: 1500
dns:
  enable: true
  ipv6: false
  nameserver:
    - 1.1.1.1
    - udp://[2001:db8::1]:5353
    - tcp://8.8.8.8
    - tcp://[::1]
rules:
  - domain,Example.COM.,DIRECT
  - DOMAIN-SUFFIX,example.cn,DIRECT
  - DOMAIN-KEYWORD,Tracker,REJECT
  - GEOSITE,GEOLOCATION-!CN,REJECT
  - GEOIP,CN,DIRECT,no-resolve
  - IP-CIDR,192.168.1.42/24,DIRECT,no-resolve
  - IP-CIDR6,2001:db8::1/64,DIRECT
  - DST-PORT,25/100-110,REJECT
  - NETWORK,udp,proxy
  - MATCH,proxy"#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();

        assert_eq!(config.proxies[0].tag, "proxy");
        assert_eq!(config.inbounds.len(), 2);
        assert!(matches!(
            &config.inbounds[..],
            [
                InboundConfig::Http(HttpInboundConfig {
                    listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 1080,
                    ..
                }),
                InboundConfig::Tun(TunInboundConfig { mtu: 1500, .. })
            ]
        ));
        let InboundConfig::Http(http) = &config.inbounds[0] else {
            unreachable!("first inbound is the normalized HTTP listener");
        };
        assert_eq!(http.username, "measure");
        assert_eq!(http.password, "secret");

        assert_eq!(config.http_port, Some(1080));
        assert_eq!(
            config.tun,
            TunConfig {
                enable: true,
                mtu: 1500
            }
        );
        assert!(!config.dns.ipv6);
        assert_eq!(
            config.dns.nameservers,
            [
                DnsNameserver {
                    transport: DnsTransport::Udp,
                    address: "1.1.1.1".parse().unwrap(),
                    port: 53,
                    route: DnsRoute::Direct,
                },
                DnsNameserver {
                    transport: DnsTransport::Udp,
                    address: "2001:db8::1".parse().unwrap(),
                    port: 5353,
                    route: DnsRoute::Direct,
                },
                DnsNameserver {
                    transport: DnsTransport::Tcp,
                    address: "8.8.8.8".parse().unwrap(),
                    port: 53,
                    route: DnsRoute::Direct,
                },
                DnsNameserver {
                    transport: DnsTransport::Tcp,
                    address: "::1".parse().unwrap(),
                    port: 53,
                    route: DnsRoute::Direct,
                },
            ]
        );
        assert_eq!(
            config.rules[0],
            RuleSpec {
                kind: RuleKind::Domain("example.com".to_owned()),
                action: RuleAction::Direct,
                no_resolve: false,
            }
        );
        assert_eq!(
            config.rules[3].kind,
            RuleKind::GeoSite("geolocation-!cn".to_owned())
        );
        assert_eq!(
            config.rules[4],
            RuleSpec {
                kind: RuleKind::GeoIp("cn".to_owned()),
                action: RuleAction::Direct,
                no_resolve: true,
            }
        );
        assert_eq!(
            config.rules[5].kind,
            RuleKind::IpCidr(IpCidr {
                network: "192.168.1.0".parse().unwrap(),
                prefix_len: 24,
            })
        );
        assert_eq!(
            config.rules[6].kind,
            RuleKind::IpCidr(IpCidr {
                network: "2001:db8::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            config.rules[7].kind,
            RuleKind::DstPorts(vec![
                PortRange { start: 25, end: 25 },
                PortRange {
                    start: 100,
                    end: 110
                }
            ])
        );
        assert_eq!(config.rules[8].kind, RuleKind::Network(Network::Udp));
        assert_eq!(config.rules.last().unwrap().kind, RuleKind::Match);
    }

    #[test]
    fn documented_current_examples_stay_parseable() {
        Config::parse_yaml(include_bytes!("../../docs/config.yaml")).unwrap();
        Config::parse_yaml(include_bytes!("../../example/windows-uwp/demo.yaml")).unwrap();
    }

    #[test]
    fn current_rules_share_runtime_domain_normalization() {
        let yaml = current_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - DOMAIN,XN--WCVS22D1M.HK,DIRECT\n  - DOMAIN-SUFFIX,例子.中国,proxy\n  - MATCH,proxy",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let rules = &config.rules;
        assert_eq!(
            rules[0].kind,
            RuleKind::Domain("xn--wcvs22d1m.hk".to_owned())
        );
        assert_eq!(
            rules[1].kind,
            RuleKind::DomainSuffix("xn--fsqu00a.xn--fiqs8s".to_owned())
        );
    }

    #[test]
    fn current_config_defaults_disabled_dns_and_tun() {
        let config = Config::parse_yaml(
            current_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            config.tun,
            TunConfig {
                enable: false,
                mtu: 1500
            }
        );
        assert_eq!(config.dns, DnsConfig::disabled().unwrap());
        assert_eq!(
            config.rules,
            [RuleSpec {
                kind: RuleKind::Match,
                action: RuleAction::Proxy(ProxyId::new(0).unwrap()),
                no_resolve: false,
            }]
        );
        assert_eq!(config.inbounds.len(), 1);

        let tun_only = Config::parse_yaml(current_yaml("tun:\n  enable: true").as_bytes()).unwrap();
        assert_eq!(tun_only.inbounds.len(), 1);
        assert!(matches!(tun_only.inbounds[0], InboundConfig::Tun(_)));
    }

    #[test]
    fn current_config_requires_listener_rules_and_nonempty_proxies() {
        for yaml in [
            current_yaml("port: 0\nauthentication:\n  - measure:secret"),
            current_yaml("tun:\n  enable: false"),
            current_yaml("tun:\n  enable: true\n  mtu: 1400"),
            current_yaml(
                "port: 1080
authentication:
  - measure:secret\nrules: []",
            ),
            current_yaml(
                "port: 1080
authentication:
  - measure:secret\ntypo: true",
            ),
            current_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("    alpn: [h2]", "    alpn: [h2]\n    allowInsecure: false"),
            CURRENT_TLS.replace("MATCH,proxy", "MATCH,PROXY"),
            CURRENT_TLS.replace("MATCH,proxy", "MATCH,unknown"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let missing_proxy = "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,proxy\n";
        assert!(Config::parse_yaml(missing_proxy.as_bytes()).is_err());
        let empty_proxies = "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,proxy\nproxies: []\n";
        assert!(Config::parse_yaml(empty_proxies.as_bytes()).is_err());
        assert!(
            Config::parse_yaml(
                two_proxy_yaml(
                    "port: 1080
authentication:
  - measure:secret"
                )
                .as_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn parses_strict_socks5_settings_and_utf8_credentials() {
        let yaml = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-hop",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(config.default_proxy, ProxyId::new(1).unwrap());
        let ProxyProtocol::Socks5(socks5) = &config.proxies[1].protocol else {
            panic!("expected SOCKS5 proxy");
        };
        assert_eq!(socks5.address, "socks.example.com");
        assert_eq!(socks5.port, 1080);
        assert_eq!(socks5.username.as_deref(), Some("user"));
        assert_eq!(socks5.password.as_deref(), Some("password"));

        let no_auth = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replace("    username: user\n    password: password\n", "");
        let config = Config::parse_yaml(no_auth.as_bytes()).unwrap();
        let ProxyProtocol::Socks5(socks5) = &config.proxies[1].protocol else {
            panic!("expected SOCKS5 proxy");
        };
        assert_eq!(
            (socks5.username.as_ref(), socks5.password.as_ref()),
            (None, None)
        );

        let username = "用".repeat(85);
        let password = "密".repeat(85);
        let utf8 = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replace("username: user", &format!("username: '{username}'"))
        .replace("password: password", &format!("password: '{password}'"));
        assert!(Config::parse_yaml(utf8.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_invalid_socks5_settings() {
        let oversized = "a".repeat(256);
        for yaml in [
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("    password: password\n", ""),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("    username: user\n", ""),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("username: user", "username: ''"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("password: password", "password: ''"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("username: user", "username: null"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("password: password", "password: null"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("type: socks5", "type: socks"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("username: user", &format!("username: '{oversized}'")),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("    port: 1080", "    port: 0"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("server: socks.example.com", "server: 'bad host'"),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace(
                "    server: socks.example.com",
                "    typo: true\n    server: socks.example.com",
            ),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace(
                "    server: socks.example.com",
                "    streamSettings: {}\n    server: socks.example.com",
            ),
            two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("    type: socks5", "    type: socks5\n    tls: true"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn resolves_default_rules_tags_and_dialer_proxy_graph() {
        let yaml = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - DOMAIN-SUFFIX,example.com,proxy\n  - NETWORK,UDP,socks-hop\n  - MATCH,socks-hop",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: socks-hop\n    server: edge.example.com\n",
            1,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let first = ProxyId::new(0).unwrap();
        let second = ProxyId::new(1).unwrap();
        assert_eq!(config.default_proxy, second);
        assert_eq!(config.proxies[0].dialer_proxy, Some(second));
        assert_eq!(config.proxies[1].dialer_proxy, None);
        assert_eq!(config.rules[0].action, RuleAction::Proxy(first));
        assert_eq!(config.rules[1].action, RuleAction::Proxy(second));
        assert_eq!(config.rules[2].action, RuleAction::Proxy(second));

        let proxy_default = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        );
        let config = Config::parse_yaml(proxy_default.as_bytes()).unwrap();
        assert_eq!(
            config.rules,
            [RuleSpec {
                kind: RuleKind::Match,
                action: RuleAction::Proxy(first),
                no_resolve: false,
            }]
        );
    }

    #[test]
    fn accepts_many_proxies_and_resolves_rule_and_dns_tags() {
        let yaml = format!(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver:
    - 1.1.1.1#node-0
    - 8.8.8.8#node-1
    - 9.9.9.9#node-2
    - 4.4.4.4#node-3
rules:
  - DOMAIN,one.example,node-1
  - DOMAIN,two.example,node-2
  - MATCH,node-3
proxies:
{}"#,
            socks_proxy_entries(4, false)
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();

        assert_eq!(config.proxies.len(), 4);
        assert_eq!(config.default_proxy.index(), 3);
        assert_eq!(
            config
                .dns
                .nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Proxy(ProxyId::from_index(0)),
                DnsRoute::Proxy(ProxyId::from_index(1)),
                DnsRoute::Proxy(ProxyId::from_index(2)),
                DnsRoute::Proxy(ProxyId::from_index(3)),
            ]
        );
        assert_eq!(
            config
                .rules
                .iter()
                .map(|rule| rule.action)
                .collect::<Vec<_>>(),
            [
                RuleAction::Proxy(ProxyId::from_index(1)),
                RuleAction::Proxy(ProxyId::from_index(2)),
                RuleAction::Proxy(ProxyId::from_index(3)),
            ]
        );
    }

    #[test]
    fn validates_long_proxy_chains_beyond_u8_indices() {
        let entries = socks_proxy_entries(300, true);
        let yaml = format!(
            "port: 1080\nauthentication:\n  - measure:secret\n\
             rules:\n  - MATCH,node-299\nproxies:\n{entries}"
        );
        assert!(yaml.len() <= MAX_CONFIG_BYTES);
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 300);
        assert_eq!(config.default_proxy.index(), 299);
        assert_eq!(
            config.proxies[299]
                .dialer_proxy
                .expect("last node uses the preceding hop")
                .index(),
            298
        );

        let cycle_entries = entries.replacen(
            "    type: socks5\n",
            "    type: socks5\n    dialer-proxy: node-299\n",
            1,
        );
        let cycle = format!(
            "port: 1080\nauthentication:\n  - measure:secret\n\
             rules:\n  - MATCH,node-299\nproxies:\n{cycle_entries}"
        );
        let error = Config::parse_yaml(cycle.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("circular dialer-proxy"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_proxy_tags_references_and_cycles() {
        for tag in [
            "DIRECT", "REJECT", "RULES", "-edge", "edge,one", "edge#one", "节点",
        ] {
            let yaml = CURRENT_TLS.replace("name: proxy", &format!("name: '{tag}'"));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
        let literal_proxy = CURRENT_TLS
            .replace("name: proxy", "name: PROXY")
            .replace("MATCH,proxy", "MATCH,PROXY");
        assert!(Config::parse_yaml(literal_proxy.as_bytes()).is_ok());
        let long_tag = "a".repeat(65);
        let yaml = CURRENT_TLS.replace("name: proxy", &format!("name: {long_tag}"));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let duplicate = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replace("name: socks-hop", "name: proxy");
        assert!(Config::parse_yaml(duplicate.as_bytes()).is_err());

        let unknown = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: unknown\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(unknown.as_bytes()).is_err());

        for invalid_reference in ["''", "null", "'-bad'"] {
            let yaml = two_proxy_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replacen(
                "    server: edge.example.com\n",
                &format!("    dialer-proxy: {invalid_reference}\n    server: edge.example.com\n"),
                1,
            );
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let self_reference = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: proxy\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(self_reference.as_bytes()).is_err());

        let cycle = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: socks-hop\n    server: edge.example.com\n",
            1,
        )
        .replace(
            "  - name: socks-hop\n    type: socks5\n    server:",
            "  - name: socks-hop\n    type: socks5\n    dialer-proxy: proxy\n    server:",
        );
        assert!(Config::parse_yaml(cycle.as_bytes()).is_err());
    }

    #[test]
    fn accepts_all_two_hop_protocol_combinations() {
        let vless_socks = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: socks-hop\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(vless_socks.as_bytes()).is_ok());

        let socks_vless = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-hop",
        )
        .replace(
            "  - name: socks-hop\n    type: socks5\n    server:",
            "  - name: socks-hop\n    type: socks5\n    dialer-proxy: proxy\n    server:",
        );
        assert!(Config::parse_yaml(socks_vless.as_bytes()).is_ok());

        let vless_vless = format!(
            "{}{}",
            current_yaml(
                "port: 1080
authentication:
  - measure:secret"
            ),
            second_vless_entry()
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: vless-two\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(vless_vless.as_bytes()).is_ok());

        let first_socks = SOCKS_PROXY_ENTRY
            .replace("name: socks-hop", "name: socks-one")
            .replace("server: socks.example.com", "server: first.example.com")
            .replace(
                "    server: first.example.com\n",
                "    dialer-proxy: socks-hop\n    server: first.example.com\n",
            );
        let socks_socks = format!(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-one\nproxies:\n{first_socks}{SOCKS_PROXY_ENTRY}"
        );
        assert!(Config::parse_yaml(socks_socks.as_bytes()).is_ok());
    }

    #[test]
    fn current_config_validates_dns_schema_and_fixed_ip_nameservers() {
        let valid = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: [udp://1.1.1.1:53]"#,
        );
        let config = Config::parse_yaml(valid.as_bytes()).unwrap();
        let dns = &config.dns;
        assert!(dns.ipv6);
        assert_eq!(dns.nameservers[0].route, DnsRoute::Direct);

        for fields in [
            "port: 1080
authentication:
  - measure:secret\ndns:\n  nameserver: []",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: []",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: false\n  nameserver: [1.1.1.1]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [1.1.1.1]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [udp://dns.example:53]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [https://1.1.1.1/dns-query]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [tcp://1.1.1.1:0]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1, 8.8.8.8, 9.9.9.9, 4.4.4.4, 208.67.222.222]",
        ] {
            let yaml = current_yaml(fields);
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn current_config_normalizes_dns_nameserver_routes() {
        let yaml = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - udp://[2001:db8::1]:5353#DIRECT
    - tcp://8.8.8.8#RULES
    - tcp://[::1]#proxy"#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let dns = &config.dns;
        assert_eq!(
            dns.nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Direct,
                DnsRoute::Direct,
                DnsRoute::Rules,
                DnsRoute::Proxy(ProxyId::new(0).unwrap()),
            ]
        );

        let yaml = current_yaml(
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [udp://1.1.1.1:53#PROXY]",
        );
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let yaml = current_yaml(
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [udp://1.1.1.1:53#PROXY]",
        )
        .replace("name: proxy", "name: PROXY")
        .replace("MATCH,proxy", "MATCH,PROXY");
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config.dns.nameservers[0].route,
            DnsRoute::Proxy(ProxyId::new(0).unwrap())
        );

        let yaml = two_proxy_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-hop\ndns:\n  enable: true\n  nameserver: [8.8.8.8#proxy, 9.9.9.9#socks-hop, 4.4.4.4#RULES]",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config
                .dns
                .nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Proxy(ProxyId::new(0).unwrap()),
                DnsRoute::Proxy(ProxyId::new(1).unwrap()),
                DnsRoute::Rules,
            ]
        );
    }

    #[test]
    fn current_config_parses_ordered_geosite_nameserver_policies() {
        let yaml = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#proxy"]
  nameserver-policy:
    "geosite:APPLE,CN":
      - "tcp://223.5.5.5:53#DIRECT"
    "geosite:private":
      - "udp://192.0.2.53:5353"
      - "tcp://198.51.100.53:53#proxy""#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let dns = config.dns;
        assert_eq!(
            dns.nameservers[0].route,
            DnsRoute::Proxy(config.default_proxy)
        );
        assert_eq!(dns.nameserver_policies.len(), 2);
        assert_eq!(&*dns.nameserver_policies[0].geosite_codes, ["apple", "cn"]);
        assert_eq!(
            dns.nameserver_policies[0].nameservers.as_ref(),
            [DnsNameserver {
                transport: DnsTransport::Tcp,
                address: "223.5.5.5".parse().unwrap(),
                port: 53,
                route: DnsRoute::Direct,
            }]
        );
        assert_eq!(&*dns.nameserver_policies[1].geosite_codes, ["private"]);
        assert_eq!(
            dns.nameserver_policies[1]
                .nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [DnsRoute::Direct, DnsRoute::Proxy(ProxyId::new(0).unwrap())]
        );
    }

    #[test]
    fn current_config_strictly_validates_nameserver_policy_schema_and_limits() {
        for policy in [
            r#"    "geosite:cn": "tcp://223.5.5.5""#,
            r#"    "geoip:cn": ["tcp://223.5.5.5"]"#,
            r#"    "GEOSITE:cn": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:cn,": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:cn, apple": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:cn": []"#,
            r#"    "geosite:cn": [1.1.1.1, 8.8.8.8, 9.9.9.9, 4.4.4.4, 223.5.5.5]"#,
            r#"    "geosite:cn": ["tcp://dns.example"]"#,
        ] {
            let yaml = current_yaml(&format!(
                "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n{policy}"
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let duplicate = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    "geosite:CN": ["tcp://223.5.5.5"]
    "geosite:cn": ["tcp://8.8.8.8"]"#,
        );
        assert!(Config::parse_yaml(duplicate.as_bytes()).is_err());

        let too_many_codes = (0..=MAX_DNS_POLICY_GEOSITE_CODES)
            .map(|index| format!("code{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let yaml = current_yaml(&format!(
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n    \"geosite:{too_many_codes}\": [tcp://223.5.5.5]"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let too_many_policies = (0..=MAX_DNS_NAMESERVER_POLICIES)
            .map(|index| format!("    \"geosite:code{index}\": [tcp://223.5.5.5]"))
            .collect::<Vec<_>>()
            .join("\n");
        let yaml = current_yaml(&format!(
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n{too_many_policies}"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let disabled = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: false
  nameserver-policy:
    "geosite:cn": ["tcp://223.5.5.5"]"#,
        );
        assert!(Config::parse_yaml(disabled.as_bytes()).is_err());

        let missing_main = current_yaml(
            r#"port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver-policy:
    "geosite:cn": ["tcp://223.5.5.5"]"#,
        );
        assert!(Config::parse_yaml(missing_main.as_bytes()).is_err());
    }

    #[test]
    fn current_config_strictly_rejects_invalid_dns_route_fragments() {
        for nameserver in [
            "udp://1.1.1.1:53#",
            "udp://1.1.1.1:53#direct",
            "udp://1.1.1.1:53#unknown",
            "udp://1.1.1.1:53#DIRECT&RULES",
            "udp://1.1.1.1:53#h3=true",
            "udp://1.1.1.1:53#DIRECT#RULES",
        ] {
            let yaml = current_yaml(&format!(
                "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [\"{nameserver}\"]"
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        for reserved_tag in ["DIRECT", "REJECT", "RULES"] {
            let yaml = current_yaml(
                "port: 1080
authentication:
  - measure:secret",
            )
            .replace("  - name: proxy\n", &format!("  - name: {reserved_tag}\n"));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn current_config_rejects_removed_dns_switches() {
        for fields in [
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  enhanced-mode: normal\n  nameserver: [1.1.1.1]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [1.1.1.1]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  respect-rules: false\n  nameserver: [1.1.1.1]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  respect-rules: true\n  nameserver: [1.1.1.1]",
            "port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  respectRules: false\n  nameserver: [1.1.1.1]",
        ] {
            let yaml = current_yaml(fields);
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn current_config_rejects_invalid_rule_shapes_and_ordering() {
        for rules in [
            "  - DOMAIN,example.com,BLOCK\n  - MATCH,proxy",
            "  - DOMAIN,example.com,unknown\n  - MATCH,proxy",
            "  - DOMAIN,example.com,DIRECT,no-resolve\n  - MATCH,proxy",
            "  - GEOIP,CN,DIRECT,NO-RESOLVE\n  - MATCH,proxy",
            "  - IP-CIDR,2001:db8::/32,DIRECT\n  - MATCH,proxy",
            "  - IP-CIDR6,192.0.2.0/24,DIRECT\n  - MATCH,proxy",
            "  - IP-CIDR,192.0.2.0/33,DIRECT\n  - MATCH,proxy",
            "  - DST-PORT,0,REJECT\n  - MATCH,proxy",
            "  - DST-PORT,100-10,REJECT\n  - MATCH,proxy",
            "  - NETWORK,ICMP,REJECT\n  - MATCH,proxy",
            "  - MATCH,PROXY\n  - DOMAIN,example.com,DIRECT",
            "  - MATCH,PROXY\n  - MATCH,DIRECT",
            "  - DOMAIN,example.com,DIRECT",
        ] {
            let yaml = current_yaml(&format!(
                "port: 1080
authentication:
  - measure:secret\nrules:\n{rules}"
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let explicit_empty = current_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules: []",
        );
        assert!(Config::parse_yaml(explicit_empty.as_bytes()).is_err());

        let non_ascii_whitespace = current_yaml(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,\u{a0}PROXY",
        );
        assert!(Config::parse_yaml(non_ascii_whitespace.as_bytes()).is_err());
    }

    #[test]
    fn current_config_enforces_rule_count_and_byte_limits() {
        let too_many = (0..=MAX_RULES)
            .map(|_| "  - NETWORK,TCP,proxy\n")
            .collect::<String>();
        let yaml = current_yaml(&format!(
            "port: 1080
authentication:
  - measure:secret\nrules:\n{too_many}  - MATCH,proxy"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let oversized = "a".repeat(MAX_RULE_BYTES + 1);
        let yaml = current_yaml(&format!(
            "port: 1080
authentication:
  - measure:secret\nrules:\n  - {oversized}\n  - MATCH,proxy"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let keyword = "a".repeat(240);
        let many_rules = (0..600)
            .map(|_| format!("  - DOMAIN-KEYWORD,{keyword},proxy\n"))
            .collect::<String>();
        let yaml = current_yaml(&format!(
            "port: 1080
authentication:
  - measure:secret\nrules:\n{many_rules}  - MATCH,proxy"
        ));
        let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("cumulative limit"), "{error}");
    }
}
