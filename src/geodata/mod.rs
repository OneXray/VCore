//! Selective Xray GeoData loading and allocation-free matching.
//!
//! The loader deliberately scans protobuf wire framing itself. It indexes only
//! category ranges during the first pass and decodes records only for codes
//! referenced by the prepared rule set. No generated protobuf object graph or
//! memory mapping is used.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    mem,
    net::IpAddr,
    path::{Path, PathBuf},
    str,
};

use regex_automata::{
    Input,
    dfa::{Automaton, StartKind, dense},
};
use thiserror::Error;

use crate::{
    VCoreError,
    config::{DnsNameserverPolicy, RuleKind, RuleSpec},
    routing::{GeoMatcher, normalize_domain_name},
};

mod manager;
pub(crate) mod service;
pub(crate) mod updater;

pub use manager::{
    DynamicGeoData, GeoDataLoadReport, GeoDataManager, GeoDataManagerError, GeoDataRegistration,
    GeoDataReloadReport, GeoDataResourceReport, GeoDataStatus, GeoResourceState, GeoUpdateSession,
};

pub const GEOSITE_FILE_NAME: &str = "geosite.dat";
pub const GEOIP_FILE_NAME: &str = "geoip.dat";

const MAX_CODE_BYTES: usize = 64;

/// The two supported Xray GeoData assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoDataKind {
    GeoSite,
    GeoIp,
}

impl GeoDataKind {
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::GeoSite => GEOSITE_FILE_NAME,
            Self::GeoIp => GEOIP_FILE_NAME,
        }
    }
}

impl std::fmt::Display for GeoDataKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::GeoSite => "GeoSite",
            Self::GeoIp => "GeoIP",
        })
    }
}

#[derive(Debug, Error)]
pub enum GeoDataError {
    #[error("failed to access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("GeoData asset is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("invalid {kind} category code `{code}`")]
    InvalidCode { kind: GeoDataKind, code: String },
    #[error("duplicate {kind} category code `{code}`")]
    DuplicateCode { kind: GeoDataKind, code: String },
    #[error("referenced {kind} category `{code}` is missing")]
    MissingCode { kind: GeoDataKind, code: String },
    #[error("malformed {kind} protobuf: {detail}")]
    Malformed { kind: GeoDataKind, detail: String },
    #[error("{kind} category `{code}` enables unsupported reverse_match")]
    ReverseMatch { kind: GeoDataKind, code: String },
    #[error("invalid GeoSite record in `{code}`: {detail}")]
    InvalidDomain { code: String, detail: String },
    #[error("invalid GeoSite Regex in `{code}`: {detail}")]
    InvalidRegex { code: String, detail: String },
    #[error("invalid GeoIP CIDR in `{code}`: {detail}")]
    InvalidCidr { code: String, detail: String },
    #[error("GeoData resource `{resource}` is {actual}; limit is {maximum}")]
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("GeoData allocation failed while reserving {bytes} bytes")]
    AllocationFailed { bytes: usize },
}

impl From<GeoDataError> for VCoreError {
    fn from(error: GeoDataError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

/// Diagnostic capacity accounting, never a memory admission policy.
///
/// Includes matcher/index buffers and retained DFAs, with old/new buffer
/// overlap during growth. Does not observe regex compiler internals, allocator
/// overhead or the process peak; those require independent measurements.
#[derive(Debug, Default)]
struct AllocationLedger {
    used: usize,
    peak: usize,
}

impl AllocationLedger {
    fn reserve(&mut self, bytes: usize) -> Result<(), GeoDataError> {
        let requested = self
            .used
            .checked_add(bytes)
            .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        self.used = requested;
        self.peak = self.peak.max(requested);
        Ok(())
    }

    fn release(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.used);
        self.used = self.used.saturating_sub(bytes);
    }
}

/// Prepared matchers for all GeoData codes referenced by one instance.
pub struct GeoData {
    sites: Vec<SiteCategory>,
    ips: Vec<IpCategory>,
    allocation_capacity: usize,
    peak_allocation_capacity: usize,
}

impl std::fmt::Debug for GeoData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoData")
            .field("site_categories", &self.sites.len())
            .field("ip_categories", &self.ips.len())
            .field("allocation_capacity", &self.allocation_capacity)
            .field("peak_allocation_capacity", &self.peak_allocation_capacity)
            .finish()
    }
}

impl Default for GeoData {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl GeoData {
    pub const EMPTY: Self = Self {
        sites: Vec::new(),
        ips: Vec::new(),
        allocation_capacity: 0,
        peak_allocation_capacity: 0,
    };

    /// Loads only categories referenced by `rules` from the two fixed sibling
    /// assets in `config_dir`.
    pub fn load(config_dir: &Path, rules: &[RuleSpec]) -> Result<Self, GeoDataError> {
        Self::load_with_dns_policies(config_dir, rules, &[])
    }

    /// Loads categories referenced by both business routing rules and DNS
    /// nameserver policies. Duplicate codes share one prepared category and
    /// the existing per-instance GeoData allocation ledger.
    pub fn load_with_dns_policies(
        config_dir: &Path,
        rules: &[RuleSpec],
        dns_policies: &[DnsNameserverPolicy],
    ) -> Result<Self, GeoDataError> {
        let requested = RequestedCodes::collect(rules, dns_policies)?;
        if requested.total() == 0 {
            return Ok(Self::EMPTY);
        }

        let mut ledger = AllocationLedger::default();
        let mut sites = Vec::new();
        let mut ips = Vec::new();
        ensure_vec_capacity(&mut sites, requested.sites.values.len(), &mut ledger)?;
        ensure_vec_capacity(&mut ips, requested.ips.values.len(), &mut ledger)?;

        if !requested.sites.values.is_empty() {
            load_site_file(config_dir, &requested.sites, &mut sites, &mut ledger)?;
        }
        if !requested.ips.values.is_empty() {
            load_ip_file(config_dir, &requested.ips, &mut ips, &mut ledger)?;
        }

        Ok(Self {
            sites,
            ips,
            allocation_capacity: ledger.used,
            peak_allocation_capacity: ledger.peak,
        })
    }

    /// Accounted retained matcher capacity, not allocator or process memory.
    #[must_use]
    pub const fn allocation_capacity(&self) -> usize {
        self.allocation_capacity
    }

    /// Peak of accounted capacities, excluding regex compiler internals and
    /// configuration requirements. Neither an admission quota nor a bound on
    /// actual loading or process memory.
    #[must_use]
    pub const fn peak_allocation_capacity(&self) -> usize {
        self.peak_allocation_capacity
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty() && self.ips.is_empty()
    }

    #[must_use]
    pub fn geosite_available(&self, code: &str) -> bool {
        self.sites.iter().any(|category| category.code.eq_str(code))
    }

    #[must_use]
    pub fn geoip_available(&self, code: &str) -> bool {
        self.ips.iter().any(|category| category.code.eq_str(code))
    }
}

impl GeoMatcher for GeoData {
    fn geosite_available(&self, code: &str) -> bool {
        GeoData::geosite_available(self, code)
    }

    fn geoip_available(&self, code: &str) -> bool {
        GeoData::geoip_available(self, code)
    }

    fn matches_geosite(&self, code: &str, domain: &str) -> bool {
        self.sites
            .iter()
            .find(|category| category.code.eq_str(code))
            .is_some_and(|category| category.matches(domain))
    }

    fn matches_geoip(&self, code: &str, address: IpAddr) -> bool {
        self.ips
            .iter()
            .find(|category| category.code.eq_str(code))
            .is_some_and(|category| category.matches(address))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Code {
    bytes: [u8; MAX_CODE_BYTES],
    len: u8,
}

impl Code {
    const EMPTY: Self = Self {
        bytes: [0; MAX_CODE_BYTES],
        len: 0,
    };

    fn parse(kind: GeoDataKind, raw: &[u8]) -> Result<Self, GeoDataError> {
        if raw.is_empty()
            || raw.len() > MAX_CODE_BYTES
            || !raw[0].is_ascii_alphanumeric()
            || !raw.iter().skip(1).all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'+' | b'!' | b'-')
            })
        {
            return Err(GeoDataError::InvalidCode {
                kind,
                code: String::from_utf8_lossy(raw).into_owned(),
            });
        }
        let mut code = Self::EMPTY;
        code.len = u8::try_from(raw.len()).expect("code length is bounded to 64");
        code.bytes[..raw.len()].copy_from_slice(raw);
        code.bytes[..raw.len()].make_ascii_lowercase();
        Ok(code)
    }

    fn parse_rule(kind: GeoDataKind, raw: &str) -> Result<Self, GeoDataError> {
        Self::parse(kind, raw.as_bytes())
    }

    fn as_str(&self) -> &str {
        // Code::parse admits ASCII only.
        str::from_utf8(&self.bytes[..usize::from(self.len)]).expect("validated ASCII GeoData code")
    }

    fn eq_str(&self, other: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(other)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeSet {
    values: Vec<Code>,
}

impl CodeSet {
    const EMPTY: Self = Self { values: Vec::new() };

    fn insert(&mut self, code: Code) -> Result<(), GeoDataError> {
        if self.values.contains(&code) {
            return Ok(());
        }
        self.values
            .try_reserve(1)
            .map_err(|_| GeoDataError::AllocationFailed {
                bytes: self
                    .values
                    .len()
                    .saturating_add(1)
                    .saturating_mul(mem::size_of::<Code>()),
            })?;
        self.values.push(code);
        Ok(())
    }
}

#[derive(Debug)]
struct RequestedCodes {
    sites: CodeSet,
    ips: CodeSet,
}

impl RequestedCodes {
    fn collect(
        rules: &[RuleSpec],
        dns_policies: &[DnsNameserverPolicy],
    ) -> Result<Self, GeoDataError> {
        let mut requested = Self {
            sites: CodeSet::EMPTY,
            ips: CodeSet::EMPTY,
        };
        for rule in rules {
            match &rule.kind {
                RuleKind::GeoSite(code) => requested
                    .sites
                    .insert(Code::parse_rule(GeoDataKind::GeoSite, code)?)?,
                RuleKind::GeoIp(code) => requested
                    .ips
                    .insert(Code::parse_rule(GeoDataKind::GeoIp, code)?)?,
                _ => (),
            }
        }
        for policy in dns_policies {
            for code in &policy.geosite_codes {
                requested
                    .sites
                    .insert(Code::parse_rule(GeoDataKind::GeoSite, code)?)?;
            }
        }
        Ok(requested)
    }

    const fn total(&self) -> usize {
        self.sites.values.len() + self.ips.values.len()
    }
}

/// Normalized GeoData categories referenced by one VCore configuration.
///
/// Collection performs only configuration-owned validation: code syntax,
/// and case-insensitive de-duplication, without a code-count quota. Asset
/// availability and contents are deliberately handled later by
/// [`GeoDataManager`], where one unavailable resource can become dormant
/// without disabling the other kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoRequirements {
    sites: CodeSet,
    ips: CodeSet,
}

impl GeoRequirements {
    /// Collects all GeoSite and GeoIP codes used by business rules and DNS
    /// nameserver policies.
    pub fn collect(
        rules: &[RuleSpec],
        dns_policies: &[DnsNameserverPolicy],
    ) -> Result<Self, GeoDataError> {
        let requested = RequestedCodes::collect(rules, dns_policies)?;
        Ok(Self {
            sites: requested.sites,
            ips: requested.ips,
        })
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sites.values.is_empty() && self.ips.values.is_empty()
    }

    #[must_use]
    pub const fn requires(&self, kind: GeoDataKind) -> bool {
        match kind {
            GeoDataKind::GeoSite => !self.sites.values.is_empty(),
            GeoDataKind::GeoIp => !self.ips.values.is_empty(),
        }
    }

    #[must_use]
    pub const fn total_codes(&self) -> usize {
        self.sites.values.len() + self.ips.values.len()
    }

    pub fn codes(&self, kind: GeoDataKind) -> impl Iterator<Item = &str> {
        let set = match kind {
            GeoDataKind::GeoSite => &self.sites,
            GeoDataKind::GeoIp => &self.ips,
        };
        set.values.iter().map(Code::as_str)
    }

    fn code_set(&self, kind: GeoDataKind) -> &CodeSet {
        match kind {
            GeoDataKind::GeoSite => &self.sites,
            GeoDataKind::GeoIp => &self.ips,
        }
    }
}

struct KindLoad<T> {
    values: Vec<T>,
    used: usize,
    peak: usize,
}

fn load_sites_for_requirements(
    asset_dir: &Path,
    requested: &CodeSet,
    used: usize,
    peak: usize,
) -> Result<KindLoad<SiteCategory>, GeoDataError> {
    let mut ledger = AllocationLedger { used, peak };
    let mut values = Vec::new();
    ensure_vec_capacity(&mut values, requested.values.len(), &mut ledger)?;
    load_site_file(asset_dir, requested, &mut values, &mut ledger)?;
    Ok(KindLoad {
        values,
        used: ledger.used,
        peak: ledger.peak,
    })
}

fn load_ips_for_requirements(
    asset_dir: &Path,
    requested: &CodeSet,
    used: usize,
    peak: usize,
) -> Result<KindLoad<IpCategory>, GeoDataError> {
    let mut ledger = AllocationLedger { used, peak };
    let mut values = Vec::new();
    ensure_vec_capacity(&mut values, requested.values.len(), &mut ledger)?;
    load_ip_file(asset_dir, requested, &mut values, &mut ledger)?;
    Ok(KindLoad {
        values,
        used: ledger.used,
        peak: ledger.peak,
    })
}

fn validate_asset_structure(asset_dir: &Path, kind: GeoDataKind) -> Result<(), GeoDataError> {
    let (mut file, len) = open_asset(asset_dir, kind)?;
    let mut ledger = AllocationLedger::default();
    let _ = index_selected(&mut file, len, kind, &CodeSet::EMPTY, &mut ledger)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    code: Code,
    offset: u64,
    len: u64,
}

#[derive(Debug, Clone, Copy)]
struct SelectedRange {
    code: Code,
    offset: u64,
    len: u64,
}

fn load_site_file(
    config_dir: &Path,
    requested: &CodeSet,
    output: &mut Vec<SiteCategory>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    let (mut file, len) = open_asset(config_dir, kind)?;
    let selected = index_selected(&mut file, len, kind, requested, ledger)?;
    for range in &selected {
        output.push(parse_site_category(&mut file, *range, ledger)?);
    }
    release_vec(&selected, ledger);
    Ok(())
}

fn load_ip_file(
    config_dir: &Path,
    requested: &CodeSet,
    output: &mut Vec<IpCategory>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoIp;
    let (mut file, len) = open_asset(config_dir, kind)?;
    let selected = index_selected(&mut file, len, kind, requested, ledger)?;
    for range in &selected {
        output.push(parse_ip_category(&mut file, *range, ledger)?);
    }
    release_vec(&selected, ledger);
    Ok(())
}

fn open_asset(config_dir: &Path, kind: GeoDataKind) -> Result<(File, u64), GeoDataError> {
    let path = config_dir.join(kind.file_name());
    let symlink_metadata = fs::symlink_metadata(&path).map_err(|source| GeoDataError::Io {
        path: path.clone(),
        source,
    })?;
    if !symlink_metadata.file_type().is_file() {
        return Err(GeoDataError::NotRegularFile(path));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|source| GeoDataError::Io {
        path: path.clone(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| GeoDataError::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(GeoDataError::NotRegularFile(path));
    }
    Ok((file, metadata.len()))
}

fn index_selected(
    file: &mut File,
    file_len: u64,
    kind: GeoDataKind,
    requested: &CodeSet,
    ledger: &mut AllocationLedger,
) -> Result<Vec<SelectedRange>, GeoDataError> {
    seek(file, 0, kind)?;
    let mut index = Vec::<IndexEntry>::new();
    while position(file, kind)? < file_len {
        let (field, wire) = read_key(file, file_len, kind)?;
        if field != 1 || wire != 2 {
            return malformed(
                kind,
                "top-level message accepts only repeated field 1 entries",
            );
        }
        let entry_len = read_length(file, file_len, kind)?;
        let offset = position(file, kind)?;
        let end = checked_end(offset, entry_len, file_len, kind)?;
        let code = scan_category_header(file, end, kind)?;
        ensure_vec_capacity(&mut index, 1, ledger)?;
        index.push(IndexEntry {
            code,
            offset,
            len: entry_len,
        });
        seek(file, end, kind)?;
    }

    index.sort_unstable_by_key(|entry| entry.code);
    for pair in index.windows(2) {
        if pair[0].code == pair[1].code {
            let error = GeoDataError::DuplicateCode {
                kind,
                code: pair[0].code.as_str().to_owned(),
            };
            release_vec(&index, ledger);
            return Err(error);
        }
    }

    let mut selected = Vec::new();
    ensure_vec_capacity(&mut selected, requested.values.len(), ledger)?;
    for code in &requested.values {
        let entry = index
            .binary_search_by_key(code, |entry| entry.code)
            .ok()
            .map(|at| index[at])
            .ok_or_else(|| GeoDataError::MissingCode {
                kind,
                code: code.as_str().to_owned(),
            });
        match entry {
            Ok(entry) => {
                selected.push(SelectedRange {
                    code: entry.code,
                    offset: entry.offset,
                    len: entry.len,
                });
            }
            Err(error) => {
                release_vec(&index, ledger);
                release_vec(&selected, ledger);
                return Err(error);
            }
        }
    }
    release_vec(&index, ledger);
    Ok(selected)
}

fn scan_category_header(
    file: &mut File,
    end: u64,
    kind: GeoDataKind,
) -> Result<Code, GeoDataError> {
    let mut code = None;
    let mut reverse_match = false;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match (field, kind) {
            (1, _) => {
                require_wire(kind, wire, 2, "category code")?;
                if code.is_some() {
                    return malformed(kind, "category contains code more than once");
                }
                let len = read_length(file, end, kind)?;
                if len > MAX_CODE_BYTES as u64 {
                    return Err(GeoDataError::InvalidCode {
                        kind,
                        code: "<more than 64 bytes>".to_owned(),
                    });
                }
                let mut raw = [0_u8; MAX_CODE_BYTES];
                read_exact(file, &mut raw[..len as usize], end, kind)?;
                code = Some(Code::parse(kind, &raw[..len as usize])?);
            }
            (2, _) => {
                require_wire(kind, wire, 2, "category record")?;
                skip_field_payload(file, wire, end, kind)?;
            }
            (3, GeoDataKind::GeoIp) => {
                require_wire(kind, wire, 0, "reverse_match")?;
                reverse_match |= read_varint(file, end, kind)? != 0;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    let code = code.ok_or_else(|| GeoDataError::Malformed {
        kind,
        detail: "category is missing code field 1".to_owned(),
    })?;
    if reverse_match {
        return Err(GeoDataError::ReverseMatch {
            kind,
            code: code.as_str().to_owned(),
        });
    }
    Ok(code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SitePatternKind {
    Substr,
    Domain,
    Full,
}

#[derive(Debug, Clone, Copy)]
struct SitePattern {
    kind: SitePatternKind,
    start: u32,
    len: u32,
}

impl SitePattern {
    fn value<'a>(&self, values: &'a [u8]) -> &'a [u8] {
        let start = self.start as usize;
        &values[start..start + self.len as usize]
    }
}

struct SiteCategory {
    code: Code,
    patterns: Vec<SitePattern>,
    values: Vec<u8>,
    regexes: Vec<dense::DFA<Vec<u32>>>,
}

impl SiteCategory {
    fn contains(&self, kind: SitePatternKind, value: &[u8]) -> bool {
        self.patterns
            .binary_search_by(|pattern| {
                pattern
                    .kind
                    .cmp(&kind)
                    .then_with(|| pattern.value(&self.values).cmp(value))
            })
            .is_ok()
    }

    fn matches(&self, domain: &str) -> bool {
        // The loader validates/normalizes each value once. Reuse the compact
        // ranges as a sorted index; a miss must not scan all Domain/Full records
        // for every UDP packet. Category membership is a union, not rule order.
        let bytes = domain.as_bytes();
        if self.contains(SitePatternKind::Full, bytes) {
            return true;
        }
        let mut suffix = bytes;
        loop {
            if self.contains(SitePatternKind::Domain, suffix) {
                return true;
            }
            let Some(dot) = suffix.iter().position(|byte| *byte == b'.') else {
                break;
            };
            suffix = &suffix[dot + 1..];
        }
        for pattern in self
            .patterns
            .iter()
            .take_while(|pattern| pattern.kind == SitePatternKind::Substr)
        {
            let value = pattern.value(&self.values);
            if bytes.windows(value.len()).any(|window| window == value) {
                return true;
            }
        }
        self.regexes.iter().any(|regex| {
            regex
                .try_search_fwd(&Input::new(domain.as_bytes()))
                .is_ok_and(|matched| matched.is_some())
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ValueRange {
    start: u32,
    len: u32,
}

fn parse_site_category(
    file: &mut File,
    range: SelectedRange,
    ledger: &mut AllocationLedger,
) -> Result<SiteCategory, GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    let end = checked_end(range.offset, range.len, u64::MAX, kind)?;
    seek(file, range.offset, kind)?;
    let mut patterns = Vec::new();
    let mut values = Vec::new();
    let mut regex_bytes = Vec::new();
    let mut regex_ranges = Vec::new();
    let mut scratch = Vec::new();
    let mut seen_code = false;

    let result = (|| {
        while position(file, kind)? < end {
            let (field, wire) = read_key(file, end, kind)?;
            match field {
                1 => {
                    require_wire(kind, wire, 2, "GeoSite code")?;
                    if seen_code {
                        return malformed(kind, "GeoSite contains code more than once");
                    }
                    let code = read_code(file, end, kind)?;
                    if code != range.code {
                        return malformed(kind, "GeoSite code changed between scan passes");
                    }
                    seen_code = true;
                }
                2 => {
                    require_wire(kind, wire, 2, "Domain")?;
                    let len = read_length(file, end, kind)?;
                    let start = position(file, kind)?;
                    let record_end = checked_end(start, len, end, kind)?;
                    parse_domain_record(
                        file,
                        record_end,
                        range.code,
                        &mut patterns,
                        &mut values,
                        &mut regex_bytes,
                        &mut regex_ranges,
                        &mut scratch,
                        ledger,
                    )?;
                    seek(file, record_end, kind)?;
                }
                _ => skip_field_payload(file, wire, end, kind)?,
            }
        }
        if !seen_code {
            return malformed(kind, "GeoSite is missing code");
        }
        compile_regex_set(range.code, &regex_bytes, &regex_ranges, ledger)
    })();

    release_vec(&scratch, ledger);
    release_vec(&regex_ranges, ledger);
    release_vec(&regex_bytes, ledger);
    match result {
        Ok(regexes) => {
            // In-place sort does not duplicate the arena or retain a second
            // index. Keep every record, including overlapping types/duplicates.
            patterns.sort_unstable_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| left.value(&values).cmp(right.value(&values)))
            });
            Ok(SiteCategory {
                code: range.code,
                patterns,
                values,
                regexes,
            })
        }
        Err(error) => {
            release_vec(&patterns, ledger);
            release_vec(&values, ledger);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_domain_record(
    file: &mut File,
    end: u64,
    code: Code,
    patterns: &mut Vec<SitePattern>,
    values: &mut Vec<u8>,
    regex_bytes: &mut Vec<u8>,
    regex_ranges: &mut Vec<ValueRange>,
    scratch: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    let mut domain_type = 0_u64;
    let mut seen_type = false;
    let mut value_range = None;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match field {
            1 => {
                require_wire(kind, wire, 0, "Domain.type")?;
                if seen_type {
                    return invalid_domain(code, "Domain.type occurs more than once");
                }
                domain_type = read_varint(file, end, kind)?;
                seen_type = true;
            }
            2 => {
                require_wire(kind, wire, 2, "Domain.value")?;
                if value_range.is_some() {
                    return invalid_domain(code, "Domain.value occurs more than once");
                }
                let len = read_length(file, end, kind)?;
                let start = position(file, kind)?;
                let value_end = checked_end(start, len, end, kind)?;
                value_range = Some((start, len));
                seek(file, value_end, kind)?;
            }
            3 => {
                require_wire(kind, wire, 2, "Domain.attribute")?;
                let len = read_length(file, end, kind)?;
                let start = position(file, kind)?;
                let attribute_end = checked_end(start, len, end, kind)?;
                validate_attribute(file, attribute_end, kind)?;
                seek(file, attribute_end, kind)?;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    let (value_offset, value_len) =
        value_range.ok_or_else(|| invalid_domain_error(code, "Domain.value is missing"))?;
    let value_len = usize::try_from(value_len)
        .map_err(|_| invalid_domain_error(code, "Domain.value length does not fit usize"))?;
    read_scratch(file, value_offset, value_len, scratch, ledger, kind)?;
    let raw = str::from_utf8(scratch)
        .map_err(|_| invalid_domain_error(code, "Domain.value is not UTF-8"))?;

    match domain_type {
        0 => {
            if raw.is_empty() || !raw.is_ascii() {
                return invalid_domain(code, "Substr value must be non-empty ASCII");
            }
            scratch.make_ascii_lowercase();
            append_site_value(SitePatternKind::Substr, scratch, patterns, values, ledger)?;
        }
        1 => {
            validate_regex_source(&code, raw)?;
            let start = u32::try_from(regex_bytes.len())
                .map_err(|_| invalid_domain_error(code, "Regex source offset overflow"))?;
            ensure_vec_capacity(regex_bytes, scratch.len(), ledger)?;
            regex_bytes.extend_from_slice(scratch);
            ensure_vec_capacity(regex_ranges, 1, ledger)?;
            regex_ranges.push(ValueRange {
                start,
                len: u32::try_from(scratch.len())
                    .map_err(|_| invalid_domain_error(code, "Regex source length overflow"))?,
            });
        }
        2 | 3 => {
            // Account a bounded normalization output while both the reusable
            // input scratch and final compact byte arena are live.
            ledger.reserve(253)?;
            let normalized = normalize_domain_name(raw).map_err(|error| {
                invalid_domain_error(code, &format!("invalid domain value: {error}"))
            });
            ledger.release(253);
            let normalized = normalized?;
            ledger.reserve(normalized.capacity())?;
            let result = append_site_value(
                if domain_type == 2 {
                    SitePatternKind::Domain
                } else {
                    SitePatternKind::Full
                },
                normalized.as_bytes(),
                patterns,
                values,
                ledger,
            );
            ledger.release(normalized.capacity());
            result?;
        }
        other => {
            return invalid_domain(code, &format!("unsupported Domain.type {other}"));
        }
    }
    Ok(())
}

fn validate_regex_source(code: &Code, pattern: &str) -> Result<(), GeoDataError> {
    if !pattern.is_ascii() {
        return Err(GeoDataError::InvalidRegex {
            code: code.as_str().to_owned(),
            detail: "the VCore Regex subset only accepts ASCII source".to_owned(),
        });
    }
    if has_unsupported_inline_regex_flag(pattern.as_bytes()) {
        return Err(GeoDataError::InvalidRegex {
            code: code.as_str().to_owned(),
            detail: "inline `u`, `x`, and `R` flags are outside the supported Go/Rust subset"
                .to_owned(),
        });
    }
    Ok(())
}

/// Finds Rust-only inline flags without interpreting escaped text or character
/// classes. Go and Rust share `i`, `m`, `s`, and `U`; the remaining syntax is
/// still validated by `regex-automata` during compilation.
fn has_unsupported_inline_regex_flag(pattern: &[u8]) -> bool {
    let mut escaped = false;
    let mut in_class = false;
    let mut index = 0;
    while index < pattern.len() {
        let byte = pattern[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            index += 1;
            continue;
        }
        match byte {
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class && pattern.get(index + 1) == Some(&b'?') => {
                let mut flag_index = index + 2;
                while let Some(&flag) = pattern.get(flag_index) {
                    match flag {
                        b'u' | b'x' | b'R' => return true,
                        b'i' | b'm' | b's' | b'U' | b'-' => flag_index += 1,
                        b':' | b')' => break,
                        _ => break,
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn validate_attribute(file: &mut File, end: u64, kind: GeoDataKind) -> Result<(), GeoDataError> {
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match field {
            1 => {
                require_wire(kind, wire, 2, "Attribute.key")?;
                let len = read_length(file, end, kind)?;
                validate_utf8_bytes(file, len, end, kind)?;
            }
            2 | 3 => {
                require_wire(kind, wire, 0, "Attribute value")?;
                let _ = read_varint(file, end, kind)?;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    Ok(())
}

fn validate_utf8_bytes(
    file: &mut File,
    len: u64,
    end: u64,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    let start = position(file, kind)?;
    let _ = checked_end(start, len, end, kind)?;
    let mut remaining = len;
    let mut buffer = [0_u8; 256];
    let mut continuation = 0_u8;
    let mut first_min = 0x80_u8;
    let mut first_max = 0xbf_u8;
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("UTF-8 chunk length is bounded to 256");
        file.read_exact(&mut buffer[..take])
            .map_err(|source| io_error(kind, source))?;
        remaining -= take as u64;
        for &byte in &buffer[..take] {
            if continuation != 0 {
                if byte < first_min || byte > first_max {
                    return malformed(kind, "protobuf string field is not valid UTF-8");
                }
                continuation -= 1;
                first_min = 0x80;
                first_max = 0xbf;
                continue;
            }
            match byte {
                0x00..=0x7f => {}
                0xc2..=0xdf => continuation = 1,
                0xe0 => {
                    continuation = 2;
                    first_min = 0xa0;
                }
                0xe1..=0xec | 0xee..=0xef => continuation = 2,
                0xed => {
                    continuation = 2;
                    first_max = 0x9f;
                }
                0xf0 => {
                    continuation = 3;
                    first_min = 0x90;
                }
                0xf1..=0xf3 => continuation = 3,
                0xf4 => {
                    continuation = 3;
                    first_max = 0x8f;
                }
                _ => return malformed(kind, "protobuf string field is not valid UTF-8"),
            }
        }
    }
    if continuation != 0 {
        return malformed(kind, "protobuf string field ends inside a UTF-8 sequence");
    }
    Ok(())
}

fn append_site_value(
    kind: SitePatternKind,
    value: &[u8],
    patterns: &mut Vec<SitePattern>,
    values: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let start = u32::try_from(values.len()).map_err(|_| GeoDataError::ResourceLimit {
        resource: "GeoSite compact value offset",
        actual: values.len(),
        maximum: u32::MAX as usize,
    })?;
    ensure_vec_capacity(values, value.len(), ledger)?;
    values.extend_from_slice(value);
    ensure_vec_capacity(patterns, 1, ledger)?;
    patterns.push(SitePattern {
        kind,
        start,
        len: u32::try_from(value.len()).map_err(|_| GeoDataError::ResourceLimit {
            resource: "GeoSite compact value length",
            actual: value.len(),
            maximum: u32::MAX as usize,
        })?,
    });
    Ok(())
}

fn compile_regex_set(
    code: Code,
    bytes: &[u8],
    ranges: &[ValueRange],
    ledger: &mut AllocationLedger,
) -> Result<Vec<dense::DFA<Vec<u32>>>, GeoDataError> {
    let mut regexes = Vec::new();
    ensure_vec_capacity(&mut regexes, ranges.len(), ledger)?;

    // Compile independently to avoid a multi-pattern state product. The
    // compiler has no VCore memory quota; only its retained DFA is accounted.
    for range in ranges {
        let mut builder = dense::Builder::new();
        builder.configure(
            dense::Config::new()
                .dfa_size_limit(None)
                .determinize_size_limit(None)
                .accelerate(false)
                .start_kind(StartKind::Unanchored),
        );
        builder.thompson(regex_automata::nfa::thompson::Config::new().nfa_size_limit(None));
        // Routing domains are ASCII. Byte mode avoids irrelevant Unicode
        // states without changing matches on normalized routing input.
        builder.syntax(
            regex_automata::util::syntax::Config::new()
                .unicode(false)
                .utf8(false),
        );
        let start = range.start as usize;
        let end = start + range.len as usize;
        let pattern = str::from_utf8(&bytes[start..end]).expect("validated Regex UTF-8");
        let result = builder
            .build(pattern)
            .map_err(|error| GeoDataError::InvalidRegex {
                code: code.as_str().to_owned(),
                detail: error.to_string(),
            })
            .and_then(|regex| {
                ledger.reserve(regex.memory_usage())?;
                Ok(regex)
            });
        match result {
            Ok(regex) => regexes.push(regex),
            Err(error) => {
                release_regexes(&mut regexes, ledger);
                return Err(error);
            }
        }
    }
    Ok(regexes)
}

fn release_regexes(regexes: &mut Vec<dense::DFA<Vec<u32>>>, ledger: &mut AllocationLedger) {
    for regex in regexes.iter() {
        ledger.release(regex.memory_usage());
    }
    release_vec(regexes, ledger);
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Cidr4 {
    network: [u8; 4],
    prefix: u8,
}

impl Cidr4 {
    fn numeric(self) -> u32 {
        u32::from_be_bytes(self.network)
    }

    fn contains(self, address: u32) -> bool {
        mask_v4(address, self.prefix) == self.numeric()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Cidr6 {
    network: [u8; 16],
    prefix: u8,
}

impl Cidr6 {
    fn numeric(self) -> u128 {
        u128::from_be_bytes(self.network)
    }

    fn contains(self, address: u128) -> bool {
        mask_v6(address, self.prefix) == self.numeric()
    }
}

struct IpCategory {
    code: Code,
    v4: Vec<Cidr4>,
    v6: Vec<Cidr6>,
}

impl IpCategory {
    fn matches(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => {
                let address = u32::from(address);
                let at = self.v4.partition_point(|cidr| cidr.numeric() <= address);
                at != 0 && self.v4[at - 1].contains(address)
            }
            IpAddr::V6(address) => {
                let address = u128::from(address);
                let at = self.v6.partition_point(|cidr| cidr.numeric() <= address);
                at != 0 && self.v6[at - 1].contains(address)
            }
        }
    }
}

fn parse_ip_category(
    file: &mut File,
    range: SelectedRange,
    ledger: &mut AllocationLedger,
) -> Result<IpCategory, GeoDataError> {
    let kind = GeoDataKind::GeoIp;
    let end = checked_end(range.offset, range.len, u64::MAX, kind)?;
    seek(file, range.offset, kind)?;
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut seen_code = false;
    let mut reverse_match = false;
    let result = (|| {
        while position(file, kind)? < end {
            let (field, wire) = read_key(file, end, kind)?;
            match field {
                1 => {
                    require_wire(kind, wire, 2, "GeoIP code")?;
                    if seen_code {
                        return malformed(kind, "GeoIP contains code more than once");
                    }
                    let code = read_code(file, end, kind)?;
                    if code != range.code {
                        return malformed(kind, "GeoIP code changed between scan passes");
                    }
                    seen_code = true;
                }
                2 => {
                    require_wire(kind, wire, 2, "CIDR")?;
                    let len = read_length(file, end, kind)?;
                    let start = position(file, kind)?;
                    let record_end = checked_end(start, len, end, kind)?;
                    parse_cidr_record(file, record_end, range.code, &mut v4, &mut v6, ledger)?;
                    seek(file, record_end, kind)?;
                }
                3 => {
                    require_wire(kind, wire, 0, "GeoIP.reverse_match")?;
                    reverse_match |= read_varint(file, end, kind)? != 0;
                }
                _ => skip_field_payload(file, wire, end, kind)?,
            }
        }
        if !seen_code {
            return malformed(kind, "GeoIP is missing code");
        }
        if reverse_match {
            return Err(GeoDataError::ReverseMatch {
                kind,
                code: range.code.as_str().to_owned(),
            });
        }
        compact_v4(&mut v4);
        compact_v6(&mut v6);
        Ok(())
    })();
    match result {
        Ok(()) => Ok(IpCategory {
            code: range.code,
            v4,
            v6,
        }),
        Err(error) => {
            release_vec(&v4, ledger);
            release_vec(&v6, ledger);
            Err(error)
        }
    }
}

fn parse_cidr_record(
    file: &mut File,
    end: u64,
    code: Code,
    v4: &mut Vec<Cidr4>,
    v6: &mut Vec<Cidr6>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoIp;
    let mut ip = [0_u8; 16];
    let mut ip_len = None;
    let mut prefix = 0_u64;
    let mut seen_prefix = false;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match field {
            1 => {
                require_wire(kind, wire, 2, "CIDR.ip")?;
                if ip_len.is_some() {
                    return invalid_cidr(code, "CIDR.ip occurs more than once");
                }
                let len = read_length(file, end, kind)?;
                if len != 4 && len != 16 {
                    return invalid_cidr(code, "CIDR.ip must contain 4 or 16 bytes");
                }
                read_exact(file, &mut ip[..len as usize], end, kind)?;
                ip_len = Some(len as usize);
            }
            2 => {
                require_wire(kind, wire, 0, "CIDR.prefix")?;
                if seen_prefix {
                    return invalid_cidr(code, "CIDR.prefix occurs more than once");
                }
                prefix = read_varint(file, end, kind)?;
                seen_prefix = true;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    match ip_len {
        Some(4) if prefix <= 32 => {
            let numeric = mask_v4(
                u32::from_be_bytes(ip[..4].try_into().expect("four-byte slice")),
                prefix as u8,
            );
            ensure_vec_capacity(v4, 1, ledger)?;
            v4.push(Cidr4 {
                network: numeric.to_be_bytes(),
                prefix: prefix as u8,
            });
        }
        Some(16) if prefix <= 128 => {
            let numeric = mask_v6(u128::from_be_bytes(ip), prefix as u8);
            ensure_vec_capacity(v6, 1, ledger)?;
            v6.push(Cidr6 {
                network: numeric.to_be_bytes(),
                prefix: prefix as u8,
            });
        }
        Some(4 | 16) => return invalid_cidr(code, "CIDR.prefix exceeds address width"),
        _ => return invalid_cidr(code, "CIDR.ip is missing"),
    }
    Ok(())
}

fn compact_v4(values: &mut Vec<Cidr4>) {
    values.sort_unstable_by(|left, right| {
        left.numeric()
            .cmp(&right.numeric())
            .then(left.prefix.cmp(&right.prefix))
    });
    let mut write = 0_usize;
    for read in 0..values.len() {
        let value = values[read];
        if write != 0 && values[write - 1].contains(value.numeric()) {
            continue;
        }
        values[write] = value;
        write += 1;
        while write >= 2 && sibling_v4(values[write - 2], values[write - 1]) {
            let parent = Cidr4 {
                network: values[write - 2].network,
                prefix: values[write - 2].prefix - 1,
            };
            values[write - 2] = parent;
            write -= 1;
        }
    }
    values.truncate(write);
}

fn compact_v6(values: &mut Vec<Cidr6>) {
    values.sort_unstable_by(|left, right| {
        left.numeric()
            .cmp(&right.numeric())
            .then(left.prefix.cmp(&right.prefix))
    });
    let mut write = 0_usize;
    for read in 0..values.len() {
        let value = values[read];
        if write != 0 && values[write - 1].contains(value.numeric()) {
            continue;
        }
        values[write] = value;
        write += 1;
        while write >= 2 && sibling_v6(values[write - 2], values[write - 1]) {
            let parent = Cidr6 {
                network: values[write - 2].network,
                prefix: values[write - 2].prefix - 1,
            };
            values[write - 2] = parent;
            write -= 1;
        }
    }
    values.truncate(write);
}

fn sibling_v4(left: Cidr4, right: Cidr4) -> bool {
    if left.prefix == 0 || left.prefix != right.prefix {
        return false;
    }
    let parent_prefix = left.prefix - 1;
    let parent = mask_v4(left.numeric(), parent_prefix);
    left.numeric() == parent && right.numeric() == parent | (1_u32 << (32 - u32::from(left.prefix)))
}

fn sibling_v6(left: Cidr6, right: Cidr6) -> bool {
    if left.prefix == 0 || left.prefix != right.prefix {
        return false;
    }
    let parent_prefix = left.prefix - 1;
    let parent = mask_v6(left.numeric(), parent_prefix);
    left.numeric() == parent
        && right.numeric() == parent | (1_u128 << (128 - u32::from(left.prefix)))
}

fn mask_v4(address: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        address & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask_v6(address: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        address & (u128::MAX << (128 - u32::from(prefix)))
    }
}

fn read_code(file: &mut File, end: u64, kind: GeoDataKind) -> Result<Code, GeoDataError> {
    let len = read_length(file, end, kind)?;
    if len > MAX_CODE_BYTES as u64 {
        return Err(GeoDataError::InvalidCode {
            kind,
            code: "<more than 64 bytes>".to_owned(),
        });
    }
    let mut raw = [0_u8; MAX_CODE_BYTES];
    read_exact(file, &mut raw[..len as usize], end, kind)?;
    Code::parse(kind, &raw[..len as usize])
}

fn read_scratch(
    file: &mut File,
    offset: u64,
    len: usize,
    scratch: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    ensure_vec_capacity(scratch, len.saturating_sub(scratch.len()), ledger)?;
    scratch.resize(len, 0);
    seek(file, offset, kind)?;
    let end = offset
        .checked_add(len as u64)
        .ok_or_else(|| malformed_error(kind, "value range overflows u64"))?;
    read_exact(file, scratch, end, kind)
}

fn ensure_vec_capacity<T>(
    values: &mut Vec<T>,
    additional: usize,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    if required <= values.capacity() || mem::size_of::<T>() == 0 {
        return Ok(());
    }
    let desired = required.checked_next_power_of_two().unwrap_or(required);
    let old_capacity = values.capacity();
    // An allocator can move the buffer. Charge the entire new capacity while
    // the old allocation is still live, not only the retained-size delta.
    let requested_bytes = desired
        .checked_mul(mem::size_of::<T>())
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    ledger.reserve(requested_bytes)?;
    let reserve_additional = desired - values.len();
    if values.try_reserve_exact(reserve_additional).is_err() {
        ledger.release(requested_bytes);
        return Err(GeoDataError::AllocationFailed {
            bytes: requested_bytes,
        });
    }
    let actual_elements = values.capacity();
    match actual_elements.cmp(&desired) {
        std::cmp::Ordering::Greater => {
            let extra = (actual_elements - desired)
                .checked_mul(mem::size_of::<T>())
                .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
            ledger.reserve(extra)?;
        }
        std::cmp::Ordering::Less => {
            ledger.release((desired - actual_elements) * mem::size_of::<T>());
        }
        std::cmp::Ordering::Equal => {}
    }
    ledger.release(old_capacity * mem::size_of::<T>());
    Ok(())
}

fn release_vec<T>(values: &Vec<T>, ledger: &mut AllocationLedger) {
    ledger.release(values.capacity().saturating_mul(mem::size_of::<T>()));
}

fn read_key(file: &mut File, end: u64, kind: GeoDataKind) -> Result<(u32, u8), GeoDataError> {
    let key = read_varint(file, end, kind)?;
    let field = key >> 3;
    let wire = (key & 7) as u8;
    if field == 0 || field > u64::from(u32::MAX) {
        return malformed(kind, "invalid protobuf field number");
    }
    Ok((field as u32, wire))
}

fn read_varint(file: &mut File, end: u64, kind: GeoDataKind) -> Result<u64, GeoDataError> {
    let mut value = 0_u64;
    for index in 0..10_u32 {
        if position(file, kind)? >= end {
            return malformed(kind, "truncated protobuf varint");
        }
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)
            .map_err(|source| io_error(kind, source))?;
        if index == 9 && byte[0] > 1 {
            return malformed(kind, "protobuf varint overflows u64");
        }
        value |= u64::from(byte[0] & 0x7f) << (index * 7);
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    malformed(kind, "protobuf varint exceeds ten bytes")
}

fn read_length(file: &mut File, end: u64, kind: GeoDataKind) -> Result<u64, GeoDataError> {
    let len = read_varint(file, end, kind)?;
    let start = position(file, kind)?;
    let _ = checked_end(start, len, end, kind)?;
    Ok(len)
}

fn skip_field_payload(
    file: &mut File,
    wire: u8,
    end: u64,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    match wire {
        0 => {
            let _ = read_varint(file, end, kind)?;
            Ok(())
        }
        1 => skip_bytes(file, 8, end, kind),
        2 => {
            let len = read_length(file, end, kind)?;
            skip_bytes(file, len, end, kind)
        }
        5 => skip_bytes(file, 4, end, kind),
        _ => malformed(kind, "unsupported protobuf wire type"),
    }
}

fn skip_bytes(file: &mut File, len: u64, end: u64, kind: GeoDataKind) -> Result<(), GeoDataError> {
    let start = position(file, kind)?;
    let target = checked_end(start, len, end, kind)?;
    seek(file, target, kind)
}

fn read_exact(
    file: &mut File,
    output: &mut [u8],
    end: u64,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    let start = position(file, kind)?;
    let len = u64::try_from(output.len())
        .map_err(|_| malformed_error(kind, "read length does not fit u64"))?;
    let _ = checked_end(start, len, end, kind)?;
    file.read_exact(output)
        .map_err(|source| io_error(kind, source))
}

fn checked_end(
    start: u64,
    len: u64,
    outer_end: u64,
    kind: GeoDataKind,
) -> Result<u64, GeoDataError> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| malformed_error(kind, "length-delimited field overflows u64"))?;
    if end > outer_end {
        return malformed(kind, "length-delimited field exceeds enclosing message");
    }
    Ok(end)
}

fn position(file: &mut File, kind: GeoDataKind) -> Result<u64, GeoDataError> {
    file.stream_position()
        .map_err(|source| io_error(kind, source))
}

fn seek(file: &mut File, position: u64, kind: GeoDataKind) -> Result<(), GeoDataError> {
    file.seek(SeekFrom::Start(position))
        .map(|_| ())
        .map_err(|source| io_error(kind, source))
}

fn require_wire(
    kind: GeoDataKind,
    actual: u8,
    expected: u8,
    field: &'static str,
) -> Result<(), GeoDataError> {
    if actual != expected {
        return malformed(
            kind,
            &format!("{field} uses wire type {actual}, expected {expected}"),
        );
    }
    Ok(())
}

fn io_error(kind: GeoDataKind, source: std::io::Error) -> GeoDataError {
    GeoDataError::Io {
        path: PathBuf::from(kind.file_name()),
        source,
    }
}

fn malformed<T>(kind: GeoDataKind, detail: &str) -> Result<T, GeoDataError> {
    Err(malformed_error(kind, detail))
}

fn malformed_error(kind: GeoDataKind, detail: &str) -> GeoDataError {
    GeoDataError::Malformed {
        kind,
        detail: detail.to_owned(),
    }
}

fn invalid_domain<T>(code: Code, detail: &str) -> Result<T, GeoDataError> {
    Err(invalid_domain_error(code, detail))
}

fn invalid_domain_error(code: Code, detail: &str) -> GeoDataError {
    GeoDataError::InvalidDomain {
        code: code.as_str().to_owned(),
        detail: detail.to_owned(),
    }
}

fn invalid_cidr<T>(code: Code, detail: &str) -> Result<T, GeoDataError> {
    Err(GeoDataError::InvalidCidr {
        code: code.as_str().to_owned(),
        detail: detail.to_owned(),
    })
}

#[cfg(test)]
mod tests;
