use std::{fs, net::IpAddr};

use tempfile::tempdir;

use super::*;
use crate::config::{DnsNameserverPolicy, RuleAction, RuleKind, RuleSpec};

fn varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

fn field_varint(field: u32, value: u64) -> Vec<u8> {
    let mut output = varint(u64::from(field) << 3);
    output.extend(varint(value));
    output
}

fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
    let mut output = varint((u64::from(field) << 3) | 2);
    output.extend(varint(value.len() as u64));
    output.extend(value);
    output
}

fn domain(domain_type: u64, value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    if domain_type != 0 {
        output.extend(field_varint(1, domain_type));
    }
    output.extend(field_bytes(2, value.as_bytes()));
    output
}

fn site(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
    let mut output = field_bytes(1, code.as_bytes());
    for domain in domains {
        output.extend(field_bytes(2, domain));
    }
    output
}

fn site_list(sites: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    for site in sites {
        output.extend(field_bytes(1, site));
    }
    output
}

fn cidr(ip: &[u8], prefix: u64) -> Vec<u8> {
    let mut output = field_bytes(1, ip);
    if prefix != 0 {
        output.extend(field_varint(2, prefix));
    }
    output
}

fn geoip(code: &str, cidrs: &[Vec<u8>], reverse: bool) -> Vec<u8> {
    let mut output = field_bytes(1, code.as_bytes());
    for cidr in cidrs {
        output.extend(field_bytes(2, cidr));
    }
    if reverse {
        output.extend(field_varint(3, 1));
    }
    output
}

fn geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    for entry in entries {
        output.extend(field_bytes(1, entry));
    }
    output
}

fn rule(kind: RuleKind) -> RuleSpec {
    RuleSpec {
        kind,
        action: RuleAction::Route(crate::config::RouteTargetId::Proxy(
            crate::config::ProxyId::new(0).unwrap(),
        )),
        no_resolve: false,
    }
}

fn dns_policy(codes: &[&str]) -> DnsNameserverPolicy {
    DnsNameserverPolicy {
        geosite_codes: codes
            .iter()
            .map(|code| (*code).to_owned())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        nameservers: Vec::new().into_boxed_slice(),
    }
}

fn write_asset(dir: &Path, name: &str, contents: &[u8]) {
    fs::write(dir.join(name), contents).unwrap();
}

#[test]
fn empty_rules_do_not_open_assets() {
    let dir = tempdir().unwrap();
    let data = GeoData::load(dir.path(), &[], 1).unwrap();
    assert!(data.is_empty());
    assert_eq!(data.allocation_capacity(), 0);
    assert_eq!(data.peak_allocation_capacity(), 0);
}

#[test]
fn nameserver_policy_alone_loads_geosite_and_shares_rule_categories() {
    let dir = tempdir().unwrap();
    let fixture = site_list(&[
        site("private", &[domain(2, "internal.example")]),
        site("cn", &[domain(2, "example.cn")]),
    ]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);

    let policy = dns_policy(&["private", "cn"]);
    let data = GeoData::load_with_dns_policies(
        dir.path(),
        &[],
        std::slice::from_ref(&policy),
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    assert!(data.matches_geosite("private", "host.internal.example"));
    assert!(data.matches_geosite("cn", "www.example.cn"));
    assert_eq!(data.sites.len(), 2);
    assert!(data.peak_allocation_capacity() <= GENERAL_ALLOCATION_BUDGET_BYTES);

    let data = GeoData::load_with_dns_policies(
        dir.path(),
        &[rule(RuleKind::GeoSite("private".to_owned()))],
        &[policy],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    assert_eq!(data.sites.len(), 2);
}

#[test]
fn nameserver_policy_missing_category_and_combined_code_limit_fail_closed() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("private", &[domain(2, "internal.example")])]),
    );
    let error = GeoData::load_with_dns_policies(
        dir.path(),
        &[],
        &[dns_policy(&["missing"])],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GeoDataError::MissingCode {
            kind: GeoDataKind::GeoSite,
            ..
        }
    ));

    let codes = (0..MAX_REFERENCED_CODES)
        .map(|index| format!("site{index}"))
        .collect::<Vec<_>>();
    let policy = DnsNameserverPolicy {
        geosite_codes: codes.into_boxed_slice(),
        nameservers: Vec::new().into_boxed_slice(),
    };
    let error = GeoData::load_with_dns_policies(
        dir.path(),
        &[rule(RuleKind::GeoIp("extra".to_owned()))],
        &[policy],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::TooManyReferencedCodes { .. }));
}

#[test]
fn geosite_supports_all_domain_types_and_attributes() {
    let dir = tempdir().unwrap();

    let mut attributed = domain(2, "Example.COM.");
    let mut attribute = field_bytes(1, b"ads");
    attribute.extend(field_varint(2, 1));
    attributed.extend(field_bytes(3, &attribute));

    let fixture = site_list(&[site(
        "TeSt",
        &[
            domain(0, "Needle"),
            attributed,
            domain(3, "full.example"),
            domain(1, r"^r[0-9]+\.example$"),
            domain(1, r"other\.test"),
        ],
    )]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);

    let data = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("test".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    assert!(data.matches_geosite("TEST", "has-needle.example"));
    assert!(data.matches_geosite("test", "example.com"));
    assert!(data.matches_geosite("test", "a.example.com"));
    assert!(data.matches_geosite("test", "full.example"));
    assert!(!data.matches_geosite("test", "a.full.example"));
    assert!(data.matches_geosite("test", "r42.example"));
    assert!(!data.matches_geosite("test", "R42.example"));
    assert!(data.matches_geosite("test", "prefix.other.test.example"));
    assert!(!data.matches_geosite("missing", "example.com"));
    assert!(data.allocation_capacity() <= GENERAL_ALLOCATION_BUDGET_BYTES);
    assert!(data.peak_allocation_capacity() <= GENERAL_ALLOCATION_BUDGET_BYTES);
}

#[test]
fn geosite_normalizes_unicode_domain_values() {
    let dir = tempdir().unwrap();
    let fixture = site_list(&[site("idna", &[domain(2, "例子.测试")])]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);
    let data = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("IDNA".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    let normalized = normalize_domain_name("子.例子.测试").unwrap();
    assert!(data.matches_geosite("idna", &normalized));
}

#[test]
fn geoip_matches_v4_v6_and_compacts_siblings() {
    let dir = tempdir().unwrap();
    let fixture = geoip_list(&[geoip(
        "private",
        &[
            cidr(&[10, 0, 0, 1], 9),
            cidr(&[10, 128, 0, 1], 9),
            cidr(&[10, 12, 0, 0], 16),
            cidr(
                &u128::from_be_bytes([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                    .to_be_bytes(),
                7,
            ),
        ],
        false,
    )]);
    write_asset(dir.path(), GEOIP_FILE_NAME, &fixture);
    let data = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoIp("PRIVATE".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();

    assert_eq!(data.ips[0].v4.len(), 1);
    assert!(data.matches_geoip("private", "10.255.4.1".parse().unwrap()));
    assert!(!data.matches_geoip("private", "11.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("private", "fd00::1".parse().unwrap()));
    assert!(!data.matches_geoip("private", "2001:db8::1".parse().unwrap()));
}

#[test]
fn unselected_category_payload_is_not_decoded() {
    let dir = tempdir().unwrap();
    let mut unselected = field_bytes(1, b"unused");
    unselected.extend(field_bytes(2, &[0xff]));
    let fixture = site_list(&[unselected, site("selected", &[domain(3, "ok.example")])]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);

    let data = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("selected".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    assert!(data.matches_geosite("selected", "ok.example"));
}

#[test]
fn selected_corrupt_payload_fails_closed() {
    let dir = tempdir().unwrap();
    let mut selected = field_bytes(1, b"selected");
    selected.extend(field_bytes(2, &[0xff]));
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[selected]));

    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("selected".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::Malformed { .. }));
}

#[test]
fn duplicate_codes_are_ascii_case_insensitive() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("CN", &[]), site("cn", &[])]),
    );
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("cn".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::DuplicateCode { .. }));
}

#[test]
fn missing_code_and_invalid_regex_are_errors() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("other", &[])]),
    );
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("missing".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::MissingCode { .. }));

    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("broken", &[domain(1, "(?=lookaround)")])]),
    );
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("broken".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::InvalidRegex { .. }));

    for unsupported in ["(?u:\\w+)", "(?x:example)", "例子"] {
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site("unsupported", &[domain(1, unsupported)])]),
        );
        let error = GeoData::load(
            dir.path(),
            &[rule(RuleKind::GeoSite("unsupported".to_owned()))],
            GENERAL_ALLOCATION_BUDGET_BYTES,
        )
        .unwrap_err();
        assert!(matches!(error, GeoDataError::InvalidRegex { .. }));
    }
}

#[test]
fn reverse_match_and_invalid_cidr_are_rejected() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("reverse", &[], true)]),
    );
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoIp("reverse".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::ReverseMatch { .. }));

    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("bad", &[cidr(&[10, 0, 0, 0], 33)], false)]),
    );
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoIp("bad".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::InvalidCidr { .. }));
}

#[test]
fn tiny_allocation_budget_fails_before_loading_records() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("small", &[domain(3, "example.com")])]),
    );
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("small".to_owned()))],
        1,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GeoDataError::AllocationBudgetExceeded { .. }
    ));
}

#[test]
fn malformed_outer_framing_is_rejected() {
    let dir = tempdir().unwrap();
    write_asset(dir.path(), GEOSITE_FILE_NAME, &[0x0a, 0x05, 0x0a]);
    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("cn".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::Malformed { .. }));
}

#[test]
fn matcher_is_send_and_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<GeoData>();
}

#[test]
fn more_than_sixteen_referenced_codes_fails_without_panicking() {
    let dir = tempdir().unwrap();
    let rules: Vec<_> = (0..=MAX_REFERENCED_CODES)
        .map(|index| rule(RuleKind::GeoSite(format!("code{index}"))))
        .collect();
    let error = GeoData::load(dir.path(), &rules, GENERAL_ALLOCATION_BUDGET_BYTES).unwrap_err();
    assert!(matches!(error, GeoDataError::TooManyReferencedCodes { .. }));
}

#[test]
fn literal_ip_family_does_not_cross_match() {
    let dir = tempdir().unwrap();
    let fixture = geoip_list(&[geoip("v4", &[cidr(&[0, 0, 0, 0], 0)], false)]);
    write_asset(dir.path(), GEOIP_FILE_NAME, &fixture);
    let data = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoIp("v4".to_owned()))],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    assert!(data.matches_geoip("v4", IpAddr::from([203, 0, 113, 1])));
    assert!(!data.matches_geoip("v4", "::ffff:203.0.113.1".parse().unwrap()));
}

/// Opt-in compatibility check for the real Xray GeoData assets shipped by the
/// app. CI does not require those external files; run with
/// `VCORE_GEODATA_DIR=/path/to/assets/dat cargo test real_xray_geodata -- --ignored --nocapture`.
#[test]
#[ignore = "requires VCORE_GEODATA_DIR containing real geosite.dat and geoip.dat"]
fn real_xray_geodata_loads_common_codes_with_shared_budget() {
    let dir = std::env::var_os("VCORE_GEODATA_DIR")
        .map(PathBuf::from)
        .expect("VCORE_GEODATA_DIR must point to the directory containing both .dat files");
    let rules = [
        rule(RuleKind::GeoSite("cn".to_owned())),
        rule(RuleKind::GeoSite("geolocation-!cn".to_owned())),
        rule(RuleKind::GeoIp("cn".to_owned())),
        rule(RuleKind::GeoIp("private".to_owned())),
    ];
    let baseline = GeoData::load(
        &dir,
        &[rules[0].clone(), rules[2].clone(), rules[3].clone()],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap();
    eprintln!(
        "real GeoData baseline allocation without GEOLOCATION-!CN: retained={} bytes, construction_peak={} bytes, budget={} bytes",
        baseline.allocation_capacity(),
        baseline.peak_allocation_capacity(),
        GENERAL_ALLOCATION_BUDGET_BYTES,
    );
    assert!(baseline.matches_geosite("cn", "baidu.com"));
    assert!(baseline.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    assert!(baseline.matches_geoip("cn", "1.0.1.1".parse().unwrap()));
    drop(baseline);

    let documented = GeoData::load(
        &dir,
        &[
            rule(RuleKind::GeoSite("category-ads-all".to_owned())),
            rules[0].clone(),
            rules[2].clone(),
            rules[3].clone(),
        ],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_or_else(|error| panic!("documented GeoData combination failed: {error}"));
    eprintln!(
        "documented GeoData allocation: retained={} bytes, construction_peak={} bytes, budget={} bytes",
        documented.allocation_capacity(),
        documented.peak_allocation_capacity(),
        GENERAL_ALLOCATION_BUDGET_BYTES,
    );
    assert!(documented.matches_geosite("cn", "baidu.com"));
    assert!(documented.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    drop(documented);

    let policy = dns_policy(&["private", "cn", "apple"]);
    let policy_data = GeoData::load_with_dns_policies(
        &dir,
        &[rules[2].clone(), rules[3].clone()],
        &[policy],
        GENERAL_ALLOCATION_BUDGET_BYTES,
    )
    .unwrap_or_else(|error| panic!("Simple Profile DNS policy GeoData failed: {error}"));
    assert!(policy_data.matches_geosite("private", "localhost"));
    assert!(policy_data.matches_geosite("cn", "baidu.com"));
    assert!(policy_data.matches_geosite("apple", "apple.com"));
    drop(policy_data);

    let data = GeoData::load(&dir, &rules, GENERAL_ALLOCATION_BUDGET_BYTES)
        .unwrap_or_else(|error| panic!("real GeoData compatibility failed: {error}"));

    eprintln!(
        "real GeoData allocation: retained={} bytes, construction_peak={} bytes, budget={} bytes",
        data.allocation_capacity(),
        data.peak_allocation_capacity(),
        GENERAL_ALLOCATION_BUDGET_BYTES,
    );
    assert!(data.matches_geosite("cn", "baidu.com"));
    assert!(data.matches_geosite("geolocation-!cn", "google.com"));
    assert!(data.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("cn", "1.0.1.1".parse().unwrap()));
}
