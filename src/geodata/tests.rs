use std::{fs, net::IpAddr};

use tempfile::tempdir;

use super::*;
use crate::{
    config::{DnsNameserverPolicy, RuleAction, RuleKind, RuleSpec},
    routing::normalize_domain_name,
};

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
    let data = GeoData::load(dir.path(), &[]).unwrap();
    assert!(data.is_empty());
    assert_eq!(data.allocation_capacity(), 0);
    assert_eq!(data.peak_allocation_capacity(), 0);
}

#[test]
fn category_lookup_preserves_independent_codes_through_load_and_reload() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[
            site("Az", &[domain(3, "az.example")]),
            site("AA", &[domain(3, "aa.example")]),
            site("Z", &[domain(3, "z.example")]),
            site("a-b", &[domain(3, "hyphen.example")]),
            site("a", &[domain(3, "a.example")]),
        ]),
    );
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[
            geoip("a-B", &[cidr(&[10, 4, 0, 0], 16)], false),
            geoip("z", &[cidr(&[10, 5, 0, 0], 16)], false),
            geoip("a", &[cidr(&[10, 1, 0, 0], 16)], false),
            geoip("AZ", &[cidr(&[10, 3, 0, 0], 16)], false),
            geoip("aa", &[cidr(&[10, 2, 0, 0], 16)], false),
        ]),
    );
    let rules: Vec<_> = ["z", "a-b", "a", "az", "aa"]
        .into_iter()
        .flat_map(|code| {
            [
                rule(RuleKind::GeoSite(code.to_owned())),
                rule(RuleKind::GeoIp(code.to_owned())),
            ]
        })
        .collect();
    let data = GeoData::load(dir.path(), &rules).unwrap();
    let manager = GeoDataManager::open(dir.path(), std::time::Duration::from_secs(60)).unwrap();
    let registration = manager
        .register(GeoRequirements::collect(&rules, &[]).unwrap())
        .unwrap();
    assert!(registration.initial_report().geosite.available);
    assert!(registration.initial_report().geoip.available);
    let matcher = registration.matcher();
    for loaded in [&data as &dyn GeoMatcher, matcher.as_ref()] {
        for (code, domain, address) in [
            ("A", "a.example", "10.1.0.1"),
            ("aA", "aa.example", "10.2.0.1"),
            ("AZ", "az.example", "10.3.0.1"),
            ("A-b", "hyphen.example", "10.4.0.1"),
            ("z", "z.example", "10.5.0.1"),
        ] {
            assert!(loaded.geosite_available(code), "{code}");
            assert!(loaded.geoip_available(code), "{code}");
            assert!(loaded.matches_geosite(code, domain), "{code}");
            assert!(
                loaded.matches_geoip(code, address.parse().unwrap()),
                "{code}"
            );
            assert!(!loaded.matches_geosite(code, "absent.example"), "{code}");
            assert!(
                !loaded.matches_geoip(code, "192.0.2.1".parse().unwrap()),
                "{code}"
            );
        }
        for code in ["", "0", "a-", "a-bb", "aaa", "ay", "zz", "a?", " a"] {
            assert!(!loaded.geosite_available(code), "{code}");
            assert!(!loaded.geoip_available(code), "{code}");
            assert!(!loaded.matches_geosite(code, "a.example"), "{code}");
            assert!(
                !loaded.matches_geoip(code, "10.1.0.1".parse().unwrap()),
                "{code}"
            );
        }
    }

    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[
            site("a", &[domain(3, "new-a.example")]),
            site("a-b", &[domain(3, "new-hyphen.example")]),
            site("z", &[domain(3, "new-z.example")]),
            site("aa", &[domain(3, "new-aa.example")]),
            site("az", &[domain(3, "new-az.example")]),
        ]),
    );
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[
            geoip("aa", &[cidr(&[172, 2, 0, 0], 16)], false),
            geoip("az", &[cidr(&[172, 3, 0, 0], 16)], false),
            geoip("a", &[cidr(&[172, 1, 0, 0], 16)], false),
            geoip("z", &[cidr(&[172, 5, 0, 0], 16)], false),
            geoip("a-b", &[cidr(&[172, 4, 0, 0], 16)], false),
        ]),
    );
    let report = manager.reload();
    assert!(report.geosite_available);
    assert!(report.geoip_available);
    for (code, old_domain, new_domain, old_address, new_address) in [
        ("A", "a.example", "new-a.example", "10.1.0.1", "172.1.0.1"),
        (
            "aA",
            "aa.example",
            "new-aa.example",
            "10.2.0.1",
            "172.2.0.1",
        ),
        (
            "AZ",
            "az.example",
            "new-az.example",
            "10.3.0.1",
            "172.3.0.1",
        ),
        (
            "A-b",
            "hyphen.example",
            "new-hyphen.example",
            "10.4.0.1",
            "172.4.0.1",
        ),
        ("z", "z.example", "new-z.example", "10.5.0.1", "172.5.0.1"),
    ] {
        assert!(!matcher.matches_geosite(code, old_domain), "{code}");
        assert!(matcher.matches_geosite(code, new_domain), "{code}");
        assert!(
            !matcher.matches_geoip(code, old_address.parse().unwrap()),
            "{code}"
        );
        assert!(
            matcher.matches_geoip(code, new_address.parse().unwrap()),
            "{code}"
        );
    }
}

#[test]
fn geosite_loads_beyond_former_record_value_and_memory_quotas() {
    let dir = tempdir().unwrap();
    let mut selected = field_bytes(1, b"cn");
    // Exceeds the former 131072 records, 2 MiB values and 8 MiB ledger.
    for index in 0..131_073 {
        selected.extend(field_bytes(
            2,
            &domain(
                2,
                &format!("long-domain-that-crosses-the-old-byte-budget-{index:x}.example.test"),
            ),
        ));
    }
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[selected]));
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".to_owned()))]).unwrap();
    for index in [0, 65_536, 131_071, 131_072] {
        let value = format!("long-domain-that-crosses-the-old-byte-budget-{index:x}.example.test");
        assert!(data.matches_geosite("cn", &value));
        assert!(data.matches_geosite("cn", &format!("sub.{value}")));
        assert!(!data.matches_geosite("cn", &format!("not{value}")));
    }
    assert!(data.allocation_capacity() > 8 * 1024 * 1024);
    assert!(data.peak_allocation_capacity() >= data.allocation_capacity());
    drop(data);

    // Runtime preparation uses the manager's independently loaded snapshot.
    let manager = GeoDataManager::open(
        dir.path().join("managed"),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    fs::copy(
        dir.path().join(GEOSITE_FILE_NAME),
        manager.store_dir().join(GEOSITE_FILE_NAME),
    )
    .unwrap();
    let registration = manager
        .register(GeoRequirements::collect(&[rule(RuleKind::GeoSite("cn".into()))], &[]).unwrap())
        .unwrap();
    assert!(registration.initial_report().geosite.available);
    assert!(registration.initial_report().allocation_capacity > 8 * 1024 * 1024);
    assert!(registration.matcher().matches_geosite(
        "cn",
        "long-domain-that-crosses-the-old-byte-budget-20000.example.test"
    ));
}

#[test]
fn allocation_ledger_observes_growth_without_admission_limits() {
    let mut ledger = AllocationLedger::default();
    let mut bytes = Vec::<u8>::new();
    ensure_vec_capacity(&mut bytes, 8, &mut ledger).unwrap();
    bytes.extend_from_slice(b"12345678");
    ensure_vec_capacity(&mut bytes, 1, &mut ledger).unwrap();
    assert_eq!(ledger.used, 16);
    assert_eq!(ledger.peak, 24);
    assert_eq!(bytes, b"12345678");
    assert!(ensure_vec_capacity(&mut bytes, usize::MAX, &mut ledger).is_err());
    assert_eq!(ledger.used, 16);
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
    let data =
        GeoData::load_with_dns_policies(dir.path(), &[], std::slice::from_ref(&policy)).unwrap();
    assert!(data.matches_geosite("private", "host.internal.example"));
    assert!(data.matches_geosite("cn", "www.example.cn"));
    assert_eq!(data.sites.len(), 2);

    let data = GeoData::load_with_dns_policies(
        dir.path(),
        &[rule(RuleKind::GeoSite("private".to_owned()))],
        &[policy],
    )
    .unwrap();
    assert_eq!(data.sites.len(), 2);
}

#[test]
fn nameserver_policy_missing_category_still_fails_closed() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("private", &[])]),
    );
    let error =
        GeoData::load_with_dns_policies(dir.path(), &[], &[dns_policy(&["missing"])]).unwrap_err();
    assert!(matches!(
        error,
        GeoDataError::MissingCode {
            kind: GeoDataKind::GeoSite,
            ..
        }
    ));
}

#[test]
fn references_and_asset_categories_grow_without_fixed_count_limits() {
    let dir = tempdir().unwrap();
    let sites: Vec<_> = (0..4097)
        .map(|index| {
            site(
                &format!("code{index}"),
                &[domain(3, &format!("site{index}.test"))],
            )
        })
        .collect();
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&sites));
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("cn", &[cidr(&[10, 0, 0, 0], 8)], false)]),
    );
    let codes: Vec<_> = (0..17)
        .map(|index| format!("code{index}"))
        .chain(["code4096".to_owned()])
        .collect();
    let policy = dns_policy(&codes.iter().map(String::as_str).collect::<Vec<_>>());
    let rules = [
        rule(RuleKind::GeoIp("cn".into())),
        rule(RuleKind::GeoSite("CODE0".into())),
    ];
    let requirements = GeoRequirements::collect(&rules, std::slice::from_ref(&policy)).unwrap();
    assert_eq!(requirements.total_codes(), 19);
    let data = GeoData::load_with_dns_policies(dir.path(), &rules, &[policy]).unwrap();
    for index in (0..17).chain([4096]) {
        assert!(data.matches_geosite(&format!("code{index}"), &format!("site{index}.test")));
    }
    assert!(data.matches_geoip("cn", "10.1.2.3".parse().unwrap()));
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

    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("test".to_owned()))]).unwrap();
    assert!(data.matches_geosite("TEST", "has-needle.example"));
    assert!(data.matches_geosite("test", "example.com"));
    assert!(data.matches_geosite("test", "a.example.com"));
    assert!(data.matches_geosite("test", "full.example"));
    assert!(!data.matches_geosite("test", "a.full.example"));
    assert!(data.matches_geosite("test", "r42.example"));
    assert!(!data.matches_geosite("test", "R42.example"));
    assert!(data.matches_geosite("test", "prefix.other.test.example"));
    assert!(!data.matches_geosite("missing", "example.com"));
}

#[test]
fn geosite_normalizes_unicode_domain_values() {
    let dir = tempdir().unwrap();
    let fixture = site_list(&[site("idna", &[domain(2, "例子.测试")])]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("IDNA".to_owned()))]).unwrap();
    let normalized = normalize_domain_name("子.例子.测试").unwrap();
    assert!(data.matches_geosite("idna", &normalized));
}

#[test]
fn geosite_literal_patterns_do_not_require_dns_hostname_syntax() {
    let dir = tempdir().unwrap();
    let long_label = format!("{}.test", "x".repeat(64));
    let records = [
        domain(2, "EXAMPLE.TEST"),
        domain(2, "\"QUOTED.TEST"),
        domain(2, "FOO_BAR.TEST"),
        domain(3, "FULL_VALUE.TEST"),
        domain(2, "-EDGE-.TEST"),
        domain(2, "PERCENT%VALUE.TEST"),
        domain(2, "BACK\\SLASH.TEST"),
        domain(2, &long_label),
        domain(2, "*.LITERAL.TEST"),
    ];
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("compat", &records)]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("compat".into()))]).unwrap();
    assert!(data.geosite_available("compat"));
    assert_eq!(data.sites[0].patterns.len(), records.len());
    for value in [
        "example.test",
        "sub.example.test",
        "\"quoted.test",
        "sub.\"quoted.test",
        "foo_bar.test",
        "sub.foo_bar.test",
        "full_value.test",
        "-edge-.test",
        "percent%value.test",
        "back\\slash.test",
        long_label.as_str(),
        "*.literal.test",
    ] {
        assert!(data.matches_geosite("compat", value), "{value}");
    }
    for value in [
        "quoted.test",
        "notfoo_bar.test",
        "sub.full_value.test",
        "host.literal.test",
        "absent.test",
    ] {
        assert!(!data.matches_geosite("compat", value), "{value}");
    }
}

#[test]
fn geosite_preserves_utf8_patterns_when_idna_is_not_applicable() {
    let dir = tempdir().unwrap();
    // A joiner without a valid IDNA context is still a static literal pattern.
    let value = "\u{200d}.EXAMPLE";
    assert!(idna::domain_to_ascii(value).is_err());
    // Successful IDNA conversion can also erase an ignored-only value.
    assert_eq!(idna::domain_to_ascii("\u{ad}").unwrap(), "");
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("opaque", &[domain(2, value), domain(3, "\u{ad}")])]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("opaque".into()))]).unwrap();
    assert!(data.matches_geosite("opaque", "\u{200d}.example"));
    assert!(data.matches_geosite("opaque", "\u{ad}"));
    assert!(!data.matches_geosite("opaque", ""));
    assert!(!data.matches_geosite("opaque", "example"));
}

#[test]
fn geosite_pattern_compatibility_does_not_accept_invalid_records() {
    let dir = tempdir().unwrap();
    for record in [
        domain(2, ""),
        domain(3, ""),
        field_varint(1, 2),
        [field_varint(1, 2), field_bytes(2, &[0xff])].concat(),
        domain(4, "example.test"),
    ] {
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site("invalid", &[record])]),
        );
        assert!(matches!(
            GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("invalid".into()))]),
            Err(GeoDataError::InvalidDomain { .. })
        ));
    }
}

#[test]
fn geosite_membership_preserves_overlapping_unsorted_record_types() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                domain(3, "z.example"),
                domain(2, "shared.example"),
                domain(0, "needle"),
                domain(3, "shared.example"),
                domain(2, "a.example"),
                domain(3, "only.example"),
                domain(2, "shared.example"),
                domain(1, "^r[0-9]+\\.test$"),
            ],
        )]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".into()))]).unwrap();
    for value in [
        "z.example",
        "shared.example",
        "sub.shared.example",
        "a.example",
        "deep.sub.a.example",
        "only.example",
        "has-needle.test",
        "r12.test",
    ] {
        assert!(data.matches_geosite("cn", value), "{value}");
    }
    for value in [
        "sub.z.example",
        "sub.only.example",
        "notshared.example",
        "shared.example.test",
        "not-a.example",
        "absent.test",
    ] {
        assert!(!data.matches_geosite("cn", value), "{value}");
    }
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
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("PRIVATE".to_owned()))]).unwrap();

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
    let error = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".to_owned()))]).unwrap_err();
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
    let error =
        GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("missing".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::MissingCode { .. }));

    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("broken", &[domain(1, "(?=lookaround)")])]),
    );
    let error =
        GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("broken".to_owned()))]).unwrap_err();
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
    let error =
        GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("reverse".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::ReverseMatch { .. }));

    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("bad", &[cidr(&[10, 0, 0, 0], 33)], false)]),
    );
    let error = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("bad".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::InvalidCidr { .. }));
}

#[test]
fn geosite_regex_count_source_and_retained_memory_are_not_quotas() {
    let dir = tempdir().unwrap();
    let records: Vec<_> = (0..513)
        .map(|index| domain(1, &format!("^{}r{index}\\.test$", "a".repeat(130))))
        .collect();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("regex", &records)]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("regex".into()))]).unwrap();
    for index in [0, 512] {
        assert!(data.matches_geosite("regex", &format!("{}r{index}.test", "a".repeat(130))));
    }
    assert!(!data.matches_geosite("regex", "no-match.test"));
    assert!(data.allocation_capacity() > 512 * 1024);
}

#[test]
fn geoip_raw_record_count_is_not_an_admission_limit() {
    let dir = tempdir().unwrap();
    let mut category = field_bytes(1, b"cn");
    for _ in 0..320_000 {
        category.extend(field_bytes(2, &cidr(&[10, 0, 0, 1], 32)));
    }
    category.extend(field_bytes(2, &cidr(&[203, 0, 113, 9], 32)));
    write_asset(dir.path(), GEOIP_FILE_NAME, &geoip_list(&[category]));
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("cn".into()))]).unwrap();
    assert!(data.matches_geoip("cn", "10.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("cn", "203.0.113.9".parse().unwrap()));
    assert!(!data.matches_geoip("cn", "203.0.113.10".parse().unwrap()));
}

#[test]
fn large_assets_skip_unselected_payloads_without_file_size_quotas() {
    use std::io::Write;
    let dir = tempdir().unwrap();
    for kind in [GeoDataKind::GeoSite, GeoDataKind::GeoIp] {
        // A valid unselected category with a sparse length-delimited unknown
        // field beyond both former file limits. No giant heap fixture needed.
        let padding = 33 * 1024 * 1024;
        let mut category = field_bytes(1, b"unused");
        category.extend(varint((100 << 3) | 2));
        category.extend(varint(padding));
        let mut file = File::create(dir.path().join(kind.file_name())).unwrap();
        file.write_all(&varint((1 << 3) | 2)).unwrap();
        file.write_all(&varint(category.len() as u64 + padding))
            .unwrap();
        file.write_all(&category).unwrap();
        file.seek(SeekFrom::Current(padding as i64)).unwrap();
        let (selected, rule_kind) = match kind {
            GeoDataKind::GeoSite => (
                site("selected", &[domain(3, "last.test")]),
                RuleKind::GeoSite("selected".into()),
            ),
            GeoDataKind::GeoIp => (
                geoip("selected", &[cidr(&[10, 0, 0, 1], 32)], false),
                RuleKind::GeoIp("selected".into()),
            ),
        };
        file.write_all(&field_bytes(1, &selected)).unwrap();
        let data = GeoData::load(dir.path(), &[rule(rule_kind)]).unwrap();
        match kind {
            GeoDataKind::GeoSite => assert!(data.matches_geosite("selected", "last.test")),
            GeoDataKind::GeoIp => {
                assert!(data.matches_geoip("selected", "10.0.0.1".parse().unwrap()))
            }
        }
    }
}

#[test]
fn malformed_outer_framing_is_rejected() {
    let dir = tempdir().unwrap();
    write_asset(dir.path(), GEOSITE_FILE_NAME, &[0x0a, 0x05, 0x0a]);
    let error = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::Malformed { .. }));
}

#[test]
fn matcher_is_send_and_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<GeoData>();
}

#[test]
fn literal_ip_family_does_not_cross_match() {
    let dir = tempdir().unwrap();
    let fixture = geoip_list(&[geoip("v4", &[cidr(&[0, 0, 0, 0], 0)], false)]);
    write_asset(dir.path(), GEOIP_FILE_NAME, &fixture);
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("v4".to_owned()))]).unwrap();
    assert!(data.matches_geoip("v4", IpAddr::from([203, 0, 113, 1])));
    assert!(!data.matches_geoip("v4", "::ffff:203.0.113.1".parse().unwrap()));
}

/// Opt-in compatibility check for the real Xray GeoData assets shipped by the
/// app. CI does not require those external files; run with
/// `VCORE_GEODATA_DIR=/path/to/assets/dat cargo test real_xray_geodata -- --ignored --nocapture`.
#[test]
#[ignore = "requires VCORE_GEODATA_DIR containing real geosite.dat and geoip.dat"]
fn real_xray_geodata_loads_common_codes_without_memory_quotas() {
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
    )
    .unwrap();
    eprintln!(
        "real GeoData baseline allocation without GEOLOCATION-!CN: retained={} bytes, accounted_peak={} bytes",
        baseline.allocation_capacity(),
        baseline.peak_allocation_capacity(),
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
    )
    .unwrap_or_else(|error| panic!("documented GeoData combination failed: {error}"));
    eprintln!(
        "documented GeoData allocation: retained={} bytes, accounted_peak={} bytes",
        documented.allocation_capacity(),
        documented.peak_allocation_capacity(),
    );
    assert!(documented.matches_geosite("cn", "baidu.com"));
    assert!(documented.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    drop(documented);

    let policy = dns_policy(&["private", "cn", "apple"]);
    let policy_data =
        GeoData::load_with_dns_policies(&dir, &[rules[2].clone(), rules[3].clone()], &[policy])
            .unwrap_or_else(|error| panic!("Simple Profile DNS policy GeoData failed: {error}"));
    assert!(policy_data.matches_geosite("private", "localhost"));
    assert!(policy_data.matches_geosite("cn", "baidu.com"));
    assert!(policy_data.matches_geosite("apple", "apple.com"));
    drop(policy_data);

    let data = GeoData::load(&dir, &rules)
        .unwrap_or_else(|error| panic!("real GeoData compatibility failed: {error}"));

    eprintln!(
        "real GeoData allocation: retained={} bytes, accounted_peak={} bytes",
        data.allocation_capacity(),
        data.peak_allocation_capacity(),
    );
    assert!(data.matches_geosite("cn", "baidu.com"));
    assert!(data.matches_geosite("geolocation-!cn", "google.com"));
    assert!(data.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("cn", "1.0.1.1".parse().unwrap()));
}
