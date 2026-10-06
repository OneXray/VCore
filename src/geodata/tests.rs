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

fn repeated_site(code: &str, record: &[u8], count: usize) -> Vec<u8> {
    let mut output = field_bytes(1, code.as_bytes());
    let framed_record = field_bytes(2, record);
    for _ in 0..count {
        output.extend_from_slice(&framed_record);
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

fn load_with_record_limit(
    dir: &Path,
    rules: &[RuleSpec],
    dns_policies: &[DnsNameserverPolicy],
    limit: usize,
) -> Result<GeoData, GeoDataError> {
    GeoData::load_with_record_limit(dir, rules, dns_policies, Some(limit))
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
fn geosite_loads_beyond_former_value_and_memory_quotas() {
    let dir = tempdir().unwrap();
    let mut selected = field_bytes(1, b"cn");
    // Exceeds the former 2 MiB values and 8 MiB ledger budgets, while
    // remaining inside the iOS/tvOS raw record limit.
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
fn ios_tvos_geodata_record_limit_keeps_site_types_and_counts_raw_duplicates() {
    let dir = tempdir().unwrap();
    let limit = 5;
    let duplicate = domain(2, "domain.example");
    let mut category = repeated_site("cn", &duplicate, limit - 3);
    for record in [
        domain(3, "full.example"),
        domain(0, "needle"),
        domain(1, "^regex\\.example$"),
    ] {
        category.extend(field_bytes(2, &record));
    }
    category.extend(field_bytes(2, &domain(3, "dropped.example")));
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[category]));
    let rules = [rule(RuleKind::GeoSite("cn".into()))];
    let data = load_with_record_limit(dir.path(), &rules, &[], limit).unwrap();
    for value in [
        "sub.domain.example",
        "full.example",
        "has-needle.example",
        "regex.example",
    ] {
        assert!(data.matches_geosite("cn", value), "{value}");
    }
    assert!(!data.matches_geosite("cn", "absent.example"));
    assert!(!data.matches_geosite("cn", "dropped.example"));
}

#[test]
fn ios_tvos_geodata_record_limit_aggregates_rule_and_dns_categories_by_code() {
    let dir = tempdir().unwrap();
    let limit = 4;
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[
            site(
                "B",
                &[domain(3, "b-first.example"), domain(3, "b-last.example")],
            ),
            site(
                "A",
                &[
                    domain(3, "a-first.example"),
                    domain(3, "a-second.example"),
                    domain(3, "a-last.example"),
                ],
            ),
            site("c", &[domain(3, "c.example")]),
        ]),
    );
    for (rules, policies) in [
        (
            vec![
                rule(RuleKind::GeoSite("B".into())),
                rule(RuleKind::GeoSite("a".into())),
            ],
            vec![dns_policy(&["b", "C", "A"])],
        ),
        (
            vec![
                rule(RuleKind::GeoSite("A".into())),
                rule(RuleKind::GeoSite("b".into())),
            ],
            vec![dns_policy(&["c"])],
        ),
    ] {
        let data = load_with_record_limit(dir.path(), &rules, &policies, limit).unwrap();
        for value in ["a-first.example", "a-second.example", "a-last.example"] {
            assert!(data.matches_geosite("a", value), "{value}");
        }
        assert!(data.matches_geosite("b", "b-first.example"));
        assert!(!data.matches_geosite("b", "b-last.example"));
        assert!(data.geosite_available("c"));
        assert!(!data.matches_geosite("c", "c.example"));
    }
}

#[test]
fn ios_tvos_geodata_record_limit_deduplicates_references_and_excludes_unselected() {
    let dir = tempdir().unwrap();
    let limit = 3;
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[
            site(
                "used",
                &[
                    domain(3, "first.example"),
                    domain(3, "second.example"),
                    domain(3, "last.example"),
                ],
            ),
            repeated_site("unused", &domain(3, "unused.example"), limit + 1),
        ]),
    );
    let data = load_with_record_limit(
        dir.path(),
        &[
            rule(RuleKind::GeoSite("USED".into())),
            rule(RuleKind::GeoSite("used".into())),
        ],
        &[dns_policy(&["Used"])],
        limit,
    )
    .unwrap();
    assert!(data.matches_geosite("used", "first.example"));
    assert!(data.matches_geosite("used", "last.example"));
    assert!(!data.geosite_available("unused"));
}

#[test]
fn ios_tvos_geodata_record_limit_skips_truncated_site_decode_and_regex_compilation() {
    let dir = tempdir().unwrap();
    let limit = 2;
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                domain(2, "kept.example"),
                domain(3, "last-kept.example"),
                domain(1, "["),
                domain(99, "unsupported.example"),
            ],
        )]),
    );
    let data = load_with_record_limit(
        dir.path(),
        &[rule(RuleKind::GeoSite("cn".into()))],
        &[],
        limit,
    )
    .unwrap();
    assert!(data.matches_geosite("cn", "sub.kept.example"));
    assert!(data.matches_geosite("cn", "last-kept.example"));
    assert!(!data.matches_geosite("cn", "unsupported.example"));

    // The truncation boundary skips inner payload validation, but not the
    // category's outer field/wire framing.
    let mut category = site(
        "cn",
        &[domain(2, "kept.example"), domain(3, "last-kept.example")],
    );
    category.extend(field_varint(2, 1));
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[category]));
    let error = load_with_record_limit(
        dir.path(),
        &[rule(RuleKind::GeoSite("cn".into()))],
        &[],
        limit,
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::Malformed { .. }));
}

#[test]
fn geodata_record_limit_is_only_applied_on_ios_and_tvos() {
    let dir = tempdir().unwrap();
    let limit = crate::limits::IOS_TVOS_GEODATA_RECORDS;
    assert_eq!(limit, 1_280_000);
    // One raw GeoIP record plus limit - 1 retained GeoSite records reach the
    // shared limit exactly; the final GeoSite marker is the excess record.
    let mut category = repeated_site("cn", &domain(2, "example.cn"), limit - 2);
    category.extend(field_bytes(2, &domain(3, "last-kept.example")));
    category.extend(field_bytes(2, &domain(3, "first-dropped.example")));
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[category]));
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("private", &[cidr(&[10, 0, 0, 0], 8)], false)]),
    );
    let rules = [
        rule(RuleKind::GeoSite("cn".into())),
        rule(RuleKind::GeoIp("private".into())),
    ];
    let bounded = load_with_record_limit(dir.path(), &rules, &[], limit).unwrap();
    assert!(bounded.geosite_available("cn"));
    assert!(bounded.matches_geosite("cn", "last-kept.example"));
    assert!(!bounded.matches_geosite("cn", "first-dropped.example"));
    drop(bounded);

    let data = GeoData::load(dir.path(), &rules).unwrap();
    assert!(data.geosite_available("cn"));
    assert!(data.matches_geosite("cn", "www.example.cn"));
    assert!(data.matches_geosite("cn", "last-kept.example"));
    assert_eq!(
        data.matches_geosite("cn", "first-dropped.example"),
        !cfg!(any(target_os = "ios", target_os = "tvos"))
    );
    assert!(data.geoip_available("private"));
    assert!(data.matches_geoip("private", "10.1.2.3".parse().unwrap()));
}

#[test]
fn ios_tvos_geodata_record_limit_prioritizes_raw_ip_records_over_sites() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[
            geoip("b", &[cidr(&[203, 0, 113, 9], 32)], false),
            geoip(
                "A",
                &[cidr(&[10, 0, 0, 1], 32), cidr(&[10, 0, 0, 1], 32)],
                false,
            ),
            geoip("unused", &vec![cidr(&[192, 0, 2, 1], 32); 5], false),
        ]),
    );
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[domain(3, "kept.example"), domain(3, "dropped.example")],
        )]),
    );
    let rules = [
        rule(RuleKind::GeoSite("cn".into())),
        rule(RuleKind::GeoIp("b".into())),
        rule(RuleKind::GeoIp("a".into())),
        rule(RuleKind::GeoIp("A".into())),
    ];
    let policies = [dns_policy(&["CN"])];
    let direct = load_with_record_limit(dir.path(), &rules, &policies, 4).unwrap();
    let requirements = GeoRequirements::collect(&rules, &policies).unwrap();
    let (managed, report) =
        manager::load_snapshot_with_record_limit(dir.path(), &requirements, Some(4));
    assert!(report.geosite.available);
    assert!(report.geoip.available);
    for data in [&direct, managed.as_ref()] {
        assert!(data.matches_geoip("a", "10.0.0.1".parse().unwrap()));
        assert!(data.matches_geoip("b", "203.0.113.9".parse().unwrap()));
        assert!(!data.geoip_available("unused"));
        assert!(data.matches_geosite("cn", "kept.example"));
        // The two duplicate raw CIDRs compact to one matcher record, but
        // still consume two entries of the shared allowance.
        assert!(!data.matches_geosite("cn", "dropped.example"));
    }
}

#[test]
fn ios_tvos_geodata_record_limit_truncates_oversized_ip_and_keeps_empty_categories() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[
            geoip("b", &[cidr(&[192, 0, 2, 1], 32)], false),
            geoip(
                "a",
                &[
                    cidr(&[10, 0, 0, 1], 32),
                    cidr(&[10, 0, 0, 1], 32),
                    cidr(&[203, 0, 113, 9], 32),
                    cidr(&[198, 51, 100, 1], 33),
                ],
                false,
            ),
        ]),
    );
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("cn", &[domain(1, "[")])]),
    );
    let rules = [
        rule(RuleKind::GeoIp("B".into())),
        rule(RuleKind::GeoSite("cn".into())),
        rule(RuleKind::GeoIp("A".into())),
    ];
    let direct = load_with_record_limit(dir.path(), &rules, &[], 3).unwrap();
    let requirements = GeoRequirements::collect(&rules, &[]).unwrap();
    let (managed, report) =
        manager::load_snapshot_with_record_limit(dir.path(), &requirements, Some(3));
    assert!(report.geosite.available);
    assert!(report.geoip.available);
    for data in [&direct, managed.as_ref()] {
        assert!(data.matches_geoip("a", "10.0.0.1".parse().unwrap()));
        assert!(data.matches_geoip("a", "203.0.113.9".parse().unwrap()));
        assert!(!data.matches_geoip("a", "198.51.100.1".parse().unwrap()));
        assert!(data.geoip_available("b"));
        assert!(!data.matches_geoip("b", "192.0.2.1".parse().unwrap()));
        assert!(data.geosite_available("cn"));
        assert!(!data.matches_geosite("cn", "example.test"));
    }
    let ip_only =
        load_with_record_limit(dir.path(), &[rules[0].clone(), rules[2].clone()], &[], 3).unwrap();
    assert!(ip_only.matches_geoip("a", "203.0.113.9".parse().unwrap()));
    assert!(!ip_only.matches_geoip("b", "192.0.2.1".parse().unwrap()));
}

#[test]
fn ios_tvos_geodata_record_limit_reclaims_allowance_when_ip_is_unavailable() {
    let invalid_ip = geoip_list(&[geoip(
        "a",
        &[cidr(&[10, 0, 0, 1], 32), cidr(&[203, 0, 113, 9], 33)],
        false,
    )]);
    for ip_asset in [None, Some(invalid_ip.as_slice())] {
        let dir = tempdir().unwrap();
        if let Some(contents) = ip_asset {
            write_asset(dir.path(), GEOIP_FILE_NAME, contents);
        }
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site(
                "cn",
                &[
                    domain(3, "first.example"),
                    domain(3, "second.example"),
                    domain(3, "last.example"),
                ],
            )]),
        );
        let requirements = GeoRequirements::collect(
            &[
                rule(RuleKind::GeoSite("cn".into())),
                rule(RuleKind::GeoIp("a".into())),
            ],
            &[],
        )
        .unwrap();
        let (data, report) =
            manager::load_snapshot_with_record_limit(dir.path(), &requirements, Some(3));
        assert!(report.geosite.available);
        assert!(!report.geoip.available);
        assert!(report.geoip.error.is_some());
        assert!(data.matches_geosite("cn", "last.example"));
        assert!(!data.geoip_available("a"));
    }
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
fn geosite_regexes_load_without_separate_source_or_memory_quotas() {
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
fn geoip_records_below_shared_limit_load_before_cidr_compaction() {
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
