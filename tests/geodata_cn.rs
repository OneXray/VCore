//! Opt-in complete official CN semantics. The independent model and witnesses
//! run outside the production-ABI memory measurement process; no server or IO
//! forwarding is started by this diagnostic.
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use vcore::{
    config::{Network, RuleAction, RuleKind, RuleSpec},
    geodata::GeoData,
    routing::{GeoMatcher, RoutingContext},
    session::Destination,
};

fn rule(kind: RuleKind) -> RuleSpec {
    RuleSpec {
        kind,
        action: RuleAction::Reject,
        no_resolve: true,
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Witness {
    Site {
        id: String,
        value: String,
        matched: bool,
    },
    Ip {
        id: String,
        value: String,
        matched: bool,
    },
    Regex {
        index: usize,
        value: String,
        matched: bool,
    },
    Normalize {
        value: String,
        normalized: Option<String>,
    },
}

fn context(value: String) -> Result<RoutingContext, vcore::routing::DomainNameError> {
    RoutingContext::new(
        Network::Tcp,
        &Destination::Domain {
            host: value,
            port: 443,
        },
    )
}

fn digest(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut buffer = [0_u8; 65536];
    let mut hash = Sha256::new();
    loop {
        let size = file.read(&mut buffer).unwrap();
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
#[ignore = "requires frozen complete assets and diagnostic output directory"]
fn cold_start_allocation_ledger() {
    let asset_dir = PathBuf::from(std::env::var_os("VCORE_GEODATA_DIR").expect("asset directory"));
    let output =
        PathBuf::from(std::env::var_os("VCORE_GEODATA_REFERENCE").expect("output directory"));
    let mut profiles = serde_json::Map::new();
    for (name, kinds) in [
        ("none", vec![]),
        ("site", vec![RuleKind::GeoSite("cn".into())]),
        ("ip", vec![RuleKind::GeoIp("cn".into())]),
        (
            "both",
            vec![RuleKind::GeoSite("cn".into()), RuleKind::GeoIp("cn".into())],
        ),
    ] {
        let rules: Vec<_> = kinds.into_iter().map(rule).collect();
        let data = GeoData::load(&asset_dir, &rules).unwrap();
        assert_eq!(
            data.geosite_available("cn"),
            matches!(name, "site" | "both")
        );
        assert_eq!(data.geoip_available("cn"), matches!(name, "ip" | "both"));
        assert!(data.allocation_capacity() <= data.peak_allocation_capacity());
        profiles.insert(
            name.into(),
            serde_json::json!({
                "retained_capacity_bytes": data.allocation_capacity(),
                "peak_accounted_capacity_bytes": data.peak_allocation_capacity(),
            }),
        );
    }
    fs::write(
        output.join("ledger.json"),
        serde_json::to_vec_pretty(&profiles).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires frozen complete assets and independent VCORE_GEODATA_REFERENCE witnesses"]
fn complete_cn_matches_independent_reference_without_memory_quotas() {
    let asset_dir = PathBuf::from(std::env::var_os("VCORE_GEODATA_DIR").expect("asset directory"));
    let reference_dir =
        PathBuf::from(std::env::var_os("VCORE_GEODATA_REFERENCE").expect("reference directory"));
    let reference: serde_json::Value =
        serde_json::from_slice(&fs::read(reference_dir.join("reference.json")).unwrap()).unwrap();
    for name in ["geosite.dat", "geoip.dat"] {
        assert_eq!(
            digest(&asset_dir.join(name)),
            reference["assets"][name].as_str().unwrap(),
            "frozen reference asset identity"
        );
    }
    assert_eq!(
        digest(&reference_dir.join("cases.jsonl")),
        reference["cases_sha256"].as_str().unwrap(),
        "frozen witness identity"
    );
    let data = GeoData::load(
        &asset_dir,
        &[
            rule(RuleKind::GeoSite("cn".into())),
            rule(RuleKind::GeoIp("cn".into())),
        ],
    )
    .unwrap();
    assert!(data.geosite_available("cn") && data.geoip_available("CN"));
    assert!(data.allocation_capacity() <= data.peak_allocation_capacity());
    eprintln!(
        "complete CN ledger: retained={}, peak={}",
        data.allocation_capacity(),
        data.peak_allocation_capacity(),
    );
    let regexes: Vec<_> = (0..reference["regexes"].as_u64().unwrap())
        .map(|index| {
            GeoData::load(
                &reference_dir.join(format!("regex-{index}")),
                &[rule(RuleKind::GeoSite("cn".into()))],
            )
            .unwrap()
        })
        .collect();
    let mut counts = std::collections::BTreeMap::new();
    let mut positives = 0_usize;
    let mut negatives = 0_usize;
    let stream = BufReader::new(fs::File::open(reference_dir.join("cases.jsonl")).unwrap());
    for (number, line) in stream.lines().enumerate() {
        if number != 0 && number % 100_000 == 0 {
            eprintln!("verified {number} independent witnesses");
        }
        let line = line.unwrap();
        assert!(line.len() <= 4096);
        let row: Witness = serde_json::from_str(&line).unwrap();
        let (kind, expected) = match row {
            Witness::Site { id, value, matched } => {
                let domain = context(value).unwrap();
                assert_eq!(
                    data.matches_geosite("cN", domain.domain().unwrap()),
                    matched,
                    "site witness {id}"
                );
                ("site", Some(matched))
            }
            Witness::Ip { id, value, matched } => {
                assert_eq!(
                    data.matches_geoip("CN", value.parse().unwrap()),
                    matched,
                    "IP witness {id}"
                );
                ("ip", Some(matched))
            }
            Witness::Regex {
                index,
                value,
                matched,
            } => {
                let domain = context(value).unwrap();
                assert_eq!(
                    regexes[index].matches_geosite("cn", domain.domain().unwrap()),
                    matched,
                    "regex witness {index}"
                );
                ("regex", Some(matched))
            }
            Witness::Normalize { value, normalized } => {
                let actual = context(value)
                    .ok()
                    .and_then(|c| c.domain().map(str::to_owned));
                assert_eq!(actual, normalized, "normalization witness {number}");
                ("normalize", None)
            }
        };
        *counts.entry(kind).or_insert(0_usize) += 1;
        match expected {
            Some(true) => positives += 1,
            Some(false) => negatives += 1,
            None => {}
        }
    }
    assert!(positives > 0 && negatives > 0);
    assert_eq!(serde_json::to_value(&counts).unwrap(), reference["cases"]);
    let report = serde_json::json!({
        "status": "PASS", "scope": "diagnostic-not-process-peak", "cases": counts,
        "positives": positives, "negatives": negatives,
        "retained_bytes": data.allocation_capacity(), "peak_accounted_capacity_bytes": data.peak_allocation_capacity(),
        "reference": reference,
    });
    fs::write(
        reference_dir.join("verified.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!("{report}");
}
