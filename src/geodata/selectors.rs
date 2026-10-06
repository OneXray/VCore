//! Configuration-owned GeoData selectors; asset category codes stay separate.

use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};

use super::{Code, GeoDataError, GeoDataKind};

/// Canonicalizes the Mihomo `!code@attribute@attribute` selector subset.
/// Attribute order and duplicates do not change its set-intersection meaning.
pub(crate) fn normalize_selector(kind: GeoDataKind, raw: &str) -> Result<String, GeoDataError> {
    let (reversed, positive) = raw
        .strip_prefix('!')
        .map_or((false, raw), |raw| (true, raw));
    let mut parts = positive.split('@');
    let code = Code::parse(kind, parts.next().unwrap_or_default().as_bytes())?;
    let mut attributes = Vec::new();
    for attribute in parts {
        if kind == GeoDataKind::GeoIp {
            return Err(GeoDataError::InvalidCode {
                kind,
                code: raw.to_owned(),
            });
        }
        let attribute = attribute.trim();
        if attribute.is_empty() {
            continue;
        }
        if attribute
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '@' | ','))
        {
            return Err(GeoDataError::InvalidCode {
                kind,
                code: raw.to_owned(),
            });
        }
        // Mihomo lowercases the selector first, then compares the DAT key
        // with Unicode simple folding. Go's lowercase is one scalar (not
        // Rust's full lowercase expansion, notably for U+0130).
        let lowered: String = attribute
            .chars()
            .map(|ch| {
                ch.to_lowercase()
                    .next()
                    .expect("non-empty lowercase mapping")
            })
            .collect();
        attributes.push(fold_attribute(&lowered));
    }
    attributes.sort_unstable();
    attributes.dedup();
    let mut normalized = String::new();
    if reversed {
        normalized.push('!');
    }
    normalized.push_str(code.as_str());
    for attribute in attributes {
        normalized.push('@');
        normalized.push_str(&attribute);
    }
    Ok(normalized)
}

/// Uses the dependency's official Unicode simple-fold tables, not lowercase
/// expansion: e.g. final sigma and sigma are equivalent, but dotted capital I
/// is not a simple-fold alias of ASCII i. ASCII canonical keys stay lowercase.
pub(super) fn fold_attribute(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii() && !matches!(ch, 'k' | 'K' | 's' | 'S') {
                return ch.to_ascii_lowercase();
            }
            let mut class = ClassUnicode::new([ClassUnicodeRange::new(ch, ch)]);
            class.case_fold_simple();
            let representative = class.iter().next().expect("non-empty fold class").start();
            representative.to_ascii_lowercase()
        })
        .collect()
}

pub(super) fn positive_selector(raw: &str) -> &str {
    raw.strip_prefix('!').unwrap_or(raw)
}

pub(super) fn selector_code(raw: &str) -> &str {
    positive_selector(raw).split('@').next().unwrap_or_default()
}

pub(super) fn selector_attributes(raw: &str) -> &str {
    positive_selector(raw)
        .split_once('@')
        .map_or("", |(_, attributes)| attributes)
}
