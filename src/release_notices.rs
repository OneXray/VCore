//! Internal release retention anchor shared by executable and native transports.

#[used]
static NOTICES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vole-release-notices.txt"));

/// Keep the audited release text in the linked artifact without adding an ABI,
/// process argument, filesystem asset, or runtime output.
#[inline(never)]
pub fn retain() {
    std::hint::black_box(NOTICES);
    std::hint::black_box(crate::BUILD_IDENTITY);
}
