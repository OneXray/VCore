//! One-shot BLAKE3 key derivation with a byte-string context.

/// Derive a 32-byte key, preserving every byte of the context and key material.
///
/// The caller owns the returned secret and is responsible for erasing it.
pub fn derive_key(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    // SAFETY: both input pointers are valid for their supplied slice lengths,
    // including empty slices. The disjoint output holds exactly 32 bytes. The
    // synchronous C wrapper retains no pointers and exposes no private layout.
    unsafe {
        vole_blake3_raw_derive(
            context.as_ptr(),
            context.len(),
            key_material.as_ptr(),
            key_material.len(),
            output.as_mut_ptr(),
        );
    }
    output
}

unsafe extern "C" {
    fn vole_blake3_raw_derive(
        context: *const u8,
        context_len: usize,
        material: *const u8,
        material_len: usize,
        output: *mut u8,
    );
}
