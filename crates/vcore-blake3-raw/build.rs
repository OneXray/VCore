fn main() {
    let mut build = cc::Build::new();
    build
        .include("vendor")
        .file("src/derive.c")
        .file("vendor/blake3.c")
        .file("vendor/blake3_dispatch.c")
        .file("vendor/blake3_portable.c")
        .std("c11")
        .define("BLAKE3_NO_SSE2", None)
        .define("BLAKE3_NO_SSE41", None)
        .define("BLAKE3_NO_AVX2", None)
        .define("BLAKE3_NO_AVX512", None)
        .define("BLAKE3_USE_NEON", "0")
        .define("BLAKE3_API", "")
        .define("BLAKE3_PRIVATE", "")
        .flag_if_supported("-fvisibility=hidden");

    // Prefix at compilation, never by modifying the vendored official source.
    // The regular Rust blake3 crate can link into the same final executable.
    for symbol in [
        "blake3_version",
        "blake3_hasher_init",
        "blake3_hasher_init_keyed",
        "blake3_hasher_init_derive_key",
        "blake3_hasher_init_derive_key_raw",
        "blake3_hasher_update",
        "blake3_hasher_finalize",
        "blake3_hasher_finalize_seek",
        "blake3_hasher_reset",
        "blake3_compress_subtree_wide",
        "blake3_compress_in_place",
        "blake3_compress_xof",
        "blake3_xof_many",
        "blake3_hash_many",
        "blake3_simd_degree",
        "blake3_compress_in_place_portable",
        "blake3_compress_xof_portable",
        "blake3_hash_many_portable",
    ] {
        build.define(symbol, format!("vcore_raw_{symbol}").as_str());
    }
    build.compile("vcore_blake3_raw");
    println!("cargo:rerun-if-changed=src/derive.c");
    println!("cargo:rerun-if-changed=vendor");
}
