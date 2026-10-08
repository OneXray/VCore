use std::{env, fs, path::PathBuf};

const MAX_NOTICES_BYTES: usize = 16 * 1024 * 1024;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=VOLE_RELEASE_NOTICES");
    if env::var_os("CARGO_FEATURE_CLI").is_none() && env::var_os("CARGO_FEATURE_FFI").is_none() {
        return;
    }

    // Release packaging supplies the notices from the resolved target graph.
    // Ordinary development builds need no generated input or extra interface.
    let notices = match env::var_os("VOLE_RELEASE_NOTICES") {
        None => Vec::new(),
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let content = fs::read(path).expect("cannot read release notices");
            assert!(
                !content.is_empty() && content.len() <= MAX_NOTICES_BYTES,
                "release notices must contain at most 16 MiB of text"
            );
            assert!(
                std::str::from_utf8(&content).is_ok() && !content.contains(&0),
                "release notices must be UTF-8 text without NUL bytes"
            );
            let mut embedded = b"VOLE_RELEASE_NOTICES_BEGIN\n".to_vec();
            embedded.extend_from_slice(&content);
            embedded.extend_from_slice(b"\nVOLE_RELEASE_NOTICES_END\n");
            embedded
        }
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory unavailable"));
    fs::write(output.join("vole-release-notices.txt"), notices)
        .expect("cannot write embedded release notices");
}
