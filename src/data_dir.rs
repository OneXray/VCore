//! Stable Core-owned filesystem layout.
//!
//! Platform hosts select one writable root. VCore owns the layout below that
//! root and never infers a process role or platform-specific container.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub const CONFIGS_DIR_NAME: &str = "configs";
pub const GEODATA_DIR_NAME: &str = "geodata";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirectory {
    root: PathBuf,
    configs: PathBuf,
    geodata: PathBuf,
}

impl DataDirectory {
    /// Creates and canonicalizes the fixed VCore directory layout.
    pub fn initialize(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dataDir must be an absolute path",
            ));
        }
        fs::create_dir_all(path)?;
        let root = fs::canonicalize(path)?;
        ensure_directory(&root, "dataDir")?;

        let configs = initialize_child(&root, CONFIGS_DIR_NAME)?;
        let geodata = initialize_child(&root, GEODATA_DIR_NAME)?;
        Ok(Self {
            root,
            configs,
            geodata,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn configs(&self) -> &Path {
        &self.configs
    }

    #[must_use]
    pub fn geodata(&self) -> &Path {
        &self.geodata
    }

    /// Resolves a caller-supplied configuration path and ensures the target
    /// remains inside the fixed `configs/` subtree.
    pub fn canonical_config(&self, path: &Path) -> io::Result<PathBuf> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configPath must be an absolute path",
            ));
        }
        let canonical = fs::canonicalize(path)?;
        if !canonical.starts_with(&self.configs) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configPath must resolve inside dataDir/configs",
            ));
        }
        let metadata = fs::metadata(&canonical)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configPath must resolve to a regular file",
            ));
        }
        Ok(canonical)
    }
}

fn initialize_child(root: &Path, name: &str) -> io::Result<PathBuf> {
    let requested = root.join(name);
    fs::create_dir_all(&requested)?;
    let canonical = fs::canonicalize(&requested)?;
    if !canonical.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("dataDir/{name} resolves outside dataDir"),
        ));
    }
    ensure_directory(&canonical, name)?;
    Ok(canonical)
}

fn ensure_directory(path: &Path, label: &str) -> io::Result<()> {
    if fs::metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is not a directory"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn initializes_fixed_layout_and_accepts_nested_config() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("vcore");
        let data = DataDirectory::initialize(&root).unwrap();
        assert_eq!(data.root(), fs::canonicalize(root).unwrap());
        assert!(data.configs().is_dir());
        assert!(data.geodata().is_dir());

        let generation = data.configs().join(".generation-1");
        fs::create_dir(&generation).unwrap();
        let config = generation.join("vcore.yaml");
        fs::write(&config, "proxies: []\n").unwrap();
        assert_eq!(
            data.canonical_config(&config).unwrap(),
            fs::canonicalize(config).unwrap()
        );
    }

    #[test]
    fn rejects_relative_root_and_config_outside_configs() {
        assert!(DataDirectory::initialize(Path::new("relative")).is_err());

        let temporary = tempdir().unwrap();
        let data = DataDirectory::initialize(&temporary.path().join("vcore")).unwrap();
        let outside = temporary.path().join("outside.yaml");
        fs::write(&outside, "proxies: []\n").unwrap();
        let error = data.canonical_config(&outside).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_config_symlink_that_escapes_configs() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        let data = DataDirectory::initialize(&temporary.path().join("vcore")).unwrap();
        let outside = temporary.path().join("outside.yaml");
        fs::write(&outside, "proxies: []\n").unwrap();
        let link = data.configs().join("current.yaml");
        symlink(&outside, &link).unwrap();
        assert_eq!(
            data.canonical_config(&link).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
