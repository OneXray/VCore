use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::windows::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest as _, Sha256};
use windows::{
    Win32::Foundation::E_FAIL,
    core::{Error, Result},
};

pub(crate) const SNAPSHOT_DIRECTORY: &str = "vcore/windows/snapshots";
const SNAPSHOT_TOKEN_PREFIX: &str = "vcore-v1:";
const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
static STAGING_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SnapshotReference {
    digest: String,
}

impl SnapshotReference {
    pub(crate) fn parse(token: &str) -> Result<Self> {
        let digest = token
            .strip_prefix(SNAPSHOT_TOKEN_PREFIX)
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| Error::new(E_FAIL, "invalid Windows tunnel snapshot token"))?;
        Ok(Self {
            digest: digest.to_owned(),
        })
    }

    pub(crate) fn publish(local_folder: &Path, yaml: &[u8]) -> Result<Self> {
        if yaml.is_empty() || yaml.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(Error::new(E_FAIL, "invalid Windows tunnel snapshot size"));
        }
        let reference = Self {
            digest: snapshot_digest(yaml),
        };
        let snapshots = snapshot_directory(local_folder, true)?;
        let target = snapshots.join(reference.file_name());
        if target.exists() {
            reference.verify_file(&target)?;
            return Ok(reference);
        }

        let staging = snapshots.join(format!(
            "staging-{}-{}",
            std::process::id(),
            STAGING_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(windows_error)?;
            file.write_all(yaml).map_err(windows_error)?;
            file.sync_all().map_err(windows_error)?;
            drop(file);
            match fs::rename(&staging, &target) {
                Ok(()) => Ok(()),
                Err(_) if target.exists() => reference.verify_file(&target),
                Err(error) => Err(windows_error(error)),
            }
        })();
        _ = fs::remove_file(staging);
        result?;
        reference.verify_file(&target)?;
        Ok(reference)
    }

    pub(crate) fn token(&self) -> String {
        format!("{SNAPSHOT_TOKEN_PREFIX}{}", self.digest)
    }

    pub(crate) fn file_name(&self) -> String {
        format!("{}.yaml", self.digest)
    }

    pub(crate) fn read_yaml(&self, local_folder: &Path) -> Result<Vec<u8>> {
        let path = snapshot_directory(local_folder, false)?.join(self.file_name());
        self.verify_file(&path)?;
        fs::read(path).map_err(windows_error)
    }

    pub(crate) fn prune(
        &self,
        local_folder: &Path,
        previous: Option<&SnapshotReference>,
    ) -> Result<()> {
        let snapshots = snapshot_directory(local_folder, false)?;
        let retained = [Some(self.file_name()), previous.map(Self::file_name)];
        for entry in fs::read_dir(snapshots).map_err(windows_error)? {
            let entry = entry.map_err(windows_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if retained.iter().flatten().any(|retained| retained == &name) {
                continue;
            }
            if name.starts_with("staging-") || is_snapshot_file_name(&name) {
                _ = fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    fn verify_file(&self, path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(windows_error)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() == 0
            || metadata.len() > MAX_SNAPSHOT_BYTES
        {
            return Err(Error::new(E_FAIL, "invalid Windows tunnel snapshot file"));
        }
        let yaml = fs::read(path).map_err(windows_error)?;
        if snapshot_digest(&yaml) != self.digest {
            return Err(Error::new(
                E_FAIL,
                "Windows tunnel snapshot digest mismatch",
            ));
        }
        Ok(())
    }
}

fn snapshot_directory(local_folder: &Path, create: bool) -> Result<PathBuf> {
    let snapshots = local_folder.join(SNAPSHOT_DIRECTORY);
    if create {
        fs::create_dir_all(&snapshots).map_err(windows_error)?;
    }
    for path in [
        local_folder.join("vcore"),
        local_folder.join("vcore/windows"),
        snapshots.clone(),
    ] {
        reject_reparse_point(&path)?;
    }
    Ok(snapshots)
}

fn reject_reparse_point(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(windows_error)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::new(
            E_FAIL,
            "invalid Windows tunnel snapshot directory",
        ));
    }
    Ok(())
}

fn is_snapshot_file_name(name: &str) -> bool {
    name.len() == 69
        && name.ends_with(".yaml")
        && name[..64]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn snapshot_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn windows_error(error: impl std::fmt::Display) -> Error {
    Error::new(E_FAIL, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_accepts_only_the_canonical_versioned_digest() {
        let digest = "0123456789abcdef".repeat(4);
        let reference = SnapshotReference::parse(&format!("vcore-v1:{digest}")).unwrap();
        assert_eq!(reference.file_name(), format!("{digest}.yaml"));

        for token in [
            digest.clone(),
            format!("vcore-v2:{digest}"),
            format!("vcore-v1:{}", digest.to_uppercase()),
            "vcore-v1:../vcore.yaml".to_owned(),
            "vcore-v1:00".to_owned(),
        ] {
            assert!(
                SnapshotReference::parse(&token).is_err(),
                "accepted {token}"
            );
        }
    }

    #[test]
    fn publication_and_read_verify_the_content_digest() {
        let root = tempfile::tempdir().unwrap();
        let yaml =
            b"proxies:\n  - name: unused\n    type: socks5\n    server: 127.0.0.1\n    port: 9\n";
        let reference = SnapshotReference::publish(root.path(), yaml).unwrap();
        assert_eq!(reference.read_yaml(root.path()).unwrap(), yaml);

        fs::write(
            root.path()
                .join(SNAPSHOT_DIRECTORY)
                .join(reference.file_name()),
            b"changed",
        )
        .unwrap();
        assert!(reference.read_yaml(root.path()).is_err());
    }

    #[test]
    fn cleanup_retains_current_and_previous_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let first = SnapshotReference::publish(root.path(), b"first").unwrap();
        let second = SnapshotReference::publish(root.path(), b"second").unwrap();
        let third = SnapshotReference::publish(root.path(), b"third").unwrap();
        fs::write(
            root.path().join(SNAPSHOT_DIRECTORY).join("staging-old"),
            b"x",
        )
        .unwrap();

        third.prune(root.path(), Some(&second)).unwrap();
        let snapshots = root.path().join(SNAPSHOT_DIRECTORY);
        assert!(!snapshots.join(first.file_name()).exists());
        assert!(snapshots.join(second.file_name()).exists());
        assert!(snapshots.join(third.file_name()).exists());
        assert!(!snapshots.join("staging-old").exists());
    }
}
