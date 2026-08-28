use std::{
    fs::OpenOptions,
    io::Write as _,
    path::Path,
    sync::{Mutex, PoisonError},
};

const MAX_LOG_BYTES: u64 = 1024 * 1024;
static LOG_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn append(local_folder: &Path, name: &str, message: &str) {
    let _guard = LOG_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let directory = local_folder.join("logs");
    if std::fs::create_dir_all(&directory).is_err() {
        return;
    }
    let current = directory.join(format!("windows-vpn-{name}.log"));
    if current
        .metadata()
        .is_ok_and(|metadata| metadata.len() >= MAX_LOG_BYTES)
    {
        let previous = directory.join(format!("windows-vpn-{name}.previous.log"));
        _ = std::fs::remove_file(&previous);
        if std::fs::rename(&current, previous).is_err() {
            _ = OpenOptions::new().write(true).truncate(true).open(&current);
        }
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(current) {
        _ = writeln!(file, "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_lock_does_not_disable_logging() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                let _guard = LOG_LOCK.lock().unwrap();
                panic!("poison test log lock");
            })
            .is_err()
        );

        append(root.path(), "session", "after panic");
        LOG_LOCK.clear_poison();

        assert_eq!(
            std::fs::read_to_string(root.path().join("logs/windows-vpn-session.log")).unwrap(),
            "after panic\n"
        );
    }

    #[test]
    fn process_log_rotates_at_its_bound() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("logs");
        std::fs::create_dir_all(&directory).unwrap();
        let current = directory.join("windows-vpn-session.log");
        std::fs::write(&current, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();

        append(root.path(), "session", "next session");

        assert_eq!(std::fs::read_to_string(&current).unwrap(), "next session\n");
        assert_eq!(
            std::fs::metadata(directory.join("windows-vpn-session.previous.log"))
                .unwrap()
                .len(),
            MAX_LOG_BYTES
        );
    }
}
