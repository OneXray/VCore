#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    if let Err(error) = vcore::windows_session::run() {
        vcore::windows_session::log_startup_failure(&error);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vcore-windows-session-host is only available on Windows");
}
