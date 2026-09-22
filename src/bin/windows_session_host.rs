#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let _ = vcore::windows::session::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vcore-windows-session-host is only available on Windows");
}
