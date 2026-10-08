#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let _ = vole::windows::session::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vole-windows-session-host is only available on Windows");
}
