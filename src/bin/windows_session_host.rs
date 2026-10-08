#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    vole::release_notices::retain();
    let _ = vole::windows::session::run();
}

#[cfg(not(windows))]
fn main() {
    vole::release_notices::retain();
    eprintln!("vole-windows-session-host is only available on Windows");
}
