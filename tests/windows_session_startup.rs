#![cfg(all(windows, feature = "ffi"))]

use std::{
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    ptr, thread,
    time::{Duration, Instant},
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentPackageFullName(length: *mut u32, name: *mut u16) -> i32;
    fn SetErrorMode(mode: u32) -> u32;
}

#[test]
fn unpackaged_session_host_exits_without_crashing() {
    let mut length = 0;
    // Do not activate a packaged session or touch package-local runtime data.
    assert_eq!(
        unsafe { GetCurrentPackageFullName(&mut length, ptr::null_mut()) },
        15700,
        "this test requires an unpackaged process"
    );

    // Child processes inherit this mode; suppress loader and crash dialogs.
    let previous = unsafe { SetErrorMode(0x8003) };
    let spawned = Command::new(env!("CARGO_BIN_EXE_vcore-windows-session-host"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn();
    unsafe { SetErrorMode(previous) };
    let mut child = spawned.expect("start the session host");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("read session host status") {
            assert!(
                status.success(),
                "unpackaged startup must exit cleanly: {status}"
            );
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("terminate the timed-out test process");
            child.wait().expect("reap the timed-out test process");
            panic!("unpackaged startup must not wait for a VPN session");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
