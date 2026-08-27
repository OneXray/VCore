use std::{
    ffi::OsStr,
    fs, io,
    mem::size_of,
    os::windows::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, STILL_ACTIVE},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            },
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess,
                PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess,
                WaitForSingleObject,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

const MAX_PROCESSES: usize = 8;
const MAX_EXECUTABLE_PATH_BYTES: usize = 1_024;
const MAX_ARGUMENTS_PER_PROCESS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4 * 1_024;
const MAX_ARGUMENT_BYTES_PER_PROCESS: usize = 32 * 1_024;
const MAX_BACKEND_ARGUMENT_BYTES: usize = 128 * 1_024;
const MAX_WINDOWS_COMMAND_LINE_CODE_UNITS: usize = 32_767;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionBackend {
    processes: Vec<ManagedProcessSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ManagedProcessSpec {
    executable_relative_path: String,
    arguments: Vec<String>,
}

impl SessionBackend {
    pub(crate) fn validate(&self, install_root: &Path) -> io::Result<()> {
        if self.processes.is_empty() || self.processes.len() > MAX_PROCESSES {
            return Err(invalid_input(
                "invalid Windows session backend process count",
            ));
        }
        let mut backend_argument_bytes = 0usize;
        for process in &self.processes {
            backend_argument_bytes = backend_argument_bytes
                .checked_add(process.validate(install_root)?)
                .ok_or_else(|| invalid_input("Windows session backend arguments exceed limit"))?;
        }
        if backend_argument_bytes > MAX_BACKEND_ARGUMENT_BYTES {
            return Err(invalid_input(
                "Windows session backend arguments exceed limit",
            ));
        }
        Ok(())
    }

    fn processes(&self) -> &[ManagedProcessSpec] {
        &self.processes
    }
}

impl ManagedProcessSpec {
    fn validate(&self, install_root: &Path) -> io::Result<usize> {
        if self.executable_relative_path.is_empty()
            || self.executable_relative_path.len() > MAX_EXECUTABLE_PATH_BYTES
            || self.executable_relative_path.contains('\0')
        {
            return Err(invalid_input("invalid managed process executable path"));
        }
        if self.arguments.len() > MAX_ARGUMENTS_PER_PROCESS {
            return Err(invalid_input("managed process has too many arguments"));
        }
        let mut argument_bytes = 0usize;
        for argument in &self.arguments {
            if argument.len() > MAX_ARGUMENT_BYTES || argument.contains('\0') {
                return Err(invalid_input("invalid managed process argument"));
            }
            argument_bytes = argument_bytes
                .checked_add(argument.len())
                .ok_or_else(|| invalid_input("managed process arguments exceed limit"))?;
        }
        if argument_bytes > MAX_ARGUMENT_BYTES_PER_PROCESS {
            return Err(invalid_input("managed process arguments exceed limit"));
        }
        let executable = resolve_executable(install_root, &self.executable_relative_path)?;
        make_command_line(&executable, &self.arguments)?;
        Ok(argument_bytes)
    }
}

pub(crate) struct ManagedProcessSet {
    job: OwnedHandle,
    processes: Vec<OwnedHandle>,
}

impl ManagedProcessSet {
    pub(crate) fn start(install_root: &Path, backend: &SessionBackend) -> io::Result<Self> {
        backend.validate(install_root)?;
        let job = create_kill_on_close_job()?;
        let mut set = Self {
            job,
            processes: Vec::with_capacity(backend.processes().len()),
        };
        for process in backend.processes() {
            set.processes
                .push(start_process(&set.job, install_root, process)?);
        }
        set.ensure_running()?;
        Ok(set)
    }

    pub(crate) fn ensure_running(&self) -> io::Result<()> {
        if self.processes.iter().all(process_is_running) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "managed Windows session process exited",
            ))
        }
    }

    pub(crate) async fn wait_for_any_exit(&self) -> io::Result<()> {
        // ponytail: eight handles make bounded polling cheaper than a callback/IOCP seam;
        // replace with registered waits only if process count or exit latency changes.
        loop {
            if self
                .processes
                .iter()
                .any(|process| !process_is_running(process))
            {
                return Ok(());
            }
            sleep(PROCESS_POLL_INTERVAL).await;
        }
    }

    pub(crate) async fn terminate_and_wait(&mut self, timeout: Duration) -> io::Result<()> {
        unsafe { TerminateJobObject(self.job.raw(), 1) }.map_err(io::Error::other)?;
        let deadline = Instant::now() + timeout;
        loop {
            if active_processes(self.job.raw())? == 0
                && self
                    .processes
                    .iter()
                    .all(|process| !process_is_running(process))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed Windows session processes did not stop",
                ));
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for ManagedProcessSet {
    fn drop(&mut self) {
        unsafe {
            _ = TerminateJobObject(self.job.raw(), 1);
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_invalid() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            _ = CloseHandle(self.0);
        }
    }
}

fn create_kill_on_close_job() -> io::Result<OwnedHandle> {
    let job = OwnedHandle::new(
        unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(io::Error::other)?,
    )?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .expect("job information size fits u32"),
        )
    }
    .map_err(io::Error::other)?;
    Ok(job)
}

fn start_process(
    job: &OwnedHandle,
    install_root: &Path,
    process: &ManagedProcessSpec,
) -> io::Result<OwnedHandle> {
    let executable = resolve_executable(install_root, &process.executable_relative_path)?;
    let application = nul_terminated(executable.as_os_str())?;
    let current_directory = nul_terminated(install_root.as_os_str())?;
    let mut command_line = make_command_line(&executable, &process.arguments)?;
    let mut startup = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).expect("startup information size fits u32"),
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            PCWSTR(current_directory.as_ptr()),
            &raw mut startup,
            &raw mut information,
        )
    }
    .map_err(io::Error::other)?;

    let child = OwnedHandle::new(information.hProcess)?;
    let primary_thread = OwnedHandle::new(information.hThread)?;
    if let Err(error) = unsafe { AssignProcessToJobObject(job.raw(), child.raw()) } {
        terminate_suspended_process(&child);
        return Err(io::Error::other(error));
    }
    if unsafe { ResumeThread(primary_thread.raw()) } == u32::MAX {
        let error = io::Error::last_os_error();
        terminate_suspended_process(&child);
        return Err(error);
    }
    Ok(child)
}

fn terminate_suspended_process(process: &OwnedHandle) {
    unsafe {
        _ = TerminateProcess(process.raw(), 1);
        _ = WaitForSingleObject(process.raw(), 5_000);
    }
}

fn resolve_executable(install_root: &Path, relative: &str) -> io::Result<PathBuf> {
    if relative.contains('/') {
        return Err(invalid_input("invalid managed process executable path"));
    }
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || !relative_path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(invalid_input("invalid managed process executable path"));
    }

    let mut component_names = Vec::new();
    for component in relative_path.components() {
        let Component::Normal(name) = component else {
            return Err(invalid_input("invalid managed process executable path"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| invalid_input("invalid managed process executable path"))?;
        if name.is_empty() || name.contains([':', '"']) || name.ends_with(['.', ' ']) {
            return Err(invalid_input("invalid managed process executable path"));
        }
        component_names.push(name);
    }
    if component_names.is_empty() || component_names.join("\\") != relative {
        return Err(invalid_input("invalid managed process executable path"));
    }

    validate_directory(install_root)?;
    let mut candidate = install_root.to_path_buf();
    for (index, component) in component_names.iter().enumerate() {
        candidate.push(component);
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|_| invalid_input("managed process executable is unavailable"))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || index + 1 < component_names.len() && !metadata.is_dir()
            || index + 1 == component_names.len() && !metadata.is_file()
        {
            return Err(invalid_input("invalid managed process executable"));
        }
    }
    Ok(candidate)
}

fn validate_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid_input("package installed location is unavailable"))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid_input("invalid package installed location"));
    }
    Ok(())
}

fn make_command_line(executable: &Path, arguments: &[String]) -> io::Result<Vec<u16>> {
    let executable = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    if executable.is_empty() || executable.contains(&0) || executable.contains(&(u16::from(b'"'))) {
        return Err(invalid_input("invalid managed process executable path"));
    }

    let mut command_line = Vec::new();
    command_line.push(u16::from(b'"'));
    command_line.extend(executable);
    command_line.push(u16::from(b'"'));
    for argument in arguments {
        command_line.push(u16::from(b' '));
        append_argument(&mut command_line, argument)?;
    }
    command_line.push(0);
    if command_line.len() >= MAX_WINDOWS_COMMAND_LINE_CODE_UNITS {
        return Err(invalid_input(
            "managed process command line exceeds Windows limit",
        ));
    }
    Ok(command_line)
}

fn append_argument(command_line: &mut Vec<u16>, argument: &str) -> io::Result<()> {
    if argument.contains('\0') {
        return Err(invalid_input("invalid managed process argument"));
    }
    let quoted = argument.is_empty() || argument.contains([' ', '\t']);
    if quoted {
        command_line.push(u16::from(b'"'));
    }

    let mut backslashes = 0usize;
    for unit in argument.encode_utf16() {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if unit == u16::from(b'"') {
                command_line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
            }
            backslashes = 0;
        }
        command_line.push(unit);
    }
    if quoted {
        command_line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        command_line.push(u16::from(b'"'));
    }
    Ok(())
}

fn nul_terminated(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value = value.encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(invalid_input("invalid managed process path"));
    }
    value.push(0);
    Ok(value)
}

fn process_is_running(process: &OwnedHandle) -> bool {
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process.raw(), &raw mut exit_code) }.is_ok()
        && exit_code == STILL_ACTIVE.0 as u32
}

fn active_processes(job: HANDLE) -> io::Result<u32> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            Some(job),
            JobObjectBasicAccountingInformation,
            (&raw mut accounting).cast(),
            u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
                .expect("job accounting size fits u32"),
            None,
        )
    }
    .map_err(io::Error::other)?;
    Ok(accounting.ActiveProcesses)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _, slice};

    use windows::Win32::{
        Foundation::{HLOCAL, LocalFree},
        UI::Shell::CommandLineToArgvW,
    };

    use super::*;

    #[test]
    fn windows_command_line_round_trips_logical_arguments() {
        let executable = Path::new(r"C:\Program Files\VCore\proxy.exe");
        let arguments = vec![
            String::new(),
            "plain".to_owned(),
            "two words".to_owned(),
            r#"a\"b"#.to_owned(),
            r"ends with \".to_owned(),
            "参数".to_owned(),
        ];
        let command_line = make_command_line(executable, &arguments).unwrap();
        let actual = parse_command_line(&command_line);
        let expected = std::iter::once(executable.as_os_str().to_owned())
            .chain(arguments.iter().map(OsString::from))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn backend_validates_multiple_package_local_processes() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        fs::write(root.path().join("bin/proxy.exe"), b"fixture").unwrap();
        let backend = SessionBackend {
            processes: vec![
                ManagedProcessSpec {
                    executable_relative_path: r"bin\proxy.exe".to_owned(),
                    arguments: vec!["run".to_owned()],
                },
                ManagedProcessSpec {
                    executable_relative_path: r"bin\proxy.exe".to_owned(),
                    arguments: vec!["--helper".to_owned()],
                },
            ],
        };
        backend.validate(root.path()).unwrap();

        for path in [r"..\proxy.exe", r"bin/proxy.exe", r"bin\proxy.dll"] {
            let invalid = SessionBackend {
                processes: vec![ManagedProcessSpec {
                    executable_relative_path: path.to_owned(),
                    arguments: vec![],
                }],
            };
            assert!(invalid.validate(root.path()).is_err(), "accepted {path}");
        }
        assert!(
            SessionBackend { processes: vec![] }
                .validate(root.path())
                .is_err()
        );
        assert!(
            SessionBackend {
                processes: (0..=MAX_PROCESSES)
                    .map(|_| ManagedProcessSpec {
                        executable_relative_path: r"bin\proxy.exe".to_owned(),
                        arguments: vec![],
                    })
                    .collect(),
            }
            .validate(root.path())
            .is_err()
        );
    }

    #[test]
    fn job_owns_and_terminates_multiple_processes() {
        let executable = std::env::current_exe().unwrap();
        let install_root = executable.parent().unwrap();
        let relative = executable
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let arguments = vec![
            "--exact".to_owned(),
            "windows_managed_processes::tests::managed_process_fixture_waits".to_owned(),
            "--ignored".to_owned(),
            "--quiet".to_owned(),
        ];
        let backend = SessionBackend {
            processes: (0..2)
                .map(|_| ManagedProcessSpec {
                    executable_relative_path: relative.clone(),
                    arguments: arguments.clone(),
                })
                .collect(),
        };
        let mut processes = ManagedProcessSet::start(install_root, &backend).unwrap();
        processes.ensure_running().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(processes.terminate_and_wait(Duration::from_secs(5)))
            .unwrap();
    }

    #[test]
    fn job_observes_a_managed_process_exit() {
        let executable = std::env::current_exe().unwrap();
        let install_root = executable.parent().unwrap();
        let backend = SessionBackend {
            processes: vec![ManagedProcessSpec {
                executable_relative_path: executable
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                arguments: vec![
                    "--exact".to_owned(),
                    "windows_managed_processes::tests::managed_process_fixture_exits".to_owned(),
                    "--ignored".to_owned(),
                    "--quiet".to_owned(),
                ],
            }],
        };
        let mut processes = ManagedProcessSet::start(install_root, &backend).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), processes.wait_for_any_exit())
                    .await
                    .unwrap()
                    .unwrap();
                processes
                    .terminate_and_wait(Duration::from_secs(5))
                    .await
                    .unwrap();
            });
    }

    #[test]
    #[ignore = "managed process fixture"]
    fn managed_process_fixture_waits() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "managed process fixture"]
    fn managed_process_fixture_exits() {
        std::thread::sleep(Duration::from_millis(250));
    }

    fn parse_command_line(command_line: &[u16]) -> Vec<OsString> {
        let mut count = 0i32;
        let pointers = unsafe { CommandLineToArgvW(PCWSTR(command_line.as_ptr()), &raw mut count) };
        assert!(!pointers.is_null());
        let values = unsafe { slice::from_raw_parts(pointers, usize::try_from(count).unwrap()) }
            .iter()
            .map(|pointer| {
                let mut length = 0usize;
                while unsafe { *pointer.0.add(length) } != 0 {
                    length += 1;
                }
                OsString::from_wide(unsafe { slice::from_raw_parts(pointer.0, length) })
            })
            .collect();
        unsafe {
            _ = LocalFree(Some(HLOCAL(pointers.cast())));
        }
        values
    }
}
