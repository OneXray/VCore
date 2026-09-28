//! Structured opt-in evidence from assertion-bearing Rust tests. Human test
//! output is not a coverage source. Missing/partial events cannot become PASS.
use super::observation::ResourceSnapshot;
use std::{fs::OpenOptions, io::Write, path::PathBuf, sync::Mutex, time::Instant};

static WRITE_LOCK: Mutex<()> = Mutex::new(());

pub struct Case {
    suite: &'static str,
    assertion: &'static str,
    started: Instant,
    path: Option<PathBuf>,
    resources: Option<ResourceSnapshot>,
    checkpoints: Vec<(&'static str, ResourceSnapshot)>,
}
impl Case {
    pub fn new(suite: &'static str, assertion: &'static str) -> Self {
        let case = Self {
            suite,
            assertion,
            started: Instant::now(),
            path: std::env::var_os("VCORE_CASE_EVENTS").map(PathBuf::from),
            resources: None,
            checkpoints: Vec::new(),
        };
        case.emit("BEGIN");
        case
    }
    pub fn resources(&mut self, snapshot: ResourceSnapshot) {
        self.resources = Some(snapshot);
    }
    pub fn checkpoint(&mut self, phase: &'static str, snapshot: ResourceSnapshot) {
        self.checkpoints.push((phase, snapshot));
    }
    fn emit(&self, status: &str) {
        let Some(path) = &self.path else {
            return;
        };
        let checkpoints: Vec<_> = self
            .checkpoints
            .iter()
            .map(|(phase, snapshot)| serde_json::json!({"phase":phase,"resources":snapshot}))
            .collect();
        let event = serde_json::json!({"schema_version":1,"suite":self.suite,"assertion":self.assertion,"status":status,"seconds":self.started.elapsed().as_secs_f64(),"resources":self.resources,"checkpoints":checkpoints});
        let _lock = WRITE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(file, "{event}")?;
            file.flush()
        })();
        if result.is_err() && !std::thread::panicking() {
            panic!("cannot persist structured case evidence");
        }
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        self.emit(
            if std::thread::panicking()
                || self
                    .resources
                    .as_ref()
                    .is_some_and(|snapshot| !snapshot.is_idle())
            {
                "FAIL"
            } else {
                "PASS"
            },
        );
    }
}
