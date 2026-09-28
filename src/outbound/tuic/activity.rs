//! Retired physical sessions outlive their existing logical owners, not forever.
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Activity {
    state: Mutex<State>,
    changed: Notify,
}
#[derive(Default)]
struct State {
    active: usize,
    retired: bool,
}
pub(super) struct Lease(Arc<Activity>);
impl Activity {
    pub fn acquire(self: &Arc<Self>) -> Lease {
        self.state.lock().unwrap().active += 1;
        Lease(self.clone())
    }
    pub fn retire(&self) {
        self.state.lock().unwrap().retired = true;
        self.changed.notify_one();
    }
    pub async fn retired_and_idle(&self) {
        loop {
            let notified = self.changed.notified();
            {
                let state = self.state.lock().unwrap();
                if state.retired && state.active == 0 {
                    return;
                }
            }
            notified.await;
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
        self.0.changed.notify_one();
    }
}
