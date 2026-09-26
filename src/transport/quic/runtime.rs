//! Shared ownership of Quinn background work; accepts protected IO only.
use crate::resources::observation::{self, ResourceKind};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Quinn's runtime hook makes its internal tasks part of the same stop barrier.
#[derive(Debug)]
pub(crate) struct OwnedRuntime {
    admission: Mutex<()>,
    pub cancel: CancellationToken,
    tasks: TaskTracker,
}
impl OwnedRuntime {
    pub(crate) fn new(cancel: CancellationToken) -> Self {
        Self {
            admission: Mutex::new(()),
            cancel,
            tasks: TaskTracker::new(),
        }
    }
    pub fn spawn_owned(&self, future: impl Future<Output = ()> + Send + 'static) -> io::Result<()> {
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let cancel = self.cancel.clone();
        let observation = observation::track(ResourceKind::Task);
        self.tasks.spawn(observation::bind(async move {
            let _observation = observation;
            tokio::select! {biased; ()=cancel.cancelled()=>{}, ()=future=>{}}
        }));
        Ok(())
    }
    pub(crate) async fn stop(&self) {
        {
            let _admission = self.admission.lock().unwrap();
            self.cancel.cancel();
            self.tasks.close();
        }
        self.tasks.wait().await;
    }
}
impl quinn::Runtime for OwnedRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let _ = self.spawn_owned(future);
    }
    fn wrap_udp_socket(
        &self,
        _: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "QUIC accepts controlled datagram IO only",
        ))
    }
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
