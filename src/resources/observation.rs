//! Test-only per-run RAII counters. No global allocator, admission limit or
//! process-global reset; concurrent tests use independent scopes.
use std::{
    future::Future,
    io,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Task,
    Socket,
    Session,
    Association,
    Reassembly,
    Pool,
    Waiter,
    Handshake,
}
impl ResourceKind {
    pub const ALL: [Self; 8] = [
        Self::Task,
        Self::Socket,
        Self::Session,
        Self::Association,
        Self::Reassembly,
        Self::Pool,
        Self::Waiter,
        Self::Handshake,
    ];
}

#[cfg(any(test, feature = "interop-test"))]
mod enabled {
    use super::*;
    use crate::resources::ActivityStats;
    use std::sync::{Arc, atomic::Ordering};

    tokio::task_local! { static ACTIVE: ResourceProbe; }

    #[derive(Debug, Clone)]
    pub struct ResourceProbe {
        counters: Arc<[ActivityStats; 8]>,
    }
    impl Default for ResourceProbe {
        fn default() -> Self {
            Self {
                counters: Arc::new(std::array::from_fn(|_| ActivityStats::default())),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
    pub struct ResourceCount {
        pub kind: ResourceKind,
        pub current: usize,
        pub peak: usize,
    }
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct ResourceSnapshot {
        pub counts: [ResourceCount; 8],
    }
    impl ResourceSnapshot {
        pub fn current(&self, kind: ResourceKind) -> usize {
            self.counts[kind as usize].current
        }
        pub fn peak(&self, kind: ResourceKind) -> usize {
            self.counts[kind as usize].peak
        }
        pub fn is_idle(&self) -> bool {
            self.counts.iter().all(|count| count.current == 0)
        }
    }
    impl ResourceProbe {
        pub async fn scope<F: Future>(&self, future: F) -> F::Output {
            ACTIVE.scope(self.clone(), future).await
        }
        pub fn snapshot(&self) -> ResourceSnapshot {
            ResourceSnapshot {
                counts: std::array::from_fn(|i| ResourceCount {
                    kind: ResourceKind::ALL[i],
                    current: self.counters[i].current.load(Ordering::Acquire),
                    peak: self.counters[i].peak.load(Ordering::Relaxed),
                }),
            }
        }
    }
    #[derive(Debug)]
    pub struct Guard {
        probe: Option<ResourceProbe>,
        kind: ResourceKind,
    }
    pub fn track(kind: ResourceKind) -> Guard {
        let probe = ACTIVE.try_with(Clone::clone).ok();
        if let Some(probe) = &probe {
            let count = &probe.counters[kind as usize];
            let current = count.current.fetch_add(1, Ordering::AcqRel) + 1;
            count.peak.fetch_max(current, Ordering::Relaxed);
        }
        Guard { probe, kind }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(probe) = &self.probe {
                probe.counters[self.kind as usize]
                    .current
                    .fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
    pub fn bind<F: Future>(future: F) -> impl Future<Output = F::Output> {
        let probe = ACTIVE.try_with(Clone::clone).ok();
        async move {
            if let Some(probe) = probe {
                probe.scope(future).await
            } else {
                future.await
            }
        }
    }
}

#[cfg(any(test, feature = "interop-test"))]
pub(crate) use enabled::{Guard, bind, track};
#[cfg(any(test, feature = "interop-test"))]
pub use enabled::{ResourceCount, ResourceProbe, ResourceSnapshot};

#[cfg(not(any(test, feature = "interop-test")))]
#[derive(Debug)]
pub(crate) struct Guard;
#[cfg(not(any(test, feature = "interop-test")))]
pub(crate) fn track(_: ResourceKind) -> Guard {
    Guard
}
#[cfg(not(any(test, feature = "interop-test")))]
pub(crate) fn bind<F: Future>(future: F) -> F {
    future
}

pub(crate) fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let guard = track(ResourceKind::Task);
    tokio::spawn(bind(async move {
        let _guard = guard;
        future.await
    }))
}

/// IO plus a test-only lifetime guard. In release builds the guard is a ZST;
/// it adds no allocation, shared counter or admission behavior.
#[derive(Debug)]
pub struct ObservedIo<T> {
    inner: T,
    _guard: Guard,
}
impl<T> ObservedIo<T> {
    pub(crate) fn with_guard(inner: T, guard: Guard) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
    pub(crate) fn new(inner: T, kind: ResourceKind) -> Self {
        Self::with_guard(inner, track(kind))
    }
}
impl<T> Deref for ObservedIo<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, buffers)
    }
}
