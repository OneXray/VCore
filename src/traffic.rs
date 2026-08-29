use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

const TRAFFIC_RATE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PUBLIC_TRAFFIC_BYTES: u64 = i64::MAX as u64;

/// A mihomo-compatible traffic snapshot.
///
/// `up` and `down` contain the number of raw-IP bytes observed in the most
/// recently completed one-second bucket. The totals are cumulative for this
/// TUN runtime. Upload is host-to-TUN-core traffic and download is
/// TUN-core-to-host traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrafficSnapshot {
    pub(crate) up: u64,
    pub(crate) down: u64,
    pub(crate) up_total: u64,
    pub(crate) down_total: u64,
}

/// Lock-free counters shared by the TUN I/O loops and read-only API surfaces.
#[derive(Debug, Default)]
pub(crate) struct TunTrafficStats {
    up_pending: AtomicU64,
    down_pending: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    up_total: AtomicU64,
    down_total: AtomicU64,
}

impl TunTrafficStats {
    pub(crate) fn record_up(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        saturating_add(&self.up_pending, bytes);
        saturating_add(&self.up_total, bytes);
    }

    pub(crate) fn record_down(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        saturating_add(&self.down_pending, bytes);
        saturating_add(&self.down_total, bytes);
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up: self.up.load(Ordering::Relaxed),
            down: self.down.load(Ordering::Relaxed),
            up_total: self.up_total.load(Ordering::Relaxed),
            down_total: self.down_total.load(Ordering::Relaxed),
        }
    }

    fn rotate_rate_bucket(&self) {
        self.up.store(
            self.up_pending.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.down.store(
            self.down_pending.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    pub(crate) async fn run_rate_clock(
        self: Arc<Self>,
        cancellation: CancellationToken,
    ) -> io::Result<()> {
        let mut rate_clock = interval_at(
            Instant::now() + TRAFFIC_RATE_INTERVAL,
            TRAFFIC_RATE_INTERVAL,
        );
        rate_clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(()),
                _ = rate_clock.tick() => self.rotate_rate_bucket(),
            }
        }
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value).min(MAX_PUBLIC_TRAFFIC_BYTES))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_rotate_without_resetting_totals() {
        let stats = TunTrafficStats::default();
        stats.record_up(12);
        stats.record_down(34);
        assert_eq!(
            stats.snapshot(),
            TrafficSnapshot {
                up: 0,
                down: 0,
                up_total: 12,
                down_total: 34,
            }
        );

        stats.rotate_rate_bucket();
        assert_eq!(
            stats.snapshot(),
            TrafficSnapshot {
                up: 12,
                down: 34,
                up_total: 12,
                down_total: 34,
            }
        );
        stats.rotate_rate_bucket();
        assert_eq!(
            stats.snapshot(),
            TrafficSnapshot {
                up: 0,
                down: 0,
                up_total: 12,
                down_total: 34,
            }
        );
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let stats = TunTrafficStats::default();
        stats
            .up_total
            .store(MAX_PUBLIC_TRAFFIC_BYTES - 1, Ordering::Relaxed);
        stats.record_up(8);
        assert_eq!(stats.snapshot().up_total, MAX_PUBLIC_TRAFFIC_BYTES);
    }
}
