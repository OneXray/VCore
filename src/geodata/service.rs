//! Long-lived GeoData update scheduling.
//!
//! The service is attached to a running instance, but the manager and its
//! cross-process lock own the shared resource state. Network traffic is sent
//! only through the raw configured default-proxy dispatcher supplied by the
//! runtime.

use std::{
    io,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio_util::sync::CancellationToken;

use super::{
    GeoDataKind, GeoDataManager, GeoDataManagerError,
    manager::GeoDataRegistrationLease,
    updater::{
        DEFAULT_DOWNLOAD_TIMEOUT, GeoDataDownloadOutcome, GeoDataDownloadRequest,
        download_geodata_via_proxy,
    },
};
use crate::{config::GeoDataUrls, dispatch::Dispatcher};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(15);
const MIN_LOOP_DELAY: Duration = Duration::from_secs(1);
const UPDATE_BUSY_RETRY: Duration = Duration::from_secs(5);
const RETRY_BACKOFF: [Duration; 4] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

pub(crate) struct GeoDataUpdateService {
    manager: Arc<GeoDataManager>,
    dispatcher: Arc<dyn Dispatcher>,
    registration: GeoDataRegistrationLease,
    urls: GeoDataUrls,
}

impl GeoDataUpdateService {
    #[must_use]
    pub(crate) fn new(
        manager: Arc<GeoDataManager>,
        dispatcher: Arc<dyn Dispatcher>,
        registration: GeoDataRegistrationLease,
        urls: GeoDataUrls,
    ) -> Self {
        Self {
            manager,
            dispatcher,
            registration,
            urls,
        }
    }

    #[cfg(test)]
    pub(crate) fn urls(&self) -> &GeoDataUrls {
        &self.urls
    }

    /// Runs until cancelled. GeoData failures are recorded and retried but
    /// never terminate the business data plane.
    pub(crate) async fn run(self, cancellation: CancellationToken) -> io::Result<()> {
        let mut retries = RetryState::default();
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }

            match self.manager.due_resources_for_active_registration(
                &self.registration,
                self.sources(),
                SystemTime::now(),
            ) {
                Ok(due) => {
                    retries.clear_expired_not_due(&due, Instant::now());
                    for kind in due {
                        if cancellation.is_cancelled() {
                            return Ok(());
                        }
                        if !retries.ready(kind, Instant::now()) {
                            continue;
                        }
                        match self.update_one(kind, cancellation.clone()).await {
                            Ok(UpdateAttempt::Completed) => retries.succeeded(kind),
                            Ok(UpdateAttempt::Busy) => {
                                retries.defer(kind, UPDATE_BUSY_RETRY);
                            }
                            Err(error) => {
                                let delay = retries.failed(kind);
                                tracing::warn!(
                                    geodata_kind = %kind,
                                    retry_seconds = delay.as_secs(),
                                    error = %error,
                                    "VCore GeoData update failed; business routing remains active"
                                );
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "VCore GeoData state check failed; business routing remains active"
                    );
                }
            }

            let delay = retries
                .next_delay(Instant::now())
                .unwrap_or(STATUS_POLL_INTERVAL)
                .min(STATUS_POLL_INTERVAL)
                .max(MIN_LOOP_DELAY);
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    fn sources(&self) -> [(GeoDataKind, &str); 2] {
        [
            (GeoDataKind::GeoSite, self.urls.geosite.as_str()),
            (GeoDataKind::GeoIp, self.urls.geoip.as_str()),
        ]
    }

    async fn update_one(
        &self,
        kind: GeoDataKind,
        cancellation: CancellationToken,
    ) -> Result<UpdateAttempt, String> {
        let source_url = resource_url(&self.urls, kind);
        let session = match self.manager.begin_update_for_active_registration(
            &self.registration,
            kind,
            source_url,
            SystemTime::now(),
        ) {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(UpdateAttempt::Completed),
            Err(GeoDataManagerError::UpdateBusy) => return Ok(UpdateAttempt::Busy),
            Err(error) => return Err(error.to_string()),
        };
        let etag = session.request_etag().map(ToOwned::to_owned);
        let request = GeoDataDownloadRequest {
            dispatcher: self.dispatcher.clone(),
            url: source_url.to_owned(),
            etag: etag.clone(),
            temporary_path: session.temporary_path().to_path_buf(),
            size_limit: kind.file_limit(),
            timeout: DEFAULT_DOWNLOAD_TIMEOUT,
            cancellation,
        };
        match download_geodata_via_proxy(request).await {
            Ok(GeoDataDownloadOutcome::NotModified) => {
                session
                    .not_modified(etag)
                    .map_err(|error| error.to_string())?;
                tracing::info!(geodata_kind = %kind, "VCore GeoData is current");
                Ok(UpdateAttempt::Completed)
            }
            Ok(GeoDataDownloadOutcome::Downloaded {
                etag,
                sha256,
                size,
                final_url,
            }) => {
                let report = session
                    .commit(etag, sha256, size)
                    .map_err(|error| error.to_string())?;
                tracing::info!(
                    geodata_kind = %kind,
                    bytes = size,
                    url = final_url,
                    active_registration = report.active_registration,
                    "VCore GeoData downloaded and hot-activated"
                );
                Ok(UpdateAttempt::Completed)
            }
            Err(error) => {
                let message = error.to_string();
                if let Err(cleanup_error) = session.fail(&message) {
                    return Err(format!("{message}; state cleanup failed: {cleanup_error}"));
                }
                Err(message)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateAttempt {
    Completed,
    Busy,
}

#[derive(Debug, Clone, Copy, Default)]
struct RetrySlot {
    failures: usize,
    retry_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct RetryState {
    geosite: RetrySlot,
    geoip: RetrySlot,
}

impl RetryState {
    fn slot(&self, kind: GeoDataKind) -> &RetrySlot {
        match kind {
            GeoDataKind::GeoSite => &self.geosite,
            GeoDataKind::GeoIp => &self.geoip,
        }
    }

    fn slot_mut(&mut self, kind: GeoDataKind) -> &mut RetrySlot {
        match kind {
            GeoDataKind::GeoSite => &mut self.geosite,
            GeoDataKind::GeoIp => &mut self.geoip,
        }
    }

    fn ready(&self, kind: GeoDataKind, now: Instant) -> bool {
        self.slot(kind)
            .retry_at
            .is_none_or(|retry_at| retry_at <= now)
    }

    fn succeeded(&mut self, kind: GeoDataKind) {
        *self.slot_mut(kind) = RetrySlot::default();
    }

    fn defer(&mut self, kind: GeoDataKind, delay: Duration) {
        self.slot_mut(kind).retry_at = Some(Instant::now() + delay);
    }

    fn failed(&mut self, kind: GeoDataKind) -> Duration {
        let slot = self.slot_mut(kind);
        let delay = RETRY_BACKOFF[slot.failures.min(RETRY_BACKOFF.len() - 1)];
        slot.failures = slot.failures.saturating_add(1);
        slot.retry_at = Some(Instant::now() + delay);
        delay
    }

    fn next_delay(&self, now: Instant) -> Option<Duration> {
        [self.geosite.retry_at, self.geoip.retry_at]
            .into_iter()
            .flatten()
            .map(|retry_at| retry_at.saturating_duration_since(now))
            .min()
    }

    fn clear_expired_not_due(&mut self, due: &[GeoDataKind], now: Instant) {
        for kind in [GeoDataKind::GeoSite, GeoDataKind::GeoIp] {
            if !due.contains(&kind)
                && self
                    .slot(kind)
                    .retry_at
                    .is_some_and(|retry_at| retry_at <= now)
            {
                self.succeeded(kind);
            }
        }
    }
}

fn resource_url(urls: &GeoDataUrls, kind: GeoDataKind) -> &str {
    match kind {
        GeoDataKind::GeoSite => &urls.geosite,
        GeoDataKind::GeoIp => &urls.geoip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_backoff_is_bounded_and_resets_after_success() {
        let mut retries = RetryState::default();
        assert_eq!(
            (0..5)
                .map(|_| retries.failed(GeoDataKind::GeoSite))
                .collect::<Vec<_>>(),
            [
                RETRY_BACKOFF[0],
                RETRY_BACKOFF[1],
                RETRY_BACKOFF[2],
                RETRY_BACKOFF[3],
                RETRY_BACKOFF[3],
            ]
        );
        retries.succeeded(GeoDataKind::GeoSite);
        assert_eq!(retries.slot(GeoDataKind::GeoSite).failures, 0);
        assert!(retries.slot(GeoDataKind::GeoSite).retry_at.is_none());
    }

    #[test]
    fn resources_use_configured_urls() {
        let urls = GeoDataUrls {
            geoip: "https://rules.example.test/custom-geoip".to_owned(),
            geosite: "https://rules.example.test/custom-geosite".to_owned(),
        };
        assert_eq!(
            resource_url(&urls, GeoDataKind::GeoSite),
            "https://rules.example.test/custom-geosite"
        );
        assert_eq!(
            resource_url(&urls, GeoDataKind::GeoIp),
            "https://rules.example.test/custom-geoip"
        );
    }

    #[test]
    fn expired_retry_for_a_resource_no_longer_due_is_cleared() {
        let mut retries = RetryState::default();
        retries.slot_mut(GeoDataKind::GeoIp).retry_at = Some(Instant::now());
        retries.clear_expired_not_due(&[GeoDataKind::GeoSite], Instant::now());
        assert!(retries.slot(GeoDataKind::GeoIp).retry_at.is_none());
    }
}
