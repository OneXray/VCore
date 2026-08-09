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

#[cfg(feature = "inbound-http")]
use crate::config::ExternalControllerConfig;
#[cfg(feature = "inbound-http")]
use std::net::SocketAddr;
#[cfg(feature = "inbound-http")]
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

const TRAFFIC_RATE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PUBLIC_TRAFFIC_BYTES: u64 = i64::MAX as u64;
#[cfg(feature = "inbound-http")]
const CONTROLLER_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "inbound-http")]
const MAX_CONTROLLER_CONNECTIONS: usize = 8;

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

#[cfg(feature = "inbound-http")]
pub(crate) struct TrafficController {
    listener: TcpListener,
    secret: Option<Arc<str>>,
    stats: Arc<TunTrafficStats>,
}

#[cfg(feature = "inbound-http")]
impl std::fmt::Debug for TrafficController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrafficController")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("authenticated", &self.secret.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "inbound-http")]
impl TrafficController {
    pub(crate) async fn bind(
        config: &ExternalControllerConfig,
        stats: Arc<TunTrafficStats>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            secret: config.secret.as_deref().map(Arc::from),
            stats,
        })
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined {
                        tracing::warn!(
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "traffic controller connection task failed"
                        );
                    }
                }
                accepted = self.listener.accept(), if tasks.len() < MAX_CONTROLLER_CONNECTIONS => {
                    let (stream, peer) = accepted?;
                    let secret = self.secret.clone();
                    let stats = self.stats.clone();
                    let child = cancellation.clone();
                    tasks.spawn(async move {
                        if let Err(error) =
                            handle_controller_connection(stream, peer, secret, stats, child).await
                        {
                            tracing::debug!(
                                error_kind = ?error.kind(),
                                "traffic controller request failed"
                            );
                        }
                    });
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(feature = "inbound-http")]
async fn handle_controller_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    secret: Option<Arc<str>>,
    stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if !peer.ip().is_loopback() {
        write_response(&mut stream, 403, &[], b"").await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "traffic controller rejected a non-loopback peer",
        ));
    }

    let request = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        result = timeout(
            CONTROLLER_HEADER_TIMEOUT,
            crate::inbound::http::read_request_head(
                &mut stream,
                crate::inbound::DEFAULT_HEADER_LIMIT,
            ),
        ) => match result {
            Ok(Ok(request)) => request,
            Ok(Err(error)) => {
                write_response(&mut stream, 400, &[], b"").await?;
                return Err(error);
            }
            Err(_) => {
                write_response(&mut stream, 408, &[], b"").await?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "traffic controller request head timed out",
                ));
            }
        },
    };

    if !authorized(&request.headers, secret.as_deref()) {
        let body = br#"{"message":"Unauthorized"}"#;
        write_response(
            &mut stream,
            401,
            &[
                ("WWW-Authenticate", "Bearer"),
                ("Content-Type", "application/json"),
            ],
            body,
        )
        .await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "traffic controller authentication failed",
        ));
    }
    if request.target != "/traffic" {
        write_response(&mut stream, 404, &[], b"").await?;
        return Ok(());
    }
    if request.method != "GET" {
        write_response(&mut stream, 405, &[("Allow", "GET")], b"").await?;
        return Ok(());
    }

    let body = serde_json::to_vec(&stats.snapshot()).map_err(io::Error::other)?;
    write_response(
        &mut stream,
        200,
        &[
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-store"),
        ],
        &body,
    )
    .await
}

#[cfg(feature = "inbound-http")]
fn authorized(headers: &[(String, String)], secret: Option<&str>) -> bool {
    let Some(secret) = secret else {
        return true;
    };
    let mut authorization = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str());
    let Some(value) = authorization.next() else {
        return false;
    };
    if authorization.next().is_some() {
        return false;
    }
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| constant_time_eq(token.as_bytes(), secret.as_bytes()))
}

#[cfg(feature = "inbound-http")]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(feature = "inbound-http")]
async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "inbound-http")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[cfg(feature = "inbound-http")]
    #[test]
    fn bearer_auth_is_strict_and_duplicate_safe() {
        let valid = vec![("Authorization".to_owned(), "Bearer token".to_owned())];
        assert!(authorized(&valid, Some("token")));
        assert!(authorized(&[], None));
        assert!(!authorized(&[], Some("token")));
        assert!(!authorized(
            &[("Authorization".to_owned(), "bearer token".to_owned())],
            Some("token")
        ));
        assert!(!authorized(
            &[
                ("Authorization".to_owned(), "Bearer token".to_owned()),
                ("authorization".to_owned(), "Bearer token".to_owned()),
            ],
            Some("token")
        ));
    }

    #[cfg(feature = "inbound-http")]
    #[tokio::test]
    async fn controller_returns_one_authenticated_snapshot() {
        let stats = Arc::new(TunTrafficStats::default());
        stats.record_up(123);
        stats.record_down(456);
        stats.rotate_rate_bucket();
        let config = ExternalControllerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            secret: Some("random-token".to_owned()),
        };
        let controller = TrafficController::bind(&config, stats).await.unwrap();
        let address = controller.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let server = tokio::spawn(controller.serve(cancellation.clone()));

        let response = request(
            address,
            b"GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer random-token\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        let body = response.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({
                "up": 123,
                "down": 456,
                "upTotal": 123,
                "downTotal": 456,
            })
        );

        let unauthorized = request(
            address,
            b"GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\n\r\n",
        )
        .await;
        assert!(unauthorized.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(unauthorized.contains("Content-Type: application/json\r\n"));
        assert!(unauthorized.ends_with(r#"{"message":"Unauthorized"}"#));

        cancellation.cancel();
        server.await.unwrap().unwrap();
    }

    #[cfg(feature = "inbound-http")]
    async fn request(address: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }
}
