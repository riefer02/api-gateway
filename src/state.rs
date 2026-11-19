use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use crate::auth::{KeyVerifier, store::ApiKeyStore};
use crate::limits::{BreakerRegistry, RateLimits};
use crate::net::TrustedProxies;
use crate::retry::RetryPolicy;
use crate::routing::RouteTableHandle;

/// Readiness as "can this process still serve?", not "are its dependencies
/// happy?". Caches the ping so an unauthenticated probe cannot become a
/// database amplifier, and tolerates a failed ping while credentials are still
/// servable from cache: pulling every replica out of rotation the instant
/// Postgres blips turns a dependency hiccup into an outage.
/// Upper bound on one readiness ping. Below the usual probe timeout, so a
/// hung connection is a failed probe rather than a hung probe.
const PING_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct Readiness {
    state: tokio::sync::Mutex<ReadyState>,
    ttl: Duration,
    /// How long a failed ping is tolerated, normally the credential cache TTL.
    grace: Duration,
}

struct ReadyState {
    checked: Option<(Instant, bool)>,
    last_ok: Option<Instant>,
}

impl Readiness {
    pub(crate) fn new(ttl: Duration, grace: Duration) -> Self {
        Self {
            state: tokio::sync::Mutex::new(ReadyState {
                checked: None,
                last_ok: None,
            }),
            ttl,
            grace,
        }
    }

    pub(crate) async fn check(&self, pool: &sqlx::PgPool) -> bool {
        let mut state = self.state.lock().await;

        if let Some((at, ready)) = state.checked
            && at.elapsed() < self.ttl
        {
            return ready;
        }

        let now = Instant::now();

        // Bounded: a blackholed database must not hold the probe open. The
        // readiness cache would otherwise turn one hung connection into a
        // failed liveness check.
        let healthy = tokio::time::timeout(PING_TIMEOUT, crate::db::ping(pool))
            .await
            .map(|result| result.is_ok())
            .unwrap_or(false);

        if healthy {
            state.last_ok = Some(now);
        }

        let ready = decide(healthy, state.last_ok, now, self.grace);
        state.checked = Some((now, ready));

        ready
    }
}

/// A failed check is tolerated while the last success is within the grace
/// window. A success is always ready; a failure with no recorded success is
/// not.
fn decide(healthy: bool, last_ok: Option<Instant>, now: Instant, grace: Duration) -> bool {
    if healthy {
        return true;
    }

    last_ok.is_some_and(|at| now.saturating_duration_since(at) < grace)
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) api_key_store: Arc<dyn ApiKeyStore>,
    pub(crate) verifier: Arc<KeyVerifier>,
    pub(crate) oauth: Option<Arc<crate::auth::oauth::OAuth>>,
    pub(crate) exchange: Option<Arc<crate::auth::exchange::TokenExchange>>,
    pub(crate) routes: RouteTableHandle,
    pub(crate) limits: Arc<RateLimits>,
    pub(crate) breakers: Arc<BreakerRegistry>,
    /// `None` disables the per-upstream concurrency bulkhead.
    pub(crate) bulkheads: Option<Arc<crate::limits::BulkheadRegistry>>,
    pub(crate) retry: Arc<RetryPolicy>,
    pub(crate) audit: Arc<dyn crate::audit::AuditSink>,
    /// Tool schemas learned from `tools/list`. `None` disables input
    /// validation, either because it is configured off or no TTL was set.
    pub(crate) mcp_schemas: Option<Arc<crate::mcp::schema::SchemaCache>>,
    /// Bound on a buffered `tools/list` body. See `McpConfig::filter_max_bytes`.
    pub(crate) mcp_filter_max_bytes: u64,
    pub(crate) default_request_timeout: Duration,
    pub(crate) max_request_timeout: Duration,
    pub(crate) max_response_bytes: u64,
    pub(crate) stream_idle_timeout: Duration,
    pub(crate) body_limit: usize,
    pub(crate) metrics_token: Option<crate::config::SecretString>,
    pub(crate) metrics: PrometheusHandle,
    pub(crate) readiness: Arc<Readiness>,
    pub(crate) trusted_proxies: Arc<TrustedProxies>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_tolerates_a_blip_within_the_cache_window() {
        let now = Instant::now();
        let grace = Duration::from_secs(30);

        assert!(decide(true, None, now, grace), "a healthy ping is ready");

        assert!(
            !decide(false, None, now, grace),
            "a failure with no recorded success is not ready"
        );

        assert!(
            decide(false, Some(now), now, grace),
            "a blip inside the grace window stays in rotation"
        );

        assert!(
            !decide(false, Some(now - Duration::from_secs(31)), now, grace),
            "past the grace window the cache is cold and the process cannot serve"
        );

        assert!(
            !decide(false, Some(now), now, Duration::ZERO),
            "zero grace means a failed ping is immediately not ready"
        );
    }
}
