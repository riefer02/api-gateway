use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use crate::auth::{KeyVerifier, store::ApiKeyStore};
use crate::limits::{BreakerRegistry, RateLimits};
use crate::retry::RetryPolicy;
use crate::routing::RouteTableHandle;

/// Cheap to clone: every field is a handle, never a buffer or a lock.
/// Caches the readiness ping so an unauthenticated probe cannot become a
/// database amplifier.
pub(crate) struct Readiness {
    cached: tokio::sync::Mutex<Option<(Instant, bool)>>,
    ttl: Duration,
}

impl Readiness {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            cached: tokio::sync::Mutex::new(None),
            ttl,
        }
    }

    pub(crate) async fn check(&self, pool: &sqlx::PgPool) -> bool {
        let mut cached = self.cached.lock().await;

        if let Some((at, healthy)) = *cached
            && at.elapsed() < self.ttl
        {
            return healthy;
        }

        let healthy = crate::db::ping(pool).await.is_ok();
        *cached = Some((Instant::now(), healthy));

        healthy
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) api_key_store: Arc<dyn ApiKeyStore>,
    pub(crate) verifier: Arc<KeyVerifier>,
    pub(crate) routes: RouteTableHandle,
    pub(crate) limits: Arc<RateLimits>,
    pub(crate) breakers: Arc<BreakerRegistry>,
    pub(crate) retry: Arc<RetryPolicy>,
    pub(crate) body_limit: usize,
    pub(crate) metrics_token: Option<crate::config::SecretString>,
    pub(crate) metrics: PrometheusHandle,
    pub(crate) readiness: Arc<Readiness>,
}
