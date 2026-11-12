use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use crate::auth::{KeyVerifier, store::ApiKeyStore};
use crate::limits::{BreakerRegistry, RateLimits};
use crate::retry::RetryPolicy;
use crate::routing::RouteTableHandle;

/// Cheap to clone: every field is a handle, never a buffer or a lock.
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
    pub(crate) metrics: PrometheusHandle,
}
