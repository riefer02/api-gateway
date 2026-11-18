//! Shared test scaffolding. Compiled only for tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, body::Body, http::Method, http::Request};
use sqlx::postgres::PgPoolOptions;

use crate::{
    app,
    audit::{AuditSink, DataAuditEvent},
    auth,
    auth::{KeyVerifier, store::InMemoryApiKeyStore},
    config::{Config, EnvSource},
    limits::{BreakerRegistry, RateLimits},
    routing::{CompiledRoute, RouteTable, RouteTableHandle, Upstream},
    state::AppState,
};

pub(crate) const SCOPES: &[&str] = &["read"];

pub(crate) fn config() -> Config {
    config_with(&[])
}

pub(crate) fn config_with(overrides: &[(&str, &str)]) -> Config {
    let mut source: HashMap<String, String> = HashMap::from([
        ("APP_ENV".to_owned(), "development".to_owned()),
        (
            "DATABASE_URL".to_owned(),
            "postgres://test:test@127.0.0.1:5432/test".to_owned(),
        ),
    ]);

    for (key, value) in overrides {
        source.insert((*key).to_owned(), (*value).to_owned());
    }

    Config::from_source(&source as &dyn EnvSource).expect("test configuration")
}

fn lazy_pool() -> sqlx::PgPool {
    PgPoolOptions::new()
        .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
        .expect("lazy pool")
}

/// A database for the tests that need one. Skips when `DATABASE_URL` is unset,
/// and fails with a hint when it is set but unusable — never a silent skip.
pub(crate) async fn pg_pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap_or_else(|error| {
            panic!("cannot reach DATABASE_URL ({error}); start Postgres with `just db-up`")
        });

    crate::db::migrate(&pool)
        .await
        .expect("apply migrations");

    Some(pool)
}

/// Unique identifiers keep parallel database tests from colliding.
pub(crate) fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();

    format!("{prefix}-{}-{nanos}", std::process::id())
}

pub(crate) fn metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle()
}

/// An audit sink that keeps events for assertions.
#[derive(Default)]
pub(crate) struct RecordingAudit {
    events: Mutex<Vec<DataAuditEvent>>,
}

impl RecordingAudit {
    pub(crate) fn events(&self) -> Vec<DataAuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl AuditSink for RecordingAudit {
    fn record(&self, event: DataAuditEvent) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event);
    }
}

/// A route against `upstream_url` with the caller's chosen MCP and timing
/// settings. Tests use it instead of hand-building every field.
pub(crate) fn route(
    upstream_url: &str,
    timeout: Duration,
    tool_policy: crate::mcp::ToolPolicy,
    request_timeout: Option<Duration>,
    max_response_bytes: Option<u64>,
) -> CompiledRoute {
    let upstream = Arc::new(Upstream {
        id: "test".to_owned(),
        base_url: upstream_url
            .parse()
            .expect("valid upstream url"),
        client: reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("client"),
        timeout,
        audience: None,
        exchange_scope: None,
    });

    CompiledRoute {
        id: "test".to_owned(),
        path_prefix: "/swapi".to_owned(),
        methods: vec![Method::GET, Method::POST],
        rewrite_prefix: None,
        tenant_id: None,
        scopes: SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        tool_policy,
        request_timeout,
        max_response_bytes,
        upstream,
        priority: 0,
    }
}

/// State with one `/swapi` route pointing at `upstream_url`, plus the token
/// that authenticates against it with the [`SCOPES`] scopes.
pub(crate) fn state(config: &Config, upstream_url: &str, timeout: Duration) -> (AppState, String) {
    let verifier = KeyVerifier::new(config.auth.pepper.clone());

    let (key, secret) = auth::key::generate(
        &verifier,
        auth::ClientId("client-test".to_owned()),
        SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        None,
    )
    .expect("generate key");

    let key_id = key.key_id.clone();
    let store = InMemoryApiKeyStore::default();
    store
        .insert_active(key)
        .expect("seed credential");

    let route = route(
        upstream_url,
        timeout,
        crate::mcp::ToolPolicy::default(),
        None,
        None,
    );

    let state = AppState {
        db: lazy_pool(),
        api_key_store: Arc::new(store),
        verifier: Arc::new(verifier),
        oauth: None,
        exchange: None,
        routes: RouteTableHandle::new(RouteTable::for_tests(1, vec![route])),
        limits: Arc::new(RateLimits::new(&config.limits)),
        breakers: Arc::new(BreakerRegistry::new(&config.limits)),
        retry: Arc::new(crate::retry::RetryPolicy::new(&config.retry)),
        audit: Arc::new(crate::audit::DisabledAudit),
        default_request_timeout: config.server.request_timeout,
        max_request_timeout: config.server.max_request_timeout,
        max_response_bytes: config.server.max_response_bytes,
        stream_idle_timeout: config.server.stream_idle_timeout,
        body_limit: config.server.request_body_limit_bytes,
        metrics_token: config.telemetry.metrics_token.clone(),
        metrics: metrics_handle(),
        readiness: Arc::new(crate::state::Readiness::new(
            std::time::Duration::from_secs(1),
        )),
        trusted_proxies: Arc::new(
            crate::net::TrustedProxies::parse(&config.server.trusted_proxies)
                .expect("test trusted proxies"),
        ),
    };

    (state, auth::key::token(&key_id, &secret))
}

/// A state with no routes: everything 404s.
pub(crate) fn empty_state() -> AppState {
    empty_state_with(&config())
}

pub(crate) fn empty_state_with(config: &Config) -> AppState {
    AppState {
        db: lazy_pool(),
        api_key_store: Arc::new(InMemoryApiKeyStore::default()),
        verifier: Arc::new(KeyVerifier::new(config.auth.pepper.clone())),
        oauth: None,
        exchange: None,
        routes: RouteTableHandle::new(RouteTable::for_tests(1, Vec::new())),
        limits: Arc::new(RateLimits::new(&config.limits)),
        breakers: Arc::new(BreakerRegistry::new(&config.limits)),
        retry: Arc::new(crate::retry::RetryPolicy::new(&config.retry)),
        audit: Arc::new(crate::audit::DisabledAudit),
        default_request_timeout: config.server.request_timeout,
        max_request_timeout: config.server.max_request_timeout,
        max_response_bytes: config.server.max_response_bytes,
        stream_idle_timeout: config.server.stream_idle_timeout,
        body_limit: config.server.request_body_limit_bytes,
        metrics_token: config.telemetry.metrics_token.clone(),
        metrics: metrics_handle(),
        readiness: Arc::new(crate::state::Readiness::new(
            std::time::Duration::from_secs(1),
        )),
        trusted_proxies: Arc::new(
            crate::net::TrustedProxies::parse(&config.server.trusted_proxies)
                .expect("test trusted proxies"),
        ),
    }
}

pub(crate) fn app(upstream_url: &str, timeout: Duration) -> (Router, String) {
    app_with(&config(), upstream_url, timeout)
}

pub(crate) fn app_with(config: &Config, upstream_url: &str, timeout: Duration) -> (Router, String) {
    let (state, token) = state(config, upstream_url, timeout);

    (app::build_app(config, state), token)
}

pub(crate) fn authorized(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}
