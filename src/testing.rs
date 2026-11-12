//! Shared test scaffolding. Compiled only for tests.

use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{Router, body::Body, http::Method, http::Request};
use sqlx::postgres::PgPoolOptions;

use crate::{
    app, auth,
    auth::{KeyVerifier, store::InMemoryApiKeyStore},
    config::{Config, EnvSource},
    routing::{CompiledRoute, RouteTable, RouteTableHandle, Upstream},
    state::AppState,
};

pub(crate) const SCOPES: &[&str] = &["read"];

pub(crate) fn config() -> Config {
    let source = HashMap::from([
        ("APP_ENV".to_owned(), "development".to_owned()),
        (
            "DATABASE_URL".to_owned(),
            "postgres://test:test@127.0.0.1:5432/test".to_owned(),
        ),
    ]);

    Config::from_source(&source as &dyn EnvSource).expect("test configuration")
}

fn lazy_pool() -> sqlx::PgPool {
    PgPoolOptions::new()
        .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
        .expect("lazy pool")
}

/// A state with one `/swapi` route pointing at `upstream_url`, and the token
/// that authenticates against it with the [`SCOPES`] s.
pub(crate) fn state(upstream_url: &str, timeout: Duration) -> (AppState, String) {
    let config = config();
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
    });

    let route = CompiledRoute {
        id: "test".to_owned(),
        path_prefix: "/swapi".to_owned(),
        methods: vec![Method::GET],
        rewrite_prefix: None,
        scopes: SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        upstream,
        priority: 0,
    };

    let state = AppState {
        db: lazy_pool(),
        api_key_store: Arc::new(store),
        verifier: Arc::new(verifier),
        routes: RouteTableHandle::new(RouteTable::for_tests(1, vec![route])),
    };

    (state, auth::key::token(&key_id, &secret))
}

/// A state with no routes: everything 404s.
pub(crate) fn empty_state() -> AppState {
    let config = config();

    AppState {
        db: lazy_pool(),
        api_key_store: Arc::new(InMemoryApiKeyStore::default()),
        verifier: Arc::new(KeyVerifier::new(config.auth.pepper.clone())),
        routes: RouteTableHandle::new(RouteTable::for_tests(1, Vec::new())),
    }
}

pub(crate) fn app(upstream_url: &str, timeout: Duration) -> (Router, String) {
    let config = config();
    let (state, token) = state(upstream_url, timeout);

    (app::build_app(&config, state), token)
}

pub(crate) fn authorized(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}
