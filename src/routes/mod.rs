use crate::state;

use axum::{Router, routing::get};
mod health;
mod home;
mod metadata;
mod metrics;
mod upstream;

pub(crate) fn router(state: state::AppState) -> Router {
    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::live))
        .route("/ready", get(health::ready))
        .route("/metrics", get(metrics::render))
        // Discovery is public: a connector fetches it before it has a token.
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(metadata::protected_resource),
        )
        // Everything else is resolved against the route table, which also
        // owns authentication and authorization for proxied traffic.
        .fallback(upstream::dispatch)
        .with_state(state)
}

#[cfg(test)]
mod tests;
