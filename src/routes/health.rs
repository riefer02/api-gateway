use axum::{extract::State, http::StatusCode};

use crate::state::AppState;

pub(crate) async fn live() -> StatusCode {
    StatusCode::OK
}

/// Readiness is dependency-aware: a gateway without a database cannot
/// authenticate anyone, so it must be removed from rotation.
pub(crate) async fn ready(State(state): State<AppState>) -> StatusCode {
    match crate::db::ping(&state.db).await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(%error, "readiness check failed: database unreachable");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
