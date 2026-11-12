use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::IntoResponse,
};

use crate::state::AppState;

/// Prometheus scrape endpoint. Requires `METRICS_TOKEN` when one is configured.
pub(crate) async fn render(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = &state.metrics_token
        && !crate::auth::bearer_matches(&headers, token)
    {
        return crate::error::AppError::Unauthorized.into_response();
    }

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
        .into_response()
}
