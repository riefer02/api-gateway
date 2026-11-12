use axum::{extract::State, http::header, response::IntoResponse};

use crate::state::AppState;

/// Prometheus scrape endpoint. Served from the main listener; if the gateway is
/// exposed publicly, put this path behind network policy at the edge.
pub(crate) async fn render(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
}
