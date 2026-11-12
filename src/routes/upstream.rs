use axum::{
    extract::{Path, Request, State},
    response::Response,
};

use crate::{error::AppError, proxy, state::AppState};

/// Temporary single-upstream surface. The Postgres-backed route table (W5)
/// will replace this with prefix matching and per-route policy.
pub(crate) async fn forward(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    proxy::forward(&state, request, &path).await
}
