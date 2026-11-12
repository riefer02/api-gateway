use axum::{extract::State, http::StatusCode};

use crate::state::AppState;

pub(crate) async fn live() -> StatusCode {
    StatusCode::OK
}

/// Readiness is dependency-aware: a gateway that cannot authenticate anyone or
/// whose route table has stopped refreshing is removed from rotation.
pub(crate) async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.routes.is_stale() {
        tracing::warn!(
            "readiness check failed: route table has not refreshed within its staleness window"
        );
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    match crate::db::ping(&state.db).await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(%error, "readiness check failed: database unreachable");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::routing::{RouteTable, RouteTableHandle};

    #[tokio::test]
    async fn readiness_reports_a_stale_route_table() {
        let mut state = crate::testing::empty_state();

        state.routes = RouteTableHandle::new(RouteTable::for_tests(1, Vec::new()))
            .with_stale_after(Duration::from_millis(0));

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(state.routes.is_stale());
        assert_eq!(ready(State(state)).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readiness_accepts_a_fresh_table() {
        let state = crate::testing::empty_state();

        assert!(!state.routes.is_stale());
    }
}
