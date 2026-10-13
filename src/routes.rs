use axum::{Router, routing::get};

use crate::state;
mod health;
mod home;
mod swapi;

pub(crate) fn router(state: state::AppState) -> Router {
    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::check))
        .route("/swapi/people/1", get(swapi::person))
        .with_state(state)
}
