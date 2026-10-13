use axum::{Router, routing::get};

mod health;
mod home;

pub(crate) fn router() -> Router {
    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::check))
}
