use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build_app() -> Router {
    crate::routes::router().layer(TraceLayer::new_for_http())
}
