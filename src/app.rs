use axum::{Router, body::Body, http::Request};
use opentelemetry::{global, trace::TraceContextExt};

use opentelemetry_http::HeaderExtractor;
use tower_http::trace::TraceLayer;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn build_app() -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
        let parent_context = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });

        let span = tracing::info_span!(
            "request",
            otel.kind = "server",
            method = %request.method(),
            path = %request.uri().path(),

        );

        let has_parent = parent_context
            .span()
            .span_context()
            .is_valid();

        if has_parent {
            if let Err(error) = span.set_parent(parent_context) {
                tracing::warn!(%error, "could not attach incoming trace context");
            }
        }

        span
    });

    crate::routes::router().layer(trace_layer)
}
