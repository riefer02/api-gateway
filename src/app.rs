use axum::{Router, body::Body, http::Request};
use opentelemetry::{global, trace::TraceContextExt};
use tower_http::limit::RequestBodyLimitLayer;

use opentelemetry_http::HeaderExtractor;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::config::Config;
use crate::state;

pub fn build_app(config: Config, state: state::AppState) -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
        let parent_context = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });

        let request_id = request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing");

        let span = tracing::info_span!(
            "request",
            otel.kind = "server",
            method = %request.method(),
            path = %request.uri().path(),
            request_id = %request_id,
            tenant_id = tracing::field::Empty,
            client_id = tracing::field::Empty,
            key_id = tracing::field::Empty,
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

    crate::routes::router(state)
        .layer(RequestBodyLimitLayer::new(config.max_request_body_bytes))
        .layer(trace_layer)
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
}
