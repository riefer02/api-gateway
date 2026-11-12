use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use opentelemetry::{global, trace::TraceContextExt};
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::config::Config;
use crate::{request_context, state};

/// Builds the gateway with the canonical layer order.
///
/// Outermost first. The order is a contract, not an accident:
/// the request id must exist before anything logs, the deadline must cover
/// body reads, and panics must become responses instead of dropped sockets.
pub fn build_app(config: &Config, state: state::AppState) -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
        let parent_context = global::get_text_map_propagator(|propagator| {
            propagator.extract(&opentelemetry_http::HeaderExtractor(request.headers()))
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

        if has_parent && let Err(error) = span.set_parent(parent_context) {
            tracing::warn!(%error, "could not attach incoming trace context");
        }

        span
    });

    let layers = ServiceBuilder::new()
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(axum::middleware::from_fn(record_request_id))
        .layer(trace_layer)
        .layer(CatchPanicLayer::new())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.server.request_timeout,
        ))
        .layer(RequestBodyLimitLayer::new(
            config.server.request_body_limit_bytes,
        ));

    crate::routes::router(state).layer(layers)
}

async fn record_request_id(
    request: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| "unknown".to_owned());

    request_context::scope(request_id, next.run(request)).await
}
