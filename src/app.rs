use axum::{Router, body::Body, http::Request, http::header, response::IntoResponse};
use opentelemetry::{global, trace::TraceContextExt};
use std::time::Instant;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::config::Config;
use crate::error::AppError;
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
            route = tracing::field::Empty,
            upstream = tracing::field::Empty,
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
        // Sanitise before propagation so the response echoes the value we
        // actually logged, not a client-supplied one.
        .layer(axum::middleware::from_fn(request_context::scope_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(axum::middleware::from_fn(record_metrics))
        .layer(trace_layer)
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn_with_state(
            config.server.request_timeout,
            request_deadline,
        ))
        .layer(axum::middleware::from_fn_with_state(
            config.server.request_body_limit_bytes,
            reject_declared_oversize,
        ))
        // Streaming backstop for chunked bodies without a Content-Length.
        .layer(RequestBodyLimitLayer::new(
            config.server.request_body_limit_bytes,
        ));

    crate::routes::router(state).layer(layers)
}

/// Rejects oversized bodies with the gateway's error envelope. The tower
/// limit layer below still enforces the limit while streaming.
async fn reject_declared_oversize(
    axum::extract::State(limit): axum::extract::State<usize>,
    request: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    if declared.is_some_and(|length| length > limit) {
        return AppError::PayloadTooLarge.into_response();
    }

    next.run(request).await
}

/// Whole-request deadline with the gateway's error envelope.
async fn request_deadline(
    axum::extract::State(timeout): axum::extract::State<std::time::Duration>,
    request: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => AppError::RequestTimeout.into_response(),
    }
}

/// RED metrics for every request, including ones rejected before routing.
async fn record_metrics(
    request: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().as_str().to_owned();
    let started = Instant::now();

    let response = next.run(request).await;
    let status = response.status().as_u16().to_string();

    metrics::counter!("gateway_requests_total", "method" => method, "status" => status)
        .increment(1);
    metrics::histogram!("gateway_request_duration_seconds").record(started.elapsed().as_secs_f64());

    response
}
