use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::{
    auth,
    error::AppError,
    limits::{Decision, RateLimiter},
    proxy, routing,
    state::AppState,
};

pub(crate) async fn dispatch(State(state): State<AppState>, request: Request) -> Response {
    match handle(&state, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

/// The request pipeline, in one readable place:
/// reject malformed paths -> IP limit -> authenticate -> tenant limit ->
/// resolve route -> authorize -> proxy.
///
/// Authentication comes before resolution so an unauthenticated caller cannot
/// probe which prefixes exist by comparing 401 with 404.
async fn handle(state: &AppState, mut request: Request) -> Result<Response, AppError> {
    let path = request.uri().path().to_owned();

    if routing::has_dot_segments(&path) {
        return Err(AppError::bad_request(
            "path must not contain `.` or `..` segments",
        ));
    }

    let mut rate_headers = HeaderMap::new();

    if let Some(limiter) = state.limits.ip.as_ref() {
        check_limit(
            limiter,
            &format!("ip:{}", client_ip(&request)),
            &mut rate_headers,
        )?;
    }

    let identity = auth::authenticate(state, request.headers()).await?;

    if let Some(limiter) = state.limits.tenant.as_ref() {
        check_limit(
            limiter,
            &format!("tenant:{}", identity.tenant_id),
            &mut rate_headers,
        )?;
    }

    let method = request.method().clone();
    let table = state.routes.snapshot();
    let route = table
        .resolve(&method, &path)
        .ok_or(AppError::NotFound)?;

    let span = tracing::Span::current();
    span.record("route", route.id.as_str());
    span.record("upstream", route.upstream.id.as_str());

    auth::authorize(&identity, &route.scopes)?;
    request
        .extensions_mut()
        .insert(identity);

    let mut response = proxy::forward(request, route, &state.breakers).await?;
    response
        .headers_mut()
        .extend(rate_headers);

    Ok(response)
}

/// Applies one limiter and records its headers for the eventual response.
fn check_limit(limiter: &RateLimiter, key: &str, headers: &mut HeaderMap) -> Result<(), AppError> {
    match limiter.check(key) {
        Decision::Allowed {
            remaining,
            reset_after,
        } => {
            // Two limits may apply; report the tighter one so the headers
            // never advertise more headroom than the caller actually has.
            let tighter = headers
                .get("ratelimit-limit")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u32>().ok())
                .is_none_or(|current| limiter.limit() < current);

            if tighter {
                headers.insert("ratelimit-limit", header_value(&limiter.limit()));
                headers.insert("ratelimit-remaining", header_value(&remaining));
                headers.insert(
                    "ratelimit-reset",
                    header_value(&reset_after.as_secs().max(1)),
                );
            }

            Ok(())
        }
        Decision::Denied { retry_after } => Err(AppError::RateLimited {
            retry_after_secs: retry_after.as_secs().max(1),
            limit: limiter.limit(),
            reset_after_secs: retry_after.as_secs().max(1),
        }),
    }
}

fn header_value<T: ToString>(value: &T) -> HeaderValue {
    HeaderValue::from_str(&value.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

/// Peer address, when the server was started with connect info. Forwarded
/// headers are ignored until the trusted-proxy model lands.
fn client_ip(request: &Request) -> String {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}
