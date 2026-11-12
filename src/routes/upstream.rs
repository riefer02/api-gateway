use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};

use crate::{
    auth,
    error::AppError,
    limits::{Decision, RateLimiter},
    net::{ClientIp, TrustedProxies},
    proxy, routing,
    routing::RouteMatch,
    state::AppState,
};

pub(crate) async fn dispatch(State(state): State<AppState>, request: Request) -> Response {
    let mut rate_headers = HeaderMap::new();

    let mut response = match handle(&state, request, &mut rate_headers).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };

    // Rate-limit headers belong on failures too, but never overwrite the ones a
    // 429 already set for the limiter that denied the request.
    for (name, value) in rate_headers {
        let Some(name) = name else { continue };
        response
            .headers_mut()
            .entry(name)
            .or_insert(value);
    }

    response
}

/// The request pipeline, in one readable place:
/// reject malformed paths -> IP limit -> authenticate -> tenant limit ->
/// resolve route -> authorize -> proxy.
///
/// Authentication comes before resolution so an unauthenticated caller cannot
/// probe which prefixes exist by comparing 401 with 404.
async fn handle(
    state: &AppState,
    mut request: Request,
    rate_headers: &mut HeaderMap,
) -> Result<Response, AppError> {
    let path = request.uri().path().to_owned();

    if routing::is_unsafe_path(&path) {
        return Err(AppError::bad_request(
            "path must not contain `.` or `..` segments",
        ));
    }

    let client = client_ip(&state.trusted_proxies, &request);
    request
        .extensions_mut()
        .insert(ClientIp(client));

    if let Some(limiter) = state.limits.ip.as_ref() {
        check_limit(limiter, &format!("ip:{client}"), rate_headers)?;
    }

    let identity = auth::authenticate(state, request.headers()).await?;

    if let Some(limiter) = state.limits.tenant.as_ref() {
        check_limit(
            limiter,
            &format!("tenant:{}", identity.tenant_id),
            rate_headers,
        )?;
    }

    let method = request.method().clone();
    let table = state.routes.snapshot();

    let route = match table.resolve(&method, &path) {
        RouteMatch::Found(route) => route,
        RouteMatch::MethodNotAllowed(allowed) => {
            return Err(AppError::MethodNotAllowed { allowed });
        }
        RouteMatch::NotFound => return Err(AppError::not_found()),
    };

    let span = tracing::Span::current();
    span.record("route", route.id.as_str());
    span.record("upstream", route.upstream.id.as_str());

    auth::authorize(&identity, &route.scopes)?;
    request
        .extensions_mut()
        .insert(identity);

    let request = limit_undeclared_body(request, state.body_limit).await?;

    proxy::forward(request, route, &state.breakers, &state.retry).await
}

/// Bodies with a `Content-Length` are framed by hyper and streamed. Bodies
/// without one (chunked uploads) are buffered up to the limit so an oversized
/// request gets the JSON envelope instead of an opaque upstream failure.
async fn limit_undeclared_body(request: Request, limit: usize) -> Result<Request, AppError> {
    if request
        .headers()
        .contains_key(axum::http::header::CONTENT_LENGTH)
    {
        return Ok(request);
    }

    let (mut parts, body) = request.into_parts();
    let collected = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;

    // Publish the measured size. The proxy uses Content-Length to decide
    // whether a request can be replayed, and the upstream gets a framed body
    // instead of chunked.
    if let Ok(length) = axum::http::HeaderValue::from_str(&collected.len().to_string()) {
        parts
            .headers
            .insert(axum::http::header::CONTENT_LENGTH, length);
    }

    Ok(Request::from_parts(
        parts,
        axum::body::Body::from(collected),
    ))
}

/// Applies one limiter and records its headers for the eventual response.
fn check_limit(limiter: &RateLimiter, key: &str, headers: &mut HeaderMap) -> Result<(), AppError> {
    match limiter.check(key) {
        Decision::Allowed {
            remaining,
            reset_after,
        } => {
            // Two limits may apply; report whichever leaves less headroom, so
            // the headers never promise more than the caller actually has.
            let tighter = headers
                .get("ratelimit-remaining")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u32>().ok())
                .is_none_or(|current| remaining < current);

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

/// The caller as best we can know it: the peer, or a forwarded address when
/// the peer is a trusted proxy. Never a header from an untrusted peer.
fn client_ip(trusted: &TrustedProxies, request: &Request) -> IpAddr {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip());

    match peer {
        Some(peer) => trusted.client_ip(peer, request.headers()),
        // No connect info (tests, unix sockets): a reserved address keeps the
        // bucket isolated instead of merging everyone into one.
        None => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    }
}
