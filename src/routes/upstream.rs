use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use crate::{
    audit::AuditDraft,
    auth,
    error::AppError,
    limits::{Decision, RateLimiter},
    mcp::{self, ToolFilter},
    net::{ClientIp, TrustedProxies},
    proxy::{self, ForwardOptions},
    routing,
    routing::RouteMatch,
    state::AppState,
};

pub(crate) async fn dispatch(State(state): State<AppState>, request: Request) -> Response {
    let started = Instant::now();
    let mut rate_headers = HeaderMap::new();
    let mut audit = AuditDraft::default();

    let mut response = match handle(&state, request, &mut rate_headers, &mut audit).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };

    if let Some(event) = audit.finish(response.status().as_u16(), started.elapsed()) {
        state.audit.record(event);
    }

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
/// reject malformed paths -> IP limit -> authenticate -> tenant/user limits ->
/// resolve route -> authorize -> MCP policy -> upstream auth -> proxy.
///
/// Authentication comes before resolution so an unauthenticated caller cannot
/// probe which prefixes exist by comparing 401 with 404.
async fn handle(
    state: &AppState,
    mut request: Request,
    rate_headers: &mut HeaderMap,
    audit: &mut AuditDraft,
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

    audit.identity(
        identity.tenant_id.as_str(),
        identity.subject.as_deref(),
        Some(identity.client_id.as_str()),
        identity.auth_method.as_str(),
        identity.token_id.as_deref(),
    );

    // Resolve before the tenant/user limiters so a limit rejection is still
    // attributed to a route and can be audited meaningfully.
    let method = request.method().clone();
    let table = state.routes.snapshot();

    let route = match table.resolve(&method, &path, Some(identity.tenant_id.as_str())) {
        RouteMatch::Found(route) => route,
        RouteMatch::MethodNotAllowed(allowed) => {
            return Err(AppError::MethodNotAllowed { allowed });
        }
        RouteMatch::NotFound => return Err(AppError::not_found()),
    };

    let span = tracing::Span::current();
    span.record("route", route.id.as_str());
    span.record("upstream", route.upstream.id.as_str());
    audit.route(&route.id);

    if let Some(limiter) = state.limits.tenant.as_ref() {
        check_limit(
            limiter,
            &format!("tenant:{}", identity.tenant_id),
            rate_headers,
        )?;
    }

    if let Some(limiter) = state.limits.user.as_ref()
        && let Some(key) = identity.user_key()
    {
        check_limit(limiter, &format!("user:{key}"), rate_headers)?;
    }

    if auth::authorize(&identity, &route.scopes).is_err() {
        audit.deny();
        return Err(match &state.oauth {
            Some(oauth) if identity.auth_method == auth::AuthMethod::OAuth => {
                oauth.challenge_forbidden(&route.scopes)
            }
            _ => AppError::Forbidden,
        });
    }

    let (mut request, filter_tools) =
        match apply_tool_policy(state, request, route, &identity, audit, rate_headers).await? {
            PolicyOutcome::Forward(request, filter) => (request, filter),
            PolicyOutcome::Deny(response) => return Ok(response),
        };

    let upstream_authorization = upstream_authorization(state, route, &identity).await?;
    let timeout = route.effective_timeout(state.default_request_timeout, state.max_request_timeout);
    const MCP_BUFFER_CEILING: u64 = 4 * 1024 * 1024;
    let requested_cap = route
        .max_response_bytes
        .unwrap_or(state.max_response_bytes);
    let response_cap = if requested_cap == 0 {
        u64::MAX
    } else {
        requested_cap
    };
    let response_cap = if filter_tools.is_some() {
        response_cap.min(MCP_BUFFER_CEILING)
    } else {
        response_cap
    };

    request
        .extensions_mut()
        .insert(identity);

    let forwarded = tokio::time::timeout(
        timeout,
        proxy::forward(
            request,
            route,
            &state.breakers,
            &state.retry,
            ForwardOptions {
                upstream_authorization,
                filter_tools,
                response_cap,
                stream_idle_timeout: state.stream_idle_timeout,
            },
        ),
    )
    .await;

    match forwarded {
        Ok(response) => response,
        Err(_) => Err(AppError::RequestTimeout),
    }
}

/// Buffers and inspects an MCP request only when the route enforces a tool
/// policy. Returns the rebuilt request and, for `tools/list`, the set used to
/// filter the response.
enum PolicyOutcome {
    Forward(Request, Option<ToolFilter>),
    Deny(Response),
}

async fn apply_tool_policy(
    state: &AppState,
    request: Request,
    route: &routing::CompiledRoute,
    identity: &auth::Principal,
    audit: &mut AuditDraft,
    rate_headers: &mut HeaderMap,
) -> Result<PolicyOutcome, AppError> {
    if !route.tool_policy.is_enforcing() {
        let request = limit_undeclared_body(request, state.body_limit).await?;
        return Ok(PolicyOutcome::Forward(request, None));
    }

    // Only POST carries JSON-RPC messages. A legacy GET is the server-to-client
    // event stream and a DELETE terminates a session; neither should carry a
    // body. A body on another method would otherwise bypass policy parsing.
    if request.method() != axum::http::Method::POST {
        let has_body = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > 0)
            || request
                .headers()
                .contains_key(header::TRANSFER_ENCODING);

        if has_body {
            audit.deny();
            return Ok(header_mismatch("MCP request bodies must use POST"));
        }

        let request = limit_undeclared_body(request, state.body_limit).await?;
        return Ok(PolicyOutcome::Forward(request, None));
    }

    let allowed = route
        .tool_policy
        .allowed_tools(&identity.roles);
    let claimed_method = single_header(request.headers(), "mcp-method")?;
    let claimed_name = single_header(request.headers(), "mcp-name")?;
    let claimed_version = single_header(request.headers(), "mcp-protocol-version")?;
    let (mut parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, state.body_limit)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;

    match mcp::evaluate(&bytes, &allowed) {
        Ok(evaluated) => {
            // A batch has no single unambiguous method/name/version. A header
            // that claims one is a routing/authorization split-brain.
            if evaluated.batch
                && (claimed_method.is_some() || claimed_name.is_some() || claimed_version.is_some())
            {
                audit.deny();
                return Ok(header_mismatch(
                    "MCP header is not valid on a JSON-RPC batch",
                ));
            }

            if claimed_method
                .as_deref()
                .is_some_and(|claimed| claimed != evaluated.method)
            {
                audit.deny();
                return Ok(header_mismatch(
                    "Mcp-Method does not match the JSON-RPC body",
                ));
            }

            if claimed_name
                .as_deref()
                .is_some_and(|claimed| evaluated.tool.as_deref() != Some(claimed))
            {
                audit.deny();
                return Ok(header_mismatch("Mcp-Name does not match params.name"));
            }

            if let (Some(claimed), Some(body_version)) = (
                claimed_version.as_deref(),
                evaluated.protocol_version.as_deref(),
            ) && claimed != body_version
            {
                audit.deny();
                return Ok(header_mismatch(
                    "MCP-Protocol-Version does not match the request metadata",
                ));
            }

            audit.mcp(Some(&evaluated.method), evaluated.tool.as_deref());

            // Arguments are checked against the tool's own advertised schema,
            // learned from `tools/list`. A miss (cold cache, no schema) passes:
            // the tool still validates, and rejecting on absence of evidence
            // would break a perfectly good call.
            if let Some(cache) = state.mcp_schemas.as_deref()
                && let Some(violation) =
                    mcp::schema::check(&evaluated.calls, &route.upstream.id, cache)
            {
                audit.deny();
                metrics::counter!("gateway_mcp_invalid_params_total", "route" => route.id.clone())
                    .increment(1);
                count_tool_call(identity, &violation.tool, "invalid");
                return Ok(invalid_params(&violation));
            }

            let filter = (evaluated.wants_tools_list && !allowed.is_all()).then(|| ToolFilter {
                allowed: allowed.clone(),
                require_tools: true,
                schemas: state
                    .mcp_schemas
                    .as_ref()
                    .map(|cache| (Arc::clone(cache), route.upstream.id.clone())),
            });

            // Per-tool quota. Only calls the policy already allowed reach
            // here, so a caller cannot mint buckets by inventing names.
            if let Some(limiter) = state.limits.tool.as_ref() {
                for call in &evaluated.calls {
                    check_limit(
                        limiter,
                        &format!("tool:{}:{}", identity.tenant_id.as_str(), call.name),
                        rate_headers,
                    )?;
                }
            }

            for call in &evaluated.calls {
                count_tool_call(identity, &call.name, "allow");
            }

            if let Ok(length) = HeaderValue::from_str(&bytes.len().to_string()) {
                parts
                    .headers
                    .insert(header::CONTENT_LENGTH, length);
            }

            Ok(PolicyOutcome::Forward(
                Request::from_parts(parts, Body::from(bytes)),
                filter,
            ))
        }
        Err(mcp::McpError::Denied { tool, id }) => {
            audit.mcp(Some("tools/call"), Some(&tool));
            audit.deny();
            metrics::counter!("gateway_mcp_denied_total", "route" => route.id.clone()).increment(1);
            count_tool_call(identity, &tool, "deny");

            let body = mcp::denial_body(
                id,
                &mcp::McpError::Denied {
                    tool: tool.clone(),
                    id: None,
                }
                .message(),
            );
            let response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                Body::from(body),
            )
                .into_response();

            Ok(PolicyOutcome::Deny(response))
        }
        Err(error) => {
            audit.deny();
            Err(AppError::bad_request(error.message()))
        }
    }
}

/// Reads a header that must occur at most once. Duplicate values are
/// ambiguous and therefore rejected on an enforcing route.
fn single_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, AppError> {
    let mut values = headers.get_all(name).iter();

    let Some(value) = values.next() else {
        return Ok(None);
    };

    if values.next().is_some() {
        return Err(AppError::bad_request(format!(
            "duplicate `{name}` header is not allowed"
        )));
    }

    value
        .to_str()
        .map(|value| Some(value.to_owned()))
        .map_err(|_| AppError::bad_request(format!("invalid `{name}` header")))
}

/// A `400` with a JSON-RPC `HeaderMismatch` body.
fn header_mismatch(message: &str) -> PolicyOutcome {
    let response = (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(mcp::header_mismatch_body(message)),
    )
        .into_response();

    PolicyOutcome::Deny(response)
}

/// A `200` with a JSON-RPC `InvalidParams` body. 200 is deliberate, as with a
/// denial: most MCP clients read a non-2xx as a transport failure, not a
/// protocol error they can show the model.
fn invalid_params(violation: &mcp::schema::Violation) -> PolicyOutcome {
    let response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(mcp::rpc_error_body(
            -32602,
            violation.id.clone(),
            &violation.message(),
        )),
    )
        .into_response();

    PolicyOutcome::Deny(response)
}

/// Exchanges the caller's token for one addressed to this upstream. A route
/// with no audience receives no gateway credential; the inbound token never
/// travels sideways.
async fn upstream_authorization(
    state: &AppState,
    route: &routing::CompiledRoute,
    identity: &auth::Principal,
) -> Result<Option<HeaderValue>, AppError> {
    let Some(audience) = route.upstream.audience.as_deref() else {
        return Ok(None);
    };

    let Some(exchange) = &state.exchange else {
        // Compile rejects an audience without exchange support; this is a
        // defence-in-depth failure, not a configuration the gateway accepts.
        return Err(AppError::ServiceUnavailable);
    };

    let subject = identity
        .subject
        .as_deref()
        .ok_or(AppError::Forbidden)?;
    let subject_token = identity
        .subject_token
        .as_ref()
        .ok_or(AppError::Forbidden)?;

    let exchanged = exchange
        .exchange(
            identity.tenant_id.as_str(),
            subject,
            subject_token.expose(),
            audience,
            route.upstream.exchange_scope.as_deref(),
        )
        .await
        .map_err(|error| match error {
            crate::auth::exchange::ExchangeError::Denied => {
                metrics::counter!(
                    "gateway_upstream_auth_failures_total",
                    "reason" => "denied",
                )
                .increment(1);
                AppError::UpstreamAuthFailed
            }
            crate::auth::exchange::ExchangeError::Unavailable => {
                metrics::counter!(
                    "gateway_upstream_auth_failures_total",
                    "reason" => "unavailable",
                )
                .increment(1);
                AppError::ServiceUnavailable
            }
        })?;

    let mut value = Vec::with_capacity(7 + exchanged.expose().len());
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(exchanged.expose().as_bytes());

    let header = HeaderValue::from_bytes(&value).map_err(|_| AppError::UpstreamAuthFailed);
    {
        use zeroize::Zeroize as _;
        value.zeroize();
    }

    header.map(Some)
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

/// Per-tool call counter.
///
/// The tool label carries the caller's own name only when the call was not
/// denied. A denied name is caller-controlled, so labelling it would let
/// anyone create unbounded metric series; those collapse to `unlisted`. The
/// exact name is in the audit row, which is where investigation belongs.
fn count_tool_call(identity: &auth::Principal, tool: &str, decision: &'static str) {
    let tool = if decision == "deny" { "unlisted" } else { tool };

    metrics::counter!(
        "gateway_mcp_tool_calls_total",
        "tenant" => identity.tenant_id.as_str().to_owned(),
        "tool" => tool.to_owned(),
        "decision" => decision,
    )
    .increment(1);
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
