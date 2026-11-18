use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, header, request::Parts},
    response::{IntoResponse, Response},
};
use futures_core::Stream;
use reqwest::Url;

use crate::{
    error::AppError,
    limits::{BreakerGuard, BreakerRegistry},
    mcp::{self, ToolFilter},
    request_context,
    retry::RetryPolicy,
    routing::CompiledRoute,
};

/// Everything the forwarder needs beyond the route and the request.
pub(crate) struct ForwardOptions {
    /// A token exchanged for this upstream. Applied after caller headers are
    /// stripped, so a caller can never spoof it.
    pub(crate) upstream_authorization: Option<HeaderValue>,
    /// Present when the request was `tools/list` and the route enforces a tool
    /// policy; the response is buffered and filtered.
    pub(crate) filter_tools: Option<ToolFilter>,
    pub(crate) response_cap: u64,
    pub(crate) stream_idle_timeout: Duration,
}

/// Meaningful only for a single hop; must not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Gateway credentials and framing headers: never forwarded upstream.
const GATEWAY_OWNED_REQUEST: &[&str] = &["host", "authorization", "cookie"];

/// Client-supplied forwarding headers are dropped until the trusted-proxy
/// model lands; otherwise any caller can spoof its origin.
const FORWARDED_HEADERS: &[&str] = &[
    "forwarded",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-method-override",
];

/// Prefixes that must never survive from the caller, whatever the vendor calls
/// them: `x-forwarded-*` covers for/host/proto/port and friends.
const FORWARDED_PREFIXES: &[&str] = &["x-forwarded-"];

/// Upstream identity headers: never forwarded to clients.
const GATEWAY_OWNED_RESPONSE: &[&str] = &["server", "set-cookie"];

pub(crate) async fn forward(
    request: axum::extract::Request,
    route: &CompiledRoute,
    breakers: &BreakerRegistry,
    retry: &RetryPolicy,
    options: ForwardOptions,
) -> Result<Response, AppError> {
    let upstream_id = route.upstream.id.as_str();

    if let Err(rejection) = breakers.check(upstream_id) {
        metrics::counter!("gateway_circuit_open_total", "upstream" => upstream_id.to_owned())
            .increment(1);

        return Err(AppError::CircuitOpen {
            retry_after_secs: rejection.retry_after.as_secs().max(1),
        });
    }

    let (parts, body) = request.into_parts();

    let has_body = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > 0);

    let replayable = crate::retry::is_replayable(
        &parts.method,
        has_body,
        parts
            .headers
            .contains_key("idempotency-key"),
    );

    let path = route.upstream_path(parts.uri.path());
    let url = upstream_url(&route.upstream.base_url, &path, parts.uri.query())?;
    let mut headers = Some(outbound_headers(
        &parts,
        options.upstream_authorization.as_ref(),
        options.filter_tools.is_some(),
    ));
    let mut breaker = BreakerGuard::new(breakers, upstream_id);

    retry.deposit();

    let mut body = Some(body);
    let mut attempt = 1;

    loop {
        let outbound = match body.take() {
            Some(body) => reqwest::Body::wrap_stream(body.into_data_stream()),
            None => reqwest::Body::wrap_stream(axum::body::Body::empty().into_data_stream()),
        };

        let attempt_headers = headers.take().unwrap_or_else(|| {
            outbound_headers(
                &parts,
                options.upstream_authorization.as_ref(),
                options.filter_tools.is_some(),
            )
        });

        let send = route
            .upstream
            .client
            .request(parts.method.clone(), url.clone())
            .headers(attempt_headers)
            .body(outbound)
            .send();

        // Only the wait for response headers is bounded. Once headers arrive
        // the body streams under the inbound deadline instead of being
        // truncated by the upstream timeout.
        match tokio::time::timeout(route.upstream.timeout, send).await {
            Ok(Ok(response)) => {
                let status = response.status();

                if attempt < retry.max_attempts
                    && replayable
                    && RetryPolicy::should_retry_status(status)
                {
                    if retry.try_retry() {
                        record_retry(upstream_id, "status", attempt);
                        tokio::time::sleep(retry.delay(attempt)).await;
                        attempt += 1;
                        continue;
                    }

                    metrics::counter!(
                        "gateway_retry_budget_exhausted_total",
                        "upstream" => upstream_id.to_owned(),
                    )
                    .increment(1);
                }

                // A 5xx means the upstream is unhealthy; a 4xx is a valid answer.
                if status.is_server_error() {
                    breaker.record_failure();
                } else {
                    breaker.record_success();
                }

                metrics::counter!(
                    "gateway_upstream_requests_total",
                    "upstream" => upstream_id.to_owned(),
                    "status" => status.as_u16().to_string(),
                )
                .increment(1);

                return into_gateway_response(response, options).await;
            }
            Ok(Err(error)) => {
                let transient = error.is_timeout() || error.is_connect();

                if attempt < retry.max_attempts && replayable && transient && retry.try_retry() {
                    record_retry(upstream_id, "transport", attempt);
                    tokio::time::sleep(retry.delay(attempt)).await;
                    attempt += 1;
                    continue;
                }

                breaker.record_failure();

                return Err(upstream_error(error));
            }
            Err(_) => {
                if attempt < retry.max_attempts && replayable && retry.try_retry() {
                    record_retry(upstream_id, "timeout", attempt);
                    tokio::time::sleep(retry.delay(attempt)).await;
                    attempt += 1;
                    continue;
                }

                breaker.record_failure();

                tracing::warn!(
                    upstream = upstream_id,
                    "upstream did not return headers in time"
                );

                return Err(AppError::UpstreamTimeout);
            }
        }
    }
}

fn record_retry(upstream: &str, reason: &'static str, attempt: u32) {
    metrics::counter!(
        "gateway_upstream_retries_total",
        "upstream" => upstream.to_owned(),
        "reason" => reason,
    )
    .increment(1);

    tracing::warn!(upstream, attempt, reason, "retrying upstream request");
}

fn upstream_url(base: &Url, path: &str, query: Option<&str>) -> Result<Url, AppError> {
    // Concatenate instead of pushing path segments: `path` is already
    // percent-encoded, and pushing would double-encode every escape. One
    // preallocated buffer keeps this to a single string allocation.
    let base = base.as_str().trim_end_matches('/');
    let mut raw = String::with_capacity(base.len() + path.len() + 2);

    raw.push_str(base);

    if !path.starts_with('/') {
        raw.push('/');
    }

    raw.push_str(path);

    let mut url = Url::parse(&raw)
        .map_err(|error| AppError::internal(format!("could not build upstream URL: {error}")))?;

    url.set_query(query);

    Ok(url)
}

fn outbound_headers(
    parts: &Parts,
    upstream_authorization: Option<&HeaderValue>,
    force_identity_encoding: bool,
) -> HeaderMap {
    let connection_tokens = connection_tokens(&parts.headers);
    let mut headers = HeaderMap::new();

    for (name, value) in &parts.headers {
        let name_str = name.as_str();

        if is_dropped_request_header(name_str, &connection_tokens) {
            continue;
        }

        headers.append(name.clone(), value.clone());
    }

    // A filtered `tools/list` response must be plain JSON. Ask for it
    // explicitly and avoid handing the parser compressed bytes.
    if force_identity_encoding {
        headers.remove(header::ACCEPT_ENCODING);
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    }

    // Applied after the caller's headers are gone: this is the only
    // Authorization value an upstream can see.
    if let Some(value) = upstream_authorization {
        headers.insert(header::AUTHORIZATION, value.clone());
    }

    if let Some(request_id) = request_context::current()
        && let Ok(value) = HeaderValue::from_str(&request_id)
    {
        headers.insert("x-request-id", value);
    }

    // Replace whatever the caller sent with the address we actually resolved.
    if let Some(client) = parts
        .extensions
        .get::<crate::net::ClientIp>()
        && let Ok(value) = HeaderValue::from_str(&client.0.to_string())
    {
        headers.insert("x-forwarded-for", value);
    }

    headers
}

fn is_dropped_request_header(name: &str, connection_tokens: &[String]) -> bool {
    HOP_BY_HOP.contains(&name)
        || GATEWAY_OWNED_REQUEST.contains(&name)
        || FORWARDED_HEADERS.contains(&name)
        || FORWARDED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || connection_tokens
            .iter()
            .any(|token| token == name)
}

/// RFC 7230: headers named by `Connection` are hop-by-hop too.
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

async fn into_gateway_response(
    upstream: reqwest::Response,
    options: ForwardOptions,
) -> Result<Response, AppError> {
    let status = upstream.status();
    let mut headers = inbound_headers(upstream.headers());

    if upstream
        .content_length()
        .is_some_and(|length| length > options.response_cap)
    {
        return Err(AppError::ResponseTooLarge);
    }

    if let Some(allowed) = options.filter_tools
        && status.is_success()
    {
        let content_type = headers.get(header::CONTENT_TYPE);

        if is_json(content_type) {
            let body =
                read_bounded(upstream, options.response_cap, options.stream_idle_timeout).await?;
            // Fail closed: a response we cannot parse is not passed through
            // unfiltered, because that would disclose tools outside policy.
            let body = mcp::filter_tool_list(&body, &allowed).ok_or(AppError::BadGateway)?;

            headers.remove(header::CONTENT_LENGTH);
            headers.remove(header::TRANSFER_ENCODING);
            headers.remove(header::CONTENT_ENCODING);
            if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
                headers.insert(header::CONTENT_LENGTH, value);
            }

            return Ok((status, headers, Body::from(body)).into_response());
        }

        // Policy mode requires a JSON response it can filter. Streaming the
        // list unfiltered would disclose tools outside policy.
        return Err(AppError::BadGateway);
    }

    let body = Body::from_stream(IdleTimeoutStream::new(
        CappedStream::new(upstream.bytes_stream(), options.response_cap),
        options.stream_idle_timeout,
    ));

    Ok((status, headers, body).into_response())
}

fn is_json(content_type: Option<&HeaderValue>) -> bool {
    content_type
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json") || value.contains("+json"))
}

async fn read_bounded(
    mut upstream: reqwest::Response,
    cap: u64,
    idle: Duration,
) -> Result<Vec<u8>, AppError> {
    let mut body = Vec::new();

    loop {
        let chunk = tokio::time::timeout(idle, upstream.chunk())
            .await
            .map_err(|_| AppError::UpstreamTimeout)?
            .map_err(|_| AppError::BadGateway)?;

        let Some(chunk) = chunk else {
            break;
        };

        if u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX) > cap {
            return Err(AppError::ResponseTooLarge);
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Streams a response while enforcing a byte cap. Once the cap is crossed the
/// stream ends with an error, which hyper turns into a truncated connection;
/// the status has already been sent.
struct CappedStream<S> {
    inner: S,
    remaining: u64,
}

impl<S> CappedStream<S> {
    fn new(inner: S, cap: u64) -> Self {
        Self {
            inner,
            remaining: cap,
        }
    }
}

impl<S> Stream for CappedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Ok(chunk))) => {
                let length = u64::try_from(chunk.len()).unwrap_or(u64::MAX);

                if length > self.remaining {
                    self.remaining = 0;
                    return Poll::Ready(Some(Err(std::io::Error::other(
                        "response body exceeds the configured limit",
                    ))));
                }

                self.remaining -= length;
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(std::io::Error::other(error)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Cuts a stream that stops producing bytes. This is the body-side deadline
/// that the header timeout cannot provide; an SSE stream with keep-alives keeps
/// resetting it, while a stalled upstream or non-reading client does not.
struct IdleTimeoutStream<S> {
    inner: S,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<S> IdleTimeoutStream<S> {
    fn new(inner: S, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
        }
    }
}

impl<S> Stream for IdleTimeoutStream<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let idle = self.idle;

        if self
            .sleep
            .as_mut()
            .poll(context)
            .is_ready()
        {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream response body was idle for too long",
            ))));
        }

        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(item)) => {
                if item.is_ok() {
                    self.sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle);
                }

                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn inbound_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_tokens = connection_tokens(headers);
    let mut forwarded = HeaderMap::new();

    for (name, value) in headers {
        let name_str = name.as_str();

        if HOP_BY_HOP.contains(&name_str)
            || GATEWAY_OWNED_RESPONSE.contains(&name_str)
            || name_str.starts_with("access-control-")
            || connection_tokens
                .iter()
                .any(|token| token == name_str)
        {
            continue;
        }

        forwarded.append(name.clone(), value.clone());
    }

    forwarded
}

fn upstream_error(error: reqwest::Error) -> AppError {
    // Never log `Display`: reqwest includes the full URL, which may carry
    // client query parameters.
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else {
        "request"
    };

    if kind == "timeout" {
        tracing::warn!(kind, "upstream timed out");
        return AppError::UpstreamTimeout;
    }

    if kind == "body" {
        tracing::warn!(kind, "request body failed while forwarding");
        return AppError::BadGateway;
    }

    tracing::warn!(kind, "upstream request failed");
    AppError::BadGateway
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use axum::{body::to_bytes, http::Request, http::StatusCode};
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::testing;
    use futures_util::StreamExt as _;

    #[tokio::test]
    async fn proxies_status_headers_and_body() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/people/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-upstream", "yes")
                    .insert_header("server", "wiremock")
                    .set_body_string("proxy-me"),
            )
            .mount(&upstream)
            .await;

        let (app, token) = testing::app(&upstream.uri(), Duration::from_secs(2));
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-upstream")
                .unwrap(),
            "yes"
        );
        assert!(
            response
                .headers()
                .get("server")
                .is_none(),
            "upstream identity headers must not reach clients"
        );
        assert!(
            response
                .headers()
                .get("x-request-id")
                .is_some()
        );

        let body = to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"proxy-me");
    }

    #[tokio::test]
    async fn never_forwards_gateway_credentials_upstream() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let (app, token) = testing::app(&upstream.uri(), Duration::from_secs(2));
        app.oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        let requests = upstream
            .received_requests()
            .await
            .expect("recorded requests");
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0]
                .headers
                .contains_key("authorization")
        );

        let request_id = requests[0]
            .headers
            .get("x-request-id")
            .expect("request id forwarded");
        assert!(!request_id.is_empty());
    }

    #[tokio::test]
    async fn passes_through_upstream_errors() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&upstream)
            .await;

        let (app, token) = testing::app(&upstream.uri(), Duration::from_secs(2));
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"upstream down");
    }

    #[tokio::test]
    async fn forwards_request_bodies_intact() {
        use wiremock::matchers::body_string;

        let upstream = MockServer::start().await;

        Mock::given(method("POST"))
            .and(body_string("hello upstream"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;

        let (app, token) = testing::app(&upstream.uri(), Duration::from_secs(2));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi/echo")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-length", "14")
                    .body(Body::from("hello upstream"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn maps_upstream_timeout_to_gateway_timeout() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1_500)))
            .mount(&upstream)
            .await;

        let (app, token) = testing::app(&upstream.uri(), Duration::from_millis(200));
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn ip_rate_limit_denies_the_second_request() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("RATE_LIMIT_IP_PER_MINUTE", "1")]);
        let (app, token) = testing::app_with(&config, &upstream.uri(), Duration::from_secs(2));

        let first = app
            .clone()
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            first
                .headers()
                .get("ratelimit-limit")
                .unwrap(),
            "1"
        );

        let second = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        let retry_after = second
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .expect("retry-after header");

        assert!((1..=60).contains(&retry_after));

        let body = to_bytes(second.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("\"code\":\"rate_limited\""));
    }

    #[tokio::test]
    async fn circuit_opens_after_repeated_upstream_failures() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[
            ("CIRCUIT_FAILURE_THRESHOLD", "2"),
            ("CIRCUIT_COOLDOWN_SECS", "30"),
        ]);
        let (app, token) = testing::app_with(&config, &upstream.uri(), Duration::from_secs(2));

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(testing::authorized("/swapi/people/1", &token))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("\"code\":\"circuit_open\""));
    }

    #[tokio::test]
    async fn forwards_head_when_get_is_allowed() {
        let upstream = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/people/1"))
            .respond_with(ResponseTemplate::new(200).insert_header("x-upstream", "yes"))
            .mount(&upstream)
            .await;

        let (app, token) = testing::app(&upstream.uri(), Duration::from_secs(2));
        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/swapi/people/1")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-upstream")
                .unwrap(),
            "yes"
        );
    }

    #[tokio::test]
    async fn oversized_chunked_bodies_return_the_envelope() {
        let config = testing::config_with(&[("MAX_REQUEST_BODY_BYTES", "1024")]);
        let (app, token) =
            testing::app_with(&config, "https://upstream.test", Duration::from_secs(1));

        // No Content-Length: only reading the stream can catch this.
        let stream = futures_util::stream::repeat_with(|| {
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(&[b'x'; 4096]))
        })
        .take(4);

        let request = Request::builder()
            .method("POST")
            .uri("/swapi/people/1")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from_stream(stream))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("\"code\":\"payload_too_large\""));
    }

    #[tokio::test]
    async fn retries_a_transient_upstream_failure() {
        let upstream = MockServer::start().await;

        // First request fails, the retry succeeds.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&upstream)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("recovered"))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[
            ("RETRY_MAX_ATTEMPTS", "2"),
            ("RETRY_BASE_DELAY_MS", "1"),
            ("RETRY_BUDGET_RATIO", "5"),
        ]);

        let (app, token) = testing::app_with(&config, &upstream.uri(), Duration::from_secs(2));
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"recovered");

        let requests = upstream
            .received_requests()
            .await
            .expect("recorded requests");
        assert_eq!(requests.len(), 2, "one retry happened");
    }

    #[tokio::test]
    async fn never_retries_a_buffered_body() {
        use futures_util::StreamExt as _;
        use wiremock::matchers::body_string;

        let upstream = MockServer::start().await;

        // Only a request that still carries the body matches this mock.
        Mock::given(method("POST"))
            .and(body_string("payload"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[
            ("RETRY_MAX_ATTEMPTS", "3"),
            ("RETRY_BASE_DELAY_MS", "1"),
            ("RETRY_BUDGET_RATIO", "5"),
        ]);

        let (app, token) = testing::app_with(&config, &upstream.uri(), Duration::from_secs(2));

        // No Content-Length: the gateway buffers this body before forwarding,
        // and must still treat it as un-replayable.
        let stream = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(
            axum::body::Bytes::from_static(b"payload"),
        )]);

        let request = Request::builder()
            .method("POST")
            .uri("/swapi/echo")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", "abc-123")
            .body(Body::from_stream(stream.take(1)))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let requests = upstream
            .received_requests()
            .await
            .expect("recorded requests");
        assert_eq!(
            requests.len(),
            1,
            "a body-carrying request is never retried"
        );
    }

    #[tokio::test]
    async fn does_not_retry_without_a_retry_budget() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[
            ("RETRY_MAX_ATTEMPTS", "3"),
            ("RETRY_BASE_DELAY_MS", "1"),
            ("RETRY_BUDGET_RATIO", "0"),
        ]);

        let (app, token) = testing::app_with(&config, &upstream.uri(), Duration::from_secs(2));
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let requests = upstream
            .received_requests()
            .await
            .expect("recorded requests");
        assert_eq!(requests.len(), 1, "budget denied the retry");
    }

    #[test]
    fn joins_base_path_and_segments() {
        let base = Url::parse("https://swapi.dev/api").unwrap();

        let url = upstream_url(&base, "/people/1", Some("page=2")).unwrap();

        assert_eq!(url.as_str(), "https://swapi.dev/api/people/1?page=2");
    }

    #[tokio::test]
    async fn an_idle_response_stream_is_cut() {
        use futures_util::StreamExt as _;

        let inner = CappedStream::new(
            futures_util::stream::pending::<Result<Bytes, reqwest::Error>>(),
            u64::MAX,
        );
        let mut stream = IdleTimeoutStream::new(inner, Duration::from_millis(20));

        let item = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("idle timeout fired")
            .expect("one item")
            .expect_err("stream error");

        assert_eq!(item.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn upstream_cors_headers_are_not_relayed() {
        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", "*".parse().unwrap());
        headers.insert("x-upstream", "yes".parse().unwrap());

        let filtered = inbound_headers(&headers);

        assert!(!filtered.contains_key("access-control-allow-origin"));
        assert!(filtered.contains_key("x-upstream"));
    }

    #[test]
    fn mcp_protocol_headers_pass_through() {
        let request = Request::builder()
            .uri("/mcp")
            .header(header::AUTHORIZATION, "Bearer caller-token")
            .header("mcp-method", "tools/list")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-session-id", "legacy-session")
            .header("last-event-id", "42")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = request.into_parts();

        let headers = outbound_headers(&parts, None, false);

        assert_eq!(headers.get("mcp-method").unwrap(), "tools/list");
        assert_eq!(
            headers
                .get("mcp-protocol-version")
                .unwrap(),
            "2026-07-28"
        );
        assert_eq!(headers.get("mcp-session-id").unwrap(), "legacy-session");
        assert_eq!(headers.get("last-event-id").unwrap(), "42");
        assert_eq!(
            headers.get(header::ACCEPT).unwrap(),
            "application/json, text/event-stream"
        );
        assert!(!headers.contains_key(header::AUTHORIZATION));
    }

    #[test]
    fn filtering_forces_an_uncompressed_response() {
        let request = Request::builder()
            .uri("/mcp")
            .header(header::ACCEPT_ENCODING, "gzip, br")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = request.into_parts();

        let stripped = outbound_headers(&parts, None, true);
        assert!(!stripped.contains_key(header::ACCEPT_ENCODING));
        assert_eq!(stripped.get(header::ACCEPT).unwrap(), "application/json");

        let untouched = outbound_headers(&parts, None, false);
        assert_eq!(
            untouched
                .get(header::ACCEPT_ENCODING)
                .unwrap(),
            "gzip, br"
        );
    }

    #[test]
    fn the_exchanged_token_replaces_the_caller_credential() {
        let request = Request::builder()
            .uri("/x")
            .header(header::AUTHORIZATION, "Bearer caller-token")
            .header("x-keep", "yes")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = request.into_parts();
        let upstream = HeaderValue::from_static("Bearer exchanged-token");

        let headers = outbound_headers(&parts, Some(&upstream), false);

        assert_eq!(
            headers
                .get(header::AUTHORIZATION)
                .unwrap(),
            "Bearer exchanged-token"
        );
        assert_eq!(headers.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn preserves_percent_encoding() {
        let base = Url::parse("https://swapi.dev/api").unwrap();

        let url = upstream_url(&base, "/people/a%20b", None).unwrap();

        assert_eq!(url.as_str(), "https://swapi.dev/api/people/a%20b");
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Whatever the caller puts in a forwarding, credential, or
        /// connection-named header must not reach the upstream.
        #[test]
        fn caller_controlled_headers_never_reach_the_upstream(
            connection_token in "[a-z]{3,10}",
            forwarded in prop::sample::select(vec![
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto",
                "x-forwarded-port",
                "true-client-ip",
                "cf-connecting-ip",
                "x-real-ip",
                "x-http-method-override",
            ]),
        ) {
            let request = Request::builder()
                .uri("/x")
                .header(header::CONNECTION, &connection_token)
                .header(connection_token.as_str(), "1")
                .header(forwarded, "203.0.113.9")
                .header(header::AUTHORIZATION, "Bearer secret")
                .header(header::COOKIE, "session=abc")
                .header("x-keep-me", "yes")
                .body(Body::empty())
                .unwrap();

            let (parts, _) = request.into_parts();
            let headers = outbound_headers(&parts, None, false);

            prop_assert!(!headers.contains_key(forwarded));
            prop_assert!(!headers.contains_key(header::AUTHORIZATION));
            prop_assert!(!headers.contains_key(header::COOKIE));
            prop_assert!(
                !headers.contains_key(connection_token.as_str()),
                "header named by Connection survived"
            );
            prop_assert_eq!(headers.get("x-keep-me").and_then(|v| v.to_str().ok()), Some("yes"));
        }
    }
}
