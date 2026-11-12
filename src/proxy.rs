use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, request::Parts},
    response::{IntoResponse, Response},
};
use reqwest::Url;

use crate::{error::AppError, request_context, state::AppState};

/// Headers that are meaningful only for a single hop and must not be forwarded.
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

/// Gateway-owned credentials and framing headers: never forwarded upstream.
const GATEWAY_OWNED_REQUEST: &[&str] = &["host", "content-length", "authorization", "cookie"];

/// Upstream identity headers: never forwarded to clients.
const GATEWAY_OWNED_RESPONSE: &[&str] = &["server", "set-cookie"];

pub(crate) async fn forward(
    state: &AppState,
    request: axum::extract::Request,
    path: &str,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    let url = upstream_url(&state.upstream_base_url, path, parts.uri.query())?;
    let headers = outbound_headers(&parts);

    let upstream = state
        .client
        .request(parts.method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .map_err(upstream_error)?;

    Ok(into_gateway_response(upstream))
}

fn upstream_url(base: &Url, path: &str, query: Option<&str>) -> Result<Url, AppError> {
    let mut url = base.clone();

    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            AppError::internal("configured upstream URL cannot accept path segments")
        })?;

        segments.pop_if_empty();
        for segment in path.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                continue;
            }
            segments.push(segment);
        }
    }

    url.set_query(query);

    Ok(url)
}

fn outbound_headers(parts: &Parts) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for (name, value) in &parts.headers {
        let name_str = name.as_str();

        if HOP_BY_HOP.contains(&name_str) || GATEWAY_OWNED_REQUEST.contains(&name_str) {
            continue;
        }

        headers.insert(name.clone(), value.clone());
    }

    if let Some(request_id) = request_context::current()
        && let Ok(value) = HeaderValue::from_str(&request_id)
    {
        headers.insert("x-request-id", value);
    }

    headers
}

fn into_gateway_response(upstream: reqwest::Response) -> Response {
    let status = upstream.status();
    let headers = inbound_headers(upstream.headers());
    let body = Body::from_stream(upstream.bytes_stream());

    (status, headers, body).into_response()
}

fn inbound_headers(headers: &HeaderMap) -> HeaderMap {
    let mut forwarded = HeaderMap::new();

    for (name, value) in headers {
        let name_str = name.as_str();

        if HOP_BY_HOP.contains(&name_str) || GATEWAY_OWNED_RESPONSE.contains(&name_str) {
            continue;
        }

        forwarded.insert(name.clone(), value.clone());
    }

    forwarded
}

fn upstream_error(error: reqwest::Error) -> AppError {
    if error.is_timeout() {
        tracing::warn!(%error, "upstream timed out");
        return AppError::UpstreamTimeout;
    }

    tracing::warn!(%error, "upstream request failed");
    AppError::BadGateway
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::{app, auth, auth::store::InMemoryApiKeyStore, config::Config, state::AppState};

    const SECRET: &str = "test-secret";

    fn test_config(upstream_url: &str) -> Config {
        let source = HashMap::from([
            ("APP_ENV".to_owned(), "development".to_owned()),
            (
                "DATABASE_URL".to_owned(),
                "postgres://test:test@127.0.0.1:5432/test".to_owned(),
            ),
            ("UPSTREAM_BASE_URL".to_owned(), upstream_url.to_owned()),
            ("UPSTREAM_TIMEOUT_SECS".to_owned(), "1".to_owned()),
        ]);

        Config::from_source(&source).expect("test configuration")
    }

    async fn test_app(upstream: &MockServer) -> (axum::Router, Config) {
        let config = test_config(&upstream.uri());
        let store = InMemoryApiKeyStore::default();
        auth::seed_dev_credential(&store, SECRET)
            .await
            .expect("seed credential");

        let state = AppState {
            db: PgPoolOptions::new()
                .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
                .expect("lazy pool"),
            client: reqwest::Client::builder()
                .timeout(config.upstream.timeout)
                .build()
                .expect("client"),
            upstream_base_url: config.upstream.base_url.clone(),
            api_key_store: Arc::new(store),
        };

        (app::build_app(&config, state), config)
    }

    fn authorized(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("authorization", format!("Bearer dev-local.{SECRET}"))
            .body(Body::empty())
            .expect("request")
    }

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

        let (app, _config) = test_app(&upstream).await;
        let response = app
            .oneshot(authorized("/swapi/people/1"))
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

        let (app, _config) = test_app(&upstream).await;
        app.oneshot(authorized("/swapi/people/1"))
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

        let (app, _config) = test_app(&upstream).await;
        let response = app
            .oneshot(authorized("/swapi/people/1"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"upstream down");
    }

    #[tokio::test]
    async fn maps_upstream_timeout_to_gateway_timeout() {
        let upstream = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1_500)))
            .mount(&upstream)
            .await;

        let (app, _config) = test_app(&upstream).await;
        let response = app
            .oneshot(authorized("/swapi/people/1"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn joins_base_path_and_segments() {
        let base = Url::parse("https://swapi.dev/api").unwrap();

        let url = upstream_url(&base, "people/1", Some("page=2")).unwrap();

        assert_eq!(url.as_str(), "https://swapi.dev/api/people/1?page=2");
    }

    #[test]
    fn drops_traversal_segments() {
        let base = Url::parse("https://swapi.dev/api").unwrap();

        let url = upstream_url(&base, "../../admin", None).unwrap();

        assert_eq!(url.as_str(), "https://swapi.dev/api/admin");
    }
}
