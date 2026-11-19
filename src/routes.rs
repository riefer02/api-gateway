use crate::state;

use axum::{Router, routing::get};
mod health;
mod home;
mod metadata;
mod metrics;
mod upstream;

pub(crate) fn router(state: state::AppState) -> Router {
    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::live))
        .route("/ready", get(health::ready))
        .route("/metrics", get(metrics::render))
        // Discovery is public: a connector fetches it before it has a token.
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(metadata::protected_resource),
        )
        // Everything else is resolved against the route table, which also
        // owns authentication and authorization for proxied traffic.
        .fallback(upstream::dispatch)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use crate::testing;

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_is_public() {
        let response = crate::app::build_app(&testing::config(), testing::empty_state())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_routes_use_the_json_envelope() {
        let (app, token) = testing::app("https://upstream.test", std::time::Duration::from_secs(1));

        let response = app
            .oneshot(testing::authorized("/nope", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("\"code\":\"not_found\""));
    }

    #[tokio::test]
    async fn wrong_method_returns_405_with_allow() {
        let (app, token) = testing::app("https://upstream.test", std::time::Duration::from_secs(1));

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/swapi/people/1")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response
                .headers()
                .get("allow")
                .and_then(|value| value.to_str().ok()),
            Some("GET, POST, HEAD")
        );
    }

    #[tokio::test]
    async fn declared_oversize_bodies_return_the_envelope() {
        let (app, token) = testing::app("https://upstream.test", std::time::Duration::from_secs(1));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi/people/1")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-length", "2000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("\"code\":\"payload_too_large\""));
    }

    #[tokio::test]
    async fn request_deadline_uses_the_envelope() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(1_500)),
            )
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("REQUEST_TIMEOUT_SECS", "1")]);
        let (app, token) =
            testing::app_with(&config, &upstream.uri(), std::time::Duration::from_secs(5));

        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("\"code\":\"request_timeout\""));
    }

    #[tokio::test]
    async fn configured_trusted_proxies_drive_the_forwarded_client_address() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("TRUSTED_PROXIES", "127.0.0.1")]);
        let (app, token) =
            testing::app_with(&config, &upstream.uri(), std::time::Duration::from_secs(1));

        let mut request = testing::authorized("/swapi/people/1", &token);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(
                "127.0.0.1:54321"
                    .parse::<std::net::SocketAddr>()
                    .unwrap(),
            ));
        request
            .headers_mut()
            .insert("x-forwarded-for", "203.0.113.9".parse().unwrap());

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let requests = upstream
            .received_requests()
            .await
            .expect("recorded requests");
        // The peer is a configured proxy, so the caller is the forwarded
        // address. Before the wiring fix this was the proxy's own address,
        // which collapsed every caller into one rate-limit bucket.
        assert_eq!(
            requests[0]
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.9")
        );
    }

    #[tokio::test]
    async fn unauthenticated_callers_cannot_probe_routes() {
        let (app, _token) =
            testing::app("https://upstream.test", std::time::Duration::from_secs(1));

        for uri in ["/nope", "/swapi/people/1"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    fn oauth_config() -> Vec<(&'static str, &'static str)> {
        vec![
            ("OAUTH_ISSUER", "https://issuer.test"),
            ("OAUTH_AUDIENCE", "https://gateway.test/mcp"),
            ("OAUTH_JWKS_URI", "https://issuer.test/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.test/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://issuer.test"),
            ("OAUTH_SCOPES_SUPPORTED", "mcp:tools"),
        ]
    }

    fn app_with_policy(
        upstream_uri: &str,
        policy: crate::mcp::ToolPolicy,
    ) -> (axum::Router, String) {
        app_with_policy_and_config(upstream_uri, policy, &testing::config())
    }

    fn app_with_policy_and_config(
        upstream_uri: &str,
        policy: crate::mcp::ToolPolicy,
        config: &crate::config::Config,
    ) -> (axum::Router, String) {
        let (mut state, token) =
            testing::state(config, upstream_uri, std::time::Duration::from_secs(2));

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    upstream_uri,
                    std::time::Duration::from_secs(2),
                    policy,
                    None,
                    None,
                )],
            ));

        (crate::app::build_app(config, state), token)
    }

    fn service_policy() -> crate::mcp::ToolPolicy {
        crate::mcp::ToolPolicy {
            mode: crate::mcp::ToolMode::AllowList,
            roles: std::collections::HashMap::from([(
                "service".to_owned(),
                vec!["search".to_owned()],
            )]),
        }
    }

    fn with_oauth(state: &mut crate::state::AppState, config: &crate::config::Config) {
        state.oauth = Some(std::sync::Arc::new(
            crate::auth::oauth::OAuth::new(
                config
                    .oauth
                    .as_ref()
                    .expect("oauth config"),
            )
            .expect("oauth"),
        ));
    }

    #[tokio::test]
    async fn protected_resource_metadata_is_public_and_absent_without_oauth() {
        let config = testing::config_with(&oauth_config());
        let mut state = testing::empty_state_with(&config);
        with_oauth(&mut state, &config);

        let app = crate::app::build_app(&config, state);

        for uri in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "{uri}");

            let body = to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["resource"], "https://gateway.test/mcp");
            assert_eq!(body["authorization_servers"][0], "https://issuer.test");
        }

        let other = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource/other")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::NOT_FOUND);

        let app = crate::app::build_app(&testing::config(), testing::empty_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn oauth_failures_include_a_discovery_challenge() {
        let config = testing::config_with(&oauth_config());
        let (mut state, _token) = testing::state(
            &config,
            "https://upstream.test",
            std::time::Duration::from_secs(1),
        );
        with_oauth(&mut state, &config);

        let app = crate::app::build_app(&config, state);

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/swapi/people/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let challenge = missing
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains("resource_metadata="));
        assert!(challenge.contains("scope=\"mcp:tools\""));

        let invalid = app
            .oneshot(
                Request::builder()
                    .uri("/swapi/people/1")
                    .header("authorization", "Bearer not.a.valid-jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert!(
            invalid
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("error=\"invalid_token\"")
        );
    }

    #[tokio::test]
    async fn a_route_deadline_can_exceed_the_default() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(1_500)),
            )
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("REQUEST_TIMEOUT_SECS", "1")]);
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    crate::mcp::ToolPolicy::default(),
                    Some(std::time::Duration::from_secs(3)),
                    None,
                )],
            ));

        let app = crate::app::build_app(&config, state);
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_route_response_cap_is_enforced() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("x".repeat(2_048)))
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    crate::mcp::ToolPolicy::default(),
                    None,
                    Some(1_024),
                )],
            ));

        let app = crate::app::build_app(&config, state);
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("\"code\":\"response_too_large\""));
    }

    #[tokio::test]
    async fn a_zero_response_cap_means_unlimited() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("x".repeat(4_096)))
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    crate::mcp::ToolPolicy::default(),
                    None,
                    Some(0),
                )],
            ));

        let app = crate::app::build_app(&config, state);
        let response = app
            .oneshot(testing::authorized("/swapi/people/1", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 8_192)
            .await
            .unwrap();
        assert_eq!(body.len(), 4_096);
    }

    #[tokio::test]
    async fn an_authenticated_404_does_not_write_an_audit_row() {
        let config = testing::config();
        let (mut state, token) = testing::state(
            &config,
            "https://upstream.test",
            std::time::Duration::from_secs(1),
        );

        let recorder = std::sync::Arc::new(testing::RecordingAudit::default());
        state.audit = recorder.clone();

        let app = crate::app::build_app(&config, state);
        let response = app
            .oneshot(testing::authorized("/not-a-route", &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            recorder.events().is_empty(),
            "pre-route rejects must not become per-call audit rows"
        );
    }

    #[tokio::test]
    async fn a_denied_tool_is_a_json_rpc_error_and_an_audit_event() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        let policy = crate::mcp::ToolPolicy {
            mode: crate::mcp::ToolMode::AllowList,
            roles: std::collections::HashMap::from([(
                "service".to_owned(),
                vec!["search".to_owned()],
            )]),
        };

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    policy,
                    None,
                    None,
                )],
            ));

        let recorder = std::sync::Arc::new(testing::RecordingAudit::default());
        state.audit = recorder.clone();

        let app = crate::app::build_app(&config, state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "delete_ticket", "arguments": {} }
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"]["code"], -32000);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not permitted")
        );

        let events = recorder.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, "deny");
        assert_eq!(events[0].tool_name.as_deref(), Some("delete_ticket"));
        assert_eq!(events[0].route_id.as_deref(), Some("test"));
        assert_eq!(events[0].auth_method, "api_key");
    }

    #[tokio::test]
    async fn tools_list_is_filtered_by_policy() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [
                            {"name": "search", "description": "ok"},
                            {"name": "delete_ticket", "description": "no"}
                        ]
                    }
                })),
            )
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        let policy = crate::mcp::ToolPolicy {
            mode: crate::mcp::ToolMode::AllowList,
            roles: std::collections::HashMap::from([(
                "service".to_owned(),
                vec!["search".to_owned()],
            )]),
        };

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    policy,
                    None,
                    None,
                )],
            ));

        let app = crate::app::build_app(&config, state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tools = body["result"]["tools"]
            .as_array()
            .unwrap();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "search");
    }

    #[tokio::test]
    async fn an_unfilterable_tools_list_fails_closed() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("not a json-rpc response"),
            )
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        let policy = crate::mcp::ToolPolicy {
            mode: crate::mcp::ToolMode::AllowList,
            roles: std::collections::HashMap::from([(
                "service".to_owned(),
                vec!["search".to_owned()],
            )]),
        };

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    policy,
                    None,
                    None,
                )],
            ));

        let app = crate::app::build_app(&config, state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_mcp_method_header_must_agree_with_the_body() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (mut state, token) =
            testing::state(&config, &upstream.uri(), std::time::Duration::from_secs(2));

        let policy = crate::mcp::ToolPolicy {
            mode: crate::mcp::ToolMode::AllowList,
            roles: std::collections::HashMap::from([(
                "service".to_owned(),
                vec!["search".to_owned()],
            )]),
        };

        state.routes =
            crate::routing::RouteTableHandle::new(crate::routing::RouteTable::for_tests(
                1,
                vec![testing::route(
                    &upstream.uri(),
                    std::time::Duration::from_secs(2),
                    policy,
                    None,
                    None,
                )],
            ));

        let app = crate::app::build_app(&config, state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .header("mcp-method", "tools/call")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn server_discover_is_not_a_tool_list() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": { "tools": {} }
                    }
                })),
            )
            .mount(&upstream)
            .await;

        let (app, token) = app_with_policy(&upstream.uri(), service_policy());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_batch_tools_list_is_filtered() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "tools": [
                                {"name": "search"},
                                {"name": "delete_ticket"}
                            ]
                        }
                    }
                ])),
            )
            .mount(&upstream)
            .await;

        let (app, token) = app_with_policy(&upstream.uri(), service_policy());
        let body = serde_json::json!([
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        ])
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tools = body[0]["result"]["tools"]
            .as_array()
            .unwrap();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "search");
    }

    #[tokio::test]
    async fn mcp_name_must_agree_with_the_body() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let (app, token) = app_with_policy(&upstream.uri(), service_policy());
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "search", "arguments": {} }
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .header("mcp-method", "tools/call")
                    .header("mcp-name", "delete_ticket")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"]["code"], -32020);
    }

    #[tokio::test]
    async fn a_call_missing_a_required_argument_never_reaches_the_upstream() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [{
                            "name": "search",
                            "description": "search tickets",
                            "inputSchema": {
                                "type": "object",
                                "required": ["query"],
                                "properties": {"query": {"type": "string"}}
                            }
                        }]
                    }
                })),
            )
            // Only the list is forwarded. The rejected call must not be, which
            // is what `expect(1)` proves.
            .expect(1)
            .mount(&upstream)
            .await;

        let (app, token) = app_with_policy(&upstream.uri(), service_policy());

        let list = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })
        .to_string();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", list.len())
                    .body(Body::from(list))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}}
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", call.len())
                    .body(Body::from(call))
                    .unwrap(),
            )
            .await
            .unwrap();

        // A protocol error, not a transport failure: the client gets a JSON-RPC
        // body it can show the model.
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"]["code"], -32602);
        assert_eq!(body["id"], 2);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("query"),
            "message should name the missing argument: {body}"
        );
    }

    #[tokio::test]
    async fn a_tenant_cannot_monopolise_one_tool() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            )
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("RATE_LIMIT_TOOL_PER_MINUTE", "1")]);
        let (app, token) = app_with_policy_and_config(&upstream.uri(), service_policy(), &config);

        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"query": "x"}}
        })
        .to_string();

        let request = || {
            Request::builder()
                .method("POST")
                .uri("/swapi")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("content-length", call.len())
                .body(Body::from(call.clone()))
                .unwrap()
        };

        let first = app
            .clone()
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app.oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            second
                .headers()
                .contains_key("retry-after")
        );
    }

    #[tokio::test]
    async fn a_saturated_upstream_sheds_load_with_retry_after() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("UPSTREAM_MAX_CONCURRENCY", "1")]);
        let (app, token) =
            app_with_policy_and_config(&upstream.uri(), crate::mcp::ToolPolicy::default(), &config);

        let request = || {
            Request::builder()
                .uri("/swapi")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };

        let (first, second) = tokio::join!(
            app.clone().oneshot(request()),
            app.clone().oneshot(request())
        );

        let responses = [first.unwrap(), second.unwrap()];
        let saturations: Vec<_> = responses
            .iter()
            .filter(|response| response.status() == StatusCode::SERVICE_UNAVAILABLE)
            .collect();

        assert_eq!(saturations.len(), 1, "exactly one request must be shed");
        assert!(
            saturations[0]
                .headers()
                .contains_key("retry-after"),
            "a shed request must say when to try again"
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.status() == StatusCode::OK)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn the_run_id_is_echoed_and_validated() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let config = testing::config();
        let (app, token) =
            app_with_policy_and_config(&upstream.uri(), crate::mcp::ToolPolicy::default(), &config);

        let sent = |run_id: &'static str| {
            Request::builder()
                .uri("/swapi")
                .header("authorization", format!("Bearer {token}"))
                .header("x-run-id", run_id)
                .body(Body::empty())
                .unwrap()
        };

        let response = app
            .clone()
            .oneshot(sent("run-abc.1"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-run-id")
                .and_then(|value| value.to_str().ok()),
            Some("run-abc.1"),
            "the caller must be able to join its logs to the audit row"
        );

        let response = app
            .oneshot(sent("bad value"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_malformed_run_id_still_consumes_the_ip_limit() {
        let upstream = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("RATE_LIMIT_IP_PER_MINUTE", "1")]);
        let (app, token) =
            app_with_policy_and_config(&upstream.uri(), crate::mcp::ToolPolicy::default(), &config);

        let request = || {
            Request::builder()
                .uri("/swapi")
                .header("authorization", format!("Bearer {token}"))
                .header("x-run-id", "bad value")
                .body(Body::empty())
                .unwrap()
        };

        let first = app
            .clone()
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::BAD_REQUEST);

        // Validation happens below the IP limiter, so the refusal above was
        // charged. An early return would answer 400 forever and let a caller
        // use the header to avoid the only pre-auth control.
        let second = app.oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_catalogue_over_the_filter_ceiling_is_refused_not_buffered() {
        let upstream = wiremock::MockServer::start().await;

        // 80 KiB of catalogue against a 64 KiB ceiling. Parsing this into a
        // Value costs several times the raw bytes, which is the multiplication
        // the ceiling exists to bound.
        let filler = "x".repeat(80 * 1024);
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [{"name": "search", "description": filler}]
                    }
                })),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let config = testing::config_with(&[("MCP_FILTER_MAX_BYTES", "65536")]);
        let (app, token) = app_with_policy_and_config(&upstream.uri(), service_policy(), &config);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swapi")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .header("content-length", body.len())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn cors_preflight_is_answered_before_auth_and_other_origins_are_refused() {
        let config = testing::config_with(&[("CORS_ALLOWED_ORIGINS", "https://app.example.com")]);
        let app = crate::app::build_app(&config, testing::empty_state_with(&config));

        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header("origin", "https://app.example.com")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "mcp-name")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(preflight.status().is_success());
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://app.example.com"
        );
        assert!(
            preflight
                .headers()
                .get("access-control-allow-headers")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("mcp-name")
        );

        let refused = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "https://evil.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn request_id_is_generated_and_echoed() {
        let response = crate::app::build_app(&testing::config(), testing::empty_state())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .expect("generated request id");

        assert!(!request_id.is_empty());
    }

    #[tokio::test]
    async fn metrics_are_gated_by_the_configured_token() {
        let config = testing::config_with(&[("METRICS_TOKEN", "metrics-token-0123456789")]);
        let app = crate::app::build_app(&config, testing::empty_state_with(&config));

        let open = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(open.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", "Bearer metrics-token-0123456789")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(authorized.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn hostile_request_ids_are_replaced() {
        let app = crate::app::build_app(&testing::config(), testing::empty_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-request-id", "a".repeat(400))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .expect("sanitized request id");

        assert_eq!(request_id.len(), 36, "replaced with a UUID");
        assert_ne!(request_id, "a".repeat(400));
    }

    #[tokio::test]
    async fn proxied_routes_require_authentication() {
        let (app, _token) =
            testing::app("https://upstream.test", std::time::Duration::from_secs(1));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/swapi/people/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );

        let body = to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("\"code\":\"invalid_credentials\""));
        assert!(body.contains("\"request_id\""));
        assert!(
            !body.contains("tenant"),
            "error bodies must not leak credential internals"
        );
    }
}
