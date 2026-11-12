use crate::state;

use axum::{Router, routing::get};
mod health;
mod home;
mod metrics;
mod upstream;

pub(crate) fn router(state: state::AppState) -> Router {
    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::live))
        .route("/ready", get(health::ready))
        .route("/metrics", get(metrics::render))
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
                    .method("POST")
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
            Some("GET, HEAD")
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
