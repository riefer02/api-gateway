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
