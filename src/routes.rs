use crate::{auth, state};

use axum::{
    Router, middleware,
    routing::{any, get},
};
mod health;
mod home;
mod upstream;

pub(crate) fn router(state: state::AppState) -> Router {
    let protected_upstream = Router::new()
        .route("/swapi/{*path}", any(upstream::forward))
        .route_layer(middleware::from_fn(auth::middleware::require_people_read))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::require_api_key,
        ));

    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::live))
        .route("/ready", get(health::ready))
        .merge(protected_upstream)
        .fallback(|| async { crate::error::AppError::NotFound })
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::store::InMemoryApiKeyStore,
        config::{Config, EnvSource},
        state::AppState,
    };
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_config() -> Config {
        let source = HashMap::from([
            ("APP_ENV".to_owned(), "development".to_owned()),
            (
                "DATABASE_URL".to_owned(),
                "postgres://test:test@127.0.0.1:5432/test".to_owned(),
            ),
        ]);

        Config::from_source(&source as &dyn EnvSource).expect("test configuration")
    }

    fn test_app() -> Router {
        let state = AppState {
            db: PgPoolOptions::new()
                .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
                .expect("lazy pool"),
            client: reqwest::Client::new(),
            upstream_base_url: "https://swapi.dev/api"
                .parse()
                .expect("valid url"),
            api_key_store: Arc::new(InMemoryApiKeyStore::default()),
        };

        crate::app::build_app(&test_config(), state)
    }

    #[tokio::test]
    async fn health_is_public() {
        let response = test_app()
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
    async fn swapi_requires_authentication() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/swapi/people/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authentication_errors_use_the_json_envelope() {
        let response = test_app()
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
    }

    #[tokio::test]
    async fn unknown_routes_use_the_json_envelope() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
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
    async fn request_id_is_generated_and_echoed() {
        let response = test_app()
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
}
