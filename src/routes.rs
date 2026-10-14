use crate::{auth, state};

use axum::{Router, middleware, routing::get};
mod health;
mod home;
mod swapi;

pub(crate) fn router(state: state::AppState) -> Router {
    let protected_swapi = Router::new()
        .route("/swapi/people/1", get(swapi::person))
        .route_layer(middleware::from_fn(auth::middleware::require_people_read))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::require_api_key,
        ));

    Router::new()
        .route("/", get(home::index))
        .route("/health", get(health::check))
        .merge(protected_swapi)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::router;
    use crate::{auth::store::InMemoryApiKeyStore, state::AppState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            client: reqwest::Client::new(),
            swapi_base_url: "https://swapi.dev/api".to_owned(),
            api_key_store: Arc::new(InMemoryApiKeyStore::default()),
        }
    }

    #[tokio::test]
    async fn health_is_public() {
        let response = router(test_state())
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
        let response = router(test_state())
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
}
