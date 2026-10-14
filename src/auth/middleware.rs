use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    auth::{ApiKeyId, AuthError, ClientIdentity, verify_api_key},
    state::AppState,
};

use crate::auth::scopes;

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "invalid or missing bearer credentials",
    )
        .into_response()
}

pub(crate) async fn require_api_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(value) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return unauthorized();
    };

    let Some((scheme, token)) = value.split_once(' ') else {
        return unauthorized();
    };

    if !scheme.eq_ignore_ascii_case("Bearer") {
        return unauthorized();
    }

    let Some((key_id, secret)) = token.split_once('.') else {
        return unauthorized();
    };

    if key_id.is_empty() || secret.is_empty() {
        return unauthorized();
    }

    let key_id = ApiKeyId(key_id.to_owned());

    match verify_api_key(state.api_key_store.as_ref(), &key_id, secret).await {
        Ok(identity) => {
            let span = tracing::Span::current();
            span.record("tenant_id", identity.tenant_id.0.as_str());
            span.record("client_id", identity.client_id.0.as_str());
            span.record("key_id", identity.key_id.0.as_str());

            request
                .extensions_mut()
                .insert(identity);
            next.run(request).await
        }
        Err(AuthError::InvalidCredentials) => unauthorized(),
        Err(AuthError::Forbidden) => StatusCode::FORBIDDEN.into_response(),
        Err(AuthError::StoreUnavailable) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

pub(crate) async fn require_people_read(request: Request, next: Next) -> Response {
    let Some(identity) = request
        .extensions()
        .get::<ClientIdentity>()
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if !identity
        .scopes
        .contains(scopes::PEOPLE_READ)
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::require_people_read;
    use crate::auth::{ApiKeyId, ClientId, ClientIdentity, TenantId};
    use axum::{Router, body::Body, extract::Request, http::StatusCode, middleware, routing::get};
    use std::collections::HashSet;
    use tower::ServiceExt;

    #[tokio::test]
    async fn denies_identity_without_people_read_scope() {
        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(require_people_read));

        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        request
            .extensions_mut()
            .insert(ClientIdentity {
                tenant_id: TenantId("tenant-test".to_owned()),
                client_id: ClientId("client-test".to_owned()),
                key_id: ApiKeyId("key-test".to_owned()),
                scopes: HashSet::new(),
            });

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
