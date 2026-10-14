use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    auth::{ApiKeyId, AuthError, verify_api_key},
    state::AppState,
};

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
