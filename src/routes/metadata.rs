//! RFC 9728 protected-resource metadata.
//!
//! Public by design: a connector fetches this before it has a token, to learn
//! which authorization server to use and which scopes to request.

use axum::{
    Json,
    extract::{OriginalUri, State},
    http::header,
    response::{IntoResponse, Response},
};

use crate::{error::AppError, state::AppState};

pub(crate) async fn protected_resource(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    let Some(oauth) = &state.oauth else {
        return Err(AppError::not_found());
    };

    // The root form is a valid discovery fallback; a path-suffixed form must
    // match the configured resource. Do not serve one resource's metadata for
    // another path.
    if uri.path() != "/.well-known/oauth-protected-resource" && uri.path() != oauth.metadata_path()
    {
        return Err(AppError::not_found());
    }

    let mut response = Json(oauth.metadata()).into_response();

    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, max-age=300"),
    );

    Ok(response)
}
