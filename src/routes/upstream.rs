use axum::{
    extract::{Request, State},
    response::{IntoResponse, Response},
};

use crate::{auth, error::AppError, proxy, routing, state::AppState};

pub(crate) async fn dispatch(State(state): State<AppState>, request: Request) -> Response {
    match handle(&state, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

/// The request pipeline, in one readable place:
/// reject malformed paths -> authenticate -> resolve route -> authorize -> proxy.
///
/// Authentication comes before resolution so an unauthenticated caller cannot
/// probe which prefixes exist by comparing 401 with 404.
async fn handle(state: &AppState, mut request: Request) -> Result<Response, AppError> {
    let path = request.uri().path().to_owned();

    if routing::has_dot_segments(&path) {
        return Err(AppError::bad_request(
            "path must not contain `.` or `..` segments",
        ));
    }

    let identity = auth::authenticate(state, request.headers()).await?;

    let method = request.method().clone();
    let table = state.routes.snapshot();
    let route = table
        .resolve(&method, &path)
        .ok_or(AppError::NotFound)?;

    let span = tracing::Span::current();
    span.record("route", route.id.as_str());
    span.record("upstream", route.upstream.id.as_str());

    auth::authorize(&identity, &route.scopes)?;
    request
        .extensions_mut()
        .insert(identity);

    proxy::forward(request, route).await
}
