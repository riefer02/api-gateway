//! Request-scoped context that must be readable without threading an extractor
//! through every error path.

use axum::{
    body::Body,
    http::{HeaderValue, Request},
    middleware::Next,
    response::Response,
};

tokio::task_local! {
    static REQUEST_ID: String;
}

/// Runs `future` with `request_id` visible to [`current`].
pub async fn scope<F: Future>(request_id: String, future: F) -> F::Output {
    REQUEST_ID
        .scope(request_id, future)
        .await
}

pub fn current() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// Keeps log lines and response headers safe: bounded length, printable ASCII.
pub(crate) fn is_valid_request_id(request_id: &str) -> bool {
    !request_id.is_empty()
        && request_id.len() <= 128
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
}

/// Sanitises the incoming id (replacing anything hostile with a UUID), scopes
/// it for the rest of the request, and passes the request on.
pub(crate) async fn scope_request_id(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid_request_id(value))
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert("x-request-id", value);
    }

    scope(request_id, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exposes_id_inside_scope_only() {
        assert!(current().is_none());

        let seen = scope("req-123".to_owned(), async { current() }).await;

        assert_eq!(seen.as_deref(), Some("req-123"));
        assert!(current().is_none());
    }

    #[test]
    fn validates_request_ids() {
        assert!(is_valid_request_id("trace-abc-123"));
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id(&"a".repeat(129)));
        assert!(!is_valid_request_id("has space"));
        assert!(!is_valid_request_id("line\nbreak"));
    }
}
