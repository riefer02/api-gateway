//! Request-scoped context that must be readable without threading an extractor
//! through every error path.

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
}
