use std::sync::Arc;

use reqwest::Url;
use sqlx::PgPool;

use crate::auth::store::ApiKeyStore;

/// Cheap to clone: every field is a handle, never a buffer or a lock.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) client: reqwest::Client,
    pub(crate) upstream_base_url: Url,
    pub(crate) api_key_store: Arc<dyn ApiKeyStore>,
}
