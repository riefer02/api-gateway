use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::{KeyVerifier, store::ApiKeyStore};
use crate::routing::RouteTableHandle;

/// Cheap to clone: every field is a handle, never a buffer or a lock.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) api_key_store: Arc<dyn ApiKeyStore>,
    pub(crate) verifier: Arc<KeyVerifier>,
    pub(crate) routes: RouteTableHandle,
}
