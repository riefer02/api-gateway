use crate::auth::store::ApiKeyStore;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) client: reqwest::Client,
    pub(crate) swapi_base_url: String,
    pub(crate) api_key_store: Arc<dyn ApiKeyStore>,
}
