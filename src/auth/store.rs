use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;

use super::{ApiKeyId, CredentialContext};

#[derive(Debug)]
pub(crate) enum StoreError {
    Unavailable,
}

#[async_trait]
pub(crate) trait ApiKeyStore: Send + Sync {
    async fn find_by_key_id(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<CredentialContext>, StoreError>;
}

#[derive(Clone, Default)]
pub(crate) struct InMemoryApiKeyStore {
    records: Arc<RwLock<HashMap<ApiKeyId, CredentialContext>>>,
}

impl InMemoryApiKeyStore {
    pub(crate) fn insert(&self, credential: CredentialContext) -> Result<(), StoreError> {
        let mut records = self
            .records
            .write()
            .map_err(|_| StoreError::Unavailable)?;

        records.insert(credential.key.key_id.clone(), credential);
        Ok(())
    }
}

#[async_trait]
impl ApiKeyStore for InMemoryApiKeyStore {
    async fn find_by_key_id(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<CredentialContext>, StoreError> {
        let records = self
            .records
            .read()
            .map_err(|_| StoreError::Unavailable)?;

        Ok(records.get(key_id).cloned())
    }
}
