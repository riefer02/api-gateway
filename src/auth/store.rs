use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use std::time::SystemTime;

use super::{ApiKeyId, CredentialContext};

#[derive(Debug)]
pub(crate) enum StoreError {
    Unavailable,
    DuplicateKey,
}

#[async_trait]
pub(crate) trait ApiKeyStore: Send + Sync {
    async fn find_by_key_id(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<CredentialContext>, StoreError>;

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError>;
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

        match records.entry(credential.key.key_id.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(credential);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(StoreError::DuplicateKey),
        }
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

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError> {
        let mut records = self
            .records
            .write()
            .map_err(|_| StoreError::Unavailable)?;

        let Some(credential) = records.get_mut(key_id) else {
            return Ok(false);
        };

        if credential.key.revoked_at.is_none() {
            credential.key.revoked_at = Some(SystemTime::now());
        }

        Ok(true)
    }
}
