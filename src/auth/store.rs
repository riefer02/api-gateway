use std::collections::HashSet;

use async_trait::async_trait;
use thiserror::Error;
use time::OffsetDateTime;

use super::{ApiKeyId, ClientId, Credential, SecretVerifier};

pub(crate) mod postgres;

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("credential store is unavailable")]
    Unavailable,
    #[error("api key already exists")]
    DuplicateKey,
}

/// Write model: exactly what is persisted when a key is issued.
#[derive(Clone)]
pub(crate) struct NewApiKey {
    pub(crate) key_id: ApiKeyId,
    pub(crate) client_id: ClientId,
    pub(crate) verifier: SecretVerifier,
    pub(crate) verifier_version: u8,
    pub(crate) scopes: HashSet<String>,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

#[async_trait]
pub(crate) trait ApiKeyStore: Send + Sync {
    async fn find_by_key_id(&self, key_id: &ApiKeyId) -> Result<Option<Credential>, StoreError>;

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError>;

    async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError>;
}

#[cfg(test)]
pub(crate) use memory::InMemoryApiKeyStore;

/// Test double only: production always uses Postgres.
#[cfg(test)]
mod memory {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use super::*;
    use crate::auth::{AccountStatus, ApiKeyRecord, Client, Tenant, TenantId};

    const TEST_TENANT: &str = "tenant-in-memory";

    #[derive(Clone, Default)]
    pub(crate) struct InMemoryApiKeyStore {
        records: Arc<RwLock<HashMap<ApiKeyId, Credential>>>,
    }

    impl InMemoryApiKeyStore {
        pub(crate) fn insert_active(&self, key: NewApiKey) -> Result<(), StoreError> {
            self.insert_with_status(key, AccountStatus::Active, AccountStatus::Active)
        }

        pub(crate) fn insert_with_status(
            &self,
            key: NewApiKey,
            client_status: AccountStatus,
            tenant_status: AccountStatus,
        ) -> Result<(), StoreError> {
            let tenant_id = TenantId(TEST_TENANT.to_owned());
            let credential = Credential {
                key: ApiKeyRecord {
                    key_id: key.key_id.clone(),
                    client_id: key.client_id.clone(),
                    verifier: key.verifier,
                    verifier_version: key.verifier_version,
                    scopes: key.scopes,
                    expires_at: key.expires_at,
                    revoked_at: None,
                },
                client: Client {
                    id: key.client_id,
                    tenant_id,
                    status: client_status,
                },
                tenant: Tenant {
                    id: TenantId(TEST_TENANT.to_owned()),
                    status: tenant_status,
                },
            };

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
        ) -> Result<Option<Credential>, StoreError> {
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
                credential.key.revoked_at = Some(OffsetDateTime::now_utc());
            }

            Ok(true)
        }

        async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError> {
            self.insert_active(key)
        }
    }
}
