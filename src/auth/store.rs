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

/// Read model for the control plane: a key as listed, never with its verifier.
///
/// This lives beside the store rather than in `admin` so the table has one
/// owner: an operator-facing projection cannot drift from the rows it shows.
#[derive(Debug, Clone)]
pub(crate) struct KeySummary {
    pub(crate) key_id: String,
    pub(crate) client_id: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: Option<OffsetDateTime>,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

/// The only interface to `api_keys`.
///
/// Every read and write of a credential goes through this trait. Keeping the
/// SQL here is what lets security review one file, and what makes rotation a
/// single transaction instead of an insert followed by a compensating revoke.
#[async_trait]
pub(crate) trait ApiKeyStore: Send + Sync {
    async fn find_by_key_id(&self, key_id: &ApiKeyId) -> Result<Option<Credential>, StoreError>;

    /// Summary rows for one client, newest first.
    async fn list_for_client(&self, client_id: &ClientId) -> Result<Vec<KeySummary>, StoreError>;

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError>;

    async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError>;

    /// Issues `new` and revokes `old` in one transaction.
    ///
    /// Returns `false` when `old` is missing or already revoked, and inserts
    /// nothing in that case: the caller never ends up with an active key whose
    /// token it cannot show.
    async fn rotate_key(&self, old: &ApiKeyId, new: NewApiKey) -> Result<bool, StoreError>;

    /// Replaces the row stored under `new.key_id`, if any (development seed).
    ///
    /// Destructive by design: the caller supplies a fixed id and expects a
    /// fresh verifier for it on every boot.
    async fn replace_key(&self, new: NewApiKey) -> Result<(), StoreError>;
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

    /// The production record has no creation time; the listing needs one, so
    /// the double keeps it beside the credential rather than widening the
    /// authentication model for a control-plane field.
    struct StoredKey {
        credential: Credential,
        created_at: OffsetDateTime,
    }

    #[derive(Clone, Default)]
    pub(crate) struct InMemoryApiKeyStore {
        records: Arc<RwLock<HashMap<ApiKeyId, StoredKey>>>,
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
            let mut records = self
                .records
                .write()
                .map_err(|_| StoreError::Unavailable)?;

            self.insert_locked(&mut records, key, client_status, tenant_status)
        }

        fn insert_locked(
            &self,
            records: &mut HashMap<ApiKeyId, StoredKey>,
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

            match records.entry(credential.key.key_id.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(StoredKey {
                        credential,
                        created_at: OffsetDateTime::now_utc(),
                    });
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

            Ok(records
                .get(key_id)
                .map(|stored| stored.credential.clone()))
        }

        async fn list_for_client(
            &self,
            client_id: &ClientId,
        ) -> Result<Vec<KeySummary>, StoreError> {
            let records = self
                .records
                .read()
                .map_err(|_| StoreError::Unavailable)?;

            let mut summaries: Vec<KeySummary> = records
                .values()
                .filter(|stored| &stored.credential.key.client_id == client_id)
                .map(|stored| KeySummary {
                    key_id: stored.credential.key.key_id.0.clone(),
                    client_id: stored
                        .credential
                        .key
                        .client_id
                        .0
                        .clone(),
                    scopes: {
                        let mut scopes: Vec<String> = stored
                            .credential
                            .key
                            .scopes
                            .iter()
                            .cloned()
                            .collect();
                        scopes.sort();
                        scopes
                    },
                    created_at: stored.created_at,
                    expires_at: stored.credential.key.expires_at,
                    revoked_at: stored.credential.key.revoked_at,
                })
                .collect();

            summaries.sort_by_key(|summary| std::cmp::Reverse(summary.created_at));

            Ok(summaries)
        }

        async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError> {
            let mut records = self
                .records
                .write()
                .map_err(|_| StoreError::Unavailable)?;

            let Some(stored) = records.get_mut(key_id) else {
                return Ok(false);
            };

            if stored
                .credential
                .key
                .revoked_at
                .is_none()
            {
                stored.credential.key.revoked_at = Some(OffsetDateTime::now_utc());
            }

            Ok(true)
        }

        async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError> {
            self.insert_active(key)
        }

        async fn rotate_key(&self, old: &ApiKeyId, new: NewApiKey) -> Result<bool, StoreError> {
            let mut records = self
                .records
                .write()
                .map_err(|_| StoreError::Unavailable)?;

            let Some(previous) = records.get(old) else {
                return Ok(false);
            };

            if previous
                .credential
                .key
                .revoked_at
                .is_some()
            {
                return Ok(false);
            }

            self.insert_locked(
                &mut records,
                new,
                AccountStatus::Active,
                AccountStatus::Active,
            )?;

            if let Some(previous) = records.get_mut(old) {
                previous.credential.key.revoked_at = Some(OffsetDateTime::now_utc());
            }

            Ok(true)
        }

        async fn replace_key(&self, new: NewApiKey) -> Result<(), StoreError> {
            let mut records = self
                .records
                .write()
                .map_err(|_| StoreError::Unavailable)?;

            records.remove(&new.key_id);

            self.insert_locked(
                &mut records,
                new,
                AccountStatus::Active,
                AccountStatus::Active,
            )
        }
    }
}
