use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::SystemTime};
use subtle::ConstantTimeEq;

pub(crate) mod key;
pub(crate) mod middleware;
pub(crate) mod scopes;
pub(crate) mod store;
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TenantId(pub(crate) String);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ClientId(pub(crate) String);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ApiKeyId(pub(crate) String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccountStatus {
    Active,
    Suspended,
}
#[derive(Clone)]
pub(crate) struct Tenant {
    pub(crate) id: TenantId,
    pub(crate) status: AccountStatus,
}

#[derive(Clone)]
pub(crate) struct Client {
    pub(crate) id: ClientId,
    pub(crate) tenant_id: TenantId,
    pub(crate) status: AccountStatus,
}

// Holds a 32-byte verifier, never the raw API key.
// We’ll implement how it’s calculated in a later step.
#[derive(Clone)]
pub(crate) struct SecretVerifier(pub(crate) [u8; 32]);

#[derive(Clone)]
pub(crate) struct ApiKeyRecord {
    pub(crate) key_id: ApiKeyId,
    pub(crate) client_id: ClientId,
    pub(crate) verifier: SecretVerifier,
    pub(crate) verifier_version: u8,
    pub(crate) scopes: HashSet<String>,
    pub(crate) created_at: SystemTime,
    pub(crate) expires_at: Option<SystemTime>,
    pub(crate) revoked_at: Option<SystemTime>,
}

// Constructed after successful authentication; safe to pass to handlers.
#[derive(Clone, Debug)]
pub(crate) struct ClientIdentity {
    pub(crate) tenant_id: TenantId,
    pub(crate) client_id: ClientId,
    pub(crate) key_id: ApiKeyId,
    pub(crate) scopes: HashSet<String>,
}

#[derive(Clone)]
pub(crate) struct CredentialContext {
    pub(crate) key: ApiKeyRecord,
    pub(crate) client: Client,
    pub(crate) tenant: Tenant,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthError {
    InvalidCredentials,
    Forbidden,
    StoreUnavailable,
}

fn hash_secret(secret: &str) -> SecretVerifier {
    let digest = Sha256::digest(secret.as_bytes());
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    SecretVerifier(bytes)
}

pub(crate) async fn verify_api_key(
    store: &dyn store::ApiKeyStore,
    key_id: &ApiKeyId,
    secret: &str,
) -> Result<ClientIdentity, AuthError> {
    let credential = store
        .find_by_key_id(key_id)
        .await
        .map_err(|_| AuthError::StoreUnavailable)?
        .ok_or(AuthError::InvalidCredentials)?;

    if credential.key.verifier_version != 1 {
        return Err(AuthError::InvalidCredentials);
    }

    let candidate = hash_secret(secret);
    let matches = bool::from(
        candidate
            .0
            .ct_eq(&credential.key.verifier.0),
    );

    if !matches {
        return Err(AuthError::InvalidCredentials);
    }

    let now = SystemTime::now();

    if credential.key.revoked_at.is_some()
        || credential
            .key
            .expires_at
            .is_some_and(|expires| expires <= now)
    {
        return Err(AuthError::InvalidCredentials);
    }

    if credential.key.client_id != credential.client.id
        || credential.client.tenant_id != credential.tenant.id
    {
        return Err(AuthError::StoreUnavailable);
    }

    if credential.client.status != AccountStatus::Active
        || credential.tenant.status != AccountStatus::Active
    {
        return Err(AuthError::Forbidden);
    }

    Ok(ClientIdentity {
        tenant_id: credential.tenant.id,
        client_id: credential.client.id,
        key_id: credential.key.key_id,
        scopes: credential.key.scopes,
    })
}

pub(crate) fn seed_dev_credential(
    store: &store::InMemoryApiKeyStore,
    secret: &str,
) -> Result<(), store::StoreError> {
    let tenant_id = TenantId("tenant-local".to_owned());
    let client_id = ClientId("client-local".to_owned());
    let key_id = ApiKeyId("dev-local".to_owned());

    store.insert(CredentialContext {
        key: ApiKeyRecord {
            key_id,
            client_id: client_id.clone(),
            verifier: hash_secret(secret),
            verifier_version: 1,
            scopes: HashSet::from([scopes::PEOPLE_READ.to_owned()]),
            created_at: SystemTime::now(),
            expires_at: None,
            revoked_at: None,
        },
        client: Client {
            id: client_id,
            tenant_id: tenant_id.clone(),
            status: AccountStatus::Active,
        },
        tenant: Tenant {
            id: tenant_id,
            status: AccountStatus::Active,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, time::SystemTime};

    use store::InMemoryApiKeyStore;

    const TEST_SECRET: &str = "test-only-secret";

    fn test_store() -> (InMemoryApiKeyStore, ApiKeyId) {
        let tenant_id = TenantId("tenant-test".to_owned());
        let client_id = ClientId("client-test".to_owned());
        let key_id = ApiKeyId("key-test".to_owned());

        let store = InMemoryApiKeyStore::default();
        store
            .insert(CredentialContext {
                key: ApiKeyRecord {
                    key_id: key_id.clone(),
                    client_id: client_id.clone(),
                    verifier: hash_secret(TEST_SECRET),
                    verifier_version: 1,
                    scopes: HashSet::from([scopes::PEOPLE_READ.to_owned()]),
                    created_at: SystemTime::now(),
                    expires_at: None,
                    revoked_at: None,
                },
                client: Client {
                    id: client_id,
                    tenant_id: tenant_id.clone(),
                    status: AccountStatus::Active,
                },
                tenant: Tenant {
                    id: tenant_id,
                    status: AccountStatus::Active,
                },
            })
            .expect("insert test credential");

        (store, key_id)
    }

    #[tokio::test]
    async fn accepts_valid_secret() {
        let (store, key_id) = test_store();

        let identity = verify_api_key(&store, &key_id, TEST_SECRET)
            .await
            .expect("valid key");

        assert_eq!(identity.client_id, ClientId("client-test".to_owned()));
    }

    #[tokio::test]
    async fn rejects_wrong_secret() {
        let (store, key_id) = test_store();

        let result = verify_api_key(&store, &key_id, "wrong-secret").await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }
}
