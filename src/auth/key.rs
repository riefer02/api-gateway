use super::ApiKeyId;

use std::{collections::HashSet, time::SystemTime};

use super::{
    AccountStatus, ApiKeyRecord, Client, CredentialContext, Tenant, hash_secret,
    store::{InMemoryApiKeyStore, StoreError},
};

pub(crate) fn generate_key_id() -> Result<ApiKeyId, getrandom::Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;

    Ok(ApiKeyId(hex::encode(bytes)))
}

pub(crate) fn generate_secret() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)?;

    Ok(hex::encode(bytes))
}

pub(crate) fn generate_key_and_secret() -> Result<(ApiKeyId, String), getrandom::Error> {
    let key_id = generate_key_id()?;
    let secret = generate_secret()?;

    Ok((key_id, secret))
}

#[derive(Debug)]
pub(crate) enum IssueKeyError {
    Random(getrandom::Error),
    Store(StoreError),
    TenantMismatch,
    InactiveAccount,
    KeyIdCollision,
    InvalidExpiration,
}

pub(crate) fn issue_api_key(
    store: &InMemoryApiKeyStore,
    client: &Client,
    tenant: &Tenant,
    scopes: HashSet<String>,
    expires_at: Option<SystemTime>,
) -> Result<String, IssueKeyError> {
    if client.tenant_id != tenant.id {
        return Err(IssueKeyError::TenantMismatch);
    }

    if client.status != AccountStatus::Active || tenant.status != AccountStatus::Active {
        return Err(IssueKeyError::InactiveAccount);
    }

    if expires_at.is_some_and(|expiry| expiry <= SystemTime::now()) {
        return Err(IssueKeyError::InvalidExpiration);
    }

    for _ in 0..3 {
        let (key_id, secret) = generate_key_and_secret().map_err(IssueKeyError::Random)?;

        let credential = CredentialContext {
            key: ApiKeyRecord {
                key_id: key_id.clone(),
                client_id: client.id.clone(),
                verifier: hash_secret(&secret),
                verifier_version: 1,
                scopes: scopes.clone(),
                created_at: SystemTime::now(),
                expires_at,
                revoked_at: None,
            },
            client: client.clone(),
            tenant: tenant.clone(),
        };

        match store.insert(credential) {
            Ok(()) => return Ok(format!("{}.{}", key_id.0, secret)),
            Err(StoreError::DuplicateKey) => continue,
            Err(error) => return Err(IssueKeyError::Store(error)),
        }
    }

    Err(IssueKeyError::KeyIdCollision)
}
