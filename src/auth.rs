use std::collections::HashSet;
use std::fmt;

use axum::http::{HeaderMap, header};
use time::OffsetDateTime;

use crate::error::AppError;
use crate::state::AppState;

pub(crate) mod cache;
pub(crate) mod key;
pub(crate) mod store;
pub(crate) mod verifier;

pub(crate) use verifier::KeyVerifier;

/// Newtype identifiers: no accidental mixing of a tenant id with a key id.
macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub(crate) struct $name(pub(crate) String);

        impl $name {
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier!(TenantId);
identifier!(ClientId);
identifier!(ApiKeyId);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccountStatus {
    Active,
    Suspended,
}

impl AccountStatus {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
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

/// A 32-byte verifier, never the raw API key.
#[derive(Clone)]
pub(crate) struct SecretVerifier(pub(crate) [u8; 32]);

#[derive(Clone)]
pub(crate) struct ApiKeyRecord {
    pub(crate) key_id: ApiKeyId,
    pub(crate) client_id: ClientId,
    pub(crate) verifier: SecretVerifier,
    pub(crate) verifier_version: u8,
    pub(crate) scopes: HashSet<String>,
    pub(crate) expires_at: Option<OffsetDateTime>,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

/// Read model for one authentication attempt.
#[derive(Clone)]
pub(crate) struct Credential {
    pub(crate) key: ApiKeyRecord,
    pub(crate) client: Client,
    pub(crate) tenant: Tenant,
}

/// Constructed after successful authentication; safe to pass to handlers.
#[derive(Clone, Debug)]
pub(crate) struct ClientIdentity {
    pub(crate) tenant_id: TenantId,
    pub(crate) client_id: ClientId,
    pub(crate) key_id: ApiKeyId,
    pub(crate) scopes: HashSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthError {
    InvalidCredentials,
    Forbidden,
    StoreUnavailable,
}

impl AuthError {
    fn into_app_error(self) -> AppError {
        match self {
            Self::InvalidCredentials => AppError::Unauthorized,
            Self::Forbidden => AppError::Forbidden,
            Self::StoreUnavailable => AppError::ServiceUnavailable,
        }
    }

    fn metric_reason(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::Forbidden => "forbidden",
            Self::StoreUnavailable => "store_unavailable",
        }
    }
}

/// Authenticates a bearer token against the credential store.
///
/// Every failure is indistinguishable to the client except forbidden-vs-
/// unauthenticated, so key material cannot be probed.
pub(crate) async fn verify_api_key(
    store: &dyn store::ApiKeyStore,
    verifier: &KeyVerifier,
    key_id: &ApiKeyId,
    secret: &str,
) -> Result<ClientIdentity, AuthError> {
    let credential = store
        .find_by_key_id(key_id)
        .await
        .map_err(|_| AuthError::StoreUnavailable)?
        .ok_or(AuthError::InvalidCredentials)?;

    if !verifier.matches(&credential.key, secret) {
        return Err(AuthError::InvalidCredentials);
    }

    if credential.key.revoked_at.is_some() || is_expired(&credential.key) {
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

fn is_expired(key: &ApiKeyRecord) -> bool {
    key.expires_at
        .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
}

pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ClientIdentity, AppError> {
    let token = bearer_token(headers).ok_or(AppError::Unauthorized)?;
    let (key_id, secret) = token
        .split_once('.')
        .ok_or(AppError::Unauthorized)?;

    if key_id.is_empty() || secret.is_empty() {
        return Err(AppError::Unauthorized);
    }

    let identity = verify_api_key(
        state.api_key_store.as_ref(),
        &state.verifier,
        &ApiKeyId(key_id.to_owned()),
        secret,
    )
    .await
    .map_err(|error| {
        metrics::counter!(
            "gateway_auth_failures_total",
            "reason" => error.metric_reason(),
        )
        .increment(1);

        error.into_app_error()
    })?;

    let span = tracing::Span::current();
    span.record("tenant_id", identity.tenant_id.as_str());
    span.record("client_id", identity.client_id.as_str());
    span.record("key_id", identity.key_id.as_str());

    Ok(identity)
}

/// Routes declare the scopes they require; all of them must be present.
pub(crate) fn authorize(
    identity: &ClientIdentity,
    required: &HashSet<String>,
) -> Result<(), AppError> {
    if required.is_empty()
        || required
            .iter()
            .all(|scope| identity.scopes.contains(scope))
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;

    (scheme.eq_ignore_ascii_case("bearer") && !token.contains(' ')).then_some(token)
}

/// Constant-time bearer check, shared by the admin listener and `/metrics`.
pub(crate) fn bearer_matches(headers: &HeaderMap, expected: &crate::config::SecretString) -> bool {
    use subtle::ConstantTimeEq;

    bearer_token(headers).is_some_and(|presented| {
        presented
            .as_bytes()
            .ct_eq(expected.expose().as_bytes())
            .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::{ApiKeyStore, InMemoryApiKeyStore, NewApiKey};
    use crate::config::SecretString;

    const SECRET: &str = "test-only-secret";
    const KEY_ID: &str = "key-test";

    fn verifier() -> KeyVerifier {
        KeyVerifier::new(SecretString::new("test-pepper"))
    }

    fn store_with_scopes(scopes: &[&str]) -> InMemoryApiKeyStore {
        let store = InMemoryApiKeyStore::default();
        let key = NewApiKey {
            key_id: ApiKeyId(KEY_ID.to_owned()),
            client_id: ClientId("client-test".to_owned()),
            verifier: verifier().verifier_for(SECRET),
            verifier_version: verifier::VERIFIER_VERSION,
            scopes: scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            expires_at: None,
        };

        store
            .insert_active(key)
            .expect("insert test credential");

        store
    }

    #[tokio::test]
    async fn accepts_valid_secret() {
        let identity = verify_api_key(
            &store_with_scopes(&["read"]),
            &verifier(),
            &ApiKeyId(KEY_ID.to_owned()),
            SECRET,
        )
        .await
        .expect("valid key");

        assert_eq!(identity.client_id, ClientId("client-test".to_owned()));
    }

    #[tokio::test]
    async fn rejects_wrong_secret() {
        let result = verify_api_key(
            &store_with_scopes(&["read"]),
            &verifier(),
            &ApiKeyId(KEY_ID.to_owned()),
            "wrong-secret",
        )
        .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn rejects_unknown_key_id() {
        let result = verify_api_key(
            &store_with_scopes(&["read"]),
            &verifier(),
            &ApiKeyId("absent".to_owned()),
            SECRET,
        )
        .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn rejects_revoked_key() {
        let store = store_with_scopes(&["read"]);
        store
            .revoke_by_key_id(&ApiKeyId(KEY_ID.to_owned()))
            .await
            .expect("revoke");

        let result =
            verify_api_key(&store, &verifier(), &ApiKeyId(KEY_ID.to_owned()), SECRET).await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn rejects_suspended_client() {
        let store = InMemoryApiKeyStore::default();
        store
            .insert_with_status(
                NewApiKey {
                    key_id: ApiKeyId(KEY_ID.to_owned()),
                    client_id: ClientId("client-test".to_owned()),
                    verifier: verifier().verifier_for(SECRET),
                    verifier_version: verifier::VERIFIER_VERSION,
                    scopes: HashSet::new(),
                    expires_at: None,
                },
                AccountStatus::Suspended,
                AccountStatus::Active,
            )
            .expect("insert");

        let result =
            verify_api_key(&store, &verifier(), &ApiKeyId(KEY_ID.to_owned()), SECRET).await;

        assert!(matches!(result, Err(AuthError::Forbidden)));
    }

    #[tokio::test]
    async fn rejects_expired_key() {
        let store = InMemoryApiKeyStore::default();
        store
            .insert_active(NewApiKey {
                key_id: ApiKeyId(KEY_ID.to_owned()),
                client_id: ClientId("client-test".to_owned()),
                verifier: verifier().verifier_for(SECRET),
                verifier_version: verifier::VERIFIER_VERSION,
                scopes: HashSet::new(),
                expires_at: Some(OffsetDateTime::now_utc() - time::Duration::hours(1)),
            })
            .expect("insert");

        let result =
            verify_api_key(&store, &verifier(), &ApiKeyId(KEY_ID.to_owned()), SECRET).await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[test]
    fn authorize_requires_every_declared_scope() {
        let identity = ClientIdentity {
            tenant_id: TenantId("tenant".to_owned()),
            client_id: ClientId("client".to_owned()),
            key_id: ApiKeyId("key".to_owned()),
            scopes: HashSet::from(["read".to_owned()]),
        };

        assert!(authorize(&identity, &HashSet::new()).is_ok());
        assert!(authorize(&identity, &HashSet::from(["read".to_owned()])).is_ok());
        assert!(
            authorize(
                &identity,
                &HashSet::from(["read".to_owned(), "write".to_owned()])
            )
            .is_err()
        );
    }

    #[test]
    fn bearer_parsing_is_strict() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer abc.def".parse().unwrap());

        assert_eq!(bearer_token(&headers), Some("abc.def"));

        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);

        headers.insert(header::AUTHORIZATION, "Bearer two tokens".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
