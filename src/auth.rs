use std::collections::{BTreeMap, HashSet};
use std::fmt;

use axum::http::{HeaderMap, header};
use time::OffsetDateTime;

use crate::error::AppError;

/// Bound before any store lookup, cache key, or base64 decode.
const MAX_BEARER_TOKEN_BYTES: usize = 8 * 1024;
const MAX_API_KEY_ID_BYTES: usize = 64;

pub(crate) mod cache;
pub(crate) mod exchange;
pub(crate) mod key;
pub(crate) mod oauth;
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
pub(crate) struct Principal {
    pub(crate) tenant_id: TenantId,
    pub(crate) client_id: ClientId,
    /// Present for service API keys; absent for OAuth callers.
    pub(crate) key_id: Option<ApiKeyId>,
    /// Present for OAuth callers; absent for service API keys.
    pub(crate) subject: Option<String>,
    pub(crate) auth_method: AuthMethod,
    pub(crate) scopes: HashSet<String>,
    /// Roles from the token (`roles` and `groups` claims). API keys get
    /// `service`, so tool policy can grant them deliberately.
    pub(crate) roles: HashSet<String>,
    pub(crate) token_id: Option<String>,
    /// The inbound access token, kept only for RFC 8693 exchange. It is
    /// zeroized on drop and never logged.
    pub(crate) subject_token: Option<crate::config::SecretString>,
    /// Configured token claims copied for audit attribution. Never used for
    /// authorization; empty for API keys, which have no claims.
    pub(crate) asserted: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthMethod {
    ApiKey,
    OAuth,
}

impl AuthMethod {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::OAuth => "oauth",
        }
    }
}

impl Principal {
    /// The stable key for per-user limits and audit attribution.
    pub(crate) fn user_key(&self) -> Option<String> {
        self.subject
            .as_ref()
            .map(|subject| format!("{}:{subject}", self.tenant_id))
    }
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
) -> Result<Principal, AuthError> {
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

    Ok(Principal {
        tenant_id: credential.tenant.id,
        client_id: credential.client.id,
        key_id: Some(credential.key.key_id),
        subject: None,
        auth_method: AuthMethod::ApiKey,
        scopes: credential.key.scopes,
        roles: HashSet::from(["service".to_owned()]),
        token_id: None,
        subject_token: None,
        asserted: BTreeMap::new(),
    })
}

fn is_expired(key: &ApiKeyRecord) -> bool {
    key.expires_at
        .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
}

/// The three things authentication needs.
///
/// Deliberately not `AppState`: taking the composition root made `auth` depend
/// on every subsystem and closed a module cycle with `state`. A caller builds
/// this from whatever owns the handles.
pub(crate) struct AuthContext<'a> {
    pub(crate) store: &'a dyn store::ApiKeyStore,
    pub(crate) verifier: &'a KeyVerifier,
    pub(crate) oauth: Option<&'a oauth::OAuth>,
}

pub(crate) async fn authenticate(
    context: AuthContext<'_>,
    headers: &HeaderMap,
) -> Result<Principal, AppError> {
    let AuthContext {
        store,
        verifier,
        oauth,
    } = context;

    let token = bearer_token(headers).ok_or_else(|| match oauth {
        Some(oauth) => oauth.challenge_unauthorized(None),
        None => AppError::Unauthorized,
    })?;

    if token.len() > MAX_BEARER_TOKEN_BYTES {
        return Err(match oauth {
            Some(oauth) => oauth.challenge_unauthorized(Some("invalid_token")),
            None => AppError::Unauthorized,
        });
    }

    // Access tokens are signed JWTs with three segments. API keys are
    // `key_id.secret`, so the shapes cannot be confused without an accidental
    // dot in a generated secret.
    if let Some(oauth) = oauth
        && token.split('.').count() == 3
    {
        let identity = oauth
            .authenticate(token)
            .await
            .map_err(|error| match error {
                oauth::OAuthError::Invalid => {
                    metrics::counter!(
                        crate::metric_names::AUTH_FAILURES_TOTAL,
                        "reason" => "oauth_invalid",
                    )
                    .increment(1);

                    oauth.challenge_unauthorized(Some("invalid_token"))
                }
                oauth::OAuthError::Unavailable => {
                    metrics::counter!(
                        crate::metric_names::AUTH_FAILURES_TOTAL,
                        "reason" => "oauth_unavailable",
                    )
                    .increment(1);

                    AppError::ServiceUnavailable
                }
            })?;

        let principal = Principal {
            tenant_id: TenantId(identity.tenant_id),
            client_id: ClientId(identity.client_id),
            key_id: None,
            subject: Some(identity.subject),
            auth_method: AuthMethod::OAuth,
            scopes: identity.scopes,
            roles: identity.roles,
            token_id: identity.token_id,
            subject_token: Some(crate::config::SecretString::new(token.to_owned())),
            asserted: identity.asserted,
        };

        record_identity(&principal);
        return Ok(principal);
    }

    let (key_id, secret) = token
        .split_once('.')
        .ok_or_else(|| match oauth {
            Some(oauth) => oauth.challenge_unauthorized(Some("invalid_token")),
            None => AppError::Unauthorized,
        })?;

    if key_id.is_empty() || secret.is_empty() || key_id.len() > MAX_API_KEY_ID_BYTES {
        return Err(AppError::Unauthorized);
    }

    let identity = verify_api_key(store, verifier, &ApiKeyId(key_id.to_owned()), secret)
        .await
        .map_err(|error| {
            metrics::counter!(
                crate::metric_names::AUTH_FAILURES_TOTAL,
                "reason" => error.metric_reason(),
            )
            .increment(1);

            match (oauth, &error) {
                (Some(oauth), AuthError::InvalidCredentials) => {
                    oauth.challenge_unauthorized(Some("invalid_token"))
                }
                _ => error.into_app_error(),
            }
        })?;

    record_identity(&identity);

    Ok(identity)
}

fn record_identity(identity: &Principal) {
    let span = tracing::Span::current();
    span.record("tenant_id", identity.tenant_id.as_str());
    span.record("client_id", identity.client_id.as_str());
    span.record("auth_method", identity.auth_method.as_str());

    if let Some(key_id) = &identity.key_id {
        span.record("key_id", key_id.as_str());
    }

    if let Some(subject) = &identity.subject {
        span.record("subject", subject.as_str());
    }
}

/// Routes declare the scopes they require; all of them must be present.
pub(crate) fn authorize(identity: &Principal, required: &HashSet<String>) -> Result<(), AppError> {
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
        let identity = Principal {
            tenant_id: TenantId("tenant".to_owned()),
            client_id: ClientId("client".to_owned()),
            key_id: Some(ApiKeyId("key".to_owned())),
            subject: None,
            auth_method: AuthMethod::ApiKey,
            scopes: HashSet::from(["read".to_owned()]),
            roles: HashSet::from(["service".to_owned()]),
            token_id: None,
            subject_token: None,
            asserted: BTreeMap::new(),
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

    #[test]
    fn user_key_is_tenant_scoped_and_absent_for_service_keys() {
        let mut principal = Principal {
            tenant_id: TenantId("acme".to_owned()),
            client_id: ClientId("client".to_owned()),
            key_id: None,
            subject: Some("user-1".to_owned()),
            auth_method: AuthMethod::OAuth,
            scopes: HashSet::new(),
            roles: HashSet::new(),
            token_id: None,
            subject_token: None,
            asserted: BTreeMap::new(),
        };

        assert_eq!(principal.user_key().as_deref(), Some("acme:user-1"));

        principal.subject = None;
        assert!(principal.user_key().is_none());
    }
}
