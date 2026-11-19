//! OAuth 2.1 resource-server support.
//!
//! The gateway validates access tokens. It does not issue them: the customer's
//! identity provider is the authorization server. Tokens are accepted only when
//! they are signed by a key in the issuer's JWKS, carry the configured issuer,
//! name this gateway as their audience, and have not expired.
//!
//! JWKS keys are cached in memory and refreshed on an unknown `kid` at most once
//! per [`REFRESH_COOLDOWN`]. A JWKS outage is an availability failure (`503`),
//! never an invalid-token failure: sending every user through a login cannot fix
//! an unreachable key set.

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    errors::ErrorKind,
    jwk::{Jwk, JwkSet},
};
use serde::Deserialize;
use serde_json::Value;

use crate::config::OAuthConfig;
use crate::error::AppError;

/// How often an unknown `kid` may trigger a fetch.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(10);
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_SUBJECT_LEN: usize = 256;
const MAX_EMAIL_LEN: usize = 320;
const MAX_CLIENT_LEN: usize = 256;
const MAX_TOKEN_ID_LEN: usize = 256;
const MAX_ROLES: usize = 64;
const MAX_ROLE_LEN: usize = 128;
const MAX_SCOPES: usize = 128;
const MAX_SCOPE_LEN: usize = 128;
const MAX_TENANT_LEN: usize = 128;

pub(crate) struct OAuth {
    issuer: String,
    audience: String,
    algorithms: Vec<Algorithm>,
    clock_skew: u64,
    default_tenant: String,
    scopes_supported: Vec<String>,
    resource_metadata_url: String,
    metadata_path: String,
    metadata: serde_json::Value,
    jwks: JwksCache,
    /// Claims to copy into the audit log. Empty means none.
    audit_claims: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct OAuthIdentity {
    pub(crate) tenant_id: String,
    pub(crate) subject: String,
    pub(crate) client_id: String,
    pub(crate) scopes: HashSet<String>,
    pub(crate) roles: HashSet<String>,
    pub(crate) token_id: Option<String>,
    /// Configured claims, as strings, for audit attribution.
    pub(crate) asserted: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OAuthError {
    /// The token is malformed, mis-signed, expired, or for another audience.
    Invalid,
    /// The key set could not be fetched and no usable key is cached.
    Unavailable,
}

impl OAuth {
    pub(crate) fn new(config: &OAuthConfig) -> Result<Self, String> {
        let algorithms = config
            .algorithms
            .iter()
            .map(|algorithm| parse_algorithm(algorithm))
            .collect::<Result<Vec<_>, _>>()?;

        let resource = reqwest::Url::parse(&config.resource)
            .map_err(|error| format!("OAUTH_RESOURCE is not a URL: {error}"))?;

        let mut metadata_url = resource.clone();
        let path = resource.path().trim_start_matches('/');
        metadata_url.set_path(&format!(
            "/.well-known/oauth-protected-resource{}",
            if path.is_empty() {
                String::new()
            } else {
                format!("/{path}")
            }
        ));
        metadata_url.set_query(None);
        metadata_url.set_fragment(None);

        let metadata = serde_json::json!({
            "resource": config.resource,
            "authorization_servers": config.authorization_servers,
            "scopes_supported": config.scopes_supported,
            "bearer_methods_supported": ["header"],
        });

        metrics::gauge!("gateway_oauth_jwks_ready").set(0.0);

        Ok(Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            algorithms,
            clock_skew: config.clock_skew.as_secs(),
            default_tenant: config.default_tenant.clone(),
            scopes_supported: config.scopes_supported.clone(),
            resource_metadata_url: metadata_url.to_string(),
            metadata_path: metadata_url.path().to_owned(),
            metadata,
            jwks: JwksCache::new(&config.jwks_uri, config.jwks_ttl)?,
            audit_claims: config.audit_claims.clone(),
        })
    }

    /// Warms the key cache. A failure is logged by the caller and does not stop
    /// API-key traffic or the process from starting.
    pub(crate) async fn warm(&self) -> Result<(), OAuthError> {
        self.jwks
            .refresh(true)
            .await
            .map(|_| ())
    }

    pub(crate) fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }

    pub(crate) fn resource_metadata_url(&self) -> &str {
        &self.resource_metadata_url
    }

    /// The exact path of the advertised protected-resource document.
    pub(crate) fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    /// Validates an access token and returns the identity it asserts.
    pub(crate) async fn authenticate(&self, token: &str) -> Result<OAuthIdentity, OAuthError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(OAuthError::Invalid);
        }

        let header = decode_header(token).map_err(|_| OAuthError::Invalid)?;

        if !self.algorithms.contains(&header.alg) {
            return Err(OAuthError::Invalid);
        }

        // Access tokens are `at+jwt` or a legacy `JWT`; an ID token is not an
        // access token. Audience validation is the real defence, but this keeps
        // an obviously wrong token type out early.
        if let Some(typ) = header.typ.as_deref()
            && typ
                .to_ascii_lowercase()
                .contains("id+jwt")
        {
            return Err(OAuthError::Invalid);
        }

        let jwk = self
            .jwks
            .key(header.kid.as_deref())
            .await?;
        if matches!(
            jwk.common.public_key_use,
            Some(jsonwebtoken::jwk::PublicKeyUse::Encryption)
        ) {
            return Err(OAuthError::Invalid);
        }

        if let Some(key_algorithm) = jwk.common.key_algorithm
            && !key_algorithm_matches(key_algorithm, header.alg)
        {
            return Err(OAuthError::Invalid);
        }

        let key = DecodingKey::from_jwk(&jwk).map_err(|_| OAuthError::Invalid)?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.leeway = self.clock_skew;
        validation.validate_nbf = true;
        validation.required_spec_claims = HashSet::from([
            "exp".to_owned(),
            "iss".to_owned(),
            "aud".to_owned(),
            "sub".to_owned(),
        ]);

        let data = decode::<Claims>(token, &key, &validation).map_err(|error| {
            if matches!(
                error.kind(),
                ErrorKind::InvalidSignature | ErrorKind::ExpiredSignature
            ) {
                tracing::debug!("oauth token rejected");
            } else {
                tracing::debug!(kind = ?error.kind(), "oauth token rejected");
            }

            OAuthError::Invalid
        })?;

        let claims = data.claims;
        validate_claim_lengths(&claims)?;

        let scopes = claims.scopes();
        let roles = claims.roles();
        let tenant_id = claims
            .tenant
            .as_deref()
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| self.default_tenant.clone());
        let client_id = claims
            .azp
            .clone()
            .or_else(|| claims.client_id.clone())
            .unwrap_or_else(|| "oauth-client".to_owned());

        let asserted = asserted_claims(&claims.extra, &self.audit_claims);

        Ok(OAuthIdentity {
            tenant_id,
            subject: claims.sub,
            client_id,
            scopes,
            roles,
            token_id: claims.jti,
            asserted,
        })
    }

    /// `401` for a missing or invalid token. Includes the metadata pointer so a
    /// connector can discover the authorization server.
    pub(crate) fn challenge_unauthorized(&self, error: Option<&'static str>) -> AppError {
        let scope = (!self.scopes_supported.is_empty()).then(|| self.scopes_supported.join(" "));

        AppError::OAuthUnauthorized {
            error,
            scope,
            resource_metadata: self.resource_metadata_url().to_owned(),
        }
    }

    /// `403` with `insufficient_scope` for a valid token that lacks a route's
    /// scopes, so the client can step up instead of failing opaquely.
    pub(crate) fn challenge_forbidden(&self, scopes: &HashSet<String>) -> AppError {
        let mut scope: Vec<&str> = scopes
            .iter()
            .map(String::as_str)
            .collect();
        scope.sort_unstable();

        AppError::OAuthForbidden {
            scope: scope.join(" "),
            resource_metadata: self.resource_metadata_url().to_owned(),
        }
    }
}

/// Copies configured claims out of the token as strings.
///
/// Only scalars are accepted. Arrays and objects are skipped rather than
/// serialised, because this value ends up in an audit row and later in a
/// header: a structure there is either useless or an injection vector. Control
/// characters and over-long values are refused for the same reason. A rejected
/// claim is counted and omitted — never truncated, because a silently shortened
/// identifier is worse than a missing one.
fn asserted_claims(
    extra: &std::collections::BTreeMap<String, Value>,
    configured: &[String],
) -> std::collections::BTreeMap<String, String> {
    const MAX_VALUE: usize = 128;

    let mut asserted = std::collections::BTreeMap::new();

    for name in configured {
        let Some(value) = extra.get(name) else {
            continue;
        };

        let rendered = match value {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            _ => {
                metrics::counter!("gateway_claim_rejected_total", "claim" => name.clone())
                    .increment(1);
                continue;
            }
        };

        let clean = !rendered.is_empty()
            && rendered.len() <= MAX_VALUE
            && !rendered.chars().any(char::is_control);

        if !clean {
            metrics::counter!("gateway_claim_rejected_total", "claim" => name.clone()).increment(1);
            continue;
        }

        asserted.insert(name.clone(), rendered);
    }

    asserted
}

fn key_algorithm_matches(key: jsonwebtoken::jwk::KeyAlgorithm, header: Algorithm) -> bool {
    use jsonwebtoken::jwk::KeyAlgorithm;

    matches!(
        (key, header),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
    )
}

fn parse_algorithm(raw: &str) -> Result<Algorithm, String> {
    match raw.to_ascii_uppercase().as_str() {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        other => Err(format!("unsupported OAuth algorithm `{other}`")),
    }
}

fn validate_claim_lengths(claims: &Claims) -> Result<(), OAuthError> {
    let too_long = |value: &str, max: usize| value.len() > max;
    let roles = claims.roles();
    let scopes = claims.scopes();

    if claims.sub.is_empty()
        || too_long(&claims.sub, MAX_SUBJECT_LEN)
        || claims
            .email
            .as_deref()
            .is_some_and(|email| too_long(email, MAX_EMAIL_LEN))
        || claims
            .azp
            .as_deref()
            .is_some_and(|client| too_long(client, MAX_CLIENT_LEN))
        || claims
            .client_id
            .as_deref()
            .is_some_and(|client| too_long(client, MAX_CLIENT_LEN))
        || claims
            .jti
            .as_deref()
            .is_some_and(|id| too_long(id, MAX_TOKEN_ID_LEN))
        || claims
            .tenant
            .as_deref()
            .is_some_and(|tenant| too_long(tenant.trim(), MAX_TENANT_LEN))
        || claims
            .tenant
            .as_deref()
            .is_some_and(|tenant| tenant.chars().any(char::is_control))
    {
        return Err(OAuthError::Invalid);
    }

    if roles.len() > MAX_ROLES
        || roles
            .iter()
            .any(|role| role.len() > MAX_ROLE_LEN)
        || scopes.len() > MAX_SCOPES
        || scopes
            .iter()
            .any(|scope| scope.len() > MAX_SCOPE_LEN)
    {
        return Err(OAuthError::Invalid);
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    scope: Option<StringOrList>,
    #[serde(default)]
    scp: Option<StringOrList>,
    #[serde(default)]
    roles: Option<StringOrList>,
    #[serde(default)]
    groups: Option<StringOrList>,
    /// Claims the gateway does not interpret, kept so configured ones can be
    /// recorded. Never read for authorization.
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, Value>,
}

impl Claims {
    fn scopes(&self) -> HashSet<String> {
        let mut scopes = HashSet::new();

        if let Some(scope) = &self.scope {
            scopes.extend(scope.iter());
        }
        if let Some(scp) = &self.scp {
            scopes.extend(scp.iter());
        }

        scopes
    }

    fn roles(&self) -> HashSet<String> {
        let mut roles = HashSet::new();

        if let Some(value) = &self.roles {
            roles.extend(value.iter());
        }
        if let Some(value) = &self.groups {
            roles.extend(value.iter());
        }

        roles
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    fn iter(&self) -> Vec<String> {
        match self {
            Self::One(value) => value
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            Self::Many(values) => values
                .iter()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .collect(),
        }
    }
}

struct JwksCache {
    uri: String,
    client: reqwest::Client,
    ttl: Duration,
    state: RwLock<CacheState>,
    refresh: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct CacheState {
    keys: Option<Arc<JwkSet>>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

impl JwksCache {
    fn new(uri: &str, ttl: Duration) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("api-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| format!("could not build JWKS client: {error}"))?;

        Ok(Self {
            uri: uri.to_owned(),
            client,
            ttl,
            state: RwLock::new(CacheState::default()),
            refresh: tokio::sync::Mutex::new(()),
        })
    }

    async fn key(&self, kid: Option<&str>) -> Result<jsonwebtoken::jwk::Jwk, OAuthError> {
        if let Some(jwk) = self.find(kid) {
            if self.is_fresh() {
                return Ok(jwk);
            }

            // A stale set is refreshed in the background of this request; a
            // failure still lets the cached key serve until the cooldown.
            self.refresh(false).await?;

            return self
                .find(kid)
                .ok_or(OAuthError::Invalid);
        }

        // An unknown `kid` usually means the issuer rotated keys. Refresh even
        // within the TTL, but respect the cooldown so a stream of unknown kids
        // cannot become a JWKS amplifier.
        self.refresh(true).await?;

        self.find(kid)
            .ok_or(OAuthError::Invalid)
    }

    fn is_fresh(&self) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        state
            .fetched_at
            .is_some_and(|at| at.elapsed() < self.ttl)
    }

    fn find(&self, kid: Option<&str>) -> Option<jsonwebtoken::jwk::Jwk> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys = state.keys.as_ref()?;

        match kid {
            Some(kid) => keys.find(kid).cloned(),
            None => keys
                .keys
                .iter()
                .find(|jwk| {
                    !matches!(
                        jwk.common.public_key_use,
                        Some(jsonwebtoken::jwk::PublicKeyUse::Encryption)
                    )
                })
                .cloned(),
        }
    }

    async fn refresh(&self, force: bool) -> Result<(), OAuthError> {
        let _guard = self.refresh.lock().await;

        let fresh = {
            let state = self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .fetched_at
                .is_some_and(|at| at.elapsed() < self.ttl)
        };

        if fresh && !force {
            return Ok(());
        }

        let too_soon = {
            let state = self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .last_attempt
                .is_some_and(|at| at.elapsed() < REFRESH_COOLDOWN)
        };

        // Even a forced refresh (an unknown `kid`) must respect the cooldown
        // once a usable key set exists. Without this, random `kid` values turn
        // every request into a fetch against the issuer.
        if too_soon {
            let has_keys = self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .keys
                .is_some();

            if has_keys {
                return Ok(());
            }

            // No cached key and a fetch was just attempted: report an outage
            // instead of serialising every request behind another 5 s fetch.
            return Err(OAuthError::Unavailable);
        }

        let fetched = self.fetch().await;

        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.last_attempt = Some(Instant::now());

        match fetched {
            Ok(keys) => {
                state.keys = Some(Arc::new(keys));
                state.fetched_at = Some(Instant::now());
                metrics::gauge!("gateway_oauth_jwks_ready").set(1.0);
                Ok(())
            }
            Err(error) => {
                // A transient JWKS failure must not discard a usable cache.
                if state.keys.is_some() {
                    tracing::warn!(%error, "JWKS refresh failed; using cached keys");
                    Ok(())
                } else {
                    metrics::gauge!("gateway_oauth_jwks_ready").set(0.0);
                    tracing::warn!(%error, "JWKS unavailable and no keys are cached");
                    Err(OAuthError::Unavailable)
                }
            }
        }
    }

    async fn fetch(&self) -> Result<JwkSet, String> {
        let response = self
            .client
            .get(&self.uri)
            .send()
            .await
            .map_err(|_| "JWKS request failed".to_owned())?;

        if !response.status().is_success() {
            return Err(format!("JWKS returned HTTP {}", response.status()));
        }

        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err("JWKS response is too large".to_owned());
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|_| "JWKS body failed".to_owned())?;

        if bytes.len() > MAX_JWKS_BYTES {
            return Err("JWKS response is too large".to_owned());
        }

        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "JWKS is not JSON".to_owned())?;
        let entries = value
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "JWKS has no keys array".to_owned())?;

        let mut keys = Vec::with_capacity(entries.len());

        for entry in entries {
            match serde_json::from_value::<Jwk>(entry.clone()) {
                Ok(jwk) => keys.push(jwk),
                // One unsupported algorithm (post-quantum, vendor-specific)
                // must not take the whole issuer offline.
                Err(error) => {
                    tracing::warn!(?error, "skipping unsupported JWKS key");
                }
            }
        }

        if keys.is_empty() {
            return Err("JWKS has no usable keys".to_owned());
        }

        Ok(JwkSet { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode, jwk::Jwk};
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    /// Test-only RSA key. Never used by a deployment.
    const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCmqeyy1U6aPHgP
mK/K4tu6w++auknAy+AvgvWXYFIU+8PJPoxANGhVIU0NJ//vFWHpqfgCdrCRzhul
bkrUvfLbeapby13RDGBkqqlew3TTD0POB6ju4SuyEoMLr378816BGThKCLrurX9s
oobo/meB2Z7Yv4hKFTLXodsyJ86MiEQZOgZC8OhRrWTKlpeMpeOMhwOAXxIsg5nA
dEojcEsfRmSTnxnq4k6D2UMtYKiksmakr3iXdISV9QOGTIEftopQIwsSkCMFhiP/
oG+PzUNelpiSVSQRVDKIED6Ls75mNCskK6QC7MtDG0FpvioLEvUQGsogqC17fY4x
gY5X9v+lAgMBAAECggEAEYdgC+5lDidw+zb0ZPLXkxJGMkWzOcdXmgz8i+zHWp9L
gsWE1ms3U/N6LqQ321X/jntgHdDiQPDmtc9eqHcdQq8jrJ7m4Z9FyMtYSqK6Yp5s
ORBTg2MEXP4XG/9bwaVObxE6Jd3lh0fmgIRW4HeCvG9T285yj6l2HPl62+YVknBw
0dWYQ9m5WfI/aSVXQUNCZ4eSV8rFdFD3JfZhO4zYU6I9CNOG2g/2WRI/1TLXepl2
tKqAoo/UaJZyRH+/mIi/+bAfg18L9xssIZrclk4iW49U/GQQrXGrrzbGJBbW80tX
IhJQW0pmn/D+p5w7AL2DHBnNFROinhCQJ+2GOe2sewKBgQDm91dGRGzQgddi9CMj
+POG+OS2pYoFDQ1yO1KWYmN5yYypfBr0c2TCfKbqDRzCemDBieYTdISjqXhmHZI1
bMeQU3qrjkphfhQivZ7yVPOnUvmC1rXHnYTTnFcJZsxEbJzJEyaeqCz7e+2im8y/
rYcokWiOBB3uD/lpB4qD/eJ2fwKBgQC4ul+cbbBZqTZ9aab+PddBCGcyVFs5Cz3l
DfEr5gOOTEPHvehM2bbQZTzf7X0Di5Wn0suf6hOzhe4Tq9B7vDr9SdyqPIcyUufY
+0dymgTyJ0thnsmeJYSwlv1zmzuot4bqBunOXvlCDSbZ4MI7J8RLWtdBsXakmb4c
0F7Q+n3f2wKBgC8de6843B24rvBfrx9ydHMvKLDdmgcnv3tzAIju7y3z4H7ecz00
oPRPq1kJbbl6b2xrrgR/+2LLemUSWTYOx7L4ZIjEkQXMS10+40K5865Jbd6z4Acl
aegk91hSoQ7APUeDYZhx5CM1B6fpMl5TjsPGzdZSnqxmk9FKGYaNbvoPAoGAXztl
swUxVufPOZRQDN3grJwiZ2XpqVzMSduIK3Nm/eL/Rmf27DeI8aJfYanTOxKo0l3v
r79C7NfsxqNa1Y9SceW0JucRY7Yt5ESWrtQMHLJ5QBhWJHt/DnKoswKiHPaQTPHH
cyavJYgWMViXiVuU7KwmMK3GVlEUG1Kort+UKOUCgYBCu6Qn1z00i49TpE7TIn7m
ercd4hPv3SmnBFyYV4oZRj7+BHGzfT7lkXcJTYQ0IMYTaJx6GfkORE9eawjkP3z3
ey3KM2ka3++m2mN1U9N1N5Fvhvp3m4rvGashBEc/jIgiXG/XY3z9X+67UhLx6pHO
IBtZQ7lereVwJCPn4Be5FQ==
-----END PRIVATE KEY-----"#;

    const ISSUER: &str = "https://issuer.test";
    const AUDIENCE: &str = "https://gw.test/mcp";

    fn encoding() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).expect("test key")
    }

    /// Public half of the test key, base64url modulus, exponent 65537.
    const TEST_N: &str = "pqnsstVOmjx4D5ivyuLbusPvmrpJwMvgL4L1l2BSFPvDyT6MQDRoVSFNDSf_7xVh6an4Anawkc4bpW5K1L3y23mqW8td0QxgZKqpXsN00w9Dzgeo7uErshKDC69-_PNegRk4Sgi67q1_bKKG6P5ngdme2L-IShUy16HbMifOjIhEGToGQvDoUa1kypaXjKXjjIcDgF8SLIOZwHRKI3BLH0Zkk58Z6uJOg9lDLWCopLJmpK94l3SElfUDhkyBH7aKUCMLEpAjBYYj_6Bvj81DXpaYklUkEVQyiBA-i7O-ZjQrJCukAuzLQxtBab4qCxL1EBrKIKgte32OMYGOV_b_pQ";

    fn jwks() -> JwkSet {
        JwkSet {
            keys: vec![jwk("test-key")],
        }
    }

    fn jwk(kid: &str) -> Jwk {
        serde_json::from_value(json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": TEST_N,
            "e": "AQAB",
        }))
        .expect("test jwk")
    }

    async fn issuer(jwks_status: u16) -> MockServer {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(if jwks_status == 200 {
                ResponseTemplate::new(200).set_body_json(jwks())
            } else {
                ResponseTemplate::new(jwks_status)
            })
            .mount(&server)
            .await;

        server
    }

    fn config(jwks_uri: String) -> OAuthConfig {
        OAuthConfig {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            jwks_uri,
            algorithms: vec!["rs256".to_owned()],
            clock_skew: Duration::from_secs(5),
            jwks_ttl: Duration::from_secs(300),
            resource: AUDIENCE.to_owned(),
            authorization_servers: vec![ISSUER.to_owned()],
            scopes_supported: vec!["mcp:tools".to_owned()],
            default_tenant: "acme".to_owned(),
            audit_claims: vec!["project_id".to_owned()],
            token_exchange: None,
        }
    }

    fn token(claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_owned());

        encode(&header, &claims, &encoding()).expect("token")
    }

    fn valid_claims() -> serde_json::Value {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-1",
            "exp": (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()) + 300,
            "email": "user@example.com",
            "azp": "chatgpt",
            "jti": "token-1",
            "scope": "mcp:tools read",
            "groups": ["support"],
        })
    }

    async fn oauth(server: &MockServer) -> OAuth {
        OAuth::new(&config(format!("{}/jwks", server.uri()))).expect("oauth")
    }

    #[tokio::test]
    async fn accepts_a_valid_token_and_maps_its_claims() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;

        let identity = oauth
            .authenticate(&token(valid_claims()))
            .await
            .expect("valid token");

        assert_eq!(identity.subject, "user-1");
        assert_eq!(identity.client_id, "chatgpt");
        assert_eq!(identity.tenant_id, "acme");
        assert!(identity.scopes.contains("mcp:tools"));
        assert!(identity.roles.contains("support"));
        assert_eq!(identity.token_id.as_deref(), Some("token-1"));
    }

    #[tokio::test]
    async fn accepts_scope_claims_as_a_string_or_an_array() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;
        let mut claims = valid_claims();
        claims["scope"] = json!(["mcp:tools", "read"]);

        let identity = oauth
            .authenticate(&token(claims))
            .await
            .expect("valid token");

        assert!(identity.scopes.contains("mcp:tools"));
        assert!(identity.scopes.contains("read"));
    }

    #[tokio::test]
    async fn trims_a_tenant_claim_before_using_it() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;
        let mut claims = valid_claims();
        claims["tenant"] = json!("  acme  ");

        let identity = oauth
            .authenticate(&token(claims))
            .await
            .expect("valid token");

        assert_eq!(identity.tenant_id, "acme");
    }

    #[tokio::test]
    async fn rejects_a_token_for_another_audience() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;
        let mut claims = valid_claims();
        claims["aud"] = json!("https://other.test/mcp");

        assert!(matches!(
            oauth.authenticate(&token(claims)).await,
            Err(OAuthError::Invalid)
        ));
    }

    #[tokio::test]
    async fn rejects_an_expired_token() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;
        let mut claims = valid_claims();
        claims["exp"] = json!(1);

        assert!(matches!(
            oauth.authenticate(&token(claims)).await,
            Err(OAuthError::Invalid)
        ));
    }

    #[tokio::test]
    async fn rejects_a_token_from_another_issuer() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;
        let mut claims = valid_claims();
        claims["iss"] = json!("https://evil.test");

        assert!(matches!(
            oauth.authenticate(&token(claims)).await,
            Err(OAuthError::Invalid)
        ));
    }

    #[tokio::test]
    async fn rejects_an_id_token() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        header.typ = Some("id+jwt".to_owned());
        let token = encode(&header, &valid_claims(), &encoding()).unwrap();

        assert!(matches!(
            oauth.authenticate(&token).await,
            Err(OAuthError::Invalid)
        ));
    }

    #[tokio::test]
    async fn a_token_signed_with_an_unlisted_algorithm_is_rejected() {
        let server = issuer(200).await;
        let oauth = oauth(&server).await;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_owned());
        let key = EncodingKey::from_secret(b"a-shared-secret").expect("hmac key");
        let token = encode(&header, &valid_claims(), &key).expect("token");

        assert!(matches!(
            oauth.authenticate(&token).await,
            Err(OAuthError::Invalid)
        ));
    }

    #[test]
    fn configured_claims_are_copied_and_the_rest_are_not() {
        let mut extra = std::collections::BTreeMap::new();
        extra.insert("project_id".to_owned(), serde_json::json!("proj-42"));
        extra.insert("agent_id".to_owned(), serde_json::json!(7));
        extra.insert("groups".to_owned(), serde_json::json!(["a", "b"]));

        let asserted = asserted_claims(
            &extra,
            &[
                "project_id".to_owned(),
                "agent_id".to_owned(),
                "groups".to_owned(),
                "missing".to_owned(),
            ],
        );

        assert_eq!(
            asserted
                .get("project_id")
                .map(String::as_str),
            Some("proj-42")
        );
        assert_eq!(
            asserted
                .get("agent_id")
                .map(String::as_str),
            Some("7")
        );
        assert!(!asserted.contains_key("groups"), "structures are refused");
        assert!(!asserted.contains_key("missing"));
    }

    #[test]
    fn claims_with_control_characters_or_excess_length_are_refused() {
        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            "project_id".to_owned(),
            serde_json::json!("proj\r\nX-Injected: 1"),
        );
        extra.insert("agent_id".to_owned(), serde_json::json!("a".repeat(129)));

        let asserted = asserted_claims(&extra, &["project_id".to_owned(), "agent_id".to_owned()]);

        assert!(asserted.is_empty());
    }

    #[tokio::test]
    async fn a_jwks_outage_is_availability_not_invalid_credentials() {
        let server = issuer(503).await;
        let oauth = oauth(&server).await;

        assert!(matches!(
            oauth
                .authenticate(&token(valid_claims()))
                .await,
            Err(OAuthError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn an_outage_is_not_amplified_by_one_fetch_per_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let oauth = oauth(&server).await;

        for _ in 0..3 {
            assert!(matches!(
                oauth
                    .authenticate(&token(valid_claims()))
                    .await,
                Err(OAuthError::Unavailable)
            ));
        }
    }

    #[tokio::test]
    async fn unsupported_jwks_entries_do_not_take_the_issuer_offline() {
        let server = MockServer::start().await;
        let valid = serde_json::to_value(jwk("test-key")).unwrap();
        let unsupported = json!({
            "kty": "AKP",
            "kid": "post-quantum",
            "alg": "ML-DSA-65",
            "publicKey": "AAAA"
        });

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [valid, unsupported]
            })))
            .mount(&server)
            .await;

        let oauth = oauth(&server).await;
        let identity = oauth
            .authenticate(&token(valid_claims()))
            .await
            .expect("valid RSA key is still usable");

        assert_eq!(identity.subject, "user-1");
    }

    #[tokio::test]
    async fn an_unknown_key_refreshes_once_before_failing() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(JwkSet {
                keys: vec![jwk("test-key")],
            }))
            .expect(1)
            .mount(&server)
            .await;

        let oauth = oauth(&server).await;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rotated-key".to_owned());
        let token = encode(&header, &valid_claims(), &encoding()).unwrap();

        assert!(matches!(
            oauth.authenticate(&token).await,
            Err(OAuthError::Invalid)
        ));
    }

    #[test]
    fn metadata_url_includes_the_resource_path() {
        let oauth = OAuth::new(&config("https://issuer.test/jwks".to_owned())).expect("oauth");

        assert_eq!(
            oauth.resource_metadata_url(),
            "https://gw.test/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(oauth.metadata()["resource"], AUDIENCE);
    }

    #[test]
    fn unsupported_algorithms_are_rejected_at_construction() {
        let mut config = config("https://issuer.test/jwks".to_owned());
        config.algorithms = vec!["hs256".to_owned()];

        assert!(OAuth::new(&config).is_err());
    }
}
