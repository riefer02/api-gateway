//! RFC 8693 token exchange.
//!
//! The inbound token is addressed to the gateway. An upstream with a configured
//! audience receives a different, short-lived token minted for that audience.
//! The inbound token is never forwarded: that is token passthrough, and MCP
//! forbids it.
//!
//! Exchanged tokens are cached by `(subject, audience, scope)` until shortly
//! before expiry. The cache is per replica and bounded by the number of active
//! users; entries are dropped on expiry and on a full sweep.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::config::{ClientAuth, SecretString, TokenExchangeConfig};

/// Leave a margin so a token cannot expire between our clock and the upstream.
const EXPIRY_MARGIN: Duration = Duration::from_secs(30);
const MAX_CACHE_ENTRIES: usize = 10_000;
const MAX_CACHE_TTL: Duration = Duration::from_secs(3_600);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    /// The authorization server rejected the exchange (bad token or policy).
    Denied,
    /// The authorization server could not be reached or returned a 5xx.
    Unavailable,
}

pub(crate) struct TokenExchange {
    client: Client,
    endpoint: String,
    client_id: SecretString,
    client_secret: SecretString,
    client_auth: ClientAuth,
    cache: Mutex<HashMap<CacheKey, CachedToken>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    tenant: String,
    subject: String,
    audience: String,
    scope: Option<String>,
    /// A hash of the inbound token. The AS can bind a decision to a specific
    /// token (client, acr/amr, revocation); reusing T1's result for T2 would
    /// silently discard that decision.
    token_fingerprint: String,
}

struct CachedToken {
    token: SecretString,
    expires_at: Instant,
}

impl TokenExchange {
    pub(crate) fn new(config: &TokenExchangeConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("api-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| format!("could not build token-exchange client: {error}"))?;

        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            client_auth: config.client_auth,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Returns a token for `audience`, or an error that maps to a gateway
    /// status without leaking the authorization server's response body.
    pub(crate) async fn exchange(
        &self,
        tenant: &str,
        subject: &str,
        subject_token: &str,
        audience: &str,
        scope: Option<&str>,
    ) -> Result<SecretString, ExchangeError> {
        let key = CacheKey {
            tenant: tenant.to_owned(),
            subject: subject.to_owned(),
            audience: audience.to_owned(),
            scope: scope.map(str::to_owned),
            token_fingerprint: hex::encode(Sha256::digest(subject_token.as_bytes())),
        };

        if let Some(token) = self.cached(&key).await {
            return Ok(token);
        }

        let mut form = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("subject_token", subject_token),
            ("audience", audience),
        ];

        if let Some(scope) = scope {
            form.push(("scope", scope));
        }

        let mut request = self.client.post(&self.endpoint);

        request = match self.client_auth {
            ClientAuth::Basic => {
                request.basic_auth(self.client_id.expose(), Some(self.client_secret.expose()))
            }
            ClientAuth::Post => {
                form.push(("client_id", self.client_id.expose()));
                form.push(("client_secret", self.client_secret.expose()));
                request
            }
        };

        let response = request
            .form(&form)
            .send()
            .await
            .map_err(|_| ExchangeError::Unavailable)?;

        let status = response.status();

        if status.is_server_error() {
            return Err(ExchangeError::Unavailable);
        }

        if !status.is_success() {
            return Err(ExchangeError::Denied);
        }

        let body: ExchangeResponse = response
            .json()
            .await
            .map_err(|_| ExchangeError::Unavailable)?;

        if let Some(issued) = &body.issued_token_type
            && issued != "urn:ietf:params:oauth:token-type:access_token"
        {
            return Err(ExchangeError::Denied);
        }

        if let Some(token_type) = &body.token_type
            && !token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(ExchangeError::Denied);
        }

        if body.access_token.is_empty() {
            return Err(ExchangeError::Denied);
        }

        let lifetime = Duration::from_secs(body.expires_in.unwrap_or(60).max(1));
        let cache_for = lifetime
            .min(MAX_CACHE_TTL)
            .saturating_sub(EXPIRY_MARGIN)
            .max(Duration::from_secs(1));
        let token = SecretString::new(body.access_token);

        self.store(key, token.clone(), Instant::now() + cache_for)
            .await;

        Ok(token)
    }

    async fn cached(&self, key: &CacheKey) -> Option<SecretString> {
        let mut cache = self.cache.lock().await;

        match cache.get(key) {
            Some(cached) if cached.expires_at > Instant::now() => Some(cached.token.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    async fn store(&self, key: CacheKey, token: SecretString, expires_at: Instant) {
        let mut cache = self.cache.lock().await;

        if cache.len() >= MAX_CACHE_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, cached| cached.expires_at > now);
        }

        if cache.len() >= MAX_CACHE_ENTRIES {
            // A full cache is a memory bound, not a correctness problem: fail
            // open by skipping the cache rather than evicting a live token.
            return;
        }

        cache.insert(key, CachedToken { token, expires_at });
    }
}

#[derive(Deserialize)]
struct ExchangeResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    issued_token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    async fn exchange_for(server: &MockServer) -> TokenExchange {
        TokenExchange::new(&TokenExchangeConfig {
            endpoint: format!("{}/token", server.uri()),
            client_id: SecretString::new("gateway"),
            client_secret: SecretString::new("secret"),
            client_auth: ClientAuth::Basic,
        })
        .expect("exchange")
    }

    #[tokio::test]
    async fn exchanges_and_caches_a_token() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "upstream-token",
                "token_type": "Bearer",
                "expires_in": 300
            })))
            .expect(1)
            .mount(&server)
            .await;

        let exchange = exchange_for(&server).await;

        let first = exchange
            .exchange(
                "tenant",
                "user-1",
                "subject-token",
                "https://mcp.internal",
                None,
            )
            .await
            .expect("first");
        let second = exchange
            .exchange(
                "tenant",
                "user-1",
                "subject-token",
                "https://mcp.internal",
                None,
            )
            .await
            .expect("second");

        assert_eq!(first.expose(), "upstream-token");
        assert_eq!(second.expose(), "upstream-token");
    }

    #[tokio::test]
    async fn binds_the_cache_to_the_token_and_tenant() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token",
                "token_type": "Bearer",
                "expires_in": 300
            })))
            .expect(3)
            .mount(&server)
            .await;

        let exchange = exchange_for(&server).await;

        exchange
            .exchange("tenant-a", "user", "token-1", "https://mcp", None)
            .await
            .expect("t1");
        exchange
            .exchange("tenant-a", "user", "token-1", "https://mcp", None)
            .await
            .expect("t1 cached");
        exchange
            .exchange("tenant-a", "user", "token-2", "https://mcp", None)
            .await
            .expect("t2");
        exchange
            .exchange("tenant-b", "user", "token-2", "https://mcp", None)
            .await
            .expect("other tenant");
    }

    #[tokio::test]
    async fn rejects_a_non_access_token_issued_type() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token"
            })))
            .mount(&server)
            .await;

        assert!(matches!(
            exchange_for(&server)
                .await
                .exchange("tenant", "user", "token", "https://mcp", None)
                .await,
            Err(ExchangeError::Denied)
        ));
    }

    #[tokio::test]
    async fn supports_client_secret_post() {
        use wiremock::matchers::body_string_contains;

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(body_string_contains("client_id=gateway"))
            .and(body_string_contains("client_secret=secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "upstream-token",
                "token_type": "Bearer",
                "expires_in": 300
            })))
            .expect(1)
            .mount(&server)
            .await;

        let exchange = TokenExchange::new(&TokenExchangeConfig {
            endpoint: format!("{}/token", server.uri()),
            client_id: SecretString::new("gateway"),
            client_secret: SecretString::new("secret"),
            client_auth: ClientAuth::Post,
        })
        .expect("exchange");

        exchange
            .exchange("tenant", "user", "subject", "https://mcp.internal", None)
            .await
            .expect("post auth exchange");
    }

    #[tokio::test]
    async fn separates_users_and_audiences() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token",
                "token_type": "Bearer",
                "expires_in": 300
            })))
            .expect(2)
            .mount(&server)
            .await;

        let exchange = exchange_for(&server).await;

        exchange
            .exchange("tenant", "user-1", "subject", "https://a", None)
            .await
            .expect("a");
        exchange
            .exchange("tenant", "user-2", "subject", "https://a", None)
            .await
            .expect("b");
    }

    #[tokio::test]
    async fn maps_denial_and_outage_differently() {
        let denied = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&denied)
            .await;

        assert!(matches!(
            exchange_for(&denied)
                .await
                .exchange("tenant", "user", "token", "aud", None)
                .await,
            Err(ExchangeError::Denied)
        ));

        let unavailable = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&unavailable)
            .await;

        assert!(matches!(
            exchange_for(&unavailable)
                .await
                .exchange("tenant", "user", "token", "aud", None)
                .await,
            Err(ExchangeError::Unavailable)
        ));
    }
}
