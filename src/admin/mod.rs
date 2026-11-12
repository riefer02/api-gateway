use std::{collections::BTreeSet, sync::Arc};

use sqlx::{PgPool, Row};
use thiserror::Error;
use time::OffsetDateTime;

use crate::auth::{
    self, ClientId, KeyVerifier, key,
    store::{ApiKeyStore, StoreError, postgres::is_unique_violation},
};
use crate::routing;

pub(crate) mod cli;
pub(crate) mod http;

#[derive(Debug, Error)]
pub(crate) enum AdminError {
    #[error("{entity} `{id}` already exists")]
    Conflict { entity: &'static str, id: String },
    #[error("{entity} `{id}` not found")]
    NotFound { entity: &'static str, id: String },
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("database unavailable")]
    Unavailable,
    #[error("database error")]
    Store(#[source] sqlx::Error),
}

#[derive(Debug)]
pub(crate) struct IssuedKey {
    pub(crate) key_id: String,
    pub(crate) token: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub(crate) struct KeySummary {
    pub(crate) key_id: String,
    pub(crate) client_id: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: Option<OffsetDateTime>,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub(crate) struct RouteSpec {
    pub(crate) id: String,
    pub(crate) path_prefix: String,
    pub(crate) methods: Vec<String>,
    pub(crate) upstream_id: String,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) scopes: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct RouteSummary {
    pub(crate) id: String,
    pub(crate) methods: Vec<String>,
    pub(crate) path_prefix: String,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) upstream_id: String,
}

#[derive(Debug)]
pub(crate) struct UpstreamSummary {
    pub(crate) id: String,
    pub(crate) base_url: String,
    pub(crate) timeout_ms: u32,
}

/// The control plane. One implementation, two adapters (CLI now, HTTP later).
pub(crate) struct AdminService {
    pool: PgPool,
    store: Arc<dyn ApiKeyStore>,
    verifier: Arc<KeyVerifier>,
    allow_hosts: Vec<String>,
}

impl AdminService {
    pub(crate) fn new(
        pool: PgPool,
        verifier: Arc<KeyVerifier>,
        allow_hosts: Vec<String>,
        store: Arc<dyn ApiKeyStore>,
    ) -> Self {
        Self {
            pool,
            store,
            verifier,
            allow_hosts,
        }
    }

    pub(crate) async fn create_tenant(&self, id: &str) -> Result<(), AdminError> {
        sqlx::query("INSERT INTO tenants (id, status) VALUES ($1, 'active')")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| conflict_or_store(error, "tenant", id))?;

        Ok(())
    }

    pub(crate) async fn create_client(&self, id: &str, tenant_id: &str) -> Result<(), AdminError> {
        sqlx::query("INSERT INTO clients (id, tenant_id, status) VALUES ($1, $2, 'active')")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|error| {
                if is_foreign_key_violation(&error) {
                    AdminError::NotFound {
                        entity: "tenant",
                        id: tenant_id.to_owned(),
                    }
                } else {
                    conflict_or_store(error, "client", id)
                }
            })?;

        Ok(())
    }

    pub(crate) async fn issue_key(
        &self,
        client_id: &str,
        scopes: &[String],
        expires_at: Option<OffsetDateTime>,
    ) -> Result<IssuedKey, AdminError> {
        validate_expiry(expires_at)?;
        let scopes = normalize_scopes(scopes)?;
        self.ensure_client_exists(client_id)
            .await?;

        // A key id collision is astronomically unlikely; regenerate rather than
        // retrying the same id, which could never succeed.
        for _ in 0..3 {
            let (key, secret) = key::generate(
                &self.verifier,
                ClientId(client_id.to_owned()),
                scopes.iter().cloned().collect(),
                expires_at,
            )
            .map_err(|error| AdminError::Invalid(format!("could not generate key: {error}")))?;

            let key_id = key.key_id.0.clone();
            let token = key::token(&key.key_id, &secret);

            match self.store.insert_key(key).await {
                Ok(()) => {
                    return Ok(IssuedKey {
                        key_id,
                        token,
                        scopes,
                        expires_at,
                    });
                }
                Err(StoreError::DuplicateKey) => continue,
                Err(StoreError::Unavailable) => return Err(AdminError::Unavailable),
            }
        }

        Err(AdminError::Conflict {
            entity: "key id",
            id: "generated".to_owned(),
        })
    }

    /// Issues a replacement for `key_id` with the same client, scopes, and
    /// remaining lifetime, then revokes the old key. The old key stays valid
    /// until the revoke commits.
    pub(crate) async fn rotate_key(&self, key_id: &str) -> Result<IssuedKey, AdminError> {
        let row = sqlx::query(
            r#"
            SELECT
                k.client_id,
                k.expires_at,
                k.revoked_at,
                COALESCE(array_agg(s.scope) FILTER (WHERE s.scope IS NOT NULL), '{}') AS scopes
            FROM api_keys k
            LEFT JOIN api_key_scopes s ON s.key_id = k.key_id
            WHERE k.key_id = $1
            GROUP BY k.key_id
            "#,
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AdminError::Store)?
        .ok_or_else(|| AdminError::NotFound {
            entity: "key",
            id: key_id.to_owned(),
        })?;

        let revoked_at: Option<OffsetDateTime> = row
            .try_get("revoked_at")
            .map_err(AdminError::Store)?;

        if revoked_at.is_some() {
            return Err(AdminError::Conflict {
                entity: "active key",
                id: key_id.to_owned(),
            });
        }

        let client_id: String = row
            .try_get("client_id")
            .map_err(AdminError::Store)?;
        let scopes: Vec<String> = row
            .try_get("scopes")
            .map_err(AdminError::Store)?;
        let expires_at: Option<OffsetDateTime> = row
            .try_get("expires_at")
            .map_err(AdminError::Store)?;
        let remaining = expires_at.filter(|expires_at| *expires_at > OffsetDateTime::now_utc());

        let issued = self
            .issue_key(&client_id, &scopes, remaining)
            .await?;

        let revoked = self
            .store
            .revoke_by_key_id(&auth::ApiKeyId(key_id.to_owned()))
            .await
            .map_err(store_error)?;

        if !revoked {
            // Do not leave an active credential whose token was never shown.
            let _ = self
                .store
                .revoke_by_key_id(&auth::ApiKeyId(issued.key_id.clone()))
                .await;

            return Err(AdminError::NotFound {
                entity: "key",
                id: key_id.to_owned(),
            });
        }

        Ok(issued)
    }

    pub(crate) async fn revoke_key(&self, key_id: &str) -> Result<(), AdminError> {
        let revoked = self
            .store
            .revoke_by_key_id(&auth::ApiKeyId(key_id.to_owned()))
            .await
            .map_err(store_error)?;

        if revoked {
            Ok(())
        } else {
            Err(AdminError::NotFound {
                entity: "active key",
                id: key_id.to_owned(),
            })
        }
    }

    pub(crate) async fn list_keys(&self, client_id: &str) -> Result<Vec<KeySummary>, AdminError> {
        let rows = sqlx::query(
            r#"
            SELECT
                k.key_id,
                k.client_id,
                k.created_at,
                k.expires_at,
                k.revoked_at,
                COALESCE(array_agg(s.scope) FILTER (WHERE s.scope IS NOT NULL), '{}') AS scopes
            FROM api_keys k
            LEFT JOIN api_key_scopes s ON s.key_id = k.key_id
            WHERE k.client_id = $1
            GROUP BY k.key_id
            ORDER BY k.created_at DESC
            "#,
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        rows.into_iter()
            .map(|row| {
                Ok(KeySummary {
                    key_id: row
                        .try_get("key_id")
                        .map_err(AdminError::Store)?,
                    client_id: row
                        .try_get("client_id")
                        .map_err(AdminError::Store)?,
                    scopes: row
                        .try_get("scopes")
                        .map_err(AdminError::Store)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(AdminError::Store)?,
                    expires_at: row
                        .try_get("expires_at")
                        .map_err(AdminError::Store)?,
                    revoked_at: row
                        .try_get("revoked_at")
                        .map_err(AdminError::Store)?,
                })
            })
            .collect()
    }

    /// Upstreams are declarative: re-adding one updates it. The allowlist is
    /// enforced here as well as at compile time, so a bad row is rejected
    /// before it can poison every reload.
    pub(crate) async fn put_upstream(
        &self,
        id: &str,
        base_url: &str,
        timeout_ms: u32,
    ) -> Result<(), AdminError> {
        routing::validate_upstream_url(base_url, &self.allow_hosts).map_err(AdminError::Invalid)?;

        sqlx::query(
            r#"
            INSERT INTO upstreams (id, base_url, timeout_ms)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO UPDATE
               SET base_url = EXCLUDED.base_url,
                   timeout_ms = EXCLUDED.timeout_ms,
                   updated_at = now()
            "#,
        )
        .bind(id)
        .bind(base_url)
        .bind(i32::try_from(timeout_ms).map_err(|_| {
            AdminError::Invalid(format!("timeout {timeout_ms}ms does not fit in an i32"))
        })?)
        .execute(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        Ok(())
    }

    pub(crate) async fn put_route(&self, spec: RouteSpec) -> Result<(), AdminError> {
        routing::validate_path_prefix(&spec.path_prefix).map_err(AdminError::Invalid)?;
        routing::parse_methods(&spec.methods).map_err(AdminError::Invalid)?;

        let rewrite = match spec.rewrite_prefix.as_deref() {
            Some(rewrite) => {
                routing::validate_rewrite(rewrite).map_err(AdminError::Invalid)?;
                Some(routing::normalize_rewrite(rewrite))
            }
            None => None,
        };

        let methods: Vec<String> = spec
            .methods
            .iter()
            .map(|method| method.trim().to_ascii_uppercase())
            .collect();

        self.ensure_claim_is_free(&spec).await?;

        sqlx::query(
            r#"
            INSERT INTO routes
                (id, upstream_id, path_prefix, methods, rewrite_prefix, scopes)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE
               SET upstream_id = EXCLUDED.upstream_id,
                   path_prefix = EXCLUDED.path_prefix,
                   methods = EXCLUDED.methods,
                   rewrite_prefix = EXCLUDED.rewrite_prefix,
                   scopes = EXCLUDED.scopes,
                   updated_at = now()
            "#,
        )
        .bind(&spec.id)
        .bind(&spec.upstream_id)
        .bind(&spec.path_prefix)
        .bind(&methods)
        .bind(&rewrite)
        .bind(normalize_scopes(&spec.scopes)?)
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if is_foreign_key_violation(&error) {
                AdminError::NotFound {
                    entity: "upstream",
                    id: spec.upstream_id.clone(),
                }
            } else {
                AdminError::Store(error)
            }
        })?;

        Ok(())
    }

    pub(crate) async fn list_routes(&self) -> Result<Vec<RouteSummary>, AdminError> {
        let rows = sqlx::query(
            "SELECT id, methods, path_prefix, rewrite_prefix, upstream_id
             FROM routes ORDER BY path_prefix",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        rows.into_iter()
            .map(|row| {
                Ok(RouteSummary {
                    id: row
                        .try_get("id")
                        .map_err(AdminError::Store)?,
                    methods: row
                        .try_get("methods")
                        .map_err(AdminError::Store)?,
                    path_prefix: row
                        .try_get("path_prefix")
                        .map_err(AdminError::Store)?,
                    rewrite_prefix: row
                        .try_get("rewrite_prefix")
                        .map_err(AdminError::Store)?,
                    upstream_id: row
                        .try_get("upstream_id")
                        .map_err(AdminError::Store)?,
                })
            })
            .collect()
    }

    pub(crate) async fn list_upstreams(&self) -> Result<Vec<UpstreamSummary>, AdminError> {
        let rows = sqlx::query("SELECT id, base_url, timeout_ms FROM upstreams ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(AdminError::Store)?;

        rows.into_iter()
            .map(|row| {
                Ok(UpstreamSummary {
                    id: row
                        .try_get("id")
                        .map_err(AdminError::Store)?,
                    base_url: row
                        .try_get("base_url")
                        .map_err(AdminError::Store)?,
                    timeout_ms: u32::try_from(
                        row.try_get::<i32, _>("timeout_ms")
                            .map_err(AdminError::Store)?,
                    )
                    .map_err(|_| AdminError::Invalid("timeout out of range".to_owned()))?,
                })
            })
            .collect()
    }

    /// Development convenience: provisions the local tenant/client and seeds
    /// the key from `DEV_API_KEY_SECRET`, replacing any previous one.
    pub(crate) async fn seed_development_key(
        &self,
        secret: &str,
        scopes: &[String],
    ) -> Result<(), AdminError> {
        let scopes = normalize_scopes(scopes)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query(
            "INSERT INTO tenants (id, status) VALUES ('tenant-local', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        sqlx::query(
            "INSERT INTO clients (id, tenant_id, status)
             VALUES ('client-local', 'tenant-local', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        sqlx::query("DELETE FROM api_keys WHERE key_id = 'dev-local'")
            .execute(&mut *transaction)
            .await
            .map_err(AdminError::Store)?;

        sqlx::query(
            "INSERT INTO api_keys (key_id, client_id, verifier, verifier_version, expires_at)
             VALUES ('dev-local', 'client-local', $1, $2, NULL)",
        )
        .bind(
            self.verifier
                .verifier_for(secret)
                .0
                .to_vec(),
        )
        .bind(i16::from(auth::verifier::VERIFIER_VERSION))
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        sqlx::query(
            "INSERT INTO api_key_scopes (key_id, scope) SELECT 'dev-local', unnest($1::text[])",
        )
        .bind(&scopes)
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    async fn ensure_client_exists(&self, client_id: &str) -> Result<(), AdminError> {
        let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM clients WHERE id = $1")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(AdminError::Store)?;

        if exists.is_some() {
            Ok(())
        } else {
            Err(AdminError::NotFound {
                entity: "client",
                id: client_id.to_owned(),
            })
        }
    }

    async fn ensure_claim_is_free(&self, spec: &RouteSpec) -> Result<(), AdminError> {
        let methods: Vec<String> = spec
            .methods
            .iter()
            .map(|method| method.trim().to_ascii_uppercase())
            .collect();

        let claimed: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM routes
             WHERE path_prefix = $1 AND methods && $2::text[] AND id <> $3
             LIMIT 1",
        )
        .bind(&spec.path_prefix)
        .bind(&methods)
        .bind(&spec.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        if claimed.is_some() {
            return Err(AdminError::Invalid(format!(
                "{} on `{}` is already claimed by another route",
                methods.join(","),
                spec.path_prefix
            )));
        }

        Ok(())
    }
}

fn normalize_scopes(scopes: &[String]) -> Result<Vec<String>, AdminError> {
    let mut normalized = BTreeSet::new();

    for scope in scopes {
        let scope = scope.trim();

        if scope.is_empty() {
            return Err(AdminError::Invalid("scopes must not be blank".to_owned()));
        }

        normalized.insert(scope.to_owned());
    }

    Ok(normalized.into_iter().collect())
}

fn validate_expiry(expires_at: Option<OffsetDateTime>) -> Result<(), AdminError> {
    if expires_at.is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc()) {
        return Err(AdminError::Invalid(
            "expiry must be in the future".to_owned(),
        ));
    }

    Ok(())
}

fn conflict_or_store(error: sqlx::Error, entity: &'static str, id: &str) -> AdminError {
    if is_unique_violation(&error) {
        AdminError::Conflict {
            entity,
            id: id.to_owned(),
        }
    } else {
        AdminError::Store(error)
    }
}

fn store_error(error: StoreError) -> AdminError {
    match error {
        StoreError::DuplicateKey => AdminError::Invalid("key id collision".to_owned()),
        StoreError::Unavailable => AdminError::Unavailable,
    }
}

fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if database.code().as_deref() == Some("23503"))
}
