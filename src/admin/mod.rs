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
    #[error("{message}")]
    Conflict { message: String },
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
    pub(crate) enabled: bool,
    pub(crate) priority: i32,
}

#[derive(Debug)]
pub(crate) struct RouteSummary {
    pub(crate) id: String,
    pub(crate) methods: Vec<String>,
    pub(crate) path_prefix: String,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) upstream_id: String,
    pub(crate) enabled: bool,
    pub(crate) priority: i32,
}

#[derive(Debug)]
pub(crate) struct UpstreamSummary {
    pub(crate) id: String,
    pub(crate) base_url: String,
    pub(crate) timeout_ms: u32,
}

/// Every control-plane privilege. The string form is what `ADMIN_TOKENS` grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminScope {
    TenantsWrite,
    KeysRead,
    KeysWrite,
    ConfigRead,
    ConfigWrite,
    AuditRead,
}

impl AdminScope {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::TenantsWrite,
        Self::KeysRead,
        Self::KeysWrite,
        Self::ConfigRead,
        Self::ConfigWrite,
        Self::AuditRead,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TenantsWrite => "tenants:write",
            Self::KeysRead => "keys:read",
            Self::KeysWrite => "keys:write",
            Self::ConfigRead => "config:read",
            Self::ConfigWrite => "config:write",
            Self::AuditRead => "audit:read",
        }
    }
}

/// Who performed a mutation, and what their credential allows.
#[derive(Clone, Debug)]
pub(crate) struct Actor {
    pub(crate) name: String,
    pub(crate) source_ip: Option<String>,
    scopes: std::collections::HashSet<String>,
}

impl Actor {
    /// Trusted local operator (CLI) or bootstrap work: full admin.
    pub(crate) fn local(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source_ip: None,
            scopes: std::collections::HashSet::from(["*".to_owned()]),
        }
    }

    pub(crate) fn new(name: impl Into<String>, scopes: std::collections::HashSet<String>) -> Self {
        Self {
            name: name.into(),
            source_ip: None,
            scopes,
        }
    }

    pub(crate) fn with_source_ip(mut self, source_ip: Option<String>) -> Self {
        self.source_ip = source_ip;
        self
    }

    pub(crate) fn require(&self, scope: AdminScope) -> Result<(), crate::error::AppError> {
        if self.scopes.contains("*") || self.scopes.contains(scope.as_str()) {
            Ok(())
        } else {
            Err(crate::error::AppError::Forbidden)
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuditEntry {
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) subject: String,
    pub(crate) source_ip: Option<String>,
    pub(crate) request_id: Option<String>,
}

/// The control plane. One implementation, two adapters (CLI now, HTTP later).
pub(crate) struct AdminService {
    pool: PgPool,
    store: Arc<dyn ApiKeyStore>,
    verifier: Arc<KeyVerifier>,
    allow_hosts: Vec<String>,
    request_timeout: std::time::Duration,
}

impl AdminService {
    pub(crate) fn new(
        pool: PgPool,
        verifier: Arc<KeyVerifier>,
        allow_hosts: Vec<String>,
        store: Arc<dyn ApiKeyStore>,
        request_timeout: std::time::Duration,
    ) -> Self {
        Self {
            pool,
            store,
            verifier,
            allow_hosts,
            request_timeout,
        }
    }

    pub(crate) async fn create_tenant(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query("INSERT INTO tenants (id, status) VALUES ($1, 'active')")
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| conflict_or_store(error, "tenant", id))?;

        insert_audit(
            &mut *transaction,
            actor,
            "tenant.create",
            id,
            &serde_json::json!({}),
        )
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    pub(crate) async fn create_client(
        &self,
        actor: &Actor,
        id: &str,
        tenant_id: &str,
    ) -> Result<(), AdminError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query("INSERT INTO clients (id, tenant_id, status) VALUES ($1, $2, 'active')")
            .bind(id)
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                if is_reference_violation(&error) {
                    AdminError::NotFound {
                        entity: "tenant",
                        id: tenant_id.to_owned(),
                    }
                } else {
                    conflict_or_store(error, "client", id)
                }
            })?;

        insert_audit(
            &mut *transaction,
            actor,
            "client.create",
            id,
            &serde_json::json!({ "tenant_id": tenant_id }),
        )
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    pub(crate) async fn issue_key(
        &self,
        actor: &Actor,
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
                    self.audit_best_effort(
                        actor,
                        "key.create",
                        &key_id,
                        serde_json::json!({ "client_id": client_id, "scopes": scopes }),
                    )
                    .await;

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
            message: "could not allocate a unique key id".to_owned(),
        })
    }

    /// Issues a replacement for `key_id` with the same client, scopes, and
    /// remaining lifetime, then revokes the old key. The old key stays valid
    /// until the revoke commits.
    pub(crate) async fn rotate_key(
        &self,
        actor: &Actor,
        key_id: &str,
    ) -> Result<IssuedKey, AdminError> {
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
                message: format!("key `{key_id}` is already revoked"),
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
            .issue_key(actor, &client_id, &scopes, remaining)
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

        self.audit_best_effort(
            actor,
            "key.rotate",
            key_id,
            serde_json::json!({ "replacement": issued.key_id }),
        )
        .await;

        Ok(issued)
    }

    pub(crate) async fn revoke_key(&self, actor: &Actor, key_id: &str) -> Result<(), AdminError> {
        let revoked = self
            .store
            .revoke_by_key_id(&auth::ApiKeyId(key_id.to_owned()))
            .await
            .map_err(store_error)?;

        if !revoked {
            return Err(AdminError::NotFound {
                entity: "active key",
                id: key_id.to_owned(),
            });
        }

        self.audit_best_effort(actor, "key.revoke", key_id, serde_json::json!({}))
            .await;

        Ok(())
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
        actor: &Actor,
        id: &str,
        base_url: &str,
        timeout_ms: u32,
    ) -> Result<(), AdminError> {
        routing::validate_upstream_url(base_url, &self.allow_hosts).map_err(AdminError::Invalid)?;

        if !(1..=300_000).contains(&timeout_ms) {
            return Err(AdminError::Invalid(
                "timeout_ms must be between 1 and 300000".to_owned(),
            ));
        }

        // A per-upstream timeout longer than the whole-request deadline can
        // never fire: the request is cancelled first and counts as a failure.
        if u128::from(timeout_ms) > self.request_timeout.as_millis() {
            return Err(AdminError::Invalid(format!(
                "timeout_ms must not exceed the request deadline ({} ms)",
                self.request_timeout.as_millis()
            )));
        }

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

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
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        insert_audit(
            &mut *transaction,
            actor,
            "upstream.put",
            id,
            &serde_json::json!({ "base_url": base_url, "timeout_ms": timeout_ms }),
        )
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    pub(crate) async fn put_route(&self, actor: &Actor, spec: RouteSpec) -> Result<(), AdminError> {
        routing::validate_path_prefix(&spec.path_prefix).map_err(AdminError::Invalid)?;
        routing::parse_methods(&spec.methods).map_err(AdminError::Invalid)?;

        if !(-1_000..=1_000).contains(&spec.priority) {
            return Err(AdminError::Invalid(
                "priority must be between -1000 and 1000".to_owned(),
            ));
        }

        let rewrite = match spec.rewrite_prefix.as_deref() {
            Some(rewrite) => {
                routing::validate_rewrite(rewrite).map_err(AdminError::Invalid)?;
                Some(routing::normalize_rewrite(rewrite))
            }
            None => None,
        };

        let methods = normalize_methods(&spec.methods);

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        // Serialise competing writers on the single version row so two admins
        // cannot both pass the claim check and poison the table.
        sqlx::query("SELECT 1 FROM route_table_state WHERE only_one FOR UPDATE")
            .execute(&mut *transaction)
            .await
            .map_err(AdminError::Store)?;

        self.ensure_claim_is_free(&mut transaction, &spec.id, &spec.path_prefix, &methods)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO routes
                (id, upstream_id, path_prefix, methods, rewrite_prefix, scopes, enabled, priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE
               SET upstream_id = EXCLUDED.upstream_id,
                   path_prefix = EXCLUDED.path_prefix,
                   methods = EXCLUDED.methods,
                   rewrite_prefix = EXCLUDED.rewrite_prefix,
                   scopes = EXCLUDED.scopes,
                   enabled = EXCLUDED.enabled,
                   priority = EXCLUDED.priority,
                   updated_at = now()
            "#,
        )
        .bind(&spec.id)
        .bind(&spec.upstream_id)
        .bind(&spec.path_prefix)
        .bind(&methods)
        .bind(&rewrite)
        .bind(normalize_scopes(&spec.scopes)?)
        .bind(spec.enabled)
        .bind(spec.priority)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if is_reference_violation(&error) {
                AdminError::NotFound {
                    entity: "upstream",
                    id: spec.upstream_id.clone(),
                }
            } else {
                AdminError::Store(error)
            }
        })?;

        insert_audit(
            &mut *transaction,
            actor,
            "route.put",
            &spec.id,
            &serde_json::json!({
                "path_prefix": spec.path_prefix,
                "methods": methods,
                "upstream_id": spec.upstream_id,
                "scopes": spec.scopes,
            }),
        )
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    pub(crate) async fn list_routes(&self) -> Result<Vec<RouteSummary>, AdminError> {
        let rows = sqlx::query(
            "SELECT id, methods, path_prefix, rewrite_prefix, upstream_id, enabled, priority
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
                    enabled: row
                        .try_get("enabled")
                        .map_err(AdminError::Store)?,
                    priority: row
                        .try_get("priority")
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
            .map_err(AdminError::Store)?;

        self.audit_best_effort(
            &Actor::local("system"),
            "key.seed",
            "dev-local",
            serde_json::json!({ "scopes": scopes }),
        )
        .await;

        Ok(())
    }

    pub(crate) async fn delete_tenant(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        self.delete_row(
            actor,
            "tenant",
            "tenant.delete",
            id,
            "DELETE FROM tenants WHERE id = $1",
        )
        .await
    }

    pub(crate) async fn delete_client(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        self.delete_row(
            actor,
            "client",
            "client.delete",
            id,
            "DELETE FROM clients WHERE id = $1",
        )
        .await
    }

    pub(crate) async fn delete_upstream(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        self.delete_row(
            actor,
            "upstream",
            "upstream.delete",
            id,
            "DELETE FROM upstreams WHERE id = $1",
        )
        .await
    }

    pub(crate) async fn delete_route(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        self.delete_row(
            actor,
            "route",
            "route.delete",
            id,
            "DELETE FROM routes WHERE id = $1",
        )
        .await
    }

    /// One delete path for every table: unknown ids are a 404, rows still
    /// referenced by a foreign key are a 409, and the audit row commits with
    /// the delete.
    async fn delete_row(
        &self,
        actor: &Actor,
        entity: &'static str,
        action: &'static str,
        id: &str,
        statement: &'static str,
    ) -> Result<(), AdminError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        let result = sqlx::query(statement)
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                if is_reference_violation(&error) {
                    AdminError::Conflict {
                        message: format!(
                            "{entity} `{id}` is still referenced and cannot be deleted"
                        ),
                    }
                } else {
                    AdminError::Store(error)
                }
            })?;

        if result.rows_affected() == 0 {
            return Err(AdminError::NotFound {
                entity,
                id: id.to_owned(),
            });
        }

        insert_audit(&mut *transaction, actor, action, id, &serde_json::json!({}))
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

    /// Deletes audit rows older than the retention window. Called at boot and
    /// on a timer; a zero window means "keep everything".
    pub(crate) async fn prune_audit(
        &self,
        retention: std::time::Duration,
    ) -> Result<u64, AdminError> {
        if retention.is_zero() {
            return Ok(0);
        }

        let cutoff = OffsetDateTime::now_utc()
            - time::Duration::seconds(i64::try_from(retention.as_secs()).unwrap_or(i64::MAX));

        let result = sqlx::query("DELETE FROM audit_events WHERE occurred_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .map_err(AdminError::Store)?;

        Ok(result.rows_affected())
    }

    pub(crate) async fn list_audit(&self, limit: i64) -> Result<Vec<AuditEntry>, AdminError> {
        let rows = sqlx::query(
            "SELECT occurred_at, actor, action, subject, source_ip, request_id
             FROM audit_events
             ORDER BY occurred_at DESC, id DESC
             LIMIT $1",
        )
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    occurred_at: row
                        .try_get("occurred_at")
                        .map_err(AdminError::Store)?,
                    actor: row
                        .try_get("actor")
                        .map_err(AdminError::Store)?,
                    action: row
                        .try_get("action")
                        .map_err(AdminError::Store)?,
                    subject: row
                        .try_get("subject")
                        .map_err(AdminError::Store)?,
                    source_ip: row
                        .try_get("source_ip")
                        .map_err(AdminError::Store)?,
                    request_id: row
                        .try_get("request_id")
                        .map_err(AdminError::Store)?,
                })
            })
            .collect()
    }

    /// Store-backed mutations commit inside the store, so their audit row is a
    /// second write. A failure is logged rather than reported as a failed
    /// mutation, because the mutation did happen.
    async fn audit_best_effort(
        &self,
        actor: &Actor,
        action: &str,
        subject: &str,
        detail: serde_json::Value,
    ) {
        if let Err(error) = insert_audit(&self.pool, actor, action, subject, &detail).await {
            tracing::warn!(%error, action, subject, "audit write failed");
        }
    }

    async fn ensure_claim_is_free(
        &self,
        transaction: &mut sqlx::PgConnection,
        id: &str,
        path_prefix: &str,
        methods: &[String],
    ) -> Result<(), AdminError> {
        let claimed: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM routes
             WHERE path_prefix = $1 AND methods && $2::text[] AND id <> $3
             LIMIT 1",
        )
        .bind(path_prefix)
        .bind(methods)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        if claimed.is_some() {
            return Err(AdminError::Invalid(format!(
                "{} on `{}` is already claimed by another route",
                methods.join(","),
                path_prefix
            )));
        }

        Ok(())
    }
}

async fn insert_audit<'e, E>(
    executor: E,
    actor: &Actor,
    action: &str,
    subject: &str,
    detail: &serde_json::Value,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO audit_events (actor, action, subject, source_ip, request_id, detail)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
    )
    .bind(&actor.name)
    .bind(action)
    .bind(subject)
    .bind(&actor.source_ip)
    .bind(crate::request_context::current())
    .bind(detail.to_string())
    .execute(executor)
    .await
    .map(|_| ())
}

fn normalize_methods(methods: &[String]) -> Vec<String> {
    methods
        .iter()
        .map(|method| method.trim().to_ascii_uppercase())
        .collect()
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
            message: format!("{entity} `{id}` already exists"),
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

/// A row still referenced by another table. Postgres reports `23503` for a
/// missing parent on insert and `23001` for a RESTRICT block on delete; both
/// mean "this would orphan something".
fn is_reference_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| {
            database.is_foreign_key_violation() || database.code().as_deref() == Some("23001")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{pg_pool, unique};

    #[tokio::test]
    async fn deleting_a_referenced_tenant_is_a_conflict() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let store: Arc<dyn ApiKeyStore> = Arc::new(
            auth::store::postgres::PostgresApiKeyStore::new(pool.clone()),
        );
        let service = AdminService::new(
            pool.clone(),
            Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
            Vec::new(),
            store,
            std::time::Duration::from_secs(15),
        );

        let actor = Actor::local("test");
        let tenant = unique("del-tenant");
        let client = unique("del-client");

        service
            .create_tenant(&actor, &tenant)
            .await
            .expect("create tenant");
        service
            .create_client(&actor, &client, &tenant)
            .await
            .expect("create client");

        let error = service
            .delete_tenant(&actor, &tenant)
            .await
            .expect_err("tenant is still referenced");

        assert!(
            matches!(error, AdminError::Conflict { .. }),
            "expected Conflict, got {error:?}"
        );

        service
            .delete_client(&actor, &client)
            .await
            .expect("delete client");
        service
            .delete_tenant(&actor, &tenant)
            .await
            .expect("delete tenant");
    }

    #[test]
    fn scope_vocabulary_matches_configuration() {
        let declared: Vec<&str> = AdminScope::ALL
            .iter()
            .map(|scope| scope.as_str())
            .collect();

        assert_eq!(
            declared,
            crate::config::ADMIN_SCOPES.to_vec(),
            "AdminScope and ADMIN_SCOPES must list the same privileges"
        );
    }

    #[tokio::test]
    async fn mutations_record_the_actor_and_source() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let store: Arc<dyn ApiKeyStore> = Arc::new(
            auth::store::postgres::PostgresApiKeyStore::new(pool.clone()),
        );
        let service = AdminService::new(
            pool.clone(),
            Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
            Vec::new(),
            store,
            std::time::Duration::from_secs(15),
        );

        let tenant = unique("audit-tenant");
        let actor = Actor::local("alice").with_source_ip(Some("10.0.0.7".to_owned()));

        service
            .create_tenant(&actor, &tenant)
            .await
            .expect("create tenant");

        let entries = service
            .list_audit(50)
            .await
            .expect("list audit");
        let entry = entries
            .iter()
            .find(|entry| entry.subject == tenant)
            .expect("audit entry for the tenant");

        assert_eq!(entry.actor, "alice");
        assert_eq!(entry.action, "tenant.create");
        assert_eq!(entry.source_ip.as_deref(), Some("10.0.0.7"));

        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }
}
