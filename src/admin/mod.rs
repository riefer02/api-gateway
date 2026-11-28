use std::{collections::BTreeSet, sync::Arc};

use sqlx::{PgPool, Row};
use thiserror::Error;
use time::OffsetDateTime;

use crate::auth::{
    self, ClientId, KeyVerifier, key,
    store::{ApiKeyStore, StoreError, postgres::is_unique_violation},
};
use crate::mcp::ToolPolicy;
use crate::routing;

/// The privilege vocabulary is owned by `config`, where `ADMIN_TOKENS` is
/// parsed. Re-exported so the adapters keep one import site.
pub(crate) use crate::config::AdminScope;

pub(crate) mod accounts;
pub(crate) mod audit_read;
pub(crate) mod cli;
pub(crate) mod http;
pub(crate) mod keys;
pub(crate) mod routes;

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

/// The credential listing is a store read model, not a second definition.
pub(crate) use crate::auth::store::KeySummary;
pub(crate) use crate::auth::store::NewApiKey;

#[derive(Debug)]
/// A route write. `None` means "preserve the stored value" for every optional
/// field; an explicit empty string/`0` clears the field. This keeps a routine
/// timeout edit from widening tenancy or disabling tool policy.
pub(crate) struct RouteSpec {
    pub(crate) id: String,
    pub(crate) path_prefix: String,
    pub(crate) methods: Vec<String>,
    pub(crate) upstream_id: String,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) tenant_id: Option<String>,
    pub(crate) scopes: Option<Vec<String>>,
    pub(crate) tool_policy: Option<ToolPolicy>,
    pub(crate) request_timeout_ms: Option<u32>,
    pub(crate) max_response_bytes: Option<u64>,
    pub(crate) enabled: Option<bool>,
    pub(crate) priority: Option<i32>,
}

#[derive(Debug)]
pub(crate) struct RouteSummary {
    pub(crate) id: String,
    pub(crate) methods: Vec<String>,
    pub(crate) path_prefix: String,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) tenant_id: Option<String>,
    pub(crate) upstream_id: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) tool_policy: ToolPolicy,
    pub(crate) request_timeout_ms: Option<u32>,
    pub(crate) max_response_bytes: Option<u64>,
    pub(crate) enabled: bool,
    pub(crate) priority: i32,
}

#[derive(Debug)]
pub(crate) struct UpstreamSummary {
    pub(crate) id: String,
    pub(crate) base_url: String,
    pub(crate) timeout_ms: u32,
    pub(crate) audience: Option<String>,
    pub(crate) exchange_scope: Option<String>,
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

/// One data-plane call, as read back by an operator or SIEM exporter.
#[derive(Debug)]
pub(crate) struct DataAuditEntry {
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) tenant_id: String,
    pub(crate) subject: Option<String>,
    pub(crate) assistant: Option<String>,
    pub(crate) auth_method: String,
    pub(crate) mcp_method: Option<String>,
    pub(crate) route_id: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) decision: String,
    pub(crate) status: Option<u16>,
    pub(crate) latency_ms: Option<u32>,
    pub(crate) request_id: Option<String>,
    pub(crate) token_id: Option<String>,
    /// Configured claims and the caller's run id, as recorded. Identifiers
    /// only; this is what makes a claim worth recording.
    pub(crate) detail: serde_json::Value,
}

/// The control plane. One implementation, two adapters (CLI now, HTTP later).
pub(crate) struct AdminService {
    pool: PgPool,
    store: Arc<dyn ApiKeyStore>,
    verifier: Arc<KeyVerifier>,
    /// The routing policy the compiler will apply, so a write can be rejected
    /// for the same reasons a reload would reject it.
    routing: crate::config::RoutingConfig,
    max_request_timeout: std::time::Duration,
    token_exchange_enabled: bool,
}

mod audit;

pub(crate) use audit::ChainReport;

impl AdminService {
    /// Walks the control-plane audit chain. Paged, and pre-chain rows are
    /// counted rather than failed; see `audit::verify`.
    pub(crate) async fn verify_audit_chain(&self) -> Result<ChainReport, AdminError> {
        audit::verify(&self.pool).await
    }

    pub(crate) fn new(
        pool: PgPool,
        verifier: Arc<KeyVerifier>,
        routing: crate::config::RoutingConfig,
        store: Arc<dyn ApiKeyStore>,
        max_request_timeout: std::time::Duration,
        token_exchange_enabled: bool,
    ) -> Self {
        Self {
            pool,
            store,
            verifier,
            routing,
            max_request_timeout,
            token_exchange_enabled,
        }
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

        audit::insert(&mut transaction, actor, action, id, &serde_json::json!({}))
            .await
            .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
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
        let chained = async {
            let mut transaction = self.pool.begin().await?;
            audit::insert(&mut transaction, actor, action, subject, &detail).await?;
            transaction.commit().await?;

            Ok::<(), sqlx::Error>(())
        }
        .await;

        if let Err(error) = chained {
            metrics::counter!(crate::metric_names::ADMIN_AUDIT_WRITE_FAILURES_TOTAL).increment(1);
            tracing::warn!(%error, action, subject, "audit write failed");
        }
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
mod tests;
