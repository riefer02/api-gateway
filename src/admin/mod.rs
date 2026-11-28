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

pub(crate) struct IssuedKey {
    pub(crate) key_id: String,
    pub(crate) token: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

/// The token is the one secret the control plane hands out; it reaches an
/// operator through the CLI's stdout or the issue/rotate response body, and
/// nowhere else. A derived `Debug` would put it in any log line, panic message
/// or trace that formats the struct, so this is written by hand.
impl std::fmt::Debug for IssuedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedKey")
            .field("key_id", &self.key_id)
            .field("token", &"[redacted]")
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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

/// Default page size when a caller does not ask for one.
pub(crate) const DEFAULT_PAGE_SIZE: u32 = 100;
/// Largest page a caller may ask for. Bounds the work one request can cause.
pub(crate) const MAX_PAGE_SIZE: u32 = 1_000;

/// One page of a control-plane listing.
#[derive(Debug)]
pub(crate) struct Page<T> {
    pub(crate) items: Vec<T>,
    /// Pass to the next request as `cursor`. `None` means the listing ended.
    pub(crate) next_cursor: Option<String>,
}

/// A validated page request, shared by the HTTP and CLI adapters.
#[derive(Debug, Clone)]
pub(crate) struct PageRequest {
    pub(crate) limit: u32,
    cursor: Option<String>,
}

impl PageRequest {
    pub(crate) fn new(limit: Option<u32>, cursor: Option<String>) -> Result<Self, AdminError> {
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE);

        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(AdminError::Invalid(format!(
                "limit must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }

        // A present but blank cursor is a caller error, not "no cursor":
        // treating it as the first page makes a broken client loop forever
        // instead of seeing the 400 that names its mistake.
        let cursor = match cursor {
            Some(cursor) => {
                let cursor = cursor.trim();

                if cursor.is_empty() {
                    return Err(invalid_cursor());
                }

                Some(cursor.to_owned())
            }
            None => None,
        };

        Ok(Self { limit, cursor })
    }

    pub(crate) fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

/// Cursors are keyset, not offsets: they name the last row returned, so a row
/// inserted or deleted between pages cannot shift the page boundary.
///
/// Every listing sorts on a column a row never changes (`id`, `created_at`,
/// `occurred_at`). Sorting on a mutable column such as a route's path prefix
/// would let an edit move a row across the boundary, which is a skip or a
/// repeat the client cannot detect.
///
/// Each part is hex-encoded and the parts are joined with `.`, which hex can
/// never contain. Encoding the parts separately rather than joining them first
/// matters: a route id or path prefix may contain any character, including the
/// separator an "encode, then split" scheme would use.
///
/// A cursor starts with the listing it belongs to. Every listing is a keyset
/// over a different tuple, so a cursor from one is not merely wrong at another,
/// it is meaningless — and two listings can have the same arity, which made the
/// old "reject the wrong part count" check accept a keys cursor at the audit
/// endpoint. The tag makes that a 400, and makes every cursor nonempty by
/// construction: an empty id is `routes.`, not the empty string.
const MAX_CURSOR_BYTES: usize = 16_384;

/// The listings that page. The tag is the wire name; renaming one invalidates
/// cursors issued by the previous build, which is why it is not derived from a
/// type or a position.
#[derive(Clone, Copy)]
pub(crate) enum CursorKind {
    Routes,
    Upstreams,
    Keys,
    Audit,
    DataAudit,
}

impl CursorKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Routes => "routes",
            Self::Upstreams => "upstreams",
            Self::Keys => "keys",
            Self::Audit => "audit",
            Self::DataAudit => "data-audit",
        }
    }
}

pub(crate) fn encode_cursor(kind: CursorKind, parts: &[&str]) -> String {
    let mut cursor = String::with_capacity(16 + parts.len() * 16);
    cursor.push_str(kind.tag());

    for part in parts {
        cursor.push('.');
        cursor.push_str(&hex::encode(part));
    }

    cursor
}

/// The one rejection for an unusable cursor, wherever it is decoded.
pub(crate) fn invalid_cursor() -> AdminError {
    AdminError::Invalid(
        "cursor is not valid for this listing; pass `next_cursor` from the previous page"
            .to_owned(),
    )
}

pub(crate) fn decode_cursor(
    kind: CursorKind,
    encoded: &str,
    expected: usize,
) -> Result<Vec<String>, AdminError> {
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(invalid_cursor());
    }

    let Some((tag, encoded_parts)) = encoded.split_once('.') else {
        return Err(invalid_cursor());
    };

    if tag != kind.tag() {
        return Err(invalid_cursor());
    }

    let encoded_parts: Vec<&str> = encoded_parts.split('.').collect();

    if encoded_parts.len() != expected {
        return Err(invalid_cursor());
    }

    let mut parts = Vec::with_capacity(expected);

    for encoded_part in encoded_parts {
        let bytes = hex::decode(encoded_part).map_err(|_| invalid_cursor())?;
        let part = String::from_utf8(bytes).map_err(|_| invalid_cursor())?;
        parts.push(part);
    }

    Ok(parts)
}

/// Cursor for a listing ordered by `(timestamp, tiebreak)` descending.
///
/// The timestamp travels as Unix nanoseconds: exact, cheap to parse back, and
/// independent of `time`'s formatting features.
pub(crate) fn encode_timestamp_cursor(
    kind: CursorKind,
    at: OffsetDateTime,
    tiebreak: &str,
) -> String {
    let nanos = at.unix_timestamp_nanos().to_string();
    encode_cursor(kind, &[nanos.as_str(), tiebreak])
}

pub(crate) fn decode_timestamp_cursor(
    kind: CursorKind,
    cursor: &str,
) -> Result<(OffsetDateTime, String), AdminError> {
    let parts = decode_cursor(kind, cursor, 2)?;
    let nanos: i128 = parts[0]
        .parse()
        .map_err(|_| invalid_cursor())?;
    let at = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| invalid_cursor())?;

    Ok((at, parts[1].clone()))
}

/// Trims the extra row fetched to detect a next page and returns the cursor of
/// the last row that is actually part of this page.
fn finish_page<T>(mut entries: Vec<(T, String)>, limit: u32) -> Page<T> {
    let next_cursor = if entries.len() > limit as usize {
        entries.truncate(limit as usize);
        entries
            .last()
            .map(|(_, cursor)| cursor.clone())
    } else {
        None
    };

    Page {
        items: entries
            .into_iter()
            .map(|(item, _)| item)
            .collect(),
        next_cursor,
    }
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

/// Ids are keys, not labels: one addresses a row in a URL, names it in the
/// audit log, and becomes a keyset boundary. A blank id is none of those, and
/// as a single-part cursor it would encode to nothing, so the write path
/// refuses it. Rows written before this check still page correctly.
fn validate_id(entity: &'static str, id: &str) -> Result<(), AdminError> {
    if id.trim().is_empty() {
        return Err(AdminError::Invalid(format!(
            "{entity} id must not be blank"
        )));
    }

    Ok(())
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
