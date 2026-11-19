//! Control-plane audit: append, chain, verify.
//!
//! The chain is the control plane's alone. The data-plane audit is high volume
//! and batched, and is not the log an auditor reads; chaining it would cost a
//! serialised write per tool call to prove something nobody asks it to prove.
//!
//! One writer at a time is affordable here. The advisory lock is taken inside
//! the caller's transaction, so the mutation and its audit row still commit
//! together, and two writers cannot claim the same predecessor.

use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;

use super::{Actor, AdminError};

/// Outcome of walking the control-plane audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainReport {
    /// Rows whose hash was recomputed and matched.
    pub(crate) verified: usize,
    /// Rows written before the chain existed; they carry no hash.
    pub(crate) unchained: usize,
    /// First row that did not verify, if any.
    pub(crate) broken: Option<ChainBreak>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainBreak {
    pub(crate) id: i64,
    pub(crate) reason: String,
}

/// One row of the chain, independent of sqlx so verification is testable.
#[derive(Debug, Clone)]
struct AuditRow {
    id: i64,
    occurred_at: OffsetDateTime,
    actor: String,
    source_ip: Option<String>,
    action: String,
    subject: String,
    request_id: Option<String>,
    detail: serde_json::Value,
    prev_hash: String,
    row_hash: String,
}

/// The hash that anchors the chain before its first row.
const AUDIT_GENESIS: &str = "genesis";

/// Advisory lock key for the audit chain. Any fixed value works; it only has to
/// be unique within this database. Control-plane writes are low volume, so one
/// writer at a time costs nothing and removes the read-then-insert race that
/// would let two rows claim the same predecessor.
const AUDIT_CHAIN_LOCK: i64 = 0x6175_6469_745f_6368; // "audit_ch"

/// Appends one chained audit row. Takes a connection rather than an executor
/// because the lock, the predecessor read and the insert must share one
/// transaction — a pool-issued statement would release the lock immediately.
pub(super) async fn insert(
    connection: &mut sqlx::PgConnection,
    actor: &Actor,
    action: &str,
    subject: &str,
    detail: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_CHAIN_LOCK)
        .execute(&mut *connection)
        .await?;

    let previous: Option<String> =
        sqlx::query_scalar("SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *connection)
            .await?;

    let prev_hash = match previous {
        // An empty hash is a pre-chain row; treat it as genesis.
        Some(hash) if !hash.is_empty() => hash,
        _ => AUDIT_GENESIS.to_owned(),
    };

    // Postgres stores timestamptz to microsecond precision, so truncate before
    // hashing: otherwise the recomputed hash after a round trip differs from
    // the stored one by the digits the database discarded.
    let now = time::OffsetDateTime::now_utc();
    let occurred_at =
        time::OffsetDateTime::from_unix_timestamp_nanos(now.unix_timestamp_nanos() / 1_000 * 1_000)
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;

    let row_hash = chain_hash(
        &prev_hash,
        occurred_at,
        actor,
        action,
        subject,
        detail,
        crate::request_context::current().as_deref(),
    );

    sqlx::query(
        "INSERT INTO audit_events
            (occurred_at, actor, action, subject, source_ip, request_id, detail, prev_hash, row_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)",
    )
    .bind(occurred_at)
    .bind(&actor.name)
    .bind(action)
    .bind(subject)
    .bind(&actor.source_ip)
    .bind(crate::request_context::current())
    .bind(detail.to_string())
    .bind(&prev_hash)
    .bind(&row_hash)
    .execute(connection)
    .await
    .map(|_| ())
}

/// Hash of one audit row, including its predecessor.
///
/// The material is a JSON object so field boundaries cannot be forged by
/// embedding separators in a field. Key order is stable because `serde_json`
/// maps are sorted by default.
#[cfg(test)]
fn verify_rows(rows: &[AuditRow]) -> ChainReport {
    let mut report = ChainReport {
        verified: 0,
        unchained: 0,
        broken: None,
    };
    let mut expected_prev = AUDIT_GENESIS.to_owned();

    for row in rows {
        match verify_row(row, &expected_prev, &mut report) {
            Some(next) => expected_prev = next,
            None => break,
        }
    }

    report
}

/// Checks one row against its expected predecessor, updating the report.
/// Returns the hash the next row must point at, or `None` once the chain has
/// broken (or the row was written before the chain existed).
fn verify_row(row: &AuditRow, expected_prev: &str, report: &mut ChainReport) -> Option<String> {
    if row.row_hash.is_empty() {
        report.unchained += 1;
        return Some(expected_prev.to_owned());
    }

    let actor = Actor {
        name: row.actor.clone(),
        source_ip: row.source_ip.clone(),
        scopes: std::collections::HashSet::new(),
    };

    if row.prev_hash != expected_prev {
        report.broken = Some(ChainBreak {
            id: row.id,
            reason: "prev_hash does not match the preceding row".to_owned(),
        });
        return None;
    }

    let recomputed = chain_hash(
        &row.prev_hash,
        row.occurred_at,
        &actor,
        &row.action,
        &row.subject,
        &row.detail,
        row.request_id.as_deref(),
    );

    if recomputed != row.row_hash {
        report.broken = Some(ChainBreak {
            id: row.id,
            reason: "row_hash does not match the row's contents".to_owned(),
        });
        return None;
    }

    report.verified += 1;

    Some(row.row_hash.clone())
}

fn chain_hash(
    prev_hash: &str,
    occurred_at: time::OffsetDateTime,
    actor: &Actor,
    action: &str,
    subject: &str,
    detail: &serde_json::Value,
    request_id: Option<&str>,
) -> String {
    use sha2::Digest as _;

    let material = serde_json::json!({
        "prev": prev_hash,
        "at": occurred_at.unix_timestamp_nanos().to_string(),
        "actor": actor.name,
        "action": action,
        "subject": subject,
        "source_ip": actor.source_ip,
        "request_id": request_id,
        "detail": detail,
    });

    hex::encode(sha2::Sha256::digest(canonical_json(&material).as_bytes()))
}

/// Serialises a value with object keys in byte order, at every depth.
///
/// `serde_json` happens to sort keys because its map is a `BTreeMap`, but that
/// is a property of a feature flag: enabling `preserve_order` anywhere in the
/// dependency graph would make serialisation follow insertion order. `detail`
/// is stored as `jsonb`, which returns keys in its own order (length first,
/// then bytes), so the write and the verify would then disagree and every hash
/// would silently stop matching. Canonicalising here removes the dependency on
/// how the map happens to be implemented.
fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;

    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));

            out.push('{');

            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }

                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical(value, out);
            }

            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');

            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }

                write_canonical(item, out);
            }

            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).unwrap_or_default()),
    }
}

/// Walks the control-plane audit chain and reports the first row that does not
/// verify. Rows written before the chain existed are counted, not failed: they
/// cannot be checked, and pretending otherwise would be worse than saying so.
pub(crate) async fn verify(pool: &PgPool) -> Result<ChainReport, AdminError> {
    // Paged by id so a long audit log does not have to fit in memory, and
    // so a verification running during normal traffic does not hold the
    // whole table at once.
    const PAGE: i64 = 512;

    let mut report = ChainReport {
        verified: 0,
        unchained: 0,
        broken: None,
    };
    let mut expected_prev = AUDIT_GENESIS.to_owned();
    let mut cursor = 0i64;

    loop {
        let page = sqlx::query(
            "SELECT id, occurred_at, actor, action, subject, source_ip, request_id,
                    detail, prev_hash, row_hash
             FROM audit_events
             WHERE id > $1
             ORDER BY id ASC
             LIMIT $2",
        )
        .bind(cursor)
        .bind(PAGE)
        .fetch_all(pool)
        .await
        .map_err(AdminError::Store)?;

        if page.is_empty() {
            break;
        }

        let rows = page
            .iter()
            .map(|row| {
                Ok(AuditRow {
                    id: row.try_get("id")?,
                    occurred_at: row.try_get("occurred_at")?,
                    actor: row.try_get("actor")?,
                    source_ip: row.try_get("source_ip")?,
                    action: row.try_get("action")?,
                    subject: row.try_get("subject")?,
                    request_id: row.try_get("request_id")?,
                    detail: row.try_get("detail")?,
                    prev_hash: row.try_get("prev_hash")?,
                    row_hash: row.try_get("row_hash")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(AdminError::Store)?;

        for row in &rows {
            match verify_row(row, &expected_prev, &mut report) {
                Some(next) => expected_prev = next,
                None => return Ok(report),
            }
        }

        cursor = rows.last().map_or(cursor, |row| row.id);
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::admin::AdminService;
    use crate::auth::KeyVerifier;
    use crate::auth::store::ApiKeyStore;
    use crate::testing::{pg_pool, unique};

    fn row(id: i64, prev: &str, action: &str, detail: serde_json::Value) -> AuditRow {
        row_with(id, prev, action, detail, time::OffsetDateTime::UNIX_EPOCH)
    }

    fn row_with(
        id: i64,
        prev: &str,
        action: &str,
        detail: serde_json::Value,
        occurred_at: time::OffsetDateTime,
    ) -> AuditRow {
        let actor = Actor {
            name: "tester".to_owned(),
            source_ip: Some("203.0.113.9".to_owned()),
            scopes: std::collections::HashSet::new(),
        };
        let subject = format!("subject-{id}");
        let hash = chain_hash(
            prev,
            occurred_at,
            &actor,
            action,
            &subject,
            &detail,
            Some("req-1"),
        );

        AuditRow {
            id,
            occurred_at,
            actor: actor.name,
            source_ip: actor.source_ip,
            action: action.to_owned(),
            subject,
            request_id: Some("req-1".to_owned()),
            detail,
            prev_hash: prev.to_owned(),
            row_hash: hash,
        }
    }

    fn chain_of_two() -> Vec<AuditRow> {
        let first = row(
            1,
            AUDIT_GENESIS,
            "tenant.create",
            serde_json::json!({"a": 1}),
        );
        let second = row(
            2,
            &first.row_hash,
            "client.create",
            serde_json::json!({"tenant_id": "t"}),
        );

        vec![first, second]
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let nested: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":{"z":2,"y":[{"d":4,"c":3}]}}"#).expect("json");

        assert_eq!(
            canonical_json(&nested),
            r#"{"a":{"y":[{"c":3,"d":4}],"z":2},"b":1}"#
        );
    }

    #[test]
    fn a_valid_chain_verifies() {
        let report = verify_rows(&chain_of_two());

        assert_eq!(report.verified, 2);
        assert_eq!(report.unchained, 0);
        assert_eq!(report.broken, None);
    }

    #[test]
    fn an_edited_row_breaks_the_chain_at_itself() {
        let mut rows = chain_of_two();
        rows[1].detail = serde_json::json!({"tenant_id": "someone-else"});

        let report = verify_rows(&rows);

        assert_eq!(report.verified, 1);
        assert_eq!(
            report.broken,
            Some(ChainBreak {
                id: 2,
                reason: "row_hash does not match the row's contents".to_owned(),
            })
        );
    }

    #[test]
    fn a_reordered_row_breaks_the_chain() {
        let rows = chain_of_two();
        let report = verify_rows(&[rows[1].clone()]);

        assert!(matches!(report.broken, Some(ChainBreak { id: 2, .. })));
    }

    #[test]
    fn pre_chain_rows_are_counted_not_failed() {
        let mut rows = chain_of_two();
        rows.insert(
            0,
            AuditRow {
                prev_hash: String::new(),
                row_hash: String::new(),
                ..row(0, "", "legacy.event", serde_json::json!({}))
            },
        );

        let report = verify_rows(&rows);

        assert_eq!(report.unchained, 1);
        assert_eq!(report.verified, 2);
        assert_eq!(report.broken, None);
    }

    #[test]
    fn the_hash_covers_every_field_and_is_stable() {
        let actor = Actor {
            name: "tester".to_owned(),
            source_ip: None,
            scopes: std::collections::HashSet::new(),
        };
        let detail = serde_json::json!({"a": 1, "b": 2});

        let base = chain_hash(
            AUDIT_GENESIS,
            time::OffsetDateTime::UNIX_EPOCH,
            &actor,
            "tenant.create",
            "subject",
            &detail,
            None,
        );

        assert_eq!(
            base,
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.create",
                "subject",
                &detail,
                None,
            ),
            "the same row must hash the same way"
        );

        assert_ne!(
            base,
            chain_hash(
                "other",
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.create",
                "subject",
                &detail,
                None,
            ),
            "the predecessor must be part of the hash"
        );
    }

    #[tokio::test]
    async fn written_events_verify_against_the_live_chain() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let store: Arc<dyn ApiKeyStore> =
            Arc::new(crate::auth::store::InMemoryApiKeyStore::default());
        let service = AdminService::new(
            pool,
            Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
            Vec::new(),
            store,
            std::time::Duration::from_secs(300),
            false,
        );

        let actor = Actor::local("chain-test");

        for detail in [
            serde_json::json!({"n": 1}),
            // Keys whose jsonb order (length, then bytes) differs from their
            // lexical order, so a hash that followed storage order would fail.
            serde_json::json!({"zeta": 1, "alpha": 2, "mid": "x"}),
        ] {
            service
                .audit_best_effort(&actor, "chain.test", &unique("chain"), detail)
                .await;
        }

        let report = service
            .verify_audit_chain()
            .await
            .expect("verify");

        assert!(report.verified >= 2, "inserted rows must be chained");
        assert_eq!(report.broken, None, "the live chain must verify");
    }
}
