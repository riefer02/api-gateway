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
    /// Unhashed rows before the chain starts. Rows retained after a prune are
    /// not counted here: the walk begins at the oldest surviving hashed row.
    pub(crate) unchained: usize,
    /// Id of the oldest hashed row the walk could verify. `None` means no
    /// hashed row was found at all, which proves nothing either way.
    pub(crate) chain_start: Option<i64>,
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
    /// False for rows written before the chain, or by a replica that had not
    /// been upgraded. Their hash column is irrelevant: they are gaps, and a
    /// hashed row that claims to be chained must still verify.
    chained: bool,
}

/// The hash that anchors the chain before its first row.
const AUDIT_GENESIS: &str = "genesis";

/// Advisory lock key for the audit chain. Any fixed value works; it only has to
/// be unique within this database. Control-plane writes are low volume, so one
/// writer at a time costs nothing and removes the read-then-insert race that
/// would let two rows claim the same predecessor.
pub(super) const AUDIT_CHAIN_LOCK: i64 = 0x6175_6469_745f_6368; // "audit_ch"

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

    // Link to the last *hashed* row. During a rolling deploy an older binary
    // may still insert an unchained row; linking to it would restart the chain
    // at genesis and break verification for everything after it.
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT row_hash FROM audit_events
         WHERE chained AND row_hash <> ''
         ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;

    let prev_hash = previous.unwrap_or_else(|| AUDIT_GENESIS.to_owned());

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
            (occurred_at, actor, action, subject, source_ip, request_id, detail,
             prev_hash, row_hash, chained)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, true)",
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
/// embedding separators in a field; `canonical_json` makes the encoding
/// independent of map order and of how Postgres returns jsonb.
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

/// Walks rows in id order, checking each one against the one before it.
///
/// The walk starts at the oldest *hashed* row rather than at genesis, because
/// retention deletes the oldest rows and a healthy deployment must still
/// verify. The cost is explicit: removing the oldest rows is indistinguishable
/// from retention, so the chain proves that nothing after its start was
/// altered, not that the start is original.
///
/// A row with no hash **after** the chain has started is a break, not a gap:
/// otherwise blanking the hash column would hide any number of edited rows.
struct Walk {
    report: ChainReport,
    expected: Option<String>,
}

impl Walk {
    fn new() -> Self {
        Self {
            report: ChainReport {
                verified: 0,
                unchained: 0,
                chain_start: None,
                broken: None,
            },
            expected: None,
        }
    }

    /// Returns false once the chain has broken and the walk should stop.
    fn push(&mut self, row: &AuditRow) -> bool {
        if !row.chained {
            // Before the chain starts, this is simply history. After it starts,
            // an unchained row is a break: otherwise clearing the marker on a
            // suffix would present an edited log as intact, which is the same
            // attack as blanking the hash with one extra column.
            if self.expected.is_some() {
                self.report.broken = Some(ChainBreak {
                    id: row.id,
                    reason: "a row after the chain start is outside the chain".to_owned(),
                });
                return false;
            }

            self.report.unchained += 1;
            return true;
        }

        if row.row_hash.is_empty() {
            self.report.broken = Some(ChainBreak {
                id: row.id,
                reason: "a chained row is missing its hash".to_owned(),
            });
            return false;
        }

        if let Some(expected) = &self.expected
            && row.prev_hash != *expected
        {
            self.report.broken = Some(ChainBreak {
                id: row.id,
                reason: "prev_hash does not match the preceding row".to_owned(),
            });
            return false;
        }

        let actor = Actor {
            name: row.actor.clone(),
            source_ip: row.source_ip.clone(),
            scopes: std::collections::HashSet::new(),
        };

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
            self.report.broken = Some(ChainBreak {
                id: row.id,
                reason: "row_hash does not match the row's contents".to_owned(),
            });
            return false;
        }

        self.report
            .chain_start
            .get_or_insert(row.id);
        self.report.verified += 1;
        self.expected = Some(row.row_hash.clone());

        true
    }
}

#[cfg(test)]
fn verify_rows(rows: &[AuditRow]) -> ChainReport {
    let mut walk = Walk::new();

    for row in rows {
        if !walk.push(row) {
            break;
        }
    }

    walk.report
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

    let mut walk = Walk::new();
    let mut cursor = 0i64;

    loop {
        let page = sqlx::query(
            "SELECT id, occurred_at, actor, action, subject, source_ip, request_id,
                    detail, prev_hash, row_hash, chained
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
                    chained: row.try_get("chained")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(AdminError::Store)?;

        for row in &rows {
            if !walk.push(row) {
                return Ok(walk.report);
            }
        }

        cursor = rows.last().map_or(cursor, |row| row.id);
    }

    Ok(walk.report)
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
            chained: true,
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
        assert_eq!(report.chain_start, Some(1));
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
        let report = verify_rows(&[rows[1].clone(), rows[0].clone()]);

        assert!(matches!(report.broken, Some(ChainBreak { id: 1, .. })));
    }

    #[test]
    fn a_blank_hash_after_the_chain_starts_is_a_break() {
        let mut rows = chain_of_two();
        rows[1].row_hash.clear();

        let report = verify_rows(&rows);

        assert_eq!(report.verified, 1);
        assert_eq!(
            report.broken,
            Some(ChainBreak {
                id: 2,
                reason: "a chained row is missing its hash".to_owned(),
            })
        );
    }

    #[test]
    fn a_row_outside_the_chain_after_it_starts_is_a_break() {
        // Clearing `chained` on a suffix must not hide an edit. A replica that
        // has not been upgraded produces the same shape, which is why a mixed
        // upgrade has to be followed by a verification.
        let rows = chain_of_two();
        let mut with_gap = vec![rows[0].clone()];

        let mut gap = row(99, "", "edited.event", serde_json::json!({}));
        gap.chained = false;
        gap.row_hash.clear();
        with_gap.push(gap);

        let report = verify_rows(&with_gap);

        assert_eq!(report.verified, 1);
        assert_eq!(
            report.broken,
            Some(ChainBreak {
                id: 99,
                reason: "a row after the chain start is outside the chain".to_owned(),
            })
        );
    }

    #[test]
    fn a_pruned_prefix_still_verifies() {
        // Retention deletes the oldest rows, so the first surviving hashed row
        // points at a predecessor that is gone. That is not tampering.
        let rows = chain_of_two();
        let report = verify_rows(&rows[1..]);

        assert_eq!(report.verified, 1);
        assert_eq!(report.chain_start, Some(2));
        assert_eq!(report.broken, None);
    }

    #[test]
    fn pre_chain_rows_are_counted_not_failed() {
        let mut rows = chain_of_two();
        rows.insert(
            0,
            AuditRow {
                prev_hash: String::new(),
                row_hash: String::new(),
                chained: false,
                ..row(0, "", "legacy.event", serde_json::json!({}))
            },
        );

        let report = verify_rows(&rows);

        assert_eq!(report.unchained, 1);
        assert_eq!(report.verified, 2);
        assert_eq!(report.chain_start, Some(1));
        assert_eq!(report.broken, None);
    }

    #[test]
    fn the_hash_covers_every_field_and_is_stable() {
        let actor = Actor {
            name: "tester".to_owned(),
            source_ip: Some("203.0.113.9".to_owned()),
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
            Some("req"),
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
                Some("req"),
            ),
            "the same row must hash the same way"
        );

        let variants = [
            chain_hash(
                "other",
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.create",
                "subject",
                &detail,
                Some("req"),
            ),
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
                &actor,
                "tenant.create",
                "subject",
                &detail,
                Some("req"),
            ),
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH,
                &Actor {
                    name: "other".to_owned(),
                    source_ip: actor.source_ip.clone(),
                    scopes: std::collections::HashSet::new(),
                },
                "tenant.create",
                "subject",
                &detail,
                Some("req"),
            ),
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.delete",
                "subject",
                &detail,
                Some("req"),
            ),
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.create",
                "other-subject",
                &detail,
                Some("req"),
            ),
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.create",
                "subject",
                &serde_json::json!({"a": 1, "b": 3}),
                Some("req"),
            ),
            chain_hash(
                AUDIT_GENESIS,
                time::OffsetDateTime::UNIX_EPOCH,
                &actor,
                "tenant.create",
                "subject",
                &detail,
                Some("other-request"),
            ),
        ];

        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(&base, variant, "field {index} is not covered by the hash");
        }
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
            crate::routing::test_routing(),
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
        assert!(
            report.chain_start.is_some(),
            "the walk must find where the chain begins"
        );
        assert_eq!(report.broken, None, "the live chain must verify");
    }
}
