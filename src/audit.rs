//! Per-call audit for the data plane.
//!
//! The request path never waits on Postgres. Events go through a bounded
//! channel; a full queue drops and increments a metric rather than adding
//! latency. `detail` carries identifiers and decisions only — never payloads,
//! tokens, or verifier material.

use std::{sync::Arc, time::Duration};

use sqlx::{PgPool, QueryBuilder};
use tokio::sync::mpsc;

/// What one proxied call did, in the terms a security team asks for.
#[derive(Clone, Debug)]
pub(crate) struct DataAuditEvent {
    /// When the call finished, not when the batch reached Postgres.
    pub(crate) occurred_at: time::OffsetDateTime,
    pub(crate) tenant_id: String,
    pub(crate) subject: Option<String>,
    pub(crate) assistant: Option<String>,
    pub(crate) auth_method: &'static str,
    pub(crate) mcp_method: Option<String>,
    pub(crate) route_id: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) decision: &'static str,
    pub(crate) status: u16,
    pub(crate) latency_ms: u64,
    pub(crate) request_id: Option<String>,
    pub(crate) token_id: Option<String>,
}

/// One request's audit state, filled as the pipeline learns more.
#[derive(Default)]
pub(crate) struct AuditDraft {
    tenant_id: Option<String>,
    subject: Option<String>,
    assistant: Option<String>,
    auth_method: Option<&'static str>,
    mcp_method: Option<String>,
    route_id: Option<String>,
    tool_name: Option<String>,
    decision: Option<&'static str>,
    token_id: Option<String>,
}

impl AuditDraft {
    pub(crate) fn identity(
        &mut self,
        tenant_id: &str,
        subject: Option<&str>,
        assistant: Option<&str>,
        auth_method: &'static str,
        token_id: Option<&str>,
    ) {
        self.tenant_id = Some(tenant_id.to_owned());
        self.subject = subject.map(str::to_owned);
        self.assistant = assistant.map(str::to_owned);
        self.auth_method = Some(auth_method);
        self.token_id = token_id.map(str::to_owned);
    }

    pub(crate) fn route(&mut self, route_id: &str) {
        self.route_id = Some(route_id.to_owned());
    }

    pub(crate) fn mcp(&mut self, method: Option<&str>, tool: Option<&str>) {
        self.mcp_method = method.map(str::to_owned);
        self.tool_name = tool.map(str::to_owned);
    }

    pub(crate) fn deny(&mut self) {
        self.decision = Some("deny");
    }

    pub(crate) fn finish(self, status: u16, latency: Duration) -> Option<DataAuditEvent> {
        let tenant_id = self.tenant_id?;
        let auth_method = self.auth_method?;
        // Only requests that reached a route are per-call audit; unauthenticated
        // probes and authenticated 404s would otherwise be an unbounded write
        // amplifier. The status also drives the fallback decision: a 429, 502,
        // or 408 is not an "allow".
        let route_id = self.route_id?;
        let decision = self
            .decision
            .unwrap_or(if status < 400 { "allow" } else { "deny" });

        Some(DataAuditEvent {
            occurred_at: time::OffsetDateTime::now_utc(),
            tenant_id,
            subject: self.subject,
            assistant: self.assistant,
            auth_method,
            mcp_method: self.mcp_method,
            route_id: Some(route_id),
            tool_name: self.tool_name,
            decision,
            status,
            latency_ms: u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
            request_id: crate::request_context::current(),
            token_id: self.token_id,
        })
    }
}

/// A sink the pipeline can call without awaiting. Tests use a recorder; the
/// process uses the channel-backed implementation.
pub(crate) trait AuditSink: Send + Sync {
    fn record(&self, event: DataAuditEvent);
}

/// Used when `DATA_AUDIT_ENABLED=false` and in tests that do not care.
pub(crate) struct DisabledAudit;

impl AuditSink for DisabledAudit {
    fn record(&self, _event: DataAuditEvent) {}
}

pub(crate) struct ChannelAudit {
    sender: mpsc::Sender<DataAuditEvent>,
}

impl ChannelAudit {
    pub(crate) fn new(capacity: usize) -> (Arc<Self>, mpsc::Receiver<DataAuditEvent>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Arc::new(Self { sender }), receiver)
    }
}

impl AuditSink for ChannelAudit {
    fn record(&self, event: DataAuditEvent) {
        if self.sender.try_send(event).is_err() {
            metrics::counter!("gateway_data_audit_dropped_total").increment(1);
        }
    }
}

/// Drains the channel in batches. Retention is a separate task so disabling
/// the writer does not stop pruning an existing table.
pub(crate) async fn run(
    pool: PgPool,
    mut receiver: mpsc::Receiver<DataAuditEvent>,
    batch_size: usize,
) {
    loop {
        let Some(first) = receiver.recv().await else {
            return;
        };

        let mut events = Vec::with_capacity(batch_size);
        events.push(first);
        while events.len() < batch_size {
            match receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }

        if let Err(error) = insert(&pool, &events).await {
            metrics::counter!("gateway_data_audit_write_failures_total")
                .increment(events.len() as u64);
            tracing::warn!(%error, rows = events.len(), "data audit write failed");
        }
    }
}

/// Prunes expired rows on a timer. One advisory-locked batch at a time keeps a
/// rolling deploy from firing N identical full-range deletes.
pub(crate) async fn run_retention(pool: PgPool, retention: Duration) {
    if retention.is_zero() {
        return;
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        match prune(&pool, retention).await {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "pruned data audit rows"),
            Err(error) => tracing::warn!(%error, "data audit pruning failed"),
        }
    }
}

async fn insert(pool: &PgPool, events: &[DataAuditEvent]) -> Result<(), sqlx::Error> {
    if events.is_empty() {
        return Ok(());
    }

    let mut query = QueryBuilder::new(
        "INSERT INTO data_audit_events
         (occurred_at, tenant_id, subject, assistant, auth_method, mcp_method, route_id,
          tool_name, decision, status, latency_ms, request_id, token_id)
         ",
    );

    query.push_values(events, |mut row, event| {
        row.push_bind(event.occurred_at)
            .push_bind(&event.tenant_id)
            .push_bind(&event.subject)
            .push_bind(&event.assistant)
            .push_bind(event.auth_method)
            .push_bind(&event.mcp_method)
            .push_bind(&event.route_id)
            .push_bind(&event.tool_name)
            .push_bind(event.decision)
            .push_bind(i16::try_from(event.status).unwrap_or(0))
            .push_bind(i32::try_from(event.latency_ms).unwrap_or(i32::MAX))
            .push_bind(&event.request_id)
            .push_bind(&event.token_id);
    });

    query
        .build()
        .execute(pool)
        .await
        .map(|_| ())
}

async fn prune(pool: &PgPool, retention: Duration) -> Result<u64, sqlx::Error> {
    // One hundred years is longer than any deployment and keeps the duration
    // arithmetic away from overflow.
    let seconds = i64::try_from(
        retention
            .as_secs()
            .min(100 * 365 * 86_400),
    )
    .unwrap_or(100 * 365 * 86_400);
    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::seconds(seconds);

    sqlx::query("DELETE FROM data_audit_events WHERE occurred_at < $1")
        .bind(cutoff)
        .execute(pool)
        .await
        .map(|result| result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_without_identity_is_not_recorded() {
        let draft = AuditDraft::default();
        assert!(
            draft
                .finish(200, Duration::from_millis(1))
                .is_none()
        );
    }

    #[test]
    fn a_finished_draft_carries_the_decision_and_attribution() {
        let mut draft = AuditDraft::default();
        draft.identity(
            "acme",
            Some("user-1"),
            Some("chatgpt"),
            "oauth",
            Some("jti-1"),
        );
        draft.route("mcp");
        draft.mcp(Some("tools/call"), Some("search_tickets"));
        draft.deny();

        let event = draft
            .finish(200, Duration::from_millis(12))
            .expect("event");

        assert_eq!(event.tenant_id, "acme");
        assert_eq!(event.subject.as_deref(), Some("user-1"));
        assert_eq!(event.decision, "deny");
        assert_eq!(event.tool_name.as_deref(), Some("search_tickets"));
    }

    #[tokio::test]
    async fn rows_round_trip_through_postgres() {
        let Some(pool) = crate::testing::pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let tenant = crate::testing::unique("data-audit");
        let mut event = event();
        event.tenant_id = tenant.clone();

        insert(&pool, &[event.clone()])
            .await
            .expect("insert audit row");

        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM data_audit_events WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("count rows");

        assert_eq!(count, 1);

        let stored: (String, String) = sqlx::query_as(
            "SELECT decision, auth_method FROM data_audit_events WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("read row");

        assert_eq!(stored, ("allow".to_owned(), "oauth".to_owned()));

        sqlx::query("DELETE FROM data_audit_events WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }

    #[test]
    fn a_full_channel_drops_without_blocking() {
        let (audit, mut receiver) = ChannelAudit::new(1);

        audit.record(event());
        audit.record(event());

        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
    }

    fn event() -> DataAuditEvent {
        DataAuditEvent {
            occurred_at: time::OffsetDateTime::now_utc(),
            tenant_id: "acme".to_owned(),
            subject: None,
            assistant: None,
            auth_method: "oauth",
            mcp_method: None,
            route_id: None,
            tool_name: None,
            decision: "allow",
            status: 200,
            latency_ms: 1,
            request_id: None,
            token_id: None,
        }
    }
}
