use super::*;

impl AdminService {
    /// Deletes audit rows older than the retention window. Called at boot and
    /// on a timer; a zero window means "keep everything".
    pub(crate) async fn prune_audit(
        &self,
        retention: std::time::Duration,
    ) -> Result<u64, AdminError> {
        if retention.is_zero() {
            return Ok(0);
        }

        let seconds = i64::try_from(
            retention
                .as_secs()
                .min(100 * 365 * 86_400),
        )
        .unwrap_or(100 * 365 * 86_400);
        let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(seconds);

        // Prune under the chain lock and only as a prefix. Deleting by
        // `occurred_at` alone can remove a middle row if the clock moved, and a
        // hole in the chain is indistinguishable from tampering to `verify`.
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(audit::AUDIT_CHAIN_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(AdminError::Store)?;

        let result = sqlx::query(
            "DELETE FROM audit_events
             WHERE id <= (
                 SELECT COALESCE(MAX(id), 0) FROM audit_events WHERE occurred_at < $1
             )",
        )
        .bind(cutoff)
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
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

    pub(crate) async fn list_data_audit(
        &self,
        limit: i64,
        before_id: Option<i64>,
        since: Option<OffsetDateTime>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<DataAuditEntry>, AdminError> {
        let rows = sqlx::query(
            "SELECT occurred_at, tenant_id, subject, assistant, auth_method, mcp_method,
                    route_id, tool_name, decision, status, latency_ms, request_id, token_id,
                    detail
             FROM data_audit_events
             WHERE ($1::bigint IS NULL OR id < $1)
               AND ($2::timestamptz IS NULL OR occurred_at >= $2)
               AND ($3::text IS NULL OR tenant_id = $3)
             ORDER BY occurred_at DESC, id DESC
             LIMIT $4",
        )
        .bind(before_id)
        .bind(since)
        .bind(tenant_id)
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        rows.into_iter()
            .map(|row| {
                Ok(DataAuditEntry {
                    occurred_at: row
                        .try_get("occurred_at")
                        .map_err(AdminError::Store)?,
                    tenant_id: row
                        .try_get("tenant_id")
                        .map_err(AdminError::Store)?,
                    subject: row
                        .try_get("subject")
                        .map_err(AdminError::Store)?,
                    assistant: row
                        .try_get("assistant")
                        .map_err(AdminError::Store)?,
                    auth_method: row
                        .try_get("auth_method")
                        .map_err(AdminError::Store)?,
                    mcp_method: row
                        .try_get("mcp_method")
                        .map_err(AdminError::Store)?,
                    route_id: row
                        .try_get("route_id")
                        .map_err(AdminError::Store)?,
                    tool_name: row
                        .try_get("tool_name")
                        .map_err(AdminError::Store)?,
                    decision: row
                        .try_get("decision")
                        .map_err(AdminError::Store)?,
                    status: row
                        .try_get::<Option<i16>, _>("status")
                        .map_err(AdminError::Store)?
                        .and_then(|status| u16::try_from(status).ok()),
                    latency_ms: row
                        .try_get::<Option<i32>, _>("latency_ms")
                        .map_err(AdminError::Store)?
                        .and_then(|latency| u32::try_from(latency).ok()),
                    request_id: row
                        .try_get("request_id")
                        .map_err(AdminError::Store)?,
                    token_id: row
                        .try_get("token_id")
                        .map_err(AdminError::Store)?,
                    detail: row
                        .try_get("detail")
                        .map_err(AdminError::Store)?,
                })
            })
            .collect()
    }
}
