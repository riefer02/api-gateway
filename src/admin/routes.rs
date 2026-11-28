use super::*;

impl AdminService {
    /// Upstreams are declarative: re-adding one updates it. The allowlist is
    /// enforced here as well as at compile time, so a bad row is rejected
    /// before it can poison every reload.
    pub(crate) async fn put_upstream(
        &self,
        actor: &Actor,
        id: &str,
        base_url: &str,
        timeout_ms: u32,
        audience: Option<&str>,
        exchange_scope: Option<&str>,
    ) -> Result<(), AdminError> {
        let url = routing::validate_upstream_url(base_url, &self.routing.allow_hosts)
            .map_err(AdminError::Invalid)?;
        // The same verdict the compiler will reach, applied at write time so a
        // stored row cannot fail every subsequent reload.
        routing::reject_literal_egress(&url, self.routing.egress).map_err(AdminError::Invalid)?;

        if !(1..=300_000).contains(&timeout_ms) {
            return Err(AdminError::Invalid(
                "timeout_ms must be between 1 and 300000".to_owned(),
            ));
        }

        let audience = audience
            .map(str::trim)
            .filter(|audience| !audience.is_empty());

        if let Some(audience) = audience {
            if audience.len() > 512 {
                return Err(AdminError::Invalid(
                    "audience must be at most 512 characters".to_owned(),
                ));
            }

            if !self.token_exchange_enabled {
                return Err(AdminError::Invalid(
                    "an upstream audience requires OAUTH_TOKEN_ENDPOINT and its client credentials"
                        .to_owned(),
                ));
            }
        }

        let exchange_scope = exchange_scope
            .map(str::trim)
            .filter(|scope| !scope.is_empty());

        if audience.is_none() && exchange_scope.is_some() {
            return Err(AdminError::Invalid(
                "exchange_scope requires an audience".to_owned(),
            ));
        }

        // A per-upstream timeout longer than the hard request deadline can
        // never fire: the request is cancelled first and counts as a failure.
        if u128::from(timeout_ms) > self.max_request_timeout.as_millis() {
            return Err(AdminError::Invalid(format!(
                "timeout_ms must not exceed the maximum request deadline ({} ms)",
                self.max_request_timeout.as_millis()
            )));
        }

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query(
            r#"
            INSERT INTO upstreams (id, base_url, timeout_ms, audience, exchange_scope)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (id) DO UPDATE
               SET base_url = EXCLUDED.base_url,
                   timeout_ms = EXCLUDED.timeout_ms,
                   audience = EXCLUDED.audience,
                   exchange_scope = EXCLUDED.exchange_scope,
                   updated_at = now()
            "#,
        )
        .bind(id)
        .bind(base_url)
        .bind(i32::try_from(timeout_ms).map_err(|_| {
            AdminError::Invalid(format!("timeout {timeout_ms}ms does not fit in an i32"))
        })?)
        .bind(audience)
        .bind(exchange_scope)
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        audit::insert(
            &mut transaction,
            actor,
            "upstream.put",
            id,
            &serde_json::json!({
                "base_url": base_url,
                "timeout_ms": timeout_ms,
                "audience": audience,
                "exchange_scope": exchange_scope,
            }),
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

        if let Some(priority) = spec.priority
            && !(-1_000..=1_000).contains(&priority)
        {
            return Err(AdminError::Invalid(
                "priority must be between -1000 and 1000".to_owned(),
            ));
        }

        let tenant_provided = spec.tenant_id.is_some();
        let tenant_value = spec
            .tenant_id
            .as_deref()
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty())
            .map(str::to_owned);

        let scopes_provided = spec.scopes.is_some();
        let scopes = match &spec.scopes {
            Some(scopes) => Some(normalize_scopes(scopes)?),
            None => None,
        };

        if let Some(ms) = spec.request_timeout_ms
            && ms != 0
        {
            // The same range the compiler enforces. Without it, a deployment
            // with MAX_REQUEST_TIMEOUT_SECS above an hour could store a value
            // the next refresh rejects, taking the whole route table with it.
            routing::validate_stored_timeout_ms(i64::from(ms)).map_err(AdminError::Invalid)?;

            if u128::from(ms) > self.max_request_timeout.as_millis() {
                return Err(AdminError::Invalid(format!(
                    "request_timeout_ms must not exceed the maximum request deadline ({} ms)",
                    self.max_request_timeout.as_millis()
                )));
            }
        }

        if let Some(cap) = spec.max_response_bytes {
            routing::validate_response_cap(cap).map_err(AdminError::Invalid)?;
        }

        if let Some(policy) = &spec.tool_policy {
            policy
                .validate()
                .map_err(AdminError::Invalid)?;
        }

        let rewrite_provided = spec.rewrite_prefix.is_some();
        let rewrite = match spec.rewrite_prefix.as_deref() {
            Some("") => None,
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

        let existing_tenant: Option<Option<String>> =
            sqlx::query_scalar("SELECT tenant_id FROM routes WHERE id = $1")
                .bind(&spec.id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(AdminError::Store)?;

        let effective_tenant = if tenant_provided {
            tenant_value.clone()
        } else {
            existing_tenant.flatten()
        };

        if let Some(tenant) = &effective_tenant {
            let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM tenants WHERE id = $1")
                .bind(tenant)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(AdminError::Store)?;

            if exists.is_none() {
                return Err(AdminError::NotFound {
                    entity: "tenant",
                    id: tenant.clone(),
                });
            }
        }

        self.ensure_claim_is_free(
            &mut transaction,
            &spec.id,
            &spec.path_prefix,
            &methods,
            effective_tenant.as_deref(),
        )
        .await?;

        let policy = spec
            .tool_policy
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| AdminError::Invalid(format!("invalid tool policy: {error}")))?;
        let timeout = spec
            .request_timeout_ms
            .filter(|ms| *ms != 0)
            .map(i32::try_from)
            .transpose()
            .map_err(|_| {
                AdminError::Invalid("request_timeout_ms does not fit in an i32".to_owned())
            })?;
        let cap = spec
            .max_response_bytes
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                AdminError::Invalid("max_response_bytes does not fit in an i64".to_owned())
            })?;

        sqlx::query(
            r#"
            INSERT INTO routes
                (id, upstream_id, path_prefix, methods, rewrite_prefix, tenant_id,
                 scopes, tool_policy, request_timeout_ms, max_response_bytes,
                 enabled, priority)
            VALUES (
                $1, $2, $3, $4, $5, $6,
                COALESCE($7::text[], '{}'::text[]),
                COALESCE($8::jsonb, '{"mode":"off","roles":{}}'::jsonb),
                $9, $10, COALESCE($11, true), COALESCE($12, 0)
            )
            ON CONFLICT (id) DO UPDATE
               SET upstream_id = EXCLUDED.upstream_id,
                   path_prefix = EXCLUDED.path_prefix,
                   methods = EXCLUDED.methods,
                   rewrite_prefix = CASE WHEN $13 THEN EXCLUDED.rewrite_prefix ELSE routes.rewrite_prefix END,
                   tenant_id = CASE WHEN $14 THEN EXCLUDED.tenant_id ELSE routes.tenant_id END,
                   scopes = CASE WHEN $15 THEN EXCLUDED.scopes ELSE routes.scopes END,
                   tool_policy = CASE WHEN $16 THEN EXCLUDED.tool_policy ELSE routes.tool_policy END,
                   request_timeout_ms = CASE WHEN $17 THEN EXCLUDED.request_timeout_ms ELSE routes.request_timeout_ms END,
                   max_response_bytes = CASE WHEN $18 THEN EXCLUDED.max_response_bytes ELSE routes.max_response_bytes END,
                   enabled = CASE WHEN $19 THEN EXCLUDED.enabled ELSE routes.enabled END,
                   priority = CASE WHEN $20 THEN EXCLUDED.priority ELSE routes.priority END,
                   updated_at = now()
            "#,
        )
        .bind(&spec.id)
        .bind(&spec.upstream_id)
        .bind(&spec.path_prefix)
        .bind(&methods)
        .bind(&rewrite)
        .bind(&tenant_value)
        .bind(&scopes)
        .bind(policy)
        .bind(timeout)
        .bind(cap)
        .bind(spec.enabled)
        .bind(spec.priority)
        .bind(rewrite_provided)
        .bind(tenant_provided)
        .bind(scopes_provided)
        .bind(spec.tool_policy.is_some())
        .bind(spec.request_timeout_ms.is_some())
        .bind(spec.max_response_bytes.is_some())
        .bind(spec.enabled.is_some())
        .bind(spec.priority.is_some())
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

        audit::insert(
            &mut transaction,
            actor,
            "route.put",
            &spec.id,
            &serde_json::json!({
                "path_prefix": spec.path_prefix,
                "methods": methods,
                "upstream_id": spec.upstream_id,
                "tenant_id": tenant_value,
                "scopes": scopes,
                "request_timeout_ms": timeout,
                "max_response_bytes": cap,
                "tool_policy_mode": spec.tool_policy.as_ref().map(|policy| policy.mode),
                "partial": !(tenant_provided
                    && scopes_provided
                    && spec.tool_policy.is_some()
                    && rewrite_provided),
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
            "SELECT id, methods, path_prefix, rewrite_prefix, tenant_id, upstream_id,
                    scopes, tool_policy, request_timeout_ms, max_response_bytes, enabled, priority
             FROM routes ORDER BY path_prefix",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        rows.into_iter()
            .map(|row| {
                let tool_policy = serde_json::from_value::<ToolPolicy>(
                    row.try_get("tool_policy")
                        .map_err(AdminError::Store)?,
                )
                .map_err(|error| {
                    AdminError::Invalid(format!("stored tool policy is invalid: {error}"))
                })?;

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
                    tenant_id: row
                        .try_get("tenant_id")
                        .map_err(AdminError::Store)?,
                    upstream_id: row
                        .try_get("upstream_id")
                        .map_err(AdminError::Store)?,
                    scopes: row
                        .try_get("scopes")
                        .map_err(AdminError::Store)?,
                    tool_policy,
                    request_timeout_ms: row
                        .try_get::<Option<i32>, _>("request_timeout_ms")
                        .map_err(AdminError::Store)?
                        .and_then(|ms| u32::try_from(ms).ok()),
                    max_response_bytes: row
                        .try_get::<Option<i64>, _>("max_response_bytes")
                        .map_err(AdminError::Store)?
                        .and_then(|bytes| u64::try_from(bytes).ok()),
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
        let rows = sqlx::query(
            "SELECT id, base_url, timeout_ms, audience, exchange_scope
             FROM upstreams ORDER BY id",
        )
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
                    audience: row
                        .try_get("audience")
                        .map_err(AdminError::Store)?,
                    exchange_scope: row
                        .try_get("exchange_scope")
                        .map_err(AdminError::Store)?,
                })
            })
            .collect()
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

    async fn ensure_claim_is_free(
        &self,
        transaction: &mut sqlx::PgConnection,
        id: &str,
        path_prefix: &str,
        methods: &[String],
        tenant_id: Option<&str>,
    ) -> Result<(), AdminError> {
        let claimed: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM routes
             WHERE path_prefix = $1 AND methods && $2::text[] AND id <> $3
               AND tenant_id IS NOT DISTINCT FROM $4 AND enabled
             LIMIT 1",
        )
        .bind(path_prefix)
        .bind(methods)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(AdminError::Store)?;

        if claimed.is_some() {
            return Err(AdminError::Invalid(format!(
                "{} on `{}` is already claimed by another route in this tenant",
                methods.join(","),
                path_prefix
            )));
        }

        Ok(())
    }
}

fn normalize_methods(methods: &[String]) -> Vec<String> {
    methods
        .iter()
        .map(|method| method.trim().to_ascii_uppercase())
        .collect()
}
