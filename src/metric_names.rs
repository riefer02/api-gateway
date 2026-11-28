//! Every metric name the process emits, in one place.
//!
//! The names are also a contract with `deploy/alerts.yml`, which is parsed by a
//! test below. Nothing here wraps the `metrics` macros: the constants keep the
//! macro's compile-time label checking, and a rename becomes one edit instead
//! of a grep.

pub(crate) const REQUESTS_TOTAL: &str = "gateway_requests_total";
pub(crate) const REQUEST_DURATION_SECONDS: &str = "gateway_request_duration_seconds";
pub(crate) const READY: &str = "gateway_ready";
pub(crate) const CONNECTIONS_REJECTED_TOTAL: &str = "gateway_connections_rejected_total";

pub(crate) const AUTH_FAILURES_TOTAL: &str = "gateway_auth_failures_total";
pub(crate) const AUTH_CACHE_TOTAL: &str = "gateway_auth_cache_total";
pub(crate) const CLAIM_REJECTED_TOTAL: &str = "gateway_claim_rejected_total";
pub(crate) const OAUTH_JWKS_READY: &str = "gateway_oauth_jwks_ready";

pub(crate) const UPSTREAM_REQUESTS_TOTAL: &str = "gateway_upstream_requests_total";
pub(crate) const UPSTREAM_AUTH_FAILURES_TOTAL: &str = "gateway_upstream_auth_failures_total";
pub(crate) const UPSTREAM_RETRIES_TOTAL: &str = "gateway_upstream_retries_total";
pub(crate) const UPSTREAM_SATURATED_TOTAL: &str = "gateway_upstream_saturated_total";
pub(crate) const CIRCUIT_OPEN_TOTAL: &str = "gateway_circuit_open_total";
pub(crate) const RETRY_BUDGET_EXHAUSTED_TOTAL: &str = "gateway_retry_budget_exhausted_total";

pub(crate) const MCP_DENIED_TOTAL: &str = "gateway_mcp_denied_total";
pub(crate) const MCP_INVALID_PARAMS_TOTAL: &str = "gateway_mcp_invalid_params_total";
pub(crate) const MCP_SCHEMA_SKIPPED_TOTAL: &str = "gateway_mcp_schema_skipped_total";
pub(crate) const MCP_TOOL_CALLS_TOTAL: &str = "gateway_mcp_tool_calls_total";

pub(crate) const DATA_AUDIT_DROPPED_TOTAL: &str = "gateway_data_audit_dropped_total";
pub(crate) const DATA_AUDIT_WRITE_FAILURES_TOTAL: &str = "gateway_data_audit_write_failures_total";
pub(crate) const DATA_AUDIT_SHUTDOWN_TIMEOUTS_TOTAL: &str =
    "gateway_data_audit_shutdown_timeouts_total";

pub(crate) const ADMIN_AUTH_FAILURES_TOTAL: &str = "gateway_admin_auth_failures_total";
pub(crate) const ADMIN_AUDIT_WRITE_FAILURES_TOTAL: &str =
    "gateway_admin_audit_write_failures_total";

/// Every name above. The alert-rule test walks this; it is not used at runtime.
#[cfg(test)]
pub(crate) const ALL: &[&str] = &[
    REQUESTS_TOTAL,
    REQUEST_DURATION_SECONDS,
    READY,
    CONNECTIONS_REJECTED_TOTAL,
    AUTH_FAILURES_TOTAL,
    AUTH_CACHE_TOTAL,
    CLAIM_REJECTED_TOTAL,
    OAUTH_JWKS_READY,
    UPSTREAM_REQUESTS_TOTAL,
    UPSTREAM_AUTH_FAILURES_TOTAL,
    UPSTREAM_RETRIES_TOTAL,
    UPSTREAM_SATURATED_TOTAL,
    CIRCUIT_OPEN_TOTAL,
    RETRY_BUDGET_EXHAUSTED_TOTAL,
    MCP_DENIED_TOTAL,
    MCP_INVALID_PARAMS_TOTAL,
    MCP_SCHEMA_SKIPPED_TOTAL,
    MCP_TOOL_CALLS_TOTAL,
    DATA_AUDIT_DROPPED_TOTAL,
    DATA_AUDIT_WRITE_FAILURES_TOTAL,
    DATA_AUDIT_SHUTDOWN_TIMEOUTS_TOTAL,
    ADMIN_AUTH_FAILURES_TOTAL,
    ADMIN_AUDIT_WRITE_FAILURES_TOTAL,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Prometheus derives these from a histogram, so the alert rules may name
    /// them even though nothing emits them directly.
    fn base_name(token: &str) -> &str {
        token
            .strip_suffix("_bucket")
            .or_else(|| token.strip_suffix("_sum"))
            .or_else(|| token.strip_suffix("_count"))
            .unwrap_or(token)
    }

    #[test]
    fn alert_rules_only_reference_names_this_process_emits() {
        let alerts = include_str!("../deploy/alerts.yml");
        let mut checked = 0;

        for token in
            alerts.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        {
            if !token.starts_with("gateway_") {
                continue;
            }

            let base = base_name(token);
            assert!(
                ALL.contains(&base),
                "deploy/alerts.yml references `{token}`, which this process does not emit"
            );
            checked += 1;
        }

        assert!(
            checked >= 10,
            "expected the alert rules to reference the metrics; found {checked}"
        );
    }
}
