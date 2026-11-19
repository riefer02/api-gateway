use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use reqwest::{Method, Url};
use sqlx::{FromRow, PgPool};

use crate::mcp::ToolPolicy;

/// A route compiled for request matching: no allocation, no locks on the path.
#[derive(Clone, Debug)]
pub(crate) struct CompiledRoute {
    pub(crate) id: String,
    pub(crate) path_prefix: String,
    pub(crate) methods: Vec<Method>,
    pub(crate) rewrite_prefix: Option<String>,
    /// `None` matches every tenant. `Some` matches only that tenant.
    pub(crate) tenant_id: Option<String>,
    pub(crate) scopes: HashSet<String>,
    pub(crate) tool_policy: ToolPolicy,
    /// Overrides `REQUEST_TIMEOUT_SECS` for this route.
    pub(crate) request_timeout: Option<Duration>,
    /// Overrides `MAX_RESPONSE_BYTES` for this route.
    pub(crate) max_response_bytes: Option<u64>,
    pub(crate) upstream: Arc<Upstream>,
    pub(crate) priority: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct Upstream {
    pub(crate) id: String,
    pub(crate) base_url: Url,
    pub(crate) client: reqwest::Client,
    pub(crate) timeout: Duration,
    /// RFC 8693 `audience` for the exchanged upstream token.
    pub(crate) audience: Option<String>,
    /// Optional scope to request during exchange.
    pub(crate) exchange_scope: Option<String>,
}

/// Immutable snapshot. Replaced atomically; in-flight requests keep the
/// snapshot they started with, so a reload can never corrupt a request.
#[derive(Clone, Debug)]
pub(crate) struct RouteTable {
    version: i64,
    routes: Vec<CompiledRoute>,
}

/// Outcome of route resolution. Distinguishes "no such path" from "wrong
/// method" so clients get a correct `405` with `Allow` instead of a `404`.
pub(crate) enum RouteMatch<'a> {
    Found(&'a CompiledRoute),
    MethodNotAllowed(Vec<Method>),
    NotFound,
}

impl RouteTable {
    pub(crate) fn version(&self) -> i64 {
        self.version
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.routes.len()
    }

    /// Longest matching prefix wins, then the higher priority. Routes are
    /// pre-sorted, so this is a scan over a usually tiny vector.
    ///
    /// A tenant-specific route only matches its tenant. If the longest prefix
    /// belongs to another tenant, this returns `NotFound` rather than falling
    /// through to a shorter prefix: falling through would proxy the request
    /// under scopes it never earned.
    pub(crate) fn resolve(
        &self,
        method: &Method,
        path: &str,
        tenant: Option<&str>,
    ) -> RouteMatch<'_> {
        let Some(prefix) = self
            .routes
            .iter()
            .find(|route| path_is_within(path, &route.path_prefix))
            .map(|route| route.path_prefix.clone())
        else {
            return RouteMatch::NotFound;
        };

        let mut allowed: Vec<Method> = Vec::new();
        let tenant_owns_prefix = tenant.is_some_and(|tenant| {
            self.routes.iter().any(|route| {
                route.path_prefix == prefix && route.tenant_id.as_deref() == Some(tenant)
            })
        });

        for route in self
            .routes
            .iter()
            .filter(|route| route.path_prefix == prefix)
        {
            if !route.matches_tenant(tenant) {
                continue;
            }

            // A tenant route owns the prefix for that tenant: a shared route
            // at the same prefix must not quietly serve methods the tenant
            // route did not list.
            if tenant_owns_prefix && route.tenant_id.is_none() {
                continue;
            }

            if route.allows(method) {
                return RouteMatch::Found(route);
            }

            for candidate in &route.methods {
                if !allowed.contains(candidate) {
                    allowed.push(candidate.clone());
                }
            }
        }

        if allowed.is_empty() {
            return RouteMatch::NotFound;
        }

        // GET implies HEAD, which the gateway forwards and hyper answers
        // without a body.
        if allowed.contains(&Method::GET) && !allowed.contains(&Method::HEAD) {
            allowed.push(Method::HEAD);
        }

        RouteMatch::MethodNotAllowed(allowed)
    }

    fn compile(
        version: i64,
        rows: Vec<RouteRow>,
        allow_hosts: &[String],
        token_exchange_enabled: bool,
        pool_max_idle_per_host: usize,
    ) -> Result<Self, Vec<String>> {
        let mut problems = Vec::new();
        let mut routes = Vec::with_capacity(rows.len());
        let mut route_ids = HashSet::new();
        let mut claims = HashSet::new();
        let mut upstreams: HashMap<UpstreamKey, Arc<Upstream>> = HashMap::new();

        for row in rows {
            if !route_ids.insert(row.id.clone()) {
                problems.push(format!("route `{}` is defined more than once", row.id));
                continue;
            }

            if let Err(problem) = validate_path_prefix(&row.path_prefix) {
                problems.push(format!("route `{}`: {problem}", row.id));
                continue;
            }

            if row
                .tenant_id
                .as_deref()
                .is_some_and(str::is_empty)
            {
                problems.push(format!("route `{}`: tenant_id must not be empty", row.id));
                continue;
            }

            let methods = compile_methods(&row, &mut problems);
            let upstream = compile_upstream(
                &row,
                allow_hosts,
                token_exchange_enabled,
                pool_max_idle_per_host,
                &mut upstreams,
                &mut problems,
            );

            let (Some(methods), Some(upstream)) = (methods, upstream) else {
                continue;
            };

            if let Some(rewrite) = &row.rewrite_prefix
                && let Err(problem) = validate_rewrite(rewrite)
            {
                problems.push(format!("route `{}`: {problem}", row.id));
                continue;
            }

            let request_timeout = match compile_optional_deadline(&row, &mut problems) {
                Some(timeout) => timeout,
                None => continue,
            };

            let max_response_bytes = match compile_response_cap(&row, &mut problems) {
                Some(cap) => cap,
                None => continue,
            };

            let tool_policy = match compile_tool_policy(&row, &mut problems) {
                Some(policy) => policy,
                None => continue,
            };

            for method in &methods {
                let claim = (
                    row.path_prefix.clone(),
                    method.clone(),
                    row.tenant_id.clone(),
                );

                if !claims.insert(claim) {
                    problems.push(format!(
                        "route `{}`: {} {} is already claimed by another route in the same tenant",
                        row.id,
                        method.as_str(),
                        row.path_prefix
                    ));
                }
            }

            routes.push(CompiledRoute {
                id: row.id,
                path_prefix: row.path_prefix,
                methods,
                rewrite_prefix: row
                    .rewrite_prefix
                    .map(|prefix| normalize_rewrite(&prefix)),
                tenant_id: row.tenant_id,
                scopes: row.scopes.into_iter().collect(),
                tool_policy,
                request_timeout,
                max_response_bytes,
                upstream,
                priority: row.priority,
            });
        }

        if !problems.is_empty() {
            return Err(problems);
        }

        sort_routes(&mut routes);

        Ok(Self { version, routes })
    }

    /// Test-only constructor: routes are sorted exactly as `compile` would.
    #[cfg(test)]
    pub(crate) fn for_tests(version: i64, mut routes: Vec<CompiledRoute>) -> Self {
        sort_routes(&mut routes);

        Self { version, routes }
    }
}

type UpstreamKey = (String, String, u64, Option<String>, Option<String>);

fn sort_routes(routes: &mut [CompiledRoute]) {
    routes.sort_by(|left, right| {
        right
            .path_prefix
            .len()
            .cmp(&left.path_prefix.len())
            .then(right.priority.cmp(&left.priority))
            // A tenant-specific route wins over a shared route at the same
            // prefix and priority.
            .then(
                right
                    .tenant_id
                    .is_some()
                    .cmp(&left.tenant_id.is_some()),
            )
    });
}

impl CompiledRoute {
    fn allows(&self, method: &Method) -> bool {
        self.methods.contains(method)
            || (*method == Method::HEAD && self.methods.contains(&Method::GET))
    }

    fn matches_tenant(&self, tenant: Option<&str>) -> bool {
        match &self.tenant_id {
            None => true,
            Some(bound) => tenant == Some(bound.as_str()),
        }
    }

    /// The effective deadline for this route, bounded by the configured cap.
    pub(crate) fn effective_timeout(&self, default: Duration, maximum: Duration) -> Duration {
        self.request_timeout
            .unwrap_or(default)
            .min(maximum)
    }

    /// The path to request upstream, after prefix stripping and rewriting.
    pub(crate) fn upstream_path(&self, path: &str) -> String {
        translate_path(path, &self.path_prefix, self.rewrite_prefix.as_deref())
    }
}

/// Strips the matched prefix and applies an optional rewrite.
///
/// `/api/people` and `/api/people/` map to the same upstream path.
fn translate_path(path: &str, prefix: &str, rewrite: Option<&str>) -> String {
    let remainder = if prefix == "/" {
        path
    } else {
        path.strip_prefix(prefix).unwrap_or("")
    };

    let remainder = remainder.trim_end_matches('/');

    match rewrite {
        Some(rewrite) => format!("{rewrite}{remainder}"),
        None if remainder.is_empty() => "/".to_owned(),
        None => remainder.to_owned(),
    }
}

/// Prefix matching respects segment boundaries: `/api` matches `/api` and
/// `/api/v1`, never `/apix`.
fn path_is_within(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }

    match path.strip_prefix(prefix) {
        Some(remainder) => remainder.is_empty() || remainder.starts_with('/'),
        None => false,
    }
}

/// `.` and `..` must be rejected before matching. Otherwise a path could match
/// a permissive prefix and still reach a different upstream path once the
/// normalizer drops those segments. Percent-encoded dots count: upstreams
/// commonly decode `%2e%2e` after routing.
pub(crate) fn has_dot_segments(path: &str) -> bool {
    if !path.contains('%') {
        return path
            .split(['/', '\\'])
            .any(is_dot_segment);
    }

    // Decode only the escapes that matter, in one pass, into a byte buffer.
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let escape = (
                bytes[index + 1].to_ascii_lowercase(),
                bytes[index + 2].to_ascii_lowercase(),
            );

            match escape {
                (b'2', b'e') => {
                    decoded.push(b'.');
                    index += 3;
                    continue;
                }
                (b'2', b'f') => {
                    decoded.push(b'/');
                    index += 3;
                    continue;
                }
                (b'5', b'c') => {
                    decoded.push(b'\\');
                    index += 3;
                    continue;
                }
                _ => {}
            }
        }

        decoded.push(bytes[index]);
        index += 1;
    }

    decoded
        .split(|byte| *byte == b'/' || *byte == b'\\')
        .any(|segment| segment == b"." || segment == b"..")
}

/// A backslash is not a path separator to us, but WHATWG URL parsing treats it
/// as one for http(s). Reject it outright so the path we authorize is the path
/// we forward.
pub(crate) fn is_unsafe_path(path: &str) -> bool {
    // Semicolons are path parameters to several frameworks (`..;/admin`).
    // The gateway does not interpret them, so accepting one would let the
    // authorized path differ from the path an upstream executes.
    path.contains('\\')
        || path.contains(';')
        || path.contains("%3b")
        || path.contains("%3B")
        || has_dot_segments(path)
}

fn is_dot_segment(segment: &str) -> bool {
    segment == "." || segment == ".."
}

/// Route syntax shared by the compiler and the admin write path.
pub(crate) fn validate_path_prefix(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/') {
        return Err("path prefix must start with `/`".to_owned());
    }

    if prefix.len() > 1 && prefix.ends_with('/') {
        return Err("path prefix must not end with `/`".to_owned());
    }

    if has_dot_segments(prefix) {
        return Err("path prefix must not contain `.` or `..` segments".to_owned());
    }

    if prefix.contains('\\') {
        return Err("path prefix must not contain a backslash".to_owned());
    }

    Ok(())
}

/// One validator for scheme, embedded credentials, and the SSRF allowlist.
pub(crate) fn validate_upstream_url(raw: &str, allow_hosts: &[String]) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|error| format!("invalid upstream URL: {error}"))?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err("upstream URL must use http or https".to_owned());
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("upstream URL must not embed credentials".to_owned());
    }

    let host = url.host_str().unwrap_or_default();

    if !allow_hosts.is_empty()
        && !allow_hosts
            .iter()
            .any(|allowed| allowed == host)
    {
        return Err(format!(
            "upstream host `{host}` is not in UPSTREAM_ALLOW_HOSTS"
        ));
    }

    Ok(url)
}

pub(crate) fn parse_methods(methods: &[String]) -> Result<Vec<Method>, String> {
    let mut parsed = Vec::with_capacity(methods.len());

    for name in methods {
        let method = Method::from_bytes(
            name.trim()
                .to_ascii_uppercase()
                .as_bytes(),
        )
        .map_err(|_| format!("invalid method `{name}`"))?;
        parsed.push(method);
    }

    if parsed.is_empty() {
        return Err("at least one method is required".to_owned());
    }

    Ok(parsed)
}

fn compile_methods(row: &RouteRow, problems: &mut Vec<String>) -> Option<Vec<Method>> {
    match parse_methods(&row.methods) {
        Ok(methods) => Some(methods),
        Err(problem) => {
            problems.push(format!("route `{}`: {problem}", row.id));
            None
        }
    }
}

fn compile_upstream(
    row: &RouteRow,
    allow_hosts: &[String],
    token_exchange_enabled: bool,
    pool_max_idle_per_host: usize,
    cache: &mut HashMap<UpstreamKey, Arc<Upstream>>,
    problems: &mut Vec<String>,
) -> Option<Arc<Upstream>> {
    let problem = |problems: &mut Vec<String>, message: String| {
        problems.push(format!("route `{}`: {message}", row.id));
    };

    let base_url = match validate_upstream_url(&row.base_url, allow_hosts) {
        Ok(url) => url,
        Err(message) => {
            problem(problems, message);
            return None;
        }
    };

    if row
        .audience
        .as_deref()
        .is_some_and(str::is_empty)
    {
        problem(problems, "upstream audience must not be empty".to_owned());
        return None;
    }

    if row.audience.is_some() && !token_exchange_enabled {
        problem(
            problems,
            "upstream has an audience but token exchange is not configured".to_owned(),
        );
        return None;
    }

    let timeout_ms = u64::try_from(row.timeout_ms)
        .unwrap_or(1)
        .max(1);
    let timeout = Duration::from_millis(timeout_ms);
    let cache_key = (
        row.upstream_id.clone(),
        base_url.as_str().to_owned(),
        timeout_ms,
        row.audience.clone(),
        row.exchange_scope.clone(),
    );

    if let Some(upstream) = cache.get(&cache_key) {
        return Some(Arc::clone(upstream));
    }

    let client = match reqwest::Client::builder()
        .connect_timeout(timeout)
        // A redirect could leave the allowlisted host, so the gateway never
        // follows one; the client receives the 3xx and decides.
        .redirect(reqwest::redirect::Policy::none())
        // Idle sockets are retained for reuse but never indefinitely: reqwest
        // defaults to unbounded, which lets replicas × upstreams hoard
        // connections the upstream still counts against its own limit.
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(30))
        .user_agent(concat!("api-gateway/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            problem(
                problems,
                format!("could not build upstream client: {error}"),
            );
            return None;
        }
    };

    let upstream = Arc::new(Upstream {
        id: row.upstream_id.clone(),
        base_url,
        client,
        timeout,
        audience: row.audience.clone(),
        exchange_scope: row.exchange_scope.clone(),
    });

    cache.insert(cache_key, Arc::clone(&upstream));

    Some(upstream)
}

/// `None` means "use the gateway default"; `Some(None)` means the row was
/// invalid and the caller should skip it.
#[allow(clippy::option_option)]
fn compile_optional_deadline(
    row: &RouteRow,
    problems: &mut Vec<String>,
) -> Option<Option<Duration>> {
    let Some(ms) = row.request_timeout_ms else {
        return Some(None);
    };

    if !(1..=3_600_000).contains(&ms) {
        problems.push(format!(
            "route `{}`: request_timeout_ms must be between 1 and 3600000",
            row.id
        ));
        return None;
    }

    Some(Some(Duration::from_millis(u64::try_from(ms).unwrap_or(1))))
}

fn compile_response_cap(row: &RouteRow, problems: &mut Vec<String>) -> Option<Option<u64>> {
    let Some(cap) = row.max_response_bytes else {
        return Some(None);
    };

    let Ok(cap) = u64::try_from(cap) else {
        problems.push(format!(
            "route `{}`: max_response_bytes must be positive",
            row.id
        ));
        return None;
    };

    if cap != 0 && !(1024..=1_073_741_824).contains(&cap) {
        problems.push(format!(
            "route `{}`: max_response_bytes must be 0 (unlimited) or between 1024 and 1073741824",
            row.id
        ));
        return None;
    }

    Some(Some(cap))
}

fn compile_tool_policy(row: &RouteRow, problems: &mut Vec<String>) -> Option<ToolPolicy> {
    let policy: ToolPolicy = match serde_json::from_value(row.tool_policy.clone()) {
        Ok(policy) => policy,
        Err(error) => {
            problems.push(format!(
                "route `{}`: tool_policy is invalid: {error}",
                row.id
            ));
            return None;
        }
    };

    if let Err(problem) = policy.validate() {
        problems.push(format!("route `{}`: {problem}", row.id));
        return None;
    }

    Some(policy)
}

pub(crate) fn normalize_rewrite(prefix: &str) -> String {
    if prefix == "/" {
        return String::new();
    }

    format!("/{}", prefix.trim_matches('/'))
}

pub(crate) fn validate_rewrite(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/') {
        return Err("rewrite prefix must start with `/`".to_owned());
    }

    if has_dot_segments(prefix) {
        return Err("rewrite prefix must not contain `.` or `..` segments".to_owned());
    }

    if prefix.contains('\\') {
        return Err("rewrite prefix must not contain a backslash".to_owned());
    }

    Ok(())
}

#[derive(Debug, FromRow)]
struct RouteRow {
    id: String,
    path_prefix: String,
    methods: Vec<String>,
    rewrite_prefix: Option<String>,
    tenant_id: Option<String>,
    scopes: Vec<String>,
    priority: i32,
    request_timeout_ms: Option<i32>,
    max_response_bytes: Option<i64>,
    tool_policy: serde_json::Value,
    upstream_id: String,
    base_url: String,
    timeout_ms: i32,
    audience: Option<String>,
    exchange_scope: Option<String>,
}

#[derive(Debug)]
pub(crate) enum RouteTableError {
    Store(sqlx::Error),
    Invalid(Vec<String>),
}

impl fmt::Display for RouteTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "route table query failed: {error}"),
            Self::Invalid(problems) => {
                writeln!(formatter, "route table is invalid:")?;
                for problem in problems {
                    writeln!(formatter, "  - {problem}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for RouteTableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<sqlx::Error> for RouteTableError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error)
    }
}

/// Reads routes from Postgres. Never called on the request path.
pub(crate) struct RouteSource {
    pool: PgPool,
    allow_hosts: Vec<String>,
    token_exchange_enabled: bool,
    pool_max_idle_per_host: usize,
}

impl RouteSource {
    pub(crate) fn new(
        pool: PgPool,
        allow_hosts: Vec<String>,
        token_exchange_enabled: bool,
        pool_max_idle_per_host: usize,
    ) -> Self {
        Self {
            pool,
            allow_hosts,
            token_exchange_enabled,
            pool_max_idle_per_host,
        }
    }

    pub(crate) async fn version(&self) -> Result<i64, RouteTableError> {
        let version: i64 =
            sqlx::query_scalar("SELECT version FROM route_table_state WHERE only_one")
                .fetch_one(&self.pool)
                .await?;

        Ok(version)
    }

    pub(crate) async fn load(&self) -> Result<RouteTable, RouteTableError> {
        // Version and rows must come from one snapshot, otherwise a table can
        // be labelled with a version it does not contain and never reload.
        let mut transaction = self.pool.begin().await?;

        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;

        let version: i64 =
            sqlx::query_scalar("SELECT version FROM route_table_state WHERE only_one")
                .fetch_one(&mut *transaction)
                .await?;

        let rows: Vec<RouteRow> = sqlx::query_as(
            r#"
            SELECT
                r.id,
                r.path_prefix,
                r.methods,
                r.rewrite_prefix,
                r.tenant_id,
                r.scopes,
                r.priority,
                r.request_timeout_ms,
                r.max_response_bytes,
                r.tool_policy,
                u.id AS upstream_id,
                u.base_url,
                u.timeout_ms,
                u.audience,
                u.exchange_scope
            FROM routes r
            JOIN upstreams u ON u.id = r.upstream_id
            WHERE r.enabled
            "#,
        )
        .fetch_all(&mut *transaction)
        .await?;

        transaction.commit().await?;

        RouteTable::compile(
            version,
            rows,
            &self.allow_hosts,
            self.token_exchange_enabled,
            self.pool_max_idle_per_host,
        )
        .map_err(RouteTableError::Invalid)
    }
}

/// Shared, atomically swappable snapshot.
#[derive(Clone)]
pub(crate) struct RouteTableHandle {
    current: Arc<ArcSwap<RouteTable>>,
    refreshed_at: Arc<std::sync::atomic::AtomicU64>,
    stale_after: Duration,
}

impl RouteTableHandle {
    pub(crate) fn new(table: RouteTable) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(table)),
            refreshed_at: Arc::new(std::sync::atomic::AtomicU64::new(now_millis())),
            stale_after: Duration::from_secs(30),
        }
    }

    /// Readiness fails once the table has not been confirmed for this long.
    pub(crate) fn with_stale_after(mut self, stale_after: Duration) -> Self {
        self.stale_after = stale_after;
        self
    }

    pub(crate) fn snapshot(&self) -> Arc<RouteTable> {
        self.current.load_full()
    }

    pub(crate) fn mark_refreshed(&self) {
        self.refreshed_at
            .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn is_stale(&self) -> bool {
        let last = self
            .refreshed_at
            .load(std::sync::atomic::Ordering::Relaxed);
        let age = now_millis().saturating_sub(last);

        age > self.stale_after.as_millis() as u64
    }

    /// Installs `table` only if it is newer than the current snapshot, so a
    /// slow load can never roll the gateway back.
    pub(crate) fn replace_if_newer(&self, table: RouteTable) -> bool {
        let current = self.current.load_full();

        if table.version <= current.version {
            return false;
        }

        self.current.store(Arc::new(table));

        true
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Polls the version counter and swaps the snapshot when it changes.
pub(crate) struct RouteRefresh {
    source: RouteSource,
    handle: RouteTableHandle,
    interval: Duration,
}

impl RouteRefresh {
    pub(crate) fn new(source: RouteSource, handle: RouteTableHandle, interval: Duration) -> Self {
        Self {
            source,
            handle,
            interval,
        }
    }

    pub(crate) async fn refresh_once(&self) -> Result<bool, RouteTableError> {
        let version = self.source.version().await?;

        if version == self.handle.snapshot().version() {
            self.handle.mark_refreshed();
            return Ok(false);
        }

        // Only a table that actually compiled counts as a healthy refresh: a
        // rejected configuration must not look ready.
        let table = self.source.load().await?;
        let installed = self.handle.replace_if_newer(table);
        self.handle.mark_refreshed();

        Ok(installed)
    }

    pub(crate) async fn run(self) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;

            match self.refresh_once().await {
                Ok(true) => tracing::info!("route table reloaded"),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, "route table refresh failed; keeping the last good snapshot")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method as HttpMethod;

    fn row(id: &str, prefix: &str, methods: &[&str]) -> RouteRow {
        RouteRow {
            id: id.to_owned(),
            path_prefix: prefix.to_owned(),
            methods: methods
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            rewrite_prefix: None,
            tenant_id: None,
            scopes: Vec::new(),
            priority: 0,
            request_timeout_ms: None,
            max_response_bytes: None,
            tool_policy: serde_json::json!({"mode": "off", "roles": {}}),
            upstream_id: "upstream".to_owned(),
            base_url: "https://example.test/api".to_owned(),
            timeout_ms: 5_000,
            audience: None,
            exchange_scope: None,
        }
    }

    fn table(rows: Vec<RouteRow>) -> RouteTable {
        RouteTable::compile(1, rows, &[], false, 64).expect("valid route table")
    }

    fn found<'a>(table: &'a RouteTable, method: HttpMethod, path: &str) -> &'a CompiledRoute {
        found_for(table, None, method, path)
    }

    fn found_for<'a>(
        table: &'a RouteTable,
        tenant: Option<&str>,
        method: HttpMethod,
        path: &str,
    ) -> &'a CompiledRoute {
        match table.resolve(&method, path, tenant) {
            RouteMatch::Found(route) => route,
            RouteMatch::MethodNotAllowed(_) => panic!("{path} matched but rejected the method"),
            RouteMatch::NotFound => panic!("{path} did not match a route"),
        }
    }

    #[test]
    fn longest_prefix_wins() {
        let table = table(vec![
            row("root", "/", &["GET"]),
            row("api", "/api", &["GET"]),
            row("people", "/api/people", &["GET"]),
        ]);

        assert_eq!(found(&table, HttpMethod::GET, "/api/people/1").id, "people");
    }

    #[test]
    fn prefix_matching_respects_segment_boundaries() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        found(&table, HttpMethod::GET, "/api");
        found(&table, HttpMethod::GET, "/api/people");
        assert!(matches!(
            table.resolve(&HttpMethod::GET, "/apix", None),
            RouteMatch::NotFound
        ));
    }

    #[test]
    fn wrong_method_is_rejected_with_allow_list() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        match table.resolve(&HttpMethod::POST, "/api", None) {
            RouteMatch::MethodNotAllowed(allowed) => {
                assert_eq!(allowed, vec![HttpMethod::GET, HttpMethod::HEAD]);
            }
            _ => panic!("expected method-not-allowed"),
        }
    }

    #[test]
    fn head_is_implied_by_get() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        assert_eq!(found(&table, HttpMethod::HEAD, "/api").id, "api");
    }

    #[test]
    fn unknown_paths_are_not_found() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        assert!(matches!(
            table.resolve(&HttpMethod::GET, "/other", None),
            RouteMatch::NotFound
        ));
    }

    #[test]
    fn detects_dot_segments_including_encoded_ones() {
        assert!(has_dot_segments("/a/../b"));
        assert!(has_dot_segments("/a/./b"));
        assert!(has_dot_segments("/.."));
        assert!(has_dot_segments("/a/%2e%2e/b"));
        assert!(has_dot_segments("/a/%2E%2E/b"));
        assert!(has_dot_segments("/a%2f..%2fb"));
        assert!(!has_dot_segments("/a/b"));
        assert!(!has_dot_segments("/a..b/c"));
        assert!(!has_dot_segments("/a%2Fb"));
    }

    #[test]
    fn rejects_backslash_paths() {
        assert!(is_unsafe_path("/api/x\\..\\..\\admin"));
        assert!(is_unsafe_path("/a%5c..%5c..%5cadmin"));
        assert!(!is_unsafe_path("/api/people/1"));
    }

    #[test]
    fn rejects_matrix_parameter_traversal() {
        assert!(is_unsafe_path("/api/x/..;/admin"));
        assert!(is_unsafe_path("/api/x/..%3b/admin"));
        assert!(is_unsafe_path("/api/x/..%3B/admin"));
    }

    #[test]
    fn a_specific_route_never_falls_through_to_a_shorter_prefix() {
        let table = table(vec![
            row("public", "/api", &["GET"]),
            row("admin", "/api/admin", &["POST"]),
        ]);

        // GET /api/admin/users matches /api/admin, which only allows POST. It
        // must not be proxied under /api's scopes.
        match table.resolve(&HttpMethod::GET, "/api/admin/users", None) {
            RouteMatch::MethodNotAllowed(allowed) => {
                assert_eq!(allowed, vec![HttpMethod::POST]);
            }
            _ => panic!("expected method-not-allowed for the longest prefix"),
        }
    }

    #[test]
    fn rejects_ambiguous_prefix_and_method_pairs() {
        let problems = RouteTable::compile(
            1,
            vec![row("a", "/api", &["GET"]), row("b", "/api", &["GET"])],
            &[],
            false,
            64,
        )
        .expect_err("ambiguous table");

        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("already claimed"))
        );
    }

    #[test]
    fn rejects_upstreams_outside_the_allowlist() {
        let problems = RouteTable::compile(
            1,
            vec![row("api", "/api", &["GET"])],
            &["allowed.example".to_owned()],
            false,
            64,
        )
        .expect_err("host not allowed");

        assert!(problems[0].contains("UPSTREAM_ALLOW_HOSTS"));
    }

    #[test]
    fn strips_and_rewrites_the_prefix() {
        let mut route = row("api", "/api/people", &["GET"]);
        route.rewrite_prefix = Some("/people".to_owned());
        let table = table(vec![route]);
        let route = found(&table, HttpMethod::GET, "/api/people/1");

        assert_eq!(route.upstream_path("/api/people/1"), "/people/1");
        assert_eq!(route.upstream_path("/api/people"), "/people");
    }

    #[test]
    fn a_tenant_route_is_invisible_to_other_tenants() {
        let mut tenant_a = row("a", "/mcp", &["POST"]);
        tenant_a.tenant_id = Some("tenant-a".to_owned());

        let table = table(vec![tenant_a]);

        assert_eq!(
            found_for(&table, Some("tenant-a"), HttpMethod::POST, "/mcp").id,
            "a"
        );
        assert!(matches!(
            table.resolve(&HttpMethod::POST, "/mcp", Some("tenant-b")),
            RouteMatch::NotFound
        ));
        assert!(matches!(
            table.resolve(&HttpMethod::POST, "/mcp", None),
            RouteMatch::NotFound
        ));
    }

    #[test]
    fn a_tenant_route_shadows_a_shared_route_for_unlisted_methods() {
        let shared = row("shared", "/mcp", &["GET", "POST"]);

        let mut tenant = row("tenant", "/mcp", &["POST"]);
        tenant.tenant_id = Some("tenant-a".to_owned());

        let table = table(vec![shared, tenant]);

        // The tenant's route owns the prefix; GET must not fall back to the
        // shared route's scopes/policy.
        assert!(matches!(
            table.resolve(&HttpMethod::GET, "/mcp", Some("tenant-a")),
            RouteMatch::MethodNotAllowed(_)
        ));
    }

    #[test]
    fn a_tenant_route_wins_over_a_shared_route() {
        let shared = row("shared", "/mcp", &["POST"]);

        let mut tenant = row("tenant", "/mcp", &["POST"]);
        tenant.tenant_id = Some("tenant-a".to_owned());

        let table = table(vec![shared, tenant]);

        assert_eq!(
            found_for(&table, Some("tenant-a"), HttpMethod::POST, "/mcp").id,
            "tenant"
        );
        assert_eq!(
            found_for(&table, Some("tenant-b"), HttpMethod::POST, "/mcp").id,
            "shared"
        );
    }

    #[test]
    fn another_tenants_route_does_not_fall_through_to_a_shorter_prefix() {
        let shared = row("shared", "/api", &["GET"]);

        let mut tenant = row("tenant", "/api/private", &["GET"]);
        tenant.tenant_id = Some("tenant-a".to_owned());

        let table = table(vec![shared, tenant]);

        assert!(matches!(
            table.resolve(&HttpMethod::GET, "/api/private/data", Some("tenant-b")),
            RouteMatch::NotFound
        ));
    }

    #[test]
    fn route_deadline_and_response_cap_are_compiled() {
        let mut route = row("mcp", "/mcp", &["POST"]);
        route.request_timeout_ms = Some(120_000);
        route.max_response_bytes = Some(32 * 1024 * 1024);

        let table = table(vec![route]);
        let route = found(&table, HttpMethod::POST, "/mcp");

        assert_eq!(
            route.effective_timeout(Duration::from_secs(15), Duration::from_secs(300)),
            Duration::from_secs(120)
        );
        assert_eq!(route.max_response_bytes, Some(32 * 1024 * 1024));
    }

    #[test]
    fn route_deadline_is_bounded_by_the_hard_cap() {
        let mut route = row("mcp", "/mcp", &["POST"]);
        route.request_timeout_ms = Some(600_000);

        let table = table(vec![route]);
        let route = found(&table, HttpMethod::POST, "/mcp");

        assert_eq!(
            route.effective_timeout(Duration::from_secs(15), Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn rejects_an_invalid_tool_policy() {
        let mut route = row("mcp", "/mcp", &["POST"]);
        route.tool_policy = serde_json::json!({"mode": "allow_list", "roles": {}});

        let problems =
            RouteTable::compile(1, vec![route], &[], false, 64).expect_err("invalid policy");
        assert!(problems[0].contains("at least one role"));
    }

    #[test]
    fn compiles_an_allow_list_tool_policy() {
        let mut route = row("mcp", "/mcp", &["POST"]);
        route.tool_policy = serde_json::json!({
            "mode": "allow_list",
            "roles": {"support": ["search_tickets"]}
        });

        let table = table(vec![route]);
        let route = found(&table, HttpMethod::POST, "/mcp");

        assert!(route.tool_policy.is_enforcing());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn safe_path() -> impl Strategy<Value = String> {
        prop::collection::vec("[A-Za-z0-9_~-]{1,10}", 0..4)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The invariant the backslash bug broke: a path we accept must survive the
        /// URL parser without becoming a dot segment or a second separator.
        #[test]
        fn accepted_paths_do_not_normalize_into_dot_segments(path in safe_path()) {
            prop_assert!(!is_unsafe_path(&path));

            let url = reqwest::Url::parse(&format!("http://upstream.test{path}"))
                .expect("safe paths parse");

            prop_assert!(!url.path().contains('\\'));
            prop_assert!(
                !url.path().split('/').any(|segment| segment == "." || segment == ".."),
                "accepted path {} normalized to {}",
                path,
                url.path()
            );
        }

        /// Every spelling of traversal we know of is rejected, wherever it appears.
        #[test]
        fn traversal_is_rejected_in_any_position(
            prefix in prop::collection::vec("[a-z]{1,6}", 0..2),
            payload in prop_oneof![
                Just("..".to_owned()),
                Just(".".to_owned()),
                Just("%2e%2e".to_owned()),
                Just("%2E%2E".to_owned()),
                Just("..\\..".to_owned()),
                Just("%5c..".to_owned()),
                Just("%2f..".to_owned()),
            ],
        ) {
            let path = format!("/{}/{payload}/admin", prefix.join("/"));
            prop_assert!(is_unsafe_path(&path), "{} was accepted", path);
        }

        /// Translation is exactly "strip the prefix, then append to the rewrite".
        #[test]
        fn translation_matches_the_oracle(
            tail in prop::collection::vec("[a-z]{1,8}", 0..3),
            rewrite in prop::option::of(Just("/rw".to_owned())),
        ) {
            let prefix = "/api";
            let path = if tail.is_empty() {
                prefix.to_owned()
            } else {
                format!("{prefix}/{}", tail.join("/"))
            };

            let translated = translate_path(&path, prefix, rewrite.as_deref());
            let remainder = if tail.is_empty() {
                String::new()
            } else {
                format!("/{}", tail.join("/"))
            };

            match rewrite {
                Some(rewrite) => prop_assert_eq!(translated, format!("{rewrite}{remainder}")),
                None if remainder.is_empty() => prop_assert_eq!(translated, "/".to_owned()),
                None => prop_assert_eq!(translated, remainder),
            }
        }

        /// Whatever path we forward stays under the upstream's base path.
        #[test]
        fn translation_never_escapes_the_prefix(
            tail in prop::collection::vec("[a-z]{1,8}", 0..3),
        ) {
            let prefix = "/api";
            let path = format!("{prefix}/{}", tail.join("/"));
            let translated = translate_path(&path, prefix, None);

            prop_assert!(translated.starts_with('/'));
            prop_assert!(!translated.split('/').any(|segment| segment == ".."));
        }
    }
}

#[cfg(test)]
mod behaviour_tests {
    use super::*;
    use std::time::Duration;

    fn empty_table(version: i64) -> RouteTable {
        RouteTable::for_tests(version, Vec::new())
    }

    #[test]
    fn prefix_validation_rejects_bad_shapes() {
        for bad in ["api", "/api/", "/a/../b", "/a\\b", "/./x", "/.."] {
            assert!(validate_path_prefix(bad).is_err(), "accepted prefix {bad}");
        }

        for good in ["/", "/api", "/api/v1"] {
            assert!(validate_path_prefix(good).is_ok(), "rejected prefix {good}");
        }
    }

    #[test]
    fn rewrite_validation_rejects_bad_shapes() {
        for bad in ["api", "/a/../b", "/a\\b"] {
            assert!(validate_rewrite(bad).is_err(), "accepted rewrite {bad}");
        }

        for good in ["/", "/api", "/v1/billing"] {
            assert!(validate_rewrite(good).is_ok(), "rejected rewrite {good}");
        }
    }

    #[test]
    fn upstream_validation_rejects_unsafe_urls() {
        assert!(validate_upstream_url("ftp://x.test", &[]).is_err());
        assert!(validate_upstream_url("https://user@x.test", &[]).is_err());
        assert!(validate_upstream_url("https://user:pw@x.test", &[]).is_err());
        assert!(validate_upstream_url("https://x.test", &["other.test".to_owned()]).is_err());
        assert!(validate_upstream_url("https://x.test", &["x.test".to_owned()]).is_ok());
        assert!(validate_upstream_url("https://x.test", &[]).is_ok());
    }

    #[test]
    fn truncated_escapes_are_not_mistaken_for_traversal() {
        // Percent-escape parsing must not read past the end or invent a match.
        for harmless in ["/a/%2", "/a/%zz", "/a2e", "/a5c", "/a/%"] {
            assert!(!has_dot_segments(harmless), "flagged {harmless}");
        }
    }

    #[test]
    fn an_empty_table_reports_no_routes() {
        let table = empty_table(1);

        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn replace_if_newer_ignores_older_and_equal_versions() {
        let handle = RouteTableHandle::new(empty_table(5));

        assert!(!handle.replace_if_newer(empty_table(5)), "equal version");
        assert_eq!(handle.snapshot().version(), 5);

        assert!(!handle.replace_if_newer(empty_table(4)), "older version");
        assert_eq!(handle.snapshot().version(), 5);

        assert!(handle.replace_if_newer(empty_table(6)), "newer version");
        assert_eq!(handle.snapshot().version(), 6);
    }

    #[test]
    fn refreshing_clears_staleness() {
        let handle = RouteTableHandle::new(empty_table(1)).with_stale_after(Duration::ZERO);

        std::thread::sleep(Duration::from_millis(5));
        assert!(handle.is_stale());

        handle.mark_refreshed();
        assert!(!handle.is_stale());
    }

    #[test]
    fn route_table_errors_describe_themselves() {
        use std::error::Error as _;

        let invalid = RouteTableError::Invalid(vec!["route `a`: broken".to_owned()]);
        assert!(
            invalid
                .to_string()
                .contains("route `a`: broken")
        );
        assert!(invalid.source().is_none());

        let store = RouteTableError::Store(sqlx::Error::RowNotFound);
        assert!(store.source().is_some());
        assert!(!store.to_string().is_empty());
    }

    #[tokio::test]
    async fn source_and_refresh_follow_the_version_counter() {
        let Some(pool) = crate::testing::pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let source = RouteSource::new(pool.clone(), Vec::new(), false, 64);

        let before = source.version().await.expect("version");

        // Distinguish a real read from a constant.
        sqlx::query("UPDATE route_table_state SET version = version + 1 WHERE only_one")
            .execute(&pool)
            .await
            .expect("bump version");

        let after = source.version().await.expect("version");
        assert_eq!(after, before + 1);

        let handle = RouteTableHandle::new(source.load().await.expect("load"));
        let refresh = RouteRefresh::new(source, handle.clone(), Duration::from_secs(1));

        assert!(
            !refresh
                .refresh_once()
                .await
                .expect("refresh"),
            "no change"
        );

        sqlx::query("UPDATE route_table_state SET version = version + 1 WHERE only_one")
            .execute(&pool)
            .await
            .expect("bump version");

        assert!(
            refresh
                .refresh_once()
                .await
                .expect("refresh"),
            "changed"
        );
        assert_eq!(handle.snapshot().version(), after + 1);
    }
}
