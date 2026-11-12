use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use reqwest::{Method, Url};
use sqlx::{FromRow, PgPool};

/// A route compiled for request matching: no allocation, no locks on the path.
#[derive(Clone, Debug)]
pub(crate) struct CompiledRoute {
    pub(crate) id: String,
    pub(crate) path_prefix: String,
    pub(crate) methods: Vec<Method>,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) scopes: HashSet<String>,
    pub(crate) upstream: Arc<Upstream>,
    pub(crate) priority: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct Upstream {
    pub(crate) id: String,
    pub(crate) base_url: Url,
    pub(crate) client: reqwest::Client,
    pub(crate) timeout: Duration,
}

/// Immutable snapshot. Replaced atomically; in-flight requests keep the
/// snapshot they started with, so a reload can never corrupt a request.
#[derive(Clone, Debug)]
pub(crate) struct RouteTable {
    version: i64,
    routes: Vec<CompiledRoute>,
}

impl RouteTable {
    pub(crate) fn version(&self) -> i64 {
        self.version
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Longest matching prefix wins, then the higher priority. Routes are
    /// pre-sorted, so this is a scan over a usually tiny vector.
    pub(crate) fn resolve(&self, method: &Method, path: &str) -> Option<&CompiledRoute> {
        self.routes
            .iter()
            .find(|route| route.matches(method, path))
    }

    fn compile(
        version: i64,
        rows: Vec<RouteRow>,
        allow_hosts: &[String],
    ) -> Result<Self, Vec<String>> {
        let mut problems = Vec::new();
        let mut routes = Vec::with_capacity(rows.len());
        let mut route_ids = HashSet::new();
        let mut claims = HashSet::new();
        let mut upstreams: HashMap<(String, String, u64), Arc<Upstream>> = HashMap::new();

        for row in rows {
            if !route_ids.insert(row.id.clone()) {
                problems.push(format!("route `{}` is defined more than once", row.id));
                continue;
            }

            if let Err(problem) = validate_path_prefix(&row.path_prefix) {
                problems.push(format!("route `{}`: {problem}", row.id));
                continue;
            }

            let methods = compile_methods(&row, &mut problems);
            let upstream = compile_upstream(&row, allow_hosts, &mut upstreams, &mut problems);

            let (Some(methods), Some(upstream)) = (methods, upstream) else {
                continue;
            };

            if let Some(rewrite) = &row.rewrite_prefix
                && let Err(problem) = validate_rewrite(rewrite)
            {
                problems.push(format!("route `{}`: {problem}", row.id));
                continue;
            }

            for method in &methods {
                if !claims.insert((row.path_prefix.clone(), method.clone())) {
                    problems.push(format!(
                        "route `{}`: {} {} is already claimed by another route",
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
                scopes: row.scopes.into_iter().collect(),
                upstream,
                priority: row.priority,
            });
        }

        if !problems.is_empty() {
            return Err(problems);
        }

        routes.sort_by(|left, right| {
            right
                .path_prefix
                .len()
                .cmp(&left.path_prefix.len())
                .then(right.priority.cmp(&left.priority))
        });

        Ok(Self { version, routes })
    }

    /// Test-only constructor: routes are sorted exactly as `compile` would.
    #[cfg(test)]
    pub(crate) fn for_tests(version: i64, mut routes: Vec<CompiledRoute>) -> Self {
        routes.sort_by(|left, right| {
            right
                .path_prefix
                .len()
                .cmp(&left.path_prefix.len())
                .then(right.priority.cmp(&left.priority))
        });

        Self { version, routes }
    }
}

impl CompiledRoute {
    fn matches(&self, method: &Method, path: &str) -> bool {
        self.methods.contains(method) && path_is_within(path, &self.path_prefix)
    }

    /// The path to request upstream, after prefix stripping and rewriting.
    pub(crate) fn upstream_path(&self, path: &str) -> String {
        let remainder = if self.path_prefix == "/" {
            path
        } else {
            path.strip_prefix(&self.path_prefix)
                .unwrap_or("")
        };

        // `/api/people` and `/api/people/` must map to the same upstream path.
        let remainder = remainder.trim_end_matches('/');

        match &self.rewrite_prefix {
            Some(prefix) => format!("{prefix}{remainder}"),
            None if remainder.is_empty() => "/".to_owned(),
            None => remainder.to_owned(),
        }
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
/// normalizer drops those segments.
pub(crate) fn has_dot_segments(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
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
    cache: &mut HashMap<(String, String, u64), Arc<Upstream>>,
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

    let timeout_ms = u64::try_from(row.timeout_ms)
        .unwrap_or(1)
        .max(1);
    let timeout = Duration::from_millis(timeout_ms);
    let cache_key = (
        row.upstream_id.clone(),
        base_url.as_str().to_owned(),
        timeout_ms,
    );

    if let Some(upstream) = cache.get(&cache_key) {
        return Some(Arc::clone(upstream));
    }

    let client = match reqwest::Client::builder()
        .connect_timeout(timeout)
        // A redirect could leave the allowlisted host, so the gateway never
        // follows one; the client receives the 3xx and decides.
        .redirect(reqwest::redirect::Policy::none())
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
    });

    cache.insert(cache_key, Arc::clone(&upstream));

    Some(upstream)
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

    Ok(())
}

#[derive(Debug, FromRow)]
struct RouteRow {
    id: String,
    path_prefix: String,
    methods: Vec<String>,
    rewrite_prefix: Option<String>,
    scopes: Vec<String>,
    priority: i32,
    upstream_id: String,
    base_url: String,
    timeout_ms: i32,
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
}

impl RouteSource {
    pub(crate) fn new(pool: PgPool, allow_hosts: Vec<String>) -> Self {
        Self { pool, allow_hosts }
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
                r.scopes,
                r.priority,
                u.id AS upstream_id,
                u.base_url,
                u.timeout_ms
            FROM routes r
            JOIN upstreams u ON u.id = r.upstream_id
            WHERE r.enabled
            "#,
        )
        .fetch_all(&mut *transaction)
        .await?;

        transaction.commit().await?;

        RouteTable::compile(version, rows, &self.allow_hosts).map_err(RouteTableError::Invalid)
    }
}

/// Shared, atomically swappable snapshot.
#[derive(Clone)]
pub(crate) struct RouteTableHandle {
    current: Arc<ArcSwap<RouteTable>>,
}

impl RouteTableHandle {
    pub(crate) fn new(table: RouteTable) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(table)),
        }
    }

    pub(crate) fn snapshot(&self) -> Arc<RouteTable> {
        self.current.load_full()
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
            return Ok(false);
        }

        let table = self.source.load().await?;
        let installed = self.handle.replace_if_newer(table);

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
            scopes: Vec::new(),
            priority: 0,
            upstream_id: "upstream".to_owned(),
            base_url: "https://example.test/api".to_owned(),
            timeout_ms: 5_000,
        }
    }

    fn table(rows: Vec<RouteRow>) -> RouteTable {
        RouteTable::compile(1, rows, &[]).expect("valid route table")
    }

    #[test]
    fn longest_prefix_wins() {
        let table = table(vec![
            row("root", "/", &["GET"]),
            row("api", "/api", &["GET"]),
            row("people", "/api/people", &["GET"]),
        ]);

        let route = table
            .resolve(&HttpMethod::GET, "/api/people/1")
            .expect("matched");

        assert_eq!(route.id, "people");
    }

    #[test]
    fn prefix_matching_respects_segment_boundaries() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        assert!(
            table
                .resolve(&HttpMethod::GET, "/api")
                .is_some()
        );
        assert!(
            table
                .resolve(&HttpMethod::GET, "/api/people")
                .is_some()
        );
        assert!(
            table
                .resolve(&HttpMethod::GET, "/apix")
                .is_none()
        );
    }

    #[test]
    fn method_must_match() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        assert!(
            table
                .resolve(&HttpMethod::POST, "/api")
                .is_none()
        );
    }

    #[test]
    fn detects_dot_segments() {
        assert!(has_dot_segments("/a/../b"));
        assert!(has_dot_segments("/a/./b"));
        assert!(has_dot_segments("/.."));
        assert!(!has_dot_segments("/a/b"));
        assert!(!has_dot_segments("/a..b/c"));
    }

    #[test]
    fn rejects_ambiguous_prefix_and_method_pairs() {
        let problems = RouteTable::compile(
            1,
            vec![row("a", "/api", &["GET"]), row("b", "/api", &["GET"])],
            &[],
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
        )
        .expect_err("host not allowed");

        assert!(problems[0].contains("UPSTREAM_ALLOW_HOSTS"));
    }

    #[test]
    fn strips_and_rewrites_the_prefix() {
        let mut route = row("api", "/api/people", &["GET"]);
        route.rewrite_prefix = Some("/people".to_owned());
        let table = table(vec![route]);
        let route = table
            .resolve(&HttpMethod::GET, "/api/people/1")
            .expect("matched");

        assert_eq!(route.upstream_path("/api/people/1"), "/people/1");
        assert_eq!(route.upstream_path("/api/people"), "/people");
    }
}
