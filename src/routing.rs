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
    pub(crate) fn resolve(&self, method: &Method, path: &str) -> RouteMatch<'_> {
        // Only the longest matching prefix participates. Falling through to a
        // shorter prefix would proxy a request under scopes it never earned.
        let Some(prefix) = self
            .routes
            .iter()
            .find(|route| path_is_within(path, &route.path_prefix))
            .map(|route| route.path_prefix.clone())
        else {
            return RouteMatch::NotFound;
        };

        let mut allowed: Vec<Method> = Vec::new();

        for route in self
            .routes
            .iter()
            .filter(|route| route.path_prefix == prefix)
        {
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
    fn allows(&self, method: &Method) -> bool {
        self.methods.contains(method)
            || (*method == Method::HEAD && self.methods.contains(&Method::GET))
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
    path.contains('\\') || has_dot_segments(path)
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

    fn found<'a>(table: &'a RouteTable, method: HttpMethod, path: &str) -> &'a CompiledRoute {
        match table.resolve(&method, path) {
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
            table.resolve(&HttpMethod::GET, "/apix"),
            RouteMatch::NotFound
        ));
    }

    #[test]
    fn wrong_method_is_rejected_with_allow_list() {
        let table = table(vec![row("api", "/api", &["GET"])]);

        match table.resolve(&HttpMethod::POST, "/api") {
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
            table.resolve(&HttpMethod::GET, "/other"),
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
    fn a_specific_route_never_falls_through_to_a_shorter_prefix() {
        let table = table(vec![
            row("public", "/api", &["GET"]),
            row("admin", "/api/admin", &["POST"]),
        ]);

        // GET /api/admin/users matches /api/admin, which only allows POST. It
        // must not be proxied under /api's scopes.
        match table.resolve(&HttpMethod::GET, "/api/admin/users") {
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
        let route = found(&table, HttpMethod::GET, "/api/people/1");

        assert_eq!(route.upstream_path("/api/people/1"), "/people/1");
        assert_eq!(route.upstream_path("/api/people"), "/people");
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
