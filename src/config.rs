use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppEnvironment {
    Development,
    Production,
}

impl AppEnvironment {
    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

impl Config {
    /// Settings that are valid but worth saying out loud at boot.
    pub fn advisories(&self) -> Vec<String> {
        let mut notes = Vec::new();

        if self.auth.cache_ttl.is_zero() {
            notes.push(
                "AUTH_CACHE_TTL_SECS=0: every request reads credentials from Postgres".to_owned(),
            );
        }
        if self.limits.ip_per_minute == 0 {
            notes.push("RATE_LIMIT_IP_PER_MINUTE=0: per-IP rate limiting is disabled".to_owned());
        }
        if self.limits.tenant_per_minute == 0 {
            notes.push(
                "RATE_LIMIT_TENANT_PER_MINUTE=0: per-tenant rate limiting is disabled".to_owned(),
            );
        }
        if self.limits.user_per_minute == 0 {
            notes.push(
                "RATE_LIMIT_USER_PER_MINUTE=0: per-user rate limiting is disabled".to_owned(),
            );
        }
        if self.retry.max_attempts <= 1 {
            notes.push("RETRY_MAX_ATTEMPTS=1: upstream retries are disabled".to_owned());
        }
        if self.admin.tokens.is_empty() {
            notes.push("ADMIN_TOKEN is unset: the HTTP control plane is disabled".to_owned());
        }
        if self.telemetry.metrics_token.is_none() {
            notes.push(
                "METRICS_TOKEN is unset: /metrics is readable by anyone who can reach the port"
                    .to_owned(),
            );
        }
        if self.environment.is_production()
            && (self
                .telemetry
                .log_level
                .contains("debug")
                || self
                    .telemetry
                    .log_level
                    .contains("trace"))
        {
            notes.push(
                "LOG_LEVEL is debug/trace in production: benchmark shows ~2.7x throughput cost"
                    .to_owned(),
            );
        }
        if !self.environment.is_production() && self.routing.allow_hosts.is_empty() {
            notes.push(
                "UPSTREAM_ALLOW_HOSTS is empty: any upstream host is allowed (development only)"
                    .to_owned(),
            );
        }
        if self.oauth.is_none() {
            notes.push(
                "OAUTH_ISSUER is unset: only API-key credentials are accepted; \
                 MCP connectors need OAuth"
                    .to_owned(),
            );
        }
        if let Some(oauth) = &self.oauth
            && oauth.token_exchange.is_none()
        {
            notes.push(
                "OAUTH_TOKEN_ENDPOINT is unset: upstreams receive no per-user token; \
                 only routes with no audience configured can be called"
                    .to_owned(),
            );
        }
        if self
            .server
            .cors_allowed_origins
            .is_empty()
        {
            notes.push(
                "CORS_ALLOWED_ORIGINS is empty: browser-based MCP clients will be blocked"
                    .to_owned(),
            );
        }
        if !self.data_audit.enabled {
            notes.push(
                "DATA_AUDIT_ENABLED=false: the data plane is not audited per call".to_owned(),
            );
        }

        notes
    }
}

/// Development-only pepper. Production must set `AUTH_PEPPER`.
pub const DEVELOPMENT_PEPPER: &str = "development-only-pepper";

/// A string that is safe to `Debug` but must be explicitly exposed.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([redacted])")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;

        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub environment: AppEnvironment,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub telemetry: TelemetryConfig,
    pub auth: AuthConfig,
    pub admin: AdminConfig,
    pub routing: RoutingConfig,
    pub limits: LimitsConfig,
    pub retry: RetryConfig,
    pub mcp: McpConfig,
    /// `None` disables OAuth. API keys keep working either way.
    pub oauth: Option<OAuthConfig>,
    pub data_audit: DataAuditConfig,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_body_limit_bytes: usize,
    /// Default deadline for a proxied request that does not override it.
    pub request_timeout: Duration,
    /// Absolute cap. A route may ask for a longer deadline, but never past this.
    pub max_request_timeout: Duration,
    /// Default cap on a proxied response body.
    pub max_response_bytes: u64,
    /// A streamed response that produces no bytes for this long is cut.
    pub stream_idle_timeout: Duration,
    /// Browser origins allowed to call the gateway. Empty disables CORS.
    pub cors_allowed_origins: Vec<String>,
    pub shutdown_drain: Duration,
    /// Bound on reading a complete request head. Without it a client can hold
    /// a connection open by trickling headers (slowloris).
    pub header_read_timeout: Duration,
    /// Hard cap on concurrent TCP connections.
    pub max_connections: usize,
    /// Peers allowed to speak for the client via forwarding headers.
    pub trusted_proxies: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub url: SecretString,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub otlp_endpoint: Option<String>,
    /// When set, `/metrics` requires this bearer token.
    pub metrics_token: Option<SecretString>,
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Server-side pepper mixed into every key verifier. Rotating it
    /// invalidates all keys derived with the previous value.
    pub pepper: SecretString,
    pub dev_api_key_secret: Option<SecretString>,
    pub dev_api_key_scopes: Vec<String>,
    /// How long a credential may be served from cache. Zero disables caching.
    pub cache_ttl: Duration,
}

#[derive(Clone, Debug)]
pub struct AdminConfig {
    /// Bind address for the HTTP control plane. Empty disables it.
    pub bind: String,
    /// Named admin tokens. Empty disables the listener.
    pub tokens: Vec<AdminToken>,
    /// Deadline for one control-plane request.
    pub timeout: Duration,
    /// How long audit rows are kept. Zero keeps them forever.
    pub audit_retention: Duration,
}

/// One operator credential. The name is what the audit log records; the scopes
/// decide what the token may do. `*` grants every scope.
#[derive(Clone, Debug)]
pub struct AdminToken {
    pub name: String,
    pub token: SecretString,
    pub scopes: HashSet<String>,
}

/// Every privilege a control-plane token can hold.
pub const ADMIN_SCOPES: &[&str] = &[
    "tenants:write",
    "keys:read",
    "keys:write",
    "config:read",
    "config:write",
    "audit:read",
];

#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Total attempts, including the first. 1 disables retries.
    pub max_attempts: u32,
    pub base_delay: Duration,
    /// Retries allowed per request, as a fraction of normal traffic.
    pub budget_ratio: f64,
}

#[derive(Clone, Debug)]
pub struct McpConfig {
    /// How long a tool schema learned from `tools/list` stays trusted. Zero
    /// disables input validation: with nothing remembered, there is nothing to
    /// check a call against.
    pub tool_schema_ttl: Duration,
}

#[derive(Clone, Debug)]
pub struct RoutingConfig {
    /// Empty means "allow any host"; production requires a non-empty list.
    pub allow_hosts: Vec<String>,
    pub refresh_interval: Duration,
    /// What an allowlisted upstream hostname is allowed to resolve to.
    pub egress: crate::net::Egress,
    /// Idle sockets kept per upstream client, per replica. It is per client,
    /// not per host: routes that differ in timeout, audience or exchange
    /// scope get their own client, and each keeps up to this many sockets to
    /// the same host. Peak concurrency is limited separately, not by this
    /// value. The default is a starting bound, not a measured optimum; size
    /// it from the upstream's connection limit divided by replicas × clients.
    pub pool_max_idle_per_host: usize,
}

#[derive(Clone, Debug)]
pub struct LimitsConfig {
    /// Requests per minute per client IP. Zero disables the limiter.
    pub ip_per_minute: u32,
    /// Requests per minute per tenant. Zero disables the limiter.
    pub tenant_per_minute: u32,
    /// Requests per minute per authenticated user. Zero disables the limiter.
    pub user_per_minute: u32,
    /// Tool calls per minute per tenant per tool. Zero disables the limiter.
    /// Only enforced on routes with a tool policy: without one, the gateway
    /// does not know which tool a request names.
    pub tool_per_minute: u32,
    /// Consecutive upstream failures before the circuit opens.
    pub circuit_failure_threshold: u32,
    pub circuit_cooldown: Duration,
    /// Only `local` is implemented; `redis` is rejected at startup.
    pub backend: RateLimitBackend,
}

/// OAuth 2.1 resource-server settings. The gateway validates tokens; it never
/// issues them. All fields are required when `OAUTH_ISSUER` is set.
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    pub issuer: String,
    /// Exact `aud` value this gateway accepts. Never a shared placeholder.
    pub audience: String,
    /// The authorization server's JWKS endpoint. Fetched and cached.
    pub jwks_uri: String,
    /// Accepted signing algorithms, e.g. `RS256,ES256`.
    pub algorithms: Vec<String>,
    pub clock_skew: Duration,
    pub jwks_ttl: Duration,
    /// The public URL clients connect to, used as RFC 9728 `resource`.
    pub resource: String,
    /// Authorization servers advertised in protected-resource metadata.
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    /// Tenant assigned to a token that carries no tenant claim. One-org
    /// deployments usually leave this at `oauth` and keep routes shared.
    pub default_tenant: String,
    /// RFC 8693 token exchange. `None` means upstreams receive no gateway token.
    pub token_exchange: Option<TokenExchangeConfig>,
}

#[derive(Clone, Debug)]
pub struct TokenExchangeConfig {
    pub endpoint: String,
    pub client_id: SecretString,
    pub client_secret: SecretString,
    pub client_auth: ClientAuth,
}

/// How the gateway authenticates to the authorization server's token endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuth {
    /// HTTP Basic (RFC 6749 §2.3.1). The default.
    Basic,
    /// Credentials in the form body (`client_secret_post`).
    Post,
}

/// Asynchronous, per-call audit of the data plane.
#[derive(Clone, Debug)]
pub struct DataAuditConfig {
    pub enabled: bool,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub retention: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitBackend {
    Local,
}

/// Anything that can supply environment-style key/value pairs.
///
/// Exists so configuration can be tested without mutating the process
/// environment (which is global and shared between threads).
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl EnvSource for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        HashMap::get(self, key).cloned()
    }
}

#[derive(Debug)]
pub struct ConfigError {
    problems: Vec<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "invalid configuration:")?;
        for problem in &self.problems {
            writeln!(formatter, "  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&ProcessEnv)
    }

    pub fn from_source(source: &dyn EnvSource) -> Result<Self, ConfigError> {
        let mut problems = Vec::new();

        let environment = match source.get("APP_ENV").as_deref() {
            Some("development") => AppEnvironment::Development,
            Some("production") => AppEnvironment::Production,
            Some(other) => {
                problems.push(format!(
                    "APP_ENV must be `development` or `production`, got `{other}`"
                ));
                AppEnvironment::Development
            }
            None => {
                problems.push("APP_ENV is required (`development` or `production`)".to_owned());
                AppEnvironment::Development
            }
        };

        let server = ServerConfig {
            host: string_or(source, "HOST", "127.0.0.1"),
            port: number_or(source, "PORT", 8080_u16, &mut problems),
            request_body_limit_bytes: number_or(
                source,
                "MAX_REQUEST_BODY_BYTES",
                1_048_576_usize,
                &mut problems,
            ),
            request_timeout: seconds_or(source, "REQUEST_TIMEOUT_SECS", 15, &mut problems),
            max_request_timeout: seconds_or(source, "MAX_REQUEST_TIMEOUT_SECS", 300, &mut problems),
            max_response_bytes: number_or(
                source,
                "MAX_RESPONSE_BYTES",
                10_485_760_u64,
                &mut problems,
            ),
            stream_idle_timeout: seconds_or(source, "STREAM_IDLE_TIMEOUT_SECS", 60, &mut problems),
            cors_allowed_origins: csv(source.get("CORS_ALLOWED_ORIGINS"))
                .into_iter()
                .map(|origin| origin.trim_end_matches('/').to_owned())
                .collect(),
            shutdown_drain: seconds_or(source, "SHUTDOWN_DRAIN_SECS", 25, &mut problems),
            header_read_timeout: seconds_or(source, "HEADER_READ_TIMEOUT_SECS", 10, &mut problems),
            max_connections: number_or(source, "MAX_CONNECTIONS", 1_024_usize, &mut problems),
            trusted_proxies: csv(source.get("TRUSTED_PROXIES")),
        };

        let database = DatabaseConfig {
            url: SecretString::new(required(source, "DATABASE_URL", &mut problems)),
            max_connections: number_or(source, "DB_MAX_CONNECTIONS", 10_u32, &mut problems),
            min_connections: number_or(source, "DB_MIN_CONNECTIONS", 1_u32, &mut problems),
            acquire_timeout: seconds_or(source, "DB_ACQUIRE_TIMEOUT_SECS", 5, &mut problems),
        };

        let telemetry = TelemetryConfig {
            log_level: string_or(source, "LOG_LEVEL", "info"),
            otlp_endpoint: non_empty(source.get("OTEL_EXPORTER_OTLP_ENDPOINT")),
            metrics_token: non_empty(source.get("METRICS_TOKEN")).map(SecretString::new),
        };

        let auth_pepper = non_empty(source.get("AUTH_PEPPER"));
        if environment.is_production() && auth_pepper.is_none() {
            problems.push("AUTH_PEPPER is required in production".to_owned());
        }

        let auth = AuthConfig {
            pepper: SecretString::new(auth_pepper.unwrap_or_else(|| DEVELOPMENT_PEPPER.to_owned())),
            dev_api_key_secret: non_empty(source.get("DEV_API_KEY_SECRET")).map(SecretString::new),
            dev_api_key_scopes: dev_scopes(source.get("DEV_API_KEY_SCOPES")),
            cache_ttl: seconds_or(source, "AUTH_CACHE_TTL_SECS", 30, &mut problems),
        };

        let admin = AdminConfig {
            bind: string_or(source, "ADMIN_BIND", "127.0.0.1:9090"),
            tokens: admin_tokens(source, &mut problems),
            timeout: seconds_or(source, "ADMIN_TIMEOUT_SECS", 10, &mut problems),
            audit_retention: Duration::from_secs(86_400_u64.saturating_mul(number_or(
                source,
                "AUDIT_RETENTION_DAYS",
                90_u64,
                &mut problems,
            ))),
        };

        let rate_limit_backend = match source
            .get("RATE_LIMIT_BACKEND")
            .as_deref()
            .map(str::trim)
        {
            None | Some("") | Some("local") => RateLimitBackend::Local,
            Some(other) => {
                problems.push(format!(
                    "RATE_LIMIT_BACKEND must be `local` (got `{other}`); \
                     a Redis backend is not implemented yet"
                ));
                RateLimitBackend::Local
            }
        };

        let routing = RoutingConfig {
            allow_hosts: csv(source.get("UPSTREAM_ALLOW_HOSTS")),
            refresh_interval: Duration::from_millis(number_or(
                source,
                "ROUTE_REFRESH_INTERVAL_MS",
                2_000_u64,
                &mut problems,
            )),
            egress: match source
                .get("UPSTREAM_EGRESS")
                .as_deref()
                .map(str::trim)
            {
                None | Some("") => crate::net::Egress::default(),
                Some(raw) => crate::net::Egress::parse(raw).unwrap_or_else(|| {
                    problems.push(format!(
                        "UPSTREAM_EGRESS must be `allow-all`, `deny-link-local` or \
                         `deny-private` (got `{raw}`)"
                    ));
                    crate::net::Egress::default()
                }),
            },
            pool_max_idle_per_host: number_or(
                source,
                "UPSTREAM_POOL_MAX_IDLE_PER_HOST",
                64_usize,
                &mut problems,
            ),
        };

        let limits = LimitsConfig {
            ip_per_minute: number_or(source, "RATE_LIMIT_IP_PER_MINUTE", 600_u32, &mut problems),
            tenant_per_minute: number_or(
                source,
                "RATE_LIMIT_TENANT_PER_MINUTE",
                6_000_u32,
                &mut problems,
            ),
            user_per_minute: number_or(
                source,
                "RATE_LIMIT_USER_PER_MINUTE",
                600_u32,
                &mut problems,
            ),
            tool_per_minute: number_or(source, "RATE_LIMIT_TOOL_PER_MINUTE", 0_u32, &mut problems),
            circuit_failure_threshold: number_or(
                source,
                "CIRCUIT_FAILURE_THRESHOLD",
                5_u32,
                &mut problems,
            ),
            circuit_cooldown: seconds_or(source, "CIRCUIT_COOLDOWN_SECS", 30, &mut problems),
            backend: rate_limit_backend,
        };

        let retry = RetryConfig {
            max_attempts: number_or(source, "RETRY_MAX_ATTEMPTS", 2_u32, &mut problems),
            base_delay: Duration::from_millis(number_or(
                source,
                "RETRY_BASE_DELAY_MS",
                50_u64,
                &mut problems,
            )),
            budget_ratio: ratio_or(source, "RETRY_BUDGET_RATIO", 0.2, &mut problems),
        };

        let oauth = oauth_config(source, &environment, &mut problems);

        let data_audit = DataAuditConfig {
            enabled: boolean_or(source, "DATA_AUDIT_ENABLED", true, &mut problems),
            queue_capacity: number_or(
                source,
                "DATA_AUDIT_QUEUE_CAPACITY",
                1_024_usize,
                &mut problems,
            ),
            batch_size: number_or(source, "DATA_AUDIT_BATCH_SIZE", 100_usize, &mut problems),
            retention: Duration::from_secs(86_400_u64.saturating_mul(number_or(
                source,
                "DATA_AUDIT_RETENTION_DAYS",
                90_u64,
                &mut problems,
            ))),
        };

        let mcp = McpConfig {
            tool_schema_ttl: Duration::from_secs(number_or(
                source,
                "MCP_TOOL_SCHEMA_TTL_SECS",
                300_u64,
                &mut problems,
            )),
        };

        let config = Self {
            environment,
            server,
            database,
            telemetry,
            auth,
            admin,
            routing,
            limits,
            retry,
            oauth,
            data_audit,
            mcp,
        };

        validate(&config, &mut problems);

        if !problems.is_empty() {
            return Err(ConfigError { problems });
        }

        Ok(config)
    }
}

fn validate(config: &Config, problems: &mut Vec<String>) {
    let server = &config.server;
    let database = &config.database;
    let auth = &config.auth;
    let admin = &config.admin;
    let environment = &config.environment;
    let routing = &config.routing;
    let limits = &config.limits;

    if server.port == 0 {
        problems.push("PORT must be between 1 and 65535".to_owned());
    }
    if server.request_body_limit_bytes < 1024 {
        problems.push("MAX_REQUEST_BODY_BYTES must be at least 1024".to_owned());
    }
    if server.request_timeout.is_zero() {
        problems.push("REQUEST_TIMEOUT_SECS must be greater than zero".to_owned());
    }
    if server.max_request_timeout.is_zero() {
        problems.push("MAX_REQUEST_TIMEOUT_SECS must be greater than zero".to_owned());
    }
    if server.max_request_timeout < server.request_timeout {
        problems.push("MAX_REQUEST_TIMEOUT_SECS must be at least REQUEST_TIMEOUT_SECS".to_owned());
    }
    if server.max_response_bytes < 1024 {
        problems.push("MAX_RESPONSE_BYTES must be at least 1024".to_owned());
    }
    if server.max_response_bytes > 1_073_741_824 {
        problems.push("MAX_RESPONSE_BYTES must not exceed 1073741824".to_owned());
    }
    if server.stream_idle_timeout.is_zero()
        || server.stream_idle_timeout > Duration::from_secs(3_600)
    {
        problems.push("STREAM_IDLE_TIMEOUT_SECS must be between 1 and 3600".to_owned());
    }
    for origin in &server.cors_allowed_origins {
        validate_cors_origin(origin, environment, problems);
    }
    if server.shutdown_drain.is_zero() {
        problems.push("SHUTDOWN_DRAIN_SECS must be greater than zero".to_owned());
    }
    if server.header_read_timeout.is_zero() {
        problems.push("HEADER_READ_TIMEOUT_SECS must be greater than zero".to_owned());
    }
    if server.max_connections == 0 {
        problems.push("MAX_CONNECTIONS must be at least 1".to_owned());
    }

    if let Err(problem) = crate::net::TrustedProxies::parse(&server.trusted_proxies) {
        problems.push(format!("TRUSTED_PROXIES: {problem}"));
    }
    if database.max_connections == 0 {
        problems.push("DB_MAX_CONNECTIONS must be at least 1".to_owned());
    }
    if database.min_connections > database.max_connections {
        problems.push("DB_MIN_CONNECTIONS must not exceed DB_MAX_CONNECTIONS".to_owned());
    }
    if database.acquire_timeout.is_zero() {
        problems.push("DB_ACQUIRE_TIMEOUT_SECS must be greater than zero".to_owned());
    }
    if !has_postgres_scheme(database.url.expose()) {
        problems.push("DATABASE_URL must start with postgres:// or postgresql://".to_owned());
    }

    if routing.refresh_interval.is_zero() {
        problems.push("ROUTE_REFRESH_INTERVAL_MS must be greater than zero".to_owned());
    }
    if !(1..=1_024).contains(&routing.pool_max_idle_per_host) {
        // 0 would turn keep-alive off entirely; the ceiling exists to catch a
        // typo, not to express a real limit.
        problems.push(
            "UPSTREAM_POOL_MAX_IDLE_PER_HOST must be between 1 and 1024 \
             (0 would disable connection reuse)"
                .to_owned(),
        );
    }
    if limits.circuit_failure_threshold == 0 {
        problems.push("CIRCUIT_FAILURE_THRESHOLD must be at least 1".to_owned());
    }
    if limits.circuit_cooldown.is_zero() {
        problems.push("CIRCUIT_COOLDOWN_SECS must be greater than zero".to_owned());
    }
    if config.mcp.tool_schema_ttl > Duration::from_secs(3_600) {
        problems.push("MCP_TOOL_SCHEMA_TTL_SECS must not exceed 3600 (0 disables)".to_owned());
    }

    if config.retry.max_attempts == 0 {
        problems.push("RETRY_MAX_ATTEMPTS must be at least 1".to_owned());
    }
    if config.retry.max_attempts > 10 {
        problems.push("RETRY_MAX_ATTEMPTS must not exceed 10".to_owned());
    }
    if config.retry.base_delay > Duration::from_secs(5) {
        problems.push("RETRY_BASE_DELAY_MS must not exceed 5000".to_owned());
    }
    if !(0.0..=10.0).contains(&config.retry.budget_ratio) {
        problems.push("RETRY_BUDGET_RATIO must be between 0 and 10".to_owned());
    }
    if !admin.tokens.is_empty()
        && admin
            .bind
            .parse::<std::net::SocketAddr>()
            .is_err()
    {
        problems.push("ADMIN_BIND must be a socket address like 127.0.0.1:9090".to_owned());
    }
    if admin.timeout.is_zero() {
        problems.push("ADMIN_TIMEOUT_SECS must be greater than zero".to_owned());
    }

    if let Some(oauth) = &config.oauth {
        validate_https_url("OAUTH_ISSUER", &oauth.issuer, environment, true, problems);
        validate_https_url(
            "OAUTH_JWKS_URI",
            &oauth.jwks_uri,
            environment,
            true,
            problems,
        );
        validate_https_url(
            "OAUTH_RESOURCE",
            &oauth.resource,
            environment,
            true,
            problems,
        );

        if oauth.audience.trim().is_empty() {
            problems.push("OAUTH_AUDIENCE must not be empty".to_owned());
        }

        if oauth.audience == "api" || oauth.audience == "*" {
            problems.push(
                "OAUTH_AUDIENCE must identify this gateway, not a shared placeholder".to_owned(),
            );
        }

        if oauth.default_tenant.trim().is_empty() || oauth.default_tenant.len() > 128 {
            problems.push("OAUTH_DEFAULT_TENANT must be 1-128 non-blank characters".to_owned());
        }

        if oauth.jwks_ttl.is_zero() || oauth.jwks_ttl > Duration::from_secs(3_600) {
            problems.push("OAUTH_JWKS_TTL_SECS must be between 1 and 3600 seconds".to_owned());
        }
        if oauth.clock_skew > Duration::from_secs(300) {
            problems.push("OAUTH_CLOCK_SKEW_SECS must not exceed 300 seconds".to_owned());
        }
        if let Some(exchange) = &oauth.token_exchange
            && exchange.client_id.expose() == oauth.audience
        {
            problems.push(
                "OAUTH_AUDIENCE must not equal OAUTH_CLIENT_ID: an ID token for the \
                 client could be mistaken for an access token"
                    .to_owned(),
            );
        }

        for server in &oauth.authorization_servers {
            validate_https_url(
                "OAUTH_AUTHORIZATION_SERVERS entry",
                server,
                environment,
                true,
                problems,
            );
        }

        if let Some(exchange) = &oauth.token_exchange {
            validate_https_url(
                "OAUTH_TOKEN_ENDPOINT",
                &exchange.endpoint,
                environment,
                true,
                problems,
            );
        }
    }

    if config.data_audit.enabled {
        if config.data_audit.queue_capacity == 0 {
            problems.push("DATA_AUDIT_QUEUE_CAPACITY must be at least 1".to_owned());
        }
        if config.data_audit.batch_size == 0 {
            problems.push("DATA_AUDIT_BATCH_SIZE must be at least 1".to_owned());
        }
        if config.data_audit.batch_size > config.data_audit.queue_capacity {
            problems
                .push("DATA_AUDIT_BATCH_SIZE must not exceed DATA_AUDIT_QUEUE_CAPACITY".to_owned());
        }
        if config.data_audit.batch_size > 5_000 {
            problems.push(
                "DATA_AUDIT_BATCH_SIZE must not exceed 5000 (Postgres parameter limit)".to_owned(),
            );
        }
    }

    if environment.is_production() {
        if auth.dev_api_key_secret.is_some() {
            problems.push("DEV_API_KEY_SECRET must not be set in production".to_owned());
        }

        let pepper = auth.pepper.expose();

        if pepper == DEVELOPMENT_PEPPER {
            problems
                .push("AUTH_PEPPER must not be the development default in production".to_owned());
        } else if pepper.len() < 32 {
            problems.push("AUTH_PEPPER must be at least 32 characters in production".to_owned());
        }

        if pepper.contains("CHANGE_ME") {
            problems
                .push("AUTH_PEPPER still contains the example placeholder CHANGE_ME".to_owned());
        }

        for token in &admin.tokens {
            if token
                .token
                .expose()
                .contains("CHANGE_ME")
            {
                problems.push(format!(
                    "ADMIN_TOKENS entry for `{}` still contains CHANGE_ME",
                    token.name
                ));
            }
        }

        if routing.allow_hosts.is_empty() {
            problems
                .push("UPSTREAM_ALLOW_HOSTS must list at least one host in production".to_owned());
        }
    }

    if tracing_subscriber::EnvFilter::try_new(&config.telemetry.log_level).is_err() {
        problems.push(format!(
            "LOG_LEVEL is not a valid filter: `{}`",
            config.telemetry.log_level
        ));
    }
}

fn has_postgres_scheme(url: &str) -> bool {
    url.starts_with("postgres://") || url.starts_with("postgresql://")
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn string_or(source: &dyn EnvSource, key: &str, default: &str) -> String {
    non_empty(source.get(key)).unwrap_or_else(|| default.to_owned())
}

fn required(source: &dyn EnvSource, key: &str, problems: &mut Vec<String>) -> String {
    match non_empty(source.get(key)) {
        Some(value) => value,
        None => {
            problems.push(format!("{key} is required"));
            String::new()
        }
    }
}

fn number_or<T>(source: &dyn EnvSource, key: &str, default: T, problems: &mut Vec<String>) -> T
where
    T: FromStr + Copy,
{
    let Some(raw) = non_empty(source.get(key)) else {
        return default;
    };

    match raw.parse::<T>() {
        Ok(value) => value,
        Err(_) => {
            problems.push(format!("{key} must be a number, got `{raw}`"));
            default
        }
    }
}

fn seconds_or(
    source: &dyn EnvSource,
    key: &str,
    default_seconds: u64,
    problems: &mut Vec<String>,
) -> Duration {
    Duration::from_secs(number_or(source, key, default_seconds, problems))
}

fn ratio_or(source: &dyn EnvSource, key: &str, default: f64, problems: &mut Vec<String>) -> f64 {
    let Some(raw) = non_empty(source.get(key)) else {
        return default;
    };

    match raw.parse::<f64>() {
        Ok(value) => value,
        Err(_) => {
            problems.push(format!("{key} must be a number, got `{raw}`"));
            default
        }
    }
}

fn boolean_or(
    source: &dyn EnvSource,
    key: &str,
    default: bool,
    problems: &mut Vec<String>,
) -> bool {
    let Some(raw) = non_empty(source.get(key)) else {
        return default;
    };

    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            problems.push(format!("{key} must be a boolean, got `{raw}`"));
            default
        }
    }
}

/// Builds the resource-server configuration. A missing issuer disables OAuth;
/// a partially configured block is an error, never a silent half-state.
fn oauth_config(
    source: &dyn EnvSource,
    environment: &AppEnvironment,
    problems: &mut Vec<String>,
) -> Option<OAuthConfig> {
    let Some(issuer) = non_empty(source.get("OAUTH_ISSUER")) else {
        // A renamed/typo'd issuer must not silently downgrade an OAuth
        // deployment to API-key-only.
        for key in [
            "OAUTH_AUDIENCE",
            "OAUTH_JWKS_URI",
            "OAUTH_RESOURCE",
            "OAUTH_AUTHORIZATION_SERVERS",
            "OAUTH_TOKEN_ENDPOINT",
        ] {
            if non_empty(source.get(key)).is_some() {
                problems.push(format!("OAUTH_ISSUER is required when {key} is set"));
            }
        }

        return None;
    };

    let audience = required(source, "OAUTH_AUDIENCE", problems);
    let jwks_uri = required(source, "OAUTH_JWKS_URI", problems);
    let resource = required(source, "OAUTH_RESOURCE", problems);
    let authorization_servers = csv_preserve(source.get("OAUTH_AUTHORIZATION_SERVERS"));

    if authorization_servers.is_empty() {
        problems.push("OAUTH_AUTHORIZATION_SERVERS must list at least one issuer".to_owned());
    }

    let mut algorithms = csv(source.get("OAUTH_ALGORITHMS"));
    if algorithms.is_empty() {
        algorithms = vec!["rs256".to_owned()];
    }
    for algorithm in &algorithms {
        if !matches!(
            algorithm.as_str(),
            "rs256" | "rs384" | "rs512" | "es256" | "es384"
        ) {
            problems.push(format!(
                "OAUTH_ALGORITHMS contains unsupported algorithm `{algorithm}`; \
                 use RS256/RS384/RS512 or ES256/ES384"
            ));
        }
    }

    match source
        .get("OAUTH_TOKEN_FORMAT")
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None | Some("jwt") => {}
        Some(other) => problems.push(format!(
            "OAUTH_TOKEN_FORMAT=`{other}` is not implemented; use `jwt` (opaque tokens need an introspection step that is deliberately deferred)"
        )),
    }

    let token_exchange = token_exchange_config(source, environment, problems);

    Some(OAuthConfig {
        issuer,
        audience,
        jwks_uri,
        algorithms,
        clock_skew: seconds_or(source, "OAUTH_CLOCK_SKEW_SECS", 30, problems),
        jwks_ttl: seconds_or(source, "OAUTH_JWKS_TTL_SECS", 300, problems),
        resource,
        authorization_servers,
        scopes_supported: csv_preserve(source.get("OAUTH_SCOPES_SUPPORTED")),
        default_tenant: string_or(source, "OAUTH_DEFAULT_TENANT", "oauth"),
        token_exchange,
    })
}

fn token_exchange_config(
    source: &dyn EnvSource,
    environment: &AppEnvironment,
    problems: &mut Vec<String>,
) -> Option<TokenExchangeConfig> {
    let endpoint = non_empty(source.get("OAUTH_TOKEN_ENDPOINT"))?;
    let client_id = required(source, "OAUTH_CLIENT_ID", problems);
    let client_secret = required(source, "OAUTH_CLIENT_SECRET", problems);

    if environment.is_production() && !endpoint.starts_with("https://") {
        problems.push("OAUTH_TOKEN_ENDPOINT must be HTTPS in production".to_owned());
    }

    let client_auth = match source
        .get("OAUTH_CLIENT_AUTH")
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("basic") => ClientAuth::Basic,
        Some("post") => ClientAuth::Post,
        Some(other) => {
            problems.push(format!(
                "OAUTH_CLIENT_AUTH must be `basic` or `post`, got `{other}`"
            ));
            ClientAuth::Basic
        }
    };

    Some(TokenExchangeConfig {
        endpoint,
        client_id: SecretString::new(client_id),
        client_secret: SecretString::new(client_secret),
        client_auth,
    })
}

/// Validates an absolute URL used for an OAuth endpoint or metadata field.
fn validate_https_url(
    label: &str,
    raw: &str,
    environment: &AppEnvironment,
    allow_path: bool,
    problems: &mut Vec<String>,
) {
    let Ok(url) = reqwest::Url::parse(raw) else {
        problems.push(format!("{label} must be an absolute URL"));
        return;
    };

    if !url.username().is_empty() || url.password().is_some() {
        problems.push(format!("{label} must not embed credentials"));
    }

    if environment.is_production() && url.scheme() != "https" {
        problems.push(format!("{label} must use https in production"));
    } else if !matches!(url.scheme(), "http" | "https") {
        problems.push(format!("{label} must use http or https"));
    }

    if url.query().is_some() || url.fragment().is_some() {
        problems.push(format!("{label} must not contain a query or fragment"));
    }

    if !allow_path && url.path() != "/" && !url.path().is_empty() {
        problems.push(format!("{label} must be an origin, not a path"));
    }
}

/// A browser origin: scheme, host, optional port, and nothing else.
fn validate_cors_origin(raw: &str, environment: &AppEnvironment, problems: &mut Vec<String>) {
    if raw.contains('*') {
        problems.push(
            "CORS_ALLOWED_ORIGINS must list exact origins; wildcards are not allowed".to_owned(),
        );
        return;
    }

    validate_https_url(
        &format!("CORS_ALLOWED_ORIGINS entry `{raw}`"),
        raw,
        environment,
        false,
        problems,
    );
}

fn csv(value: Option<String>) -> Vec<String> {
    csv_preserve(value)
        .into_iter()
        .map(|item| item.to_ascii_lowercase())
        .collect()
}

/// Comma-separated values where case is significant: scopes, issuer URLs, and
/// anything the identity provider compares exactly.
fn csv_preserve(value: Option<String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .filter_map(|item| {
                    let item = item.trim();
                    (!item.is_empty()).then(|| item.to_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dev_scopes(value: Option<String>) -> Vec<String> {
    let scopes = csv(value);

    if scopes.is_empty() {
        vec!["read".to_owned()]
    } else {
        scopes
    }
}

/// `ADMIN_TOKENS=alice:token[:scope+scope],bob:token` for named operators.
/// `ADMIN_TOKEN=x` remains supported and maps to the actor `admin`.
fn admin_tokens(source: &dyn EnvSource, problems: &mut Vec<String>) -> Vec<AdminToken> {
    let mut tokens: Vec<AdminToken> = Vec::new();

    if let Some(list) = non_empty(source.get("ADMIN_TOKENS")) {
        for entry in list.split(',') {
            let mut parts = entry.splitn(3, ':');
            let name = parts
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            let token = parts
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            let scopes_part = parts.next();

            if name.is_empty() || token.is_empty() {
                problems.push("ADMIN_TOKENS entries must look like `name:token`".to_owned());
                continue;
            }

            if tokens
                .iter()
                .any(|existing| existing.name == name)
            {
                problems.push(format!("ADMIN_TOKENS has a duplicate name `{name}`"));
                continue;
            }

            if token.len() < 16 {
                problems.push(format!(
                    "ADMIN_TOKENS token for `{name}` must be at least 16 characters"
                ));
                continue;
            }

            let Some(scopes) = parse_admin_scopes(&name, scopes_part, problems) else {
                continue;
            };

            tokens.push(AdminToken {
                name,
                token: SecretString::new(token),
                scopes,
            });
        }
    }

    if let Some(legacy) = non_empty(source.get("ADMIN_TOKEN")) {
        if legacy.len() < 16 {
            problems.push("ADMIN_TOKEN must be at least 16 characters".to_owned());
        } else if !tokens
            .iter()
            .any(|existing| existing.name == "admin")
        {
            tokens.push(AdminToken {
                name: "admin".to_owned(),
                token: SecretString::new(legacy),
                scopes: HashSet::from(["*".to_owned()]),
            });
        }
    }

    tokens
}

/// A missing scope list means full admin, so `name:token` keeps working.
fn parse_admin_scopes(
    name: &str,
    scopes: Option<&str>,
    problems: &mut Vec<String>,
) -> Option<HashSet<String>> {
    let Some(list) = scopes
        .map(str::trim)
        .filter(|list| !list.is_empty())
    else {
        return Some(HashSet::from(["*".to_owned()]));
    };

    let mut granted = HashSet::new();

    for scope in list
        .split('+')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
    {
        if scope != "*" && !ADMIN_SCOPES.contains(&scope) {
            problems.push(format!(
                "ADMIN_TOKENS scope `{scope}` for `{name}` is unknown; valid scopes are {}",
                ADMIN_SCOPES.join(", ")
            ));
            continue;
        }

        granted.insert(scope.to_owned());
    }

    if granted.is_empty() {
        problems.push(format!(
            "ADMIN_TOKENS entry for `{name}` has no valid scopes"
        ));
        return None;
    }

    Some(granted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn valid_development() -> HashMap<String, String> {
        source(&[
            ("APP_ENV", "development"),
            (
                "DATABASE_URL",
                "postgres://gateway:secret@127.0.0.1:5432/gateway",
            ),
        ])
    }

    #[test]
    fn parses_minimal_development_config() {
        let config = Config::from_source(&valid_development()).expect("valid config");

        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.request_timeout, Duration::from_secs(15));
        assert!(config.auth.dev_api_key_secret.is_none());
        assert!(config.routing.allow_hosts.is_empty());
        assert_eq!(config.auth.pepper.expose(), DEVELOPMENT_PEPPER);
    }

    #[test]
    fn egress_defaults_to_blocking_link_local_and_parses_overrides() {
        let config = Config::from_source(&valid_development()).expect("valid config");
        assert_eq!(config.routing.egress, crate::net::Egress::DenyLinkLocal);

        let mut env = valid_development();
        env.insert("UPSTREAM_EGRESS".to_owned(), "deny-private".to_owned());
        assert_eq!(
            Config::from_source(&env)
                .expect("valid config")
                .routing
                .egress,
            crate::net::Egress::DenyPrivate
        );

        let mut env = valid_development();
        env.insert("UPSTREAM_EGRESS".to_owned(), "anything".to_owned());
        let error = Config::from_source(&env).expect_err("invalid egress policy");

        assert!(
            error
                .to_string()
                .contains("UPSTREAM_EGRESS must be")
        );
    }

    #[test]
    fn upstream_pool_idle_default_is_bounded() {
        let config = Config::from_source(&valid_development()).expect("valid config");

        // reqwest's own default is unbounded, which is the bug this setting
        // exists to close; the gateway must never inherit it.
        assert_eq!(config.routing.pool_max_idle_per_host, 64);
    }

    #[test]
    fn parses_an_upstream_pool_override() {
        let mut env = valid_development();
        env.insert("UPSTREAM_POOL_MAX_IDLE_PER_HOST".to_owned(), "8".to_owned());

        let config = Config::from_source(&env).expect("valid config");

        assert_eq!(config.routing.pool_max_idle_per_host, 8);
    }

    #[test]
    fn rejects_a_pool_size_that_disables_reuse_or_hides_a_typo() {
        for value in ["0", "100000"] {
            let mut env = valid_development();
            env.insert(
                "UPSTREAM_POOL_MAX_IDLE_PER_HOST".to_owned(),
                value.to_owned(),
            );

            let error = Config::from_source(&env).expect_err("invalid pool size");

            assert!(
                error
                    .to_string()
                    .contains("UPSTREAM_POOL_MAX_IDLE_PER_HOST must be between 1 and 1024"),
                "{value} was accepted"
            );
        }
    }

    #[test]
    fn reports_every_problem_at_once() {
        let config = source(&[("APP_ENV", "staging"), ("PORT", "not-a-port")]);
        let error = Config::from_source(&config).expect_err("invalid config");
        let message = error.to_string();

        assert!(message.contains("APP_ENV must be"));
        assert!(message.contains("PORT must be a number"));
        assert!(message.contains("DATABASE_URL is required"));
    }

    #[test]
    fn production_rejects_development_secret() {
        let config = source(&[
            ("APP_ENV", "production"),
            (
                "DATABASE_URL",
                "postgres://gateway:secret@127.0.0.1:5432/gateway",
            ),
            ("DEV_API_KEY_SECRET", "leaked"),
            ("UPSTREAM_ALLOW_HOSTS", "swapi.dev"),
        ]);

        let error = Config::from_source(&config).expect_err("invalid config");

        assert!(
            error
                .to_string()
                .contains("DEV_API_KEY_SECRET")
        );
    }

    #[test]
    fn production_requires_upstream_allowlist() {
        let config = source(&[
            ("APP_ENV", "production"),
            (
                "DATABASE_URL",
                "postgres://gateway:secret@127.0.0.1:5432/gateway",
            ),
        ]);

        let error = Config::from_source(&config).expect_err("invalid config");

        assert!(
            error
                .to_string()
                .contains("UPSTREAM_ALLOW_HOSTS")
        );
    }

    #[test]
    fn production_requires_a_pepper() {
        let config = source(&[
            ("APP_ENV", "production"),
            (
                "DATABASE_URL",
                "postgres://gateway:secret@127.0.0.1:5432/gateway",
            ),
            ("UPSTREAM_ALLOW_HOSTS", "example.com"),
        ]);

        let error = Config::from_source(&config).expect_err("invalid config");

        assert!(
            error
                .to_string()
                .contains("AUTH_PEPPER")
        );
    }

    #[test]
    fn parses_allowlist_and_development_scopes() {
        let mut values = valid_development();
        values.insert(
            "UPSTREAM_ALLOW_HOSTS".to_owned(),
            "Example.com, api.test".to_owned(),
        );
        values.insert("DEV_API_KEY_SCOPES".to_owned(), "read, write".to_owned());

        let config = Config::from_source(&values).expect("valid config");

        assert_eq!(config.routing.allow_hosts, vec!["example.com", "api.test"]);
        assert_eq!(config.auth.dev_api_key_scopes, vec!["read", "write"]);
    }

    #[test]
    fn rejects_non_postgres_database_url() {
        let config = source(&[
            ("APP_ENV", "development"),
            ("DATABASE_URL", "mysql://gateway@127.0.0.1/gateway"),
        ]);

        let error = Config::from_source(&config).expect_err("invalid config");

        assert!(
            error
                .to_string()
                .contains("postgres://")
        );
    }

    #[test]
    fn development_advisories_name_the_unset_safeguards() {
        let config = Config::from_source(&valid_development()).expect("valid config");
        let notes = config.advisories();

        assert!(
            notes
                .iter()
                .any(|note| note.contains("ADMIN_TOKEN"))
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("METRICS_TOKEN"))
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("UPSTREAM_ALLOW_HOSTS"))
        );
    }

    #[test]
    fn a_complete_production_config_has_no_advisories() {
        let values = source(&[
            ("APP_ENV", "production"),
            (
                "DATABASE_URL",
                "postgres://gateway:secret@127.0.0.1:5432/gateway",
            ),
            ("AUTH_PEPPER", "a-long-production-pepper-with-32-chars"),
            ("UPSTREAM_ALLOW_HOSTS", "swapi.dev"),
            ("ADMIN_TOKEN", "admin-token-0123456789"),
            ("METRICS_TOKEN", "metrics-token-0123456789"),
            ("OAUTH_ISSUER", "https://auth.example.com"),
            ("OAUTH_AUDIENCE", "https://gateway.example.com/mcp"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com"),
            ("OAUTH_SCOPES_SUPPORTED", "mcp:tools"),
            ("OAUTH_TOKEN_ENDPOINT", "https://auth.example.com/token"),
            ("OAUTH_CLIENT_ID", "gateway-client"),
            ("OAUTH_CLIENT_SECRET", "gateway-client-secret"),
            ("CORS_ALLOWED_ORIGINS", "https://chatgpt.com"),
        ]);

        let config = Config::from_source(&values).expect("valid config");

        assert!(config.advisories().is_empty(), "{:?}", config.advisories());
    }

    #[test]
    fn parses_named_admin_tokens() {
        let mut values = valid_development();
        values.insert(
            "ADMIN_TOKENS".to_owned(),
            "alice:alice-token-0123456, bob:bob-token-01234567".to_owned(),
        );

        let config = Config::from_source(&values).expect("valid config");

        assert_eq!(config.admin.tokens.len(), 2);
        assert_eq!(config.admin.tokens[0].name, "alice");
        assert_eq!(config.admin.tokens[1].name, "bob");
    }

    #[test]
    fn parses_scoped_admin_tokens() {
        let mut values = valid_development();
        values.insert(
            "ADMIN_TOKENS".to_owned(),
            "alice:alice-token-0123456:config:read+keys:read,bob:bob-token-01234567".to_owned(),
        );

        let config = Config::from_source(&values).expect("valid config");

        let alice = &config.admin.tokens[0];
        assert!(alice.scopes.contains("config:read"));
        assert!(alice.scopes.contains("keys:read"));
        assert!(!alice.scopes.contains("*"));

        assert!(
            config.admin.tokens[1]
                .scopes
                .contains("*"),
            "no scopes means full admin"
        );
    }

    #[test]
    fn rejects_invalid_trusted_proxies() {
        let mut values = valid_development();
        values.insert("TRUSTED_PROXIES".to_owned(), "not-a-cidr".to_owned());

        let error = Config::from_source(&values).expect_err("invalid proxy list");

        assert!(
            error
                .to_string()
                .contains("TRUSTED_PROXIES")
        );
    }

    #[test]
    fn rejects_unknown_admin_scopes() {
        let mut values = valid_development();
        values.insert(
            "ADMIN_TOKENS".to_owned(),
            "alice:alice-token-0123456:config:destroy".to_owned(),
        );

        let error = Config::from_source(&values).expect_err("unknown scope");

        assert!(error.to_string().contains("unknown"));
        assert!(
            error
                .to_string()
                .contains("config:read")
        );
    }

    #[test]
    fn rejects_duplicate_admin_token_names() {
        let mut values = valid_development();
        values.insert(
            "ADMIN_TOKENS".to_owned(),
            "alice:alice-token-0123456,alice:another-token-0123".to_owned(),
        );

        let error = Config::from_source(&values).expect_err("duplicate names");

        assert!(
            error
                .to_string()
                .contains("duplicate name")
        );
    }

    #[test]
    fn rejects_short_admin_tokens() {
        let mut values = valid_development();
        values.insert("ADMIN_TOKENS".to_owned(), "alice:short".to_owned());

        let error = Config::from_source(&values).expect_err("short token");

        assert!(
            error
                .to_string()
                .contains("at least 16")
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut values = valid_development();
        values.insert(
            "DEV_API_KEY_SECRET".to_owned(),
            "super-secret-value".to_owned(),
        );
        let config = Config::from_source(&values).expect("valid config");
        let rendered = format!("{config:?}");

        assert!(!rendered.contains("super-secret-value"));
        assert!(!rendered.contains("gateway:secret"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn oauth_is_disabled_unless_an_issuer_is_set() {
        let config = Config::from_source(&valid_development()).expect("valid config");

        assert!(config.oauth.is_none());
    }

    #[test]
    fn oauth_requires_every_companion_field() {
        let mut values = valid_development();
        values.insert(
            "OAUTH_ISSUER".to_owned(),
            "https://auth.example.com".to_owned(),
        );

        let error = Config::from_source(&values).expect_err("partial OAuth config");
        let message = error.to_string();

        assert!(message.contains("OAUTH_AUDIENCE"));
        assert!(message.contains("OAUTH_JWKS_URI"));
        assert!(message.contains("OAUTH_RESOURCE"));
        assert!(message.contains("OAUTH_AUTHORIZATION_SERVERS"));
    }

    #[test]
    fn oauth_rejects_shared_audience_and_unknown_algorithms() {
        let mut values = valid_development();
        for (key, value) in [
            ("OAUTH_ISSUER", "https://auth.example.com"),
            ("OAUTH_AUDIENCE", "api"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com"),
            ("OAUTH_ALGORITHMS", "HS256,RS256"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }

        let error = Config::from_source(&values).expect_err("invalid OAuth config");
        let message = error.to_string();

        assert!(message.contains("shared placeholder"));
        assert!(message.contains("hs256"));
    }

    #[test]
    fn oauth_companions_without_an_issuer_fail_closed() {
        let mut values = valid_development();
        values.insert(
            "OAUTH_AUDIENCE".to_owned(),
            "https://gateway.example.com/mcp".to_owned(),
        );

        let error = Config::from_source(&values).expect_err("issuer missing");
        assert!(
            error
                .to_string()
                .contains("OAUTH_ISSUER is required")
        );
    }

    #[test]
    fn oauth_rejects_excessive_skew_and_jwks_ttl() {
        let mut values = valid_development();
        for (key, value) in [
            ("OAUTH_ISSUER", "https://auth.example.com"),
            ("OAUTH_AUDIENCE", "https://gateway.example.com/mcp"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com"),
            ("OAUTH_CLOCK_SKEW_SECS", "3600"),
            ("OAUTH_JWKS_TTL_SECS", "86400"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }

        let error = Config::from_source(&values).expect_err("unsafe OAuth windows");
        let message = error.to_string();

        assert!(message.contains("OAUTH_CLOCK_SKEW_SECS"));
        assert!(message.contains("OAUTH_JWKS_TTL_SECS"));
    }

    #[test]
    fn production_rejects_example_secret_placeholders() {
        let values = source(&[
            ("APP_ENV", "production"),
            (
                "DATABASE_URL",
                "postgres://gateway:secret@127.0.0.1:5432/gateway",
            ),
            ("AUTH_PEPPER", "CHANGE_ME_32_CHARACTERS_MINIMUM_VALUE"),
            ("UPSTREAM_ALLOW_HOSTS", "example.com"),
            (
                "ADMIN_TOKENS",
                "alice:CHANGE_ME_LONG_RANDOM_TOKEN:config:read",
            ),
        ]);

        let error = Config::from_source(&values).expect_err("placeholders");
        assert!(error.to_string().contains("CHANGE_ME"));
    }

    #[test]
    fn oauth_rejects_an_unimplemented_token_format() {
        let mut values = valid_development();
        for (key, value) in [
            ("OAUTH_ISSUER", "https://auth.example.com"),
            ("OAUTH_AUDIENCE", "https://gateway.example.com/mcp"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com"),
            ("OAUTH_TOKEN_FORMAT", "introspection"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }

        let error = Config::from_source(&values).expect_err("opaque tokens");
        assert!(
            error
                .to_string()
                .contains("not implemented")
        );
    }

    #[test]
    fn oauth_token_exchange_accepts_client_secret_post() {
        let mut values = valid_development();
        for (key, value) in [
            ("OAUTH_ISSUER", "https://auth.example.com"),
            ("OAUTH_AUDIENCE", "https://gateway.example.com/mcp"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com"),
            ("OAUTH_TOKEN_ENDPOINT", "https://auth.example.com/token"),
            ("OAUTH_CLIENT_ID", "gateway-client"),
            ("OAUTH_CLIENT_SECRET", "gateway-client-secret"),
            ("OAUTH_CLIENT_AUTH", "post"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }

        let config = Config::from_source(&values).expect("valid config");
        let exchange = config
            .oauth
            .and_then(|oauth| oauth.token_exchange)
            .expect("exchange");

        assert_eq!(exchange.client_auth, ClientAuth::Post);
    }

    #[test]
    fn oauth_token_exchange_requires_a_client() {
        let mut values = valid_development();
        for (key, value) in [
            ("OAUTH_ISSUER", "https://auth.example.com"),
            ("OAUTH_AUDIENCE", "https://gateway.example.com/mcp"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            ("OAUTH_AUTHORIZATION_SERVERS", "https://auth.example.com"),
            ("OAUTH_TOKEN_ENDPOINT", "https://auth.example.com/token"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }

        let error = Config::from_source(&values).expect_err("missing client");
        let message = error.to_string();

        assert!(message.contains("OAUTH_CLIENT_ID"));
        assert!(message.contains("OAUTH_CLIENT_SECRET"));
    }

    #[test]
    fn cors_requires_exact_origins() {
        let mut values = valid_development();
        values.insert(
            "CORS_ALLOWED_ORIGINS".to_owned(),
            "https://*.example.com".to_owned(),
        );

        let error = Config::from_source(&values).expect_err("wildcard origin");
        assert!(error.to_string().contains("wildcards"));

        let mut values = valid_development();
        values.insert(
            "CORS_ALLOWED_ORIGINS".to_owned(),
            "https://app.example.com/path".to_owned(),
        );

        let error = Config::from_source(&values).expect_err("origin with a path");
        assert!(error.to_string().contains("origin"));
    }

    #[test]
    fn route_override_cannot_exceed_the_hard_deadline() {
        let mut values = valid_development();
        values.insert("REQUEST_TIMEOUT_SECS".to_owned(), "120".to_owned());
        values.insert("MAX_REQUEST_TIMEOUT_SECS".to_owned(), "60".to_owned());

        let error = Config::from_source(&values).expect_err("deadline ordering");
        assert!(
            error
                .to_string()
                .contains("MAX_REQUEST_TIMEOUT_SECS")
        );
    }

    #[test]
    fn data_audit_batch_must_fit_the_queue() {
        let mut values = valid_development();
        values.insert("DATA_AUDIT_QUEUE_CAPACITY".to_owned(), "10".to_owned());
        values.insert("DATA_AUDIT_BATCH_SIZE".to_owned(), "20".to_owned());

        let error = Config::from_source(&values).expect_err("batch larger than queue");
        assert!(
            error
                .to_string()
                .contains("DATA_AUDIT_BATCH_SIZE")
        );
    }

    #[test]
    fn oauth_scopes_and_authorization_servers_preserve_case() {
        let mut values = valid_development();
        for (key, value) in [
            ("OAUTH_ISSUER", "https://auth.example.com/Tenant"),
            ("OAUTH_AUDIENCE", "https://gateway.example.com/mcp"),
            ("OAUTH_JWKS_URI", "https://auth.example.com/Tenant/jwks"),
            ("OAUTH_RESOURCE", "https://gateway.example.com/mcp"),
            (
                "OAUTH_AUTHORIZATION_SERVERS",
                "https://auth.example.com/Tenant",
            ),
            ("OAUTH_SCOPES_SUPPORTED", "Mcp:Tools,ReadAll"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }

        let config = Config::from_source(&values).expect("valid config");
        let oauth = config.oauth.expect("oauth");

        assert_eq!(
            oauth.authorization_servers,
            vec!["https://auth.example.com/Tenant"]
        );
        assert_eq!(oauth.scopes_supported, vec!["Mcp:Tools", "ReadAll"]);
    }

    #[test]
    fn stream_idle_timeout_is_bounded() {
        let mut values = valid_development();
        values.insert("STREAM_IDLE_TIMEOUT_SECS".to_owned(), "0".to_owned());

        assert!(Config::from_source(&values).is_err());

        values.insert("STREAM_IDLE_TIMEOUT_SECS".to_owned(), "3601".to_owned());
        assert!(Config::from_source(&values).is_err());

        values.insert("STREAM_IDLE_TIMEOUT_SECS".to_owned(), "90".to_owned());
        let config = Config::from_source(&values).expect("valid config");
        assert_eq!(config.server.stream_idle_timeout, Duration::from_secs(90));
    }

    #[test]
    fn per_user_limit_is_configurable() {
        let mut values = valid_development();
        values.insert("RATE_LIMIT_USER_PER_MINUTE".to_owned(), "42".to_owned());

        let config = Config::from_source(&values).expect("valid config");
        assert_eq!(config.limits.user_per_minute, 42);
    }
}
