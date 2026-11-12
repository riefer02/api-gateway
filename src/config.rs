use std::{collections::HashMap, fmt, str::FromStr, time::Duration};

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
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_body_limit_bytes: usize,
    pub request_timeout: Duration,
    pub shutdown_drain: Duration,
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
}

/// One operator credential. The name is what the audit log records.
#[derive(Clone, Debug)]
pub struct AdminToken {
    pub name: String,
    pub token: SecretString,
}

#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Total attempts, including the first. 1 disables retries.
    pub max_attempts: u32,
    pub base_delay: Duration,
    /// Retries allowed per request, as a fraction of normal traffic.
    pub budget_ratio: f64,
}

#[derive(Clone, Debug)]
pub struct RoutingConfig {
    /// Empty means "allow any host"; production requires a non-empty list.
    pub allow_hosts: Vec<String>,
    pub refresh_interval: Duration,
}

#[derive(Clone, Debug)]
pub struct LimitsConfig {
    /// Requests per minute per client IP. Zero disables the limiter.
    pub ip_per_minute: u32,
    /// Requests per minute per tenant. Zero disables the limiter.
    pub tenant_per_minute: u32,
    /// Consecutive upstream failures before the circuit opens.
    pub circuit_failure_threshold: u32,
    pub circuit_cooldown: Duration,
    /// Only `local` is implemented; `redis` is rejected at startup.
    pub backend: RateLimitBackend,
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
            shutdown_drain: seconds_or(source, "SHUTDOWN_DRAIN_SECS", 25, &mut problems),
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
        };

        let limits = LimitsConfig {
            ip_per_minute: number_or(source, "RATE_LIMIT_IP_PER_MINUTE", 600_u32, &mut problems),
            tenant_per_minute: number_or(
                source,
                "RATE_LIMIT_TENANT_PER_MINUTE",
                6_000_u32,
                &mut problems,
            ),
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
    if server.shutdown_drain.is_zero() {
        problems.push("SHUTDOWN_DRAIN_SECS must be greater than zero".to_owned());
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
    if limits.circuit_failure_threshold == 0 {
        problems.push("CIRCUIT_FAILURE_THRESHOLD must be at least 1".to_owned());
    }
    if limits.circuit_cooldown.is_zero() {
        problems.push("CIRCUIT_COOLDOWN_SECS must be greater than zero".to_owned());
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

    if environment.is_production() {
        if auth.dev_api_key_secret.is_some() {
            problems.push("DEV_API_KEY_SECRET must not be set in production".to_owned());
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

fn csv(value: Option<String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .filter_map(|item| {
                    let item = item.trim();
                    (!item.is_empty()).then(|| item.to_ascii_lowercase())
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

/// `ADMIN_TOKENS=alice:token,bob:token` for named operators; `ADMIN_TOKEN=x`
/// remains supported and maps to the actor `admin`.
fn admin_tokens(source: &dyn EnvSource, problems: &mut Vec<String>) -> Vec<AdminToken> {
    let mut tokens: Vec<AdminToken> = Vec::new();

    if let Some(list) = non_empty(source.get("ADMIN_TOKENS")) {
        for entry in list.split(',') {
            let Some((name, token)) = entry.split_once(':') else {
                problems.push("ADMIN_TOKENS entries must look like `name:token`".to_owned());
                continue;
            };

            let (name, token) = (name.trim(), token.trim());

            if name.is_empty() || token.is_empty() {
                problems
                    .push("ADMIN_TOKENS entries must have a non-empty name and token".to_owned());
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

            tokens.push(AdminToken {
                name: name.to_owned(),
                token: SecretString::new(token),
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
            });
        }
    }

    tokens
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
            ("AUTH_PEPPER", "a-long-production-pepper"),
            ("UPSTREAM_ALLOW_HOSTS", "swapi.dev"),
            ("ADMIN_TOKEN", "admin-token-0123456789"),
            ("METRICS_TOKEN", "metrics-token-0123456789"),
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
}
