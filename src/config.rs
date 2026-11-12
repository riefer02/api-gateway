use std::{collections::HashMap, fmt, str::FromStr, time::Duration};

use reqwest::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppEnvironment {
    Development,
    Production,
}

impl AppEnvironment {
    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

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
    pub upstream: UpstreamConfig,
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
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub dev_api_key_secret: Option<SecretString>,
}

#[derive(Clone, Debug)]
pub struct UpstreamConfig {
    pub base_url: Url,
    pub timeout: Duration,
    pub allow_hosts: Vec<String>,
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
        };

        let auth = AuthConfig {
            dev_api_key_secret: non_empty(source.get("DEV_API_KEY_SECRET")).map(SecretString::new),
        };

        let base_url_raw = non_empty(source.get("UPSTREAM_BASE_URL"))
            .or_else(|| non_empty(source.get("SWAPI_BASE_URL")))
            .unwrap_or_else(|| "https://swapi.dev/api".to_owned());
        let base_url = match Url::parse(&base_url_raw) {
            Ok(url) => Some(url),
            Err(error) => {
                problems.push(format!("UPSTREAM_BASE_URL is not a valid URL: {error}"));
                None
            }
        };

        let upstream = UpstreamConfig {
            base_url: base_url.unwrap_or_else(placeholder_url),
            timeout: seconds_or(source, "UPSTREAM_TIMEOUT_SECS", 10, &mut problems),
            allow_hosts: csv(source.get("UPSTREAM_ALLOW_HOSTS")),
        };

        validate(
            &server,
            &database,
            &auth,
            &environment,
            &upstream,
            &mut problems,
        );
        validate_log_filter(&telemetry.log_level, &mut problems);

        if !problems.is_empty() {
            return Err(ConfigError { problems });
        }

        Ok(Self {
            environment,
            server,
            database,
            telemetry,
            auth,
            upstream,
        })
    }
}

fn validate(
    server: &ServerConfig,
    database: &DatabaseConfig,
    auth: &AuthConfig,
    environment: &AppEnvironment,
    upstream: &UpstreamConfig,
    problems: &mut Vec<String>,
) {
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

    let scheme = upstream.base_url.scheme();
    if scheme != "http" && scheme != "https" {
        problems.push("UPSTREAM_BASE_URL must use http or https".to_owned());
    }
    if !upstream.base_url.username().is_empty() || upstream.base_url.password().is_some() {
        problems.push("UPSTREAM_BASE_URL must not contain credentials".to_owned());
    }
    if upstream.timeout.is_zero() {
        problems.push("UPSTREAM_TIMEOUT_SECS must be greater than zero".to_owned());
    }

    if environment.is_production() {
        if auth.dev_api_key_secret.is_some() {
            problems.push("DEV_API_KEY_SECRET must not be set in production".to_owned());
        }

        if !upstream.allow_hosts.is_empty() {
            let host = upstream
                .base_url
                .host_str()
                .unwrap_or_default();
            if !upstream
                .allow_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
            {
                problems.push(format!(
                    "UPSTREAM_BASE_URL host `{host}` is not listed in UPSTREAM_ALLOW_HOSTS"
                ));
            }
        } else {
            problems
                .push("UPSTREAM_ALLOW_HOSTS must list at least one host in production".to_owned());
        }
    }
}

fn validate_log_filter(filter: &str, problems: &mut Vec<String>) {
    if tracing_subscriber::EnvFilter::try_new(filter).is_err() {
        problems.push(format!("LOG_LEVEL is not a valid filter: `{filter}`"));
    }
}

fn has_postgres_scheme(url: &str) -> bool {
    url.starts_with("postgres://") || url.starts_with("postgresql://")
}

/// Never returned to callers: construction only succeeds when parsing did.
fn placeholder_url() -> Url {
    "http://invalid.local"
        .parse()
        .expect("static URL is valid")
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
        assert!(config.upstream.allow_hosts.is_empty());
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
    fn production_rejects_unlisted_upstream_host() {
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
                .contains("not listed in UPSTREAM_ALLOW_HOSTS")
        );
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
