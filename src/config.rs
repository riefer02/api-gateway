pub struct Config {
    pub port: u16,
    pub host: String,
    pub log_level: String,
    pub swapi_base_url: String,
    pub max_request_body_bytes: usize,
    pub upstream_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|_| {
                Box::new(std::env::VarError::NotUnicode(
                    "PORT must be a number".into(),
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;
        let host = std::env::var("HOST").unwrap_or_else(|_| "localhost".to_string());
        let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let swapi_base_url =
            std::env::var("SWAPI_BASE_URL").unwrap_or_else(|_| "https://swapi.dev/api".to_string());
        let max_request_body_bytes = std::env::var("MAX_REQUEST_BODY_BYTES")
            .unwrap_or_else(|_| "1048576".to_string())
            .parse::<usize>()
            .map_err(|_| {
                Box::new(std::env::VarError::NotUnicode(
                    "MAX_REQUEST_BODY_BYTES must be a number".into(),
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;

        let upstream_timeout_secs = std::env::var("UPSTREAM_TIMEOUT_SECS")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u64>()
            .map_err(|_| {
                Box::new(std::env::VarError::NotUnicode(
                    "UPSTREAM_TIMEOUT_SECS must be a number".into(),
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;
        Ok(Self {
            port,
            host,
            log_level,
            swapi_base_url,
            max_request_body_bytes,
            upstream_timeout_secs,
        })
    }
}
