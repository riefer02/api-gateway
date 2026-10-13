pub struct Config {
    pub port: u16,
    pub host: String,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|_| {
                Box::new(std::env::VarError::NotUnicode(
                    "PORT must be a number".into(),
                )) as Box<dyn std::error::Error>
            })?;
        let host = std::env::var("HOST").unwrap_or_else(|_| "localhost".to_string());
        Ok(Self { port, host })
    }
}
