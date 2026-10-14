mod app;
mod auth;
mod config;
mod routes;
use config::Config;
use std::time::Duration;
mod observability;
mod state;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;

    let tracer_provider = observability::init(config.log_level.as_str())?;

    let addr = format!("{}:{}", config.host, config.port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.upstream_timeout_secs))
        .build()?;
    let api_key_store: Arc<dyn auth::store::ApiKeyStore> =
        Arc::new(auth::store::InMemoryApiKeyStore::default());

    let app_state = state::AppState {
        client,
        swapi_base_url: config.swapi_base_url.clone(),
        api_key_store,
    };
    let app = app::build_app(config, app_state);

    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    axum::serve(listener, app)
        .await
        .unwrap();
    tracer_provider.shutdown()?;
    Ok(())
}
