mod app;
mod auth;
mod config;
mod db;
mod error;
mod observability;
mod proxy;
mod request_context;
mod routes;
mod state;

use std::{process::ExitCode, sync::Arc, time::Duration};

use config::{AppEnvironment, Config};

#[tokio::main]
async fn main() -> ExitCode {
    // Local development convenience; real deployments inject the environment.
    dotenvy::dotenv().ok();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fatal: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;

    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--check-config")
    {
        println!("{config:#?}");
        return Ok(());
    }

    let telemetry = observability::init(&config.telemetry, environment_label(config.environment))?;

    let outcome = serve(&config).await;

    if let Err(error) = telemetry.shutdown() {
        tracing::error!(%error, "telemetry shutdown failed");
    }

    outcome
}

fn environment_label(environment: AppEnvironment) -> &'static str {
    match environment {
        AppEnvironment::Development => "development",
        AppEnvironment::Production => "production",
    }
}

async fn serve(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool = db::connect(&config.database).await?;
    db::migrate(&pool).await?;

    let store = auth::store::postgres::PostgresApiKeyStore::new(pool.clone());

    if let Some(secret) = &config.auth.dev_api_key_secret {
        store.prepare_development_seed().await?;
        auth::seed_dev_credential(&store, secret.expose()).await?;
        tracing::warn!("development API key seeded; never enable this in production");
    }

    let client = reqwest::Client::builder()
        .timeout(config.upstream.timeout)
        .pool_idle_timeout(Duration::from_secs(30))
        .user_agent(concat!("api-gateway/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let state = state::AppState {
        db: pool,
        client,
        upstream_base_url: config.upstream.base_url.clone(),
        api_key_store: Arc::new(store),
    };

    let app = app::build_app(config, state);
    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;

    tracing::info!(%address, "gateway listening");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });

    let handle = tokio::spawn(server.into_future());

    wait_for_shutdown_signal().await;
    tracing::info!("shutdown requested; draining in-flight requests");

    let _ = shutdown_tx.send(());

    match tokio::time::timeout(config.server.shutdown_drain, handle).await {
        Ok(Ok(Ok(()))) => {
            tracing::info!("drained cleanly");
            Ok(())
        }
        Ok(Ok(Err(error))) => Err(error.into()),
        Ok(Err(join_error)) => Err(join_error.into()),
        Err(_) => {
            tracing::warn!(
                drain_timeout_secs = config.server.shutdown_drain.as_secs(),
                "drain timed out; exiting with requests in flight"
            );
            Ok(())
        }
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::error!(%error, "could not install SIGTERM handler; waiting for Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
