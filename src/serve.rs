use std::sync::Arc;

use crate::{
    admin,
    admin::cli::ServeArgs,
    app,
    auth::{
        KeyVerifier,
        cache::CachedApiKeyStore,
        store::{ApiKeyStore, postgres::PostgresApiKeyStore},
    },
    config::Config,
    db,
    limits::{BreakerRegistry, RateLimits},
    observability,
    retry::RetryPolicy,
    routing::{RouteRefresh, RouteSource, RouteTableHandle},
    state::AppState,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) async fn run(args: ServeArgs) -> Result<(), BoxError> {
    let config = Config::from_env()?;

    if args.check_config {
        println!("{config:#?}");
        return Ok(());
    }

    let telemetry = observability::init(&config.telemetry, config.environment.as_str())?;
    let outcome = serve(&config).await;

    if let Err(error) = telemetry.shutdown() {
        tracing::error!(%error, "telemetry shutdown failed");
    }

    outcome
}

async fn serve(config: &Config) -> Result<(), BoxError> {
    let pool = db::connect(&config.database).await?;
    db::migrate(&pool).await?;

    let verifier = Arc::new(KeyVerifier::new(config.auth.pepper.clone()));

    let store: Arc<dyn ApiKeyStore> = if config.auth.cache_ttl.is_zero() {
        Arc::new(PostgresApiKeyStore::new(pool.clone()))
    } else {
        Arc::new(CachedApiKeyStore::new(
            Arc::new(PostgresApiKeyStore::new(pool.clone())),
            config.auth.cache_ttl,
        ))
    };

    let admin = Arc::new(admin::AdminService::new(
        pool.clone(),
        Arc::clone(&verifier),
        config.routing.allow_hosts.clone(),
        Arc::clone(&store),
    ));

    seed_development_key(config, &admin).await?;

    let source = RouteSource::new(pool.clone(), config.routing.allow_hosts.clone());
    let table = source.load().await?;

    if table.is_empty() {
        tracing::warn!("no routes configured: every request will return 404");
    }

    let routes = RouteTableHandle::new(table);
    let refresh = RouteRefresh::new(source, routes.clone(), config.routing.refresh_interval);
    let refresh_task = tokio::spawn(refresh.run());

    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder()?;

    let state = AppState {
        api_key_store: Arc::clone(&store),
        db: pool,
        verifier,
        routes,
        limits: Arc::new(RateLimits::new(&config.limits)),
        breakers: Arc::new(BreakerRegistry::new(&config.limits)),
        retry: Arc::new(RetryPolicy::new(&config.retry)),
        body_limit: config.server.request_body_limit_bytes,
        metrics,
    };

    let admin_server = start_admin(config, admin).await?;

    let app = app::build_app(config, state);
    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;

    tracing::info!(%address, "gateway listening");

    let outcome = serve_until_shutdown(listener, app, config).await;
    refresh_task.abort();
    stop_admin(admin_server).await;

    outcome
}

/// The control plane is optional: it starts only when `ADMIN_TOKEN` is set, and
/// it always shares the process so cache invalidation is immediate.
struct AdminServer {
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start_admin(
    config: &Config,
    service: Arc<admin::AdminService>,
) -> Result<Option<AdminServer>, BoxError> {
    let Some(token) = config.admin.token.clone() else {
        return Ok(None);
    };

    let app = admin::http::router(service, token);
    let listener = tokio::net::TcpListener::bind(&config.admin.bind).await?;

    tracing::info!(bind = %config.admin.bind, "admin API listening");

    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .into_future(),
    );

    Ok(Some(AdminServer { task, shutdown }))
}

async fn stop_admin(server: Option<AdminServer>) {
    let Some(server) = server else {
        return;
    };

    let _ = server.shutdown.send(());

    if tokio::time::timeout(std::time::Duration::from_secs(5), server.task)
        .await
        .is_err()
    {
        tracing::warn!("admin API did not drain within 5s");
    }
}

async fn seed_development_key(
    config: &Config,
    service: &admin::AdminService,
) -> Result<(), BoxError> {
    let Some(secret) = &config.auth.dev_api_key_secret else {
        return Ok(());
    };

    service
        .seed_development_key(secret.expose(), &config.auth.dev_api_key_scopes)
        .await?;

    tracing::warn!("development API key seeded; never enable this in production");

    Ok(())
}

async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    config: &Config,
) -> Result<(), BoxError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });

    let mut handle = tokio::spawn(server.into_future());

    tokio::select! {
        _ = wait_for_shutdown_signal() => {}
        result = &mut handle => {
            return match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(join_error) => Err(join_error.into()),
            };
        }
    }

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
