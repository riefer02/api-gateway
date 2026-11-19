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

    // Install the recorder before any component can set a gauge or counter.
    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder()?;

    let verifier = Arc::new(KeyVerifier::new(config.auth.pepper.clone()));
    let oauth = config
        .oauth
        .as_ref()
        .map(crate::auth::oauth::OAuth::new)
        .transpose()
        .map_err(|problem| format!("OAUTH configuration: {problem}"))?
        .map(Arc::new);

    if let Some(oauth) = &oauth
        && let Err(error) = oauth.warm().await
    {
        // API-key traffic can still start; OAuth requests will fail closed
        // until the key set is reachable.
        tracing::warn!(?error, "could not warm the JWKS cache");
    }

    let exchange = config
        .oauth
        .as_ref()
        .and_then(|oauth| oauth.token_exchange.as_ref())
        .map(crate::auth::exchange::TokenExchange::new)
        .transpose()
        .map_err(|problem| format!("token exchange configuration: {problem}"))?
        .map(Arc::new);

    let (audit_sink, audit_receiver): (Arc<dyn crate::audit::AuditSink>, _) =
        if config.data_audit.enabled {
            let (sink, receiver) =
                crate::audit::ChannelAudit::new(config.data_audit.queue_capacity);
            (sink, Some(receiver))
        } else {
            (Arc::new(crate::audit::DisabledAudit), None)
        };

    let data_audit_task = audit_receiver.map(|receiver| {
        tokio::spawn(crate::audit::run(
            pool.clone(),
            receiver,
            config.data_audit.batch_size,
        ))
    });
    let data_retention_task = (!config.data_audit.retention.is_zero()).then(|| {
        tokio::spawn(crate::audit::run_retention(
            pool.clone(),
            config.data_audit.retention,
        ))
    });

    let mut revocation_task = None;

    let store: Arc<dyn ApiKeyStore> = if config.auth.cache_ttl.is_zero() {
        Arc::new(PostgresApiKeyStore::new(pool.clone()))
    } else {
        let cached = Arc::new(CachedApiKeyStore::new(
            Arc::new(PostgresApiKeyStore::new(pool.clone())),
            config.auth.cache_ttl,
        ));

        revocation_task = Some(tokio::spawn(crate::auth::cache::listen_for_revocations(
            pool.clone(),
            Arc::clone(&cached),
        )));

        cached
    };

    let admin = Arc::new(admin::AdminService::new(
        pool.clone(),
        Arc::clone(&verifier),
        config.routing.allow_hosts.clone(),
        Arc::clone(&store),
        config.server.max_request_timeout,
        config
            .oauth
            .as_ref()
            .is_some_and(|oauth| oauth.token_exchange.is_some()),
    ));

    seed_development_key(config, &admin).await?;

    let source = RouteSource::new(pool.clone(), config.routing.clone(), exchange.is_some());
    let table = source.load().await?;

    if table.is_empty() {
        tracing::warn!("no routes configured: every request will return 404");
    }

    let routes = RouteTableHandle::new(table)
        .with_stale_after(config.routing.refresh_interval * 3 + std::time::Duration::from_secs(5));
    let refresh = RouteRefresh::new(source, routes.clone(), config.routing.refresh_interval);
    let refresh_task = tokio::spawn(refresh.run());

    // Parsed once and shared by both listeners: the data plane needs it to
    // resolve the caller behind the edge proxy, and the control plane needs it
    // for the audit source address.
    let trusted_proxies = Arc::new(
        crate::net::TrustedProxies::parse(&config.server.trusted_proxies)
            .map_err(|problem| format!("TRUSTED_PROXIES: {problem}"))?,
    );

    // A zero TTL means no cache, which means no input validation.
    let mcp_schemas = (!config.mcp.tool_schema_ttl.is_zero()).then(|| {
        Arc::new(crate::mcp::schema::SchemaCache::new(
            config.mcp.tool_schema_ttl,
        ))
    });

    let state = AppState {
        api_key_store: Arc::clone(&store),
        db: pool,
        verifier,
        oauth,
        exchange,
        routes: routes.clone(),
        limits: Arc::new(RateLimits::new(&config.limits)),
        breakers: Arc::new(BreakerRegistry::new(&config.limits)),
        bulkheads: crate::limits::BulkheadRegistry::new(&config.routing).map(Arc::new),
        retry: Arc::new(RetryPolicy::new(&config.retry)),
        audit: audit_sink,
        mcp_schemas,
        default_request_timeout: config.server.request_timeout,
        max_request_timeout: config.server.max_request_timeout,
        max_response_bytes: config.server.max_response_bytes,
        stream_idle_timeout: config.server.stream_idle_timeout,
        body_limit: config.server.request_body_limit_bytes,
        metrics_token: config.telemetry.metrics_token.clone(),
        metrics,
        // A database blip must not drain every replica: while credentials are
        // still servable from cache, the process can still answer requests.
        readiness: Arc::new(crate::state::Readiness::new(
            std::time::Duration::from_secs(1),
            config.auth.cache_ttl,
        )),
        trusted_proxies: Arc::clone(&trusted_proxies),
    };

    let admin_server = start_admin(config, Arc::clone(&admin), trusted_proxies).await?;
    let audit_task = spawn_audit_pruning(config, Arc::clone(&admin));

    let app = app::build_app(config, state);
    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;

    log_startup(config, &routes);

    let outcome = run_server(
        listener,
        app,
        config.server.header_read_timeout,
        config.server.max_connections,
        config.server.shutdown_drain,
        wait_for_shutdown_signal(),
    )
    .await;
    refresh_task.abort();
    audit_task.abort();
    if let Some(task) = data_retention_task {
        task.abort();
    }
    if let Some(task) = data_audit_task {
        // Let the audit writer drain the queue before exit. The app (and the
        // sink's last sender) is dropped when `run_server` returns. Use most of
        // the process drain budget; a stalled database is reported explicitly.
        let audit_drain = config
            .server
            .shutdown_drain
            .min(std::time::Duration::from_secs(20));

        if tokio::time::timeout(audit_drain, task)
            .await
            .is_err()
        {
            metrics::counter!("gateway_data_audit_shutdown_timeouts_total").increment(1);
            tracing::warn!("data audit did not drain before shutdown; queued events may be lost");
        }
    }
    if let Some(task) = revocation_task {
        task.abort();
    }
    stop_admin(admin_server).await;

    outcome
}

/// One structured line that answers "what did this process just come up as?",
/// plus an advisory for every valid-but-risky setting.
fn log_startup(config: &Config, routes: &RouteTableHandle) {
    let table = routes.snapshot();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        environment = config.environment.as_str(),
        listen = %format!("{}:{}", config.server.host, config.server.port),
        admin = if config.admin.tokens.is_empty() {
            "disabled"
        } else {
            config.admin.bind.as_str()
        },
        routes = table.len(),
        table_version = table.version(),
        credential_cache_secs = config.auth.cache_ttl.as_secs(),
        ip_limit_per_min = config.limits.ip_per_minute,
        tenant_limit_per_min = config.limits.tenant_per_minute,
        user_limit_per_min = config.limits.user_per_minute,
        retry_attempts = config.retry.max_attempts,
        trusted_proxies = config.server.trusted_proxies.len(),
        oauth = if config.oauth.is_some() {
            "resource-server"
        } else {
            "disabled"
        },
        token_exchange = config
            .oauth
            .as_ref()
            .is_some_and(|oauth| oauth.token_exchange.is_some()),
        data_audit = config.data_audit.enabled,
        cors_origins = config.server.cors_allowed_origins.len(),
        "gateway ready"
    );

    for note in config.advisories() {
        tracing::warn!("{note}");
    }
}
struct AdminServer {
    task: tokio::task::JoinHandle<Result<(), BoxError>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}
async fn start_admin(
    config: &Config,
    service: Arc<admin::AdminService>,
    trusted_proxies: Arc<crate::net::TrustedProxies>,
) -> Result<Option<AdminServer>, BoxError> {
    if config.admin.tokens.is_empty() {
        return Ok(None);
    }

    let app = admin::http::router(
        service,
        Arc::new(config.admin.tokens.clone()),
        config.admin.timeout,
        trusted_proxies,
    );
    let listener = tokio::net::TcpListener::bind(&config.admin.bind).await?;

    tracing::info!(bind = %config.admin.bind, "admin API listening");

    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(run_server(
        listener,
        app,
        config.server.header_read_timeout,
        // The control plane is an internal listener; keep its footprint small.
        64,
        std::time::Duration::from_secs(5),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    Ok(Some(AdminServer { task, shutdown }))
}

async fn stop_admin(server: Option<AdminServer>) {
    let Some(server) = server else {
        return;
    };

    let _ = server.shutdown.send(());

    match tokio::time::timeout(std::time::Duration::from_secs(5), server.task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => tracing::warn!(%error, "admin API stopped with an error"),
        Ok(Err(join_error)) => tracing::warn!(%join_error, "admin API task failed"),
        Err(_) => tracing::warn!("admin API did not drain within 5s"),
    }
}

/// Audit rows are append-only by design, so retention is a scheduled delete
/// rather than an overwrite.
fn spawn_audit_pruning(
    config: &Config,
    service: Arc<admin::AdminService>,
) -> tokio::task::JoinHandle<()> {
    let retention = config.admin.audit_retention;

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(6 * 60 * 60));

        loop {
            ticker.tick().await;

            match service.prune_audit(retention).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, "pruned audit rows"),
                Err(error) => tracing::warn!(%error, "audit pruning failed"),
            }
        }
    })
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

/// Serves one listener with a bounded connection count, a header-read timeout,
/// and graceful drain. Returns when `shutdown` resolves and every connection
/// has finished or the drain budget expires.
async fn run_server(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    header_read_timeout: std::time::Duration,
    max_connections: usize,
    drain: std::time::Duration,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), BoxError> {
    use hyper_util::{
        rt::{TokioExecutor, TokioIo, TokioTimer},
        server::conn::auto,
        service::TowerToHyperService,
    };
    use std::sync::Arc;
    use tokio::sync::{Semaphore, watch};
    use tower::ServiceExt as _;

    let permits = Arc::new(Semaphore::new(max_connections));
    let (stop_tx, stop_rx) = watch::channel(());
    let mut connections = tokio::task::JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            // Finished connections must be reaped or the JoinSet grows for the
            // lifetime of the process.
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "accept failed; continuing");
                        continue;
                    }
                };

                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    metrics::counter!("gateway_connections_rejected_total").increment(1);
                    tracing::warn!(%peer, "connection limit reached; refusing");
                    drop(stream);
                    continue;
                };

                let app = app.clone();
                let mut stop = stop_rx.clone();

                connections.spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = TowerToHyperService::new(tower::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let app = app.clone();

                            async move {
                                let mut request = request.map(axum::body::Body::new);

                                // The per-IP limiter and the audit trail both
                                // depend on the real peer address.
                                request
                                    .extensions_mut()
                                    .insert(axum::extract::ConnectInfo(peer));

                                app.oneshot(request).await
                            }
                        },
                    ));

                    let mut builder = auto::Builder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(header_read_timeout);

                    let connection = builder.serve_connection_with_upgrades(io, service);
                    tokio::pin!(connection);

                    tokio::select! {
                        result = connection.as_mut() => {
                            if let Err(error) = result {
                                tracing::debug!(%error, "connection ended with an error");
                            }
                        }
                        _ = stop.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }

                    drop(permit);
                });
            }
        }
    }

    tracing::info!("shutdown requested; draining in-flight connections");
    let _ = stop_tx.send(());

    let deadline = tokio::time::sleep(drain);
    tokio::pin!(deadline);
    let mut drained = true;

    loop {
        tokio::select! {
            _ = &mut deadline => {
                drained = false;
                break;
            }
            joined = connections.join_next() => {
                if joined.is_none() {
                    break;
                }
            }
        }
    }

    if drained {
        tracing::info!("drained cleanly");
    } else {
        tracing::warn!("drain timed out; exiting with connections still open");
    }

    Ok(())
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
