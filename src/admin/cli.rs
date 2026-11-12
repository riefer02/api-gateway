use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use time::{Duration, OffsetDateTime};

use crate::{
    admin::{Actor, AdminService, IssuedKey, KeySummary, RouteSpec},
    auth::{KeyVerifier, store::ApiKeyStore},
    config::Config,
    db, observability,
};

#[derive(Debug, Parser)]
#[command(
    name = "api-gateway",
    version,
    about = "API gateway: run the data plane or administer the control plane"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run the data plane
    Serve(ServeArgs),
    /// Administer tenants, clients, keys, upstreams, and routes
    Admin(AdminArgs),
    /// Probe the local gateway (container healthcheck)
    Healthcheck,
}

#[derive(Debug, Args)]
pub(crate) struct ServeArgs {
    /// Print the resolved configuration (secrets redacted) and exit
    #[arg(long)]
    pub(crate) check_config: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AdminArgs {
    #[command(subcommand)]
    pub(crate) command: AdminCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminCommand {
    /// Tenants own clients
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// Clients own API keys
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Issue, rotate, revoke, and list API keys
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Register an upstream base URL
    Upstream {
        #[command(subcommand)]
        command: UpstreamCommand,
    },
    /// Register a route that maps a path prefix to an upstream
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Read the control-plane audit trail
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TenantCommand {
    Create { id: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ClientCommand {
    Create {
        id: String,
        #[arg(long)]
        tenant: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum KeyCommand {
    Create {
        #[arg(long)]
        client: String,
        /// Scope the key may use; repeat for several
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Days until the key expires; omit for no expiry
        #[arg(long)]
        expires_in_days: Option<i64>,
    },
    Rotate {
        key_id: String,
    },
    Revoke {
        key_id: String,
    },
    List {
        #[arg(long)]
        client: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum UpstreamCommand {
    Put {
        id: String,
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value_t = 10_000)]
        timeout_ms: u32,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RouteCommand {
    Put {
        id: String,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        upstream: String,
        /// Method this route accepts; repeat for several
        #[arg(long = "method", default_value = "GET")]
        methods: Vec<String>,
        /// Replace the matched prefix with this path (default: strip it)
        #[arg(long)]
        rewrite: Option<String>,
        /// Scope a caller needs; repeat for several
        #[arg(long = "scope")]
        scopes: Vec<String>,
    },
    List,
}

pub(crate) async fn run(args: AdminArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;
    let telemetry = observability::init(&config.telemetry, config.environment.as_str())?;
    let outcome = dispatch(&config, args.command).await;

    if let Err(error) = telemetry.shutdown() {
        eprintln!("warning: telemetry shutdown failed: {error}");
    }

    outcome
}

/// Container/orchestrator probe: a plain HTTP GET against the local listener.
pub(crate) async fn healthcheck() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;
    let url = format!("http://127.0.0.1:{}/health", config.server.port);

    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?
        .get(&url)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("unhealthy: {}", response.status()).into())
    }
}

async fn dispatch(
    config: &Config,
    command: AdminCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool = db::connect(&config.database).await?;
    db::migrate(&pool).await?;

    let verifier = Arc::new(KeyVerifier::new(config.auth.pepper.clone()));
    let store: Arc<dyn ApiKeyStore> = Arc::new(
        crate::auth::store::postgres::PostgresApiKeyStore::new(pool.clone()),
    );
    let service = AdminService::new(pool, verifier, config.routing.allow_hosts.clone(), store);

    let actor = Actor::new("cli");

    match command {
        AdminCommand::Tenant {
            command: TenantCommand::Create { id },
        } => {
            service
                .create_tenant(&actor, &id)
                .await?;
            println!("tenant `{id}` created");
        }
        AdminCommand::Client {
            command: ClientCommand::Create { id, tenant },
        } => {
            service
                .create_client(&actor, &id, &tenant)
                .await?;
            println!("client `{id}` created in tenant `{tenant}`");
        }
        AdminCommand::Key { command } => run_key_command(&service, &actor, command).await?,
        AdminCommand::Upstream { command } => {
            run_upstream_command(&service, &actor, command).await?
        }
        AdminCommand::Route { command } => run_route_command(&service, &actor, command).await?,
        AdminCommand::Audit { command } => run_audit_command(&service, command).await?,
    }

    Ok(())
}

async fn run_audit_command(
    service: &AdminService,
    command: AuditCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match command {
        AuditCommand::List { limit } => {
            let entries = service.list_audit(limit).await?;

            if entries.is_empty() {
                println!("no audit events");
                return Ok(());
            }

            for entry in entries {
                println!(
                    "{:<32} {:<12} {:<18} {:<24} {}",
                    entry.occurred_at.to_string(),
                    entry.actor,
                    entry.action,
                    entry.subject,
                    entry
                        .source_ip
                        .unwrap_or_else(|| "-".to_owned())
                );
            }
        }
    }

    Ok(())
}

async fn run_key_command(
    service: &AdminService,
    actor: &Actor,
    command: KeyCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match command {
        KeyCommand::Create {
            client,
            scopes,
            expires_in_days,
        } => {
            let expires_at = match expires_in_days {
                Some(days) => Some(
                    OffsetDateTime::now_utc()
                        .checked_add(Duration::days(days))
                        .ok_or("expiry is too far in the future")?,
                ),
                None => None,
            };

            print_issued(
                &service
                    .issue_key(actor, &client, &scopes, expires_at)
                    .await?,
            );
        }
        KeyCommand::Rotate { key_id } => {
            let issued = service
                .rotate_key(actor, &key_id)
                .await?;
            println!("key `{key_id}` revoked");
            print_issued(&issued);
        }
        KeyCommand::Revoke { key_id } => {
            service
                .revoke_key(actor, &key_id)
                .await?;
            println!("key `{key_id}` revoked");
        }
        KeyCommand::List { client } => {
            let keys = service.list_keys(&client).await?;

            if keys.is_empty() {
                println!("no keys for client `{client}`");
                return Ok(());
            }

            for key in keys {
                print_key_summary(&key);
            }
        }
    }

    Ok(())
}

async fn run_upstream_command(
    service: &AdminService,
    actor: &Actor,
    command: UpstreamCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match command {
        UpstreamCommand::Put {
            id,
            base_url,
            timeout_ms,
        } => {
            service
                .put_upstream(actor, &id, &base_url, timeout_ms)
                .await?;
            println!("upstream `{id}` -> {base_url} (timeout {timeout_ms}ms)");
        }
    }

    Ok(())
}

async fn run_route_command(
    service: &AdminService,
    actor: &Actor,
    command: RouteCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match command {
        RouteCommand::Put {
            id,
            prefix,
            upstream,
            methods,
            rewrite,
            scopes,
        } => {
            service
                .put_route(
                    actor,
                    RouteSpec {
                        id: id.clone(),
                        path_prefix: prefix.clone(),
                        methods,
                        upstream_id: upstream,
                        rewrite_prefix: rewrite,
                        scopes,
                    },
                )
                .await?;

            println!("route `{id}` configured on `{prefix}`");
        }
        RouteCommand::List => {
            let routes = service.list_routes().await?;

            if routes.is_empty() {
                println!("no routes configured");
                return Ok(());
            }

            for route in routes {
                println!(
                    "{:<20} {:<24} {:<10} -> {}  {}",
                    route.id,
                    route.path_prefix,
                    route.methods.join(","),
                    route.upstream_id,
                    match &route.rewrite_prefix {
                        Some(rewrite) => format!("rewrite {rewrite}"),
                        None => "strip prefix".to_owned(),
                    }
                );
            }
        }
    }

    Ok(())
}

fn print_issued(issued: &IssuedKey) {
    println!("key id : {}", issued.key_id);
    println!("token  : {}", issued.token);
    println!("scopes : {}", join_or_none(&issued.scopes));
    println!(
        "expires: {}",
        issued
            .expires_at
            .map(|expires_at| expires_at.to_string())
            .unwrap_or_else(|| "never".to_owned())
    );
    eprintln!("\nthe token is shown once; store it now");
}

fn print_key_summary(key: &KeySummary) {
    let state = if key.revoked_at.is_some() {
        "revoked"
    } else {
        "active"
    };

    println!(
        "{:<22} {:<8} scopes={} created={} expires={}",
        key.key_id,
        state,
        join_or_none(&key.scopes),
        key.created_at,
        key.expires_at
            .map(|expires_at| expires_at.to_string())
            .unwrap_or_else(|| "never".to_owned())
    );
    println!("{:22} client={}", "", key.client_id);
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(",")
    }
}
