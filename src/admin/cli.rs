use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use time::{Duration, OffsetDateTime};

use crate::{
    admin::{Actor, AdminService, IssuedKey, KeySummary, PageRequest, RouteSpec},
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
#[allow(clippy::large_enum_variant)] // clap owns the shape; parsed once at startup.
pub(crate) enum Command {
    /// Run the data plane
    Serve(ServeArgs),
    /// Administer tenants, clients, keys, upstreams, and routes
    Admin(AdminArgs),
    /// Probe the local gateway (container healthcheck)
    Healthcheck,
    /// Wait, then exit. Used as a Kubernetes preStop hook so the endpoint is
    /// removed from rotation before the process is asked to drain.
    Prestop {
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },
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
    /// Apply pending migrations (explicit; the other admin commands do not)
    Migrate,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditCommand {
    /// Control-plane mutations
    List {
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Data-plane calls (who used which tool)
    Data {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long)]
        before_id: Option<i64>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Walk the tamper-evident chain and report the first row that fails
    Verify,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TenantCommand {
    Create { id: String },
    Rm { id: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ClientCommand {
    Create {
        id: String,
        #[arg(long)]
        tenant: String,
    },
    Rm {
        id: String,
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
        /// Maximum keys to return (1-1000)
        #[arg(long)]
        limit: Option<u32>,
        /// Continue from the previous page's next cursor
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum UpstreamCommand {
    Rm {
        id: String,
    },
    Put {
        id: String,
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value_t = 10_000)]
        timeout_ms: u32,
        /// RFC 8693 audience for the exchanged upstream token
        #[arg(long)]
        audience: Option<String>,
        /// Optional scope to request during token exchange
        #[arg(long)]
        exchange_scope: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // clap owns the shape; parsed once at startup.
pub(crate) enum RouteCommand {
    Rm {
        id: String,
    },
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
        /// Bind the route to one tenant; omit for a shared route
        #[arg(long)]
        tenant: Option<String>,
        /// Scope a caller needs; repeat for several. Omit to preserve existing scopes.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Replace the stored scopes with the --scope values (or clear them with none)
        #[arg(long)]
        replace_scopes: bool,
        /// Tool policy as JSON, e.g. '{"mode":"allow_list","roles":{"support":["search"]}}'
        #[arg(long)]
        tool_policy: Option<String>,
        /// Per-route request deadline in milliseconds
        #[arg(long)]
        request_timeout_ms: Option<u32>,
        /// Per-route response cap in bytes
        #[arg(long)]
        max_response_bytes: Option<u64>,
        /// Register the route disabled
        #[arg(long, conflicts_with = "enable")]
        disabled: bool,
        /// Enable the route (preserves the current state if neither flag is given)
        #[arg(long)]
        enable: bool,
        /// Higher priority wins between routes with the same prefix
        #[arg(long)]
        priority: Option<i32>,
    },
    List {
        /// Maximum routes to return (1-1000)
        #[arg(long)]
        limit: Option<u32>,
        /// Continue from the previous page's next cursor
        #[arg(long)]
        cursor: Option<String>,
    },
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

    if matches!(command, AdminCommand::Migrate) {
        db::migrate(&pool).await?;
        println!("migrations applied");
        return Ok(());
    }

    let verifier = Arc::new(KeyVerifier::new(config.auth.pepper.clone()));
    let store: Arc<dyn ApiKeyStore> = Arc::new(
        crate::auth::store::postgres::PostgresApiKeyStore::new(pool.clone()),
    );
    let service = AdminService::new(
        pool,
        verifier,
        config.routing.clone(),
        store,
        config.server.max_request_timeout,
        config
            .oauth
            .as_ref()
            .is_some_and(|oauth| oauth.token_exchange.is_some()),
    );

    let actor = Actor::local("cli");

    match command {
        AdminCommand::Tenant { command } => match command {
            TenantCommand::Create { id } => {
                service
                    .create_tenant(&actor, &id)
                    .await?;
                println!("tenant `{id}` created");
            }
            TenantCommand::Rm { id } => {
                service
                    .delete_tenant(&actor, &id)
                    .await?;
                println!("tenant `{id}` deleted");
            }
        },
        AdminCommand::Client { command } => match command {
            ClientCommand::Create { id, tenant } => {
                service
                    .create_client(&actor, &id, &tenant)
                    .await?;
                println!("client `{id}` created in tenant `{tenant}`");
            }
            ClientCommand::Rm { id } => {
                service
                    .delete_client(&actor, &id)
                    .await?;
                println!("client `{id}` deleted");
            }
        },
        AdminCommand::Key { command } => run_key_command(&service, &actor, command).await?,
        AdminCommand::Upstream { command } => {
            run_upstream_command(&service, &actor, command).await?
        }
        AdminCommand::Route { command } => run_route_command(&service, &actor, command).await?,
        AdminCommand::Audit { command } => run_audit_command(&service, command).await?,
        AdminCommand::Migrate => {}
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
        AuditCommand::Verify => {
            let report = service.verify_audit_chain().await?;

            if report.unchained > 0 {
                println!(
                    "{} row(s) outside the chain (written before it, or by a replica that was not upgraded)",
                    report.unchained
                );
            }

            match report.broken {
                Some(broken) => {
                    return Err(format!(
                        "audit chain broken at event {}: {}",
                        broken.id, broken.reason
                    )
                    .into());
                }
                // No hashed rows but some unhashed ones: either the chain was
                // removed or nothing has been written since the migration.
                // Either way, saying "intact" would be a false assurance.
                None if report.verified == 0 && report.unchained > 0 => {
                    return Err(
                        "no hashed audit rows: the log predates the chain or the chain was removed; \
                         verification proves nothing"
                            .into(),
                    );
                }
                None if report.verified == 0 => println!(
                    "no audit events to verify: an emptied log looks the same as a new one"
                ),
                None => println!(
                    "chain intact: {} rows verified from event {}",
                    report.verified,
                    report.chain_start.unwrap_or_default()
                ),
            }
        }
        AuditCommand::Data {
            limit,
            before_id,
            since,
            tenant,
        } => {
            let since = since
                .as_deref()
                .map(|value| {
                    time::OffsetDateTime::parse(
                        value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_err(|_| "`--since` must be an RFC 3339 timestamp".to_owned())
                })
                .transpose()?;

            let entries = service
                .list_data_audit(limit, before_id, since, tenant.as_deref())
                .await?;

            if entries.is_empty() {
                println!("no data audit events");
                return Ok(());
            }

            for entry in entries {
                println!(
                    "{:<32} {:<12} {:<20} {:<18} {:<8} {}",
                    entry.occurred_at.to_string(),
                    entry.tenant_id,
                    entry
                        .subject
                        .unwrap_or_else(|| "-".to_owned()),
                    entry.tool_name.unwrap_or_else(|| entry
                        .mcp_method
                        .unwrap_or_else(|| "-".to_owned())),
                    entry.decision,
                    entry
                        .status
                        .map(|status| status.to_string())
                        .unwrap_or_else(|| "-".to_owned())
                );

                // Claims and the caller's run id are the point of recording
                // them; printing them only when present keeps the common line
                // readable.
                if entry.detail != serde_json::json!({}) {
                    println!("  {}", entry.detail);
                }
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
        KeyCommand::List {
            client,
            limit,
            cursor,
        } => {
            let page = PageRequest::new(limit, cursor)?;
            let keys = service.list_keys(&client, page).await?;

            if keys.items.is_empty() {
                println!("no keys for client `{client}`");
                return Ok(());
            }

            for key in &keys.items {
                print_key_summary(key);
            }

            if let Some(cursor) = &keys.next_cursor {
                println!("\nmore: --cursor {cursor}");
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
        UpstreamCommand::Rm { id } => {
            service
                .delete_upstream(actor, &id)
                .await?;
            println!("upstream `{id}` deleted");
        }
        UpstreamCommand::Put {
            id,
            base_url,
            timeout_ms,
            audience,
            exchange_scope,
        } => {
            service
                .put_upstream(
                    actor,
                    &id,
                    &base_url,
                    timeout_ms,
                    audience.as_deref(),
                    exchange_scope.as_deref(),
                )
                .await?;
            println!(
                "upstream `{id}` -> {base_url} (timeout {timeout_ms}ms{}{})",
                audience
                    .as_deref()
                    .map(|audience| format!(", audience {audience}"))
                    .unwrap_or_default(),
                exchange_scope
                    .as_deref()
                    .map(|scope| format!(", scope {scope}"))
                    .unwrap_or_default()
            );
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
        RouteCommand::Rm { id } => {
            service.delete_route(actor, &id).await?;
            println!("route `{id}` deleted");
        }
        RouteCommand::Put {
            id,
            prefix,
            upstream,
            methods,
            rewrite,
            tenant,
            scopes,
            replace_scopes,
            tool_policy,
            request_timeout_ms,
            max_response_bytes,
            disabled,
            enable,
            priority,
        } => {
            let tool_policy = match tool_policy {
                Some(json) => Some(
                    serde_json::from_str::<crate::mcp::ToolPolicy>(&json)
                        .map_err(|error| format!("invalid --tool-policy JSON: {error}"))?,
                ),
                None => None,
            };
            let scopes = if scopes.is_empty() && !replace_scopes {
                None
            } else {
                Some(scopes)
            };
            let enabled = if enable {
                Some(true)
            } else if disabled {
                Some(false)
            } else {
                None
            };

            service
                .put_route(
                    actor,
                    RouteSpec {
                        id: id.clone(),
                        path_prefix: prefix.clone(),
                        methods,
                        upstream_id: upstream,
                        rewrite_prefix: rewrite,
                        tenant_id: tenant,
                        scopes,
                        tool_policy,
                        request_timeout_ms,
                        max_response_bytes,
                        enabled,
                        priority,
                    },
                )
                .await?;

            println!("route `{id}` configured on `{prefix}`");
        }
        RouteCommand::List { limit, cursor } => {
            let page = PageRequest::new(limit, cursor)?;
            let routes = service.list_routes(page).await?;

            if routes.items.is_empty() {
                println!("no routes configured");
                return Ok(());
            }

            for route in routes.items {
                let tools = match route.tool_policy.mode {
                    crate::mcp::ToolMode::Off => "tools=off",
                    crate::mcp::ToolMode::AllowList => "tools=allow_list",
                };
                let timeout = route
                    .request_timeout_ms
                    .map(|ms| format!(" timeout={ms}ms"))
                    .unwrap_or_default();
                let cap = route
                    .max_response_bytes
                    .map(|bytes| format!(" cap={bytes}B"))
                    .unwrap_or_default();

                println!(
                    "{:<20} {:<24} {:<10} -> {}  {}{}{}{}  {}{}{}",
                    route.id,
                    route.path_prefix,
                    route.methods.join(","),
                    route.upstream_id,
                    match &route.rewrite_prefix {
                        Some(rewrite) => format!("rewrite {rewrite}"),
                        None => "strip prefix".to_owned(),
                    },
                    match &route.tenant_id {
                        Some(tenant) => format!("  tenant {tenant}"),
                        None => String::new(),
                    },
                    if route.enabled { "" } else { "  (disabled)" },
                    if route.scopes.is_empty() {
                        String::new()
                    } else {
                        format!("  scopes={}", route.scopes.join(","))
                    },
                    tools,
                    timeout,
                    cap
                );
            }

            if let Some(cursor) = &routes.next_cursor {
                println!("\nmore: --cursor {cursor}");
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
