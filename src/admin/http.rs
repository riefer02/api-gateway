use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, FromRequest, FromRequestParts, Path, Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::{Actor, AdminError, AdminScope, AdminService, RouteSpec};
use crate::config::AdminToken;
use crate::error::AppError;

#[derive(Clone)]
struct AdminState {
    service: Arc<AdminService>,
    accounts: Arc<Vec<AdminToken>>,
    timeout: std::time::Duration,
}

/// HTTP adapter over [`AdminService`]. Separate listener, bearer token, and
/// its own bind address; never mounted on the data plane.
pub(crate) fn router(
    service: Arc<AdminService>,
    accounts: Arc<Vec<AdminToken>>,
    timeout: std::time::Duration,
) -> Router {
    let state = AdminState {
        service,
        accounts,
        timeout,
    };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/tenants", post(create_tenant))
        .route("/v1/tenants/{id}", delete(delete_tenant))
        .route("/v1/clients", post(create_client))
        .route("/v1/clients/{id}", delete(delete_client))
        .route("/v1/keys", post(create_key).get(list_keys))
        .route("/v1/keys/{key_id}", delete(revoke_key))
        .route("/v1/keys/{key_id}/rotate", post(rotate_key))
        .route("/v1/upstreams", get(list_upstreams))
        .route(
            "/v1/upstreams/{id}",
            put(put_upstream).delete(delete_upstream),
        )
        .route("/v1/routes", get(list_routes))
        .route("/v1/routes/{id}", put(put_route).delete(delete_route))
        .route("/v1/audit", get(list_audit))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_admin_deadline,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ))
        .layer(
            tower::ServiceBuilder::new()
                .layer(tower_http::request_id::SetRequestIdLayer::x_request_id(
                    tower_http::request_id::MakeRequestUuid,
                ))
                .layer(axum::middleware::from_fn(
                    crate::request_context::scope_request_id,
                ))
                .layer(tower_http::request_id::PropagateRequestIdLayer::x_request_id()),
        )
        .with_state(state)
}

async fn require_admin(
    State(state): State<AdminState>,
    mut request: Request,
    next: Next,
) -> Response {
    let source_ip = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip().to_string());

    // Compare against every account so the number of configured tokens is not
    // observable through response timing.
    let mut matched: Option<&AdminToken> = None;

    for account in state.accounts.iter() {
        if crate::auth::bearer_matches(request.headers(), &account.token) {
            matched = Some(account);
        }
    }

    let Some(account) = matched else {
        metrics::counter!("gateway_admin_auth_failures_total").increment(1);
        tracing::warn!(
            source_ip = source_ip
                .as_deref()
                .unwrap_or("unknown"),
            "admin authentication failed"
        );

        return AppError::Unauthorized.into_response();
    };

    request
        .extensions_mut()
        .insert(Actor::new(account.name.clone(), account.scopes.clone()).with_source_ip(source_ip));

    next.run(request).await
}

/// JSON body extraction that fails with the gateway's envelope instead of
/// axum's plain-text rejection.
struct ApiJson<T>(T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::bad_request(format!(
                "invalid request body: {}",
                rejection.body_text()
            ))),
        }
    }
}

/// Query extraction with the same envelope contract.
struct ApiQuery<T>(T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::bad_request(format!(
                "invalid query string: {}",
                rejection.body_text()
            ))),
        }
    }
}

/// One control-plane request may not outlive `ADMIN_TIMEOUT_SECS`.
async fn enforce_admin_deadline(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(state.timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => AppError::RequestTimeout.into_response(),
    }
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

#[derive(Deserialize)]
struct CreateTenant {
    id: String,
}

async fn create_tenant(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<CreateTenant>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::TenantsWrite)?;

    state
        .service
        .create_tenant(&actor, &body.id)
        .await?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct CreateClient {
    id: String,
    tenant_id: String,
}

async fn create_client(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<CreateClient>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::TenantsWrite)?;

    state
        .service
        .create_client(&actor, &body.id, &body.tenant_id)
        .await?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct CreateKey {
    client_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_in_days: Option<i64>,
}

#[derive(Serialize)]
struct KeyView {
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    scopes: Vec<String>,
    expires_at: Option<String>,
}

#[derive(Serialize)]
struct KeySummaryView {
    key_id: String,
    client_id: String,
    scopes: Vec<String>,
    created_at: String,
    expires_at: Option<String>,
    revoked_at: Option<String>,
}

async fn create_key(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    ApiJson(body): ApiJson<CreateKey>,
) -> Result<(StatusCode, Json<KeyView>), AppError> {
    actor.require(AdminScope::KeysWrite)?;

    let expires_at = match body.expires_in_days {
        Some(days) => Some(
            OffsetDateTime::now_utc()
                .checked_add(Duration::days(days))
                .ok_or_else(|| AppError::bad_request("expiry is too far in the future"))?,
        ),
        None => None,
    };

    let issued = state
        .service
        .issue_key(&actor, &body.client_id, &body.scopes, expires_at)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(KeyView {
            key_id: issued.key_id,
            token: Some(issued.token),
            scopes: issued.scopes,
            expires_at: issued
                .expires_at
                .map(|value| value.to_string()),
        }),
    ))
}

async fn rotate_key(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyView>, AppError> {
    actor.require(AdminScope::KeysWrite)?;

    let issued = state
        .service
        .rotate_key(&actor, &key_id)
        .await?;

    Ok(Json(KeyView {
        key_id: issued.key_id,
        token: Some(issued.token),
        scopes: issued.scopes,
        expires_at: issued
            .expires_at
            .map(|value| value.to_string()),
    }))
}

async fn revoke_key(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::KeysWrite)?;

    state
        .service
        .revoke_key(&actor, &key_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ListKeysQuery {
    client_id: String,
}

async fn list_keys(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    ApiQuery(query): ApiQuery<ListKeysQuery>,
) -> Result<Json<Vec<KeySummaryView>>, AppError> {
    actor.require(AdminScope::KeysRead)?;

    let keys = state
        .service
        .list_keys(&query.client_id)
        .await?;

    Ok(Json(
        keys.into_iter()
            .map(|key| KeySummaryView {
                key_id: key.key_id,
                client_id: key.client_id,
                scopes: key.scopes,
                created_at: key.created_at.to_string(),
                expires_at: key
                    .expires_at
                    .map(|value| value.to_string()),
                revoked_at: key
                    .revoked_at
                    .map(|value| value.to_string()),
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct UpstreamView {
    id: String,
    base_url: String,
    timeout_ms: u32,
}

async fn list_upstreams(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<UpstreamView>>, AppError> {
    actor.require(AdminScope::ConfigRead)?;

    let upstreams = state.service.list_upstreams().await?;

    Ok(Json(
        upstreams
            .into_iter()
            .map(|upstream| UpstreamView {
                id: upstream.id,
                base_url: upstream.base_url,
                timeout_ms: upstream.timeout_ms,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct PutUpstream {
    base_url: String,
    timeout_ms: Option<u32>,
}

async fn put_upstream(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<PutUpstream>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::ConfigWrite)?;

    state
        .service
        .put_upstream(
            &actor,
            &id,
            &body.base_url,
            body.timeout_ms.unwrap_or(10_000),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct RouteView {
    id: String,
    path_prefix: String,
    methods: Vec<String>,
    upstream_id: String,
    rewrite_prefix: Option<String>,
    enabled: bool,
    priority: i32,
}

async fn list_routes(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<RouteView>>, AppError> {
    actor.require(AdminScope::ConfigRead)?;

    let routes = state.service.list_routes().await?;

    Ok(Json(
        routes
            .into_iter()
            .map(|route| RouteView {
                id: route.id,
                path_prefix: route.path_prefix,
                methods: route.methods,
                upstream_id: route.upstream_id,
                rewrite_prefix: route.rewrite_prefix,
                enabled: route.enabled,
                priority: route.priority,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct PutRoute {
    path_prefix: String,
    #[serde(default)]
    methods: Vec<String>,
    upstream_id: String,
    rewrite_prefix: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    enabled: Option<bool>,
    priority: Option<i32>,
}

async fn put_route(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<PutRoute>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::ConfigWrite)?;

    state
        .service
        .put_route(
            &actor,
            RouteSpec {
                id,
                path_prefix: body.path_prefix,
                methods: body.methods,
                upstream_id: body.upstream_id,
                rewrite_prefix: body.rewrite_prefix,
                scopes: body.scopes,
                enabled: body.enabled.unwrap_or(true),
                priority: body.priority.unwrap_or(0),
            },
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_tenant(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::TenantsWrite)?;
    state
        .service
        .delete_tenant(&actor, &id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_client(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::TenantsWrite)?;
    state
        .service
        .delete_client(&actor, &id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_upstream(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::ConfigWrite)?;
    state
        .service
        .delete_upstream(&actor, &id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_route(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    actor.require(AdminScope::ConfigWrite)?;
    state
        .service
        .delete_route(&actor, &id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

impl From<AdminError> for AppError {
    fn from(error: AdminError) -> Self {
        match error {
            AdminError::Conflict { message } => AppError::Conflict {
                message: message.into(),
            },
            AdminError::NotFound { entity, id } => AppError::NotFound {
                message: format!("{entity} `{id}` not found").into(),
            },
            AdminError::Invalid(message) => AppError::bad_request(message),
            AdminError::Unavailable => AppError::ServiceUnavailable,
            AdminError::Store(source) => AppError::internal(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    use crate::config::SecretString;

    fn router_with_accounts(accounts: Vec<AdminToken>) -> Router {
        router(
            Arc::new(AdminService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
                    .expect("lazy pool"),
                Arc::new(crate::auth::KeyVerifier::new(SecretString::new("pepper"))),
                Vec::new(),
                Arc::new(crate::auth::store::InMemoryApiKeyStore::default()),
            )),
            Arc::new(accounts),
            std::time::Duration::from_secs(5),
        )
    }

    fn account(name: &str, token: &str) -> AdminToken {
        AdminToken {
            name: name.to_owned(),
            token: SecretString::new(token),
            scopes: ["*".to_owned()].into_iter().collect(),
        }
    }

    fn router_with_token(token: &str) -> Router {
        router_with_accounts(vec![account("tester", token)])
    }

    #[tokio::test]
    async fn rejects_requests_without_the_admin_token() {
        let response = router_with_token("secret")
            .oneshot(
                Request::builder()
                    .uri("/v1/routes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_a_wrong_admin_token() {
        let response = router_with_token("secret")
            .oneshot(
                Request::builder()
                    .uri("/v1/routes")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_requires_the_token() {
        let response = router_with_token("secret")
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticated_requests_reach_the_service() {
        // No database: the handler surfaces a 5xx, which proves the token
        // check passed and the request reached the service.
        let response = router_with_token("secret")
            .oneshot(
                Request::builder()
                    .uri("/v1/routes")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
struct AuditView {
    occurred_at: String,
    actor: String,
    action: String,
    subject: String,
    source_ip: Option<String>,
    request_id: Option<String>,
}

async fn list_audit(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    ApiQuery(query): ApiQuery<AuditQuery>,
) -> Result<Json<Vec<AuditView>>, AppError> {
    actor.require(AdminScope::AuditRead)?;

    let entries = state
        .service
        .list_audit(query.limit.unwrap_or(100))
        .await?;

    Ok(Json(
        entries
            .into_iter()
            .map(|entry| AuditView {
                occurred_at: entry.occurred_at.to_string(),
                actor: entry.actor,
                action: entry.action,
                subject: entry.subject,
                source_ip: entry.source_ip,
                request_id: entry.request_id,
            })
            .collect(),
    ))
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::config::{AdminToken, SecretString};
    use axum::body::Body;
    use tower::ServiceExt;

    fn scoped_router(accounts: &[(&str, &str, &[&str])]) -> Router {
        let accounts = accounts
            .iter()
            .map(|(name, token, scopes)| AdminToken {
                name: (*name).to_owned(),
                token: SecretString::new(*token),
                scopes: scopes
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect(),
            })
            .collect();

        router(
            Arc::new(AdminService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
                    .expect("lazy pool"),
                Arc::new(crate::auth::KeyVerifier::new(SecretString::new("pepper"))),
                Vec::new(),
                Arc::new(crate::auth::store::InMemoryApiKeyStore::default()),
            )),
            Arc::new(accounts),
            std::time::Duration::from_secs(5),
        )
    }

    #[tokio::test]
    async fn a_scoped_token_cannot_issue_keys() {
        let app = scoped_router(&[("auditor", "auditor-token-0123", &["config:read"])]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keys")
                    .header("authorization", "Bearer auditor-token-0123")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client_id":"acme"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_scoped_token_cannot_read_audit() {
        let app = scoped_router(&[("operator", "operator-token-0123", &["keys:write"])]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit")
                    .header("authorization", "Bearer operator-token-0123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_scoped_token_reaches_an_allowed_route() {
        // Allowed by scope, then fails on the missing database: a 5xx proves
        // the scope check passed.
        let app = scoped_router(&[("auditor", "auditor-token-0123", &["config:read"])]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/routes")
                    .header("authorization", "Bearer auditor-token-0123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
