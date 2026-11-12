use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

use super::{Actor, AdminError, AdminService, RouteSpec};
use crate::config::AdminToken;
use crate::error::AppError;

#[derive(Clone)]
struct AdminState {
    service: Arc<AdminService>,
    accounts: Arc<Vec<AdminToken>>,
}

/// HTTP adapter over [`AdminService`]. Separate listener, bearer token, and
/// its own bind address; never mounted on the data plane.
pub(crate) fn router(service: Arc<AdminService>, accounts: Arc<Vec<AdminToken>>) -> Router {
    let state = AdminState { service, accounts };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/tenants", post(create_tenant))
        .route("/v1/clients", post(create_client))
        .route("/v1/keys", post(create_key).get(list_keys))
        .route("/v1/keys/{key_id}", delete(revoke_key))
        .route("/v1/keys/{key_id}/rotate", post(rotate_key))
        .route("/v1/upstreams", get(list_upstreams))
        .route("/v1/upstreams/{id}", put(put_upstream))
        .route("/v1/routes", get(list_routes))
        .route("/v1/routes/{id}", put(put_route))
        .route("/v1/audit", get(list_audit))
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
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned);

    // Compare against every account so the number of configured tokens is not
    // observable through response timing.
    let mut matched: Option<&AdminToken> = None;

    for account in state.accounts.iter() {
        let equal: bool = presented
            .as_deref()
            .is_some_and(|presented| {
                presented
                    .as_bytes()
                    .ct_eq(account.token.expose().as_bytes())
                    .into()
            });

        if equal {
            matched = Some(account);
        }
    }

    let Some(account) = matched else {
        return AppError::Unauthorized.into_response();
    };

    let source_ip = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip().to_string());

    request
        .extensions_mut()
        .insert(Actor::new(account.name.clone()).with_source_ip(source_ip));

    next.run(request).await
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
    Json(body): Json<CreateTenant>,
) -> Result<StatusCode, AppError> {
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
    Json(body): Json<CreateClient>,
) -> Result<StatusCode, AppError> {
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
    Json(body): Json<CreateKey>,
) -> Result<(StatusCode, Json<KeyView>), AppError> {
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
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<Vec<KeySummaryView>>, AppError> {
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
) -> Result<Json<Vec<UpstreamView>>, AppError> {
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
    Json(body): Json<PutUpstream>,
) -> Result<StatusCode, AppError> {
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
}

async fn list_routes(State(state): State<AdminState>) -> Result<Json<Vec<RouteView>>, AppError> {
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
}

async fn put_route(
    State(state): State<AdminState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<PutRoute>,
) -> Result<StatusCode, AppError> {
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
            },
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

impl From<AdminError> for AppError {
    fn from(error: AdminError) -> Self {
        match error {
            AdminError::Conflict { entity, id } => AppError::Conflict {
                message: format!("{entity} `{id}` already exists").into(),
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

    fn router_with_token(token: &str) -> Router {
        router(
            Arc::new(AdminService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://test:test@127.0.0.1:5432/test")
                    .expect("lazy pool"),
                Arc::new(crate::auth::KeyVerifier::new(SecretString::new("pepper"))),
                Vec::new(),
                Arc::new(crate::auth::store::InMemoryApiKeyStore::default()),
            )),
            Arc::new(vec![AdminToken {
                name: "tester".to_owned(),
                token: SecretString::new(token),
            }]),
        )
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
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditView>>, AppError> {
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
