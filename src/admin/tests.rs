use super::*;
use crate::testing::{pg_pool, unique};

#[tokio::test]
async fn deleting_a_referenced_tenant_is_a_conflict() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let tenant = unique("del-tenant");
    let client = unique("del-client");

    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("create tenant");
    service
        .create_client(&actor, &client, &tenant)
        .await
        .expect("create client");

    let error = service
        .delete_tenant(&actor, &tenant)
        .await
        .expect_err("tenant is still referenced");

    assert!(
        matches!(error, AdminError::Conflict { .. }),
        "expected Conflict, got {error:?}"
    );

    service
        .delete_client(&actor, &client)
        .await
        .expect("delete client");
    service
        .delete_tenant(&actor, &tenant)
        .await
        .expect("delete tenant");
}

#[test]
fn scope_parsing_round_trips_the_vocabulary() {
    for scope in AdminScope::ALL {
        assert_eq!(
            AdminScope::parse(scope.as_str()),
            Some(scope),
            "{} must parse back to itself",
            scope.as_str()
        );
    }

    assert_eq!(AdminScope::parse("keys:delete"), None);
    assert_eq!(AdminScope::parse("Keys:Read"), None);
}

/// The write path and the compiler must reach the same verdict. If the
/// configured hard deadline is above the compiler's per-route ceiling, a
/// deadline in between used to be storable and then invalidated every
/// reload — an admin write could take the whole route table down.
///
/// The pool is lazy: validation must finish without touching the database.
#[tokio::test]
async fn a_deadline_the_compiler_would_reject_is_refused_at_write_time() {
    let service = AdminService::new(
        crate::testing::lazy_pool(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        Arc::new(auth::store::InMemoryApiKeyStore::default()),
        // Two hours: above the one-hour ceiling the compiler applies.
        std::time::Duration::from_secs(7_200),
        false,
    );

    let error = service
        .put_route(
            &Actor::local("test"),
            RouteSpec {
                id: "slow-route".to_owned(),
                path_prefix: "/slow".to_owned(),
                methods: vec!["GET".to_owned()],
                upstream_id: "unused".to_owned(),
                rewrite_prefix: None,
                tenant_id: None,
                scopes: None,
                tool_policy: None,
                request_timeout_ms: Some(crate::routing::MAX_ROUTE_TIMEOUT_MS + 1),
                max_response_bytes: None,
                enabled: None,
                priority: None,
            },
        )
        .await
        .expect_err("a deadline above the compiler ceiling must be refused");

    assert!(
        matches!(error, AdminError::Invalid(ref message) if message.contains("request_timeout_ms must be between")),
        "expected Invalid, got {error:?}"
    );
}

#[tokio::test]
async fn mutations_record_the_actor_and_source() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let tenant = unique("audit-tenant");
    let actor = Actor::local("alice").with_source_ip(Some("10.0.0.7".to_owned()));

    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("create tenant");

    let entries = service
        .list_audit(PageRequest::new(None, None).expect("page"))
        .await
        .expect("list audit");
    let entry = entries
        .items
        .iter()
        .find(|entry| entry.subject == tenant)
        .expect("audit entry for the tenant");

    assert_eq!(entry.actor, "alice");
    assert_eq!(entry.action, "tenant.create");
    assert_eq!(entry.source_ip.as_deref(), Some("10.0.0.7"));

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn a_route_round_trips_tenant_policy_deadline_and_cap() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        true,
    );

    let actor = Actor::local("test");
    let tenant = unique("route-tenant");
    let upstream = unique("route-upstream");
    let route = unique("route");

    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("tenant");
    service
        .put_upstream(
            &actor,
            &upstream,
            "https://mcp.internal",
            5_000,
            Some("https://mcp.internal"),
            Some("mcp:tools"),
        )
        .await
        .expect("upstream");

    let policy = ToolPolicy {
        mode: crate::mcp::ToolMode::AllowList,
        roles: std::collections::HashMap::from([("support".to_owned(), vec!["search".to_owned()])]),
    };

    service
        .put_route(
            &actor,
            RouteSpec {
                id: route.clone(),
                path_prefix: format!("/{route}"),
                methods: vec!["POST".to_owned()],
                upstream_id: upstream.clone(),
                rewrite_prefix: None,
                tenant_id: Some(tenant.clone()),
                scopes: Some(vec!["mcp:tools".to_owned()]),
                tool_policy: Some(policy.clone()),
                request_timeout_ms: Some(120_000),
                max_response_bytes: Some(2 * 1024 * 1024),
                enabled: Some(true),
                priority: Some(0),
            },
        )
        .await
        .expect("route");

    let saved = service
        .list_routes(PageRequest::new(None, None).expect("page"))
        .await
        .expect("list routes")
        .items
        .into_iter()
        .find(|saved| saved.id == route)
        .expect("route");

    assert_eq!(saved.tenant_id.as_deref(), Some(tenant.as_str()));
    assert_eq!(saved.request_timeout_ms, Some(120_000));
    assert_eq!(saved.max_response_bytes, Some(2 * 1024 * 1024));
    assert_eq!(saved.tool_policy, policy);
    assert_eq!(saved.scopes, vec!["mcp:tools"]);

    service
        .delete_route(&actor, &route)
        .await
        .ok();
    service
        .delete_upstream(&actor, &upstream)
        .await
        .ok();
    service
        .delete_tenant(&actor, &tenant)
        .await
        .ok();
}

#[tokio::test]
async fn rotating_an_expired_key_is_refused() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let tenant = unique("expired-tenant");
    let client = unique("expired-client");

    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("tenant");
    service
        .create_client(&actor, &client, &tenant)
        .await
        .expect("client");

    let issued = service
        .issue_key(
            &actor,
            &client,
            &["read".to_owned()],
            Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
        )
        .await
        .expect("key");

    sqlx::query(
        "UPDATE api_keys SET created_at = now() - interval '2 hours',
                          expires_at = now() - interval '1 hour' WHERE key_id = $1",
    )
    .bind(&issued.key_id)
    .execute(&pool)
    .await
    .expect("expire key");

    let error = service
        .rotate_key(&actor, &issued.key_id)
        .await
        .expect_err("expired key");
    assert!(matches!(error, AdminError::Conflict { .. }));

    service
        .delete_client(&actor, &client)
        .await
        .ok();
    service
        .delete_tenant(&actor, &tenant)
        .await
        .ok();
}

#[tokio::test]
async fn a_partial_route_update_preserves_security_fields() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let tenant = unique("partial-tenant");
    let upstream = unique("partial-upstream");
    let route = unique("partial-route");

    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("tenant");
    service
        .put_upstream(&actor, &upstream, "https://mcp.internal", 5_000, None, None)
        .await
        .expect("upstream");

    let policy = ToolPolicy {
        mode: crate::mcp::ToolMode::AllowList,
        roles: std::collections::HashMap::from([("support".to_owned(), vec!["search".to_owned()])]),
    };

    service
        .put_route(
            &actor,
            RouteSpec {
                id: route.clone(),
                path_prefix: format!("/{route}"),
                methods: vec!["POST".to_owned()],
                upstream_id: upstream.clone(),
                rewrite_prefix: None,
                tenant_id: Some(tenant.clone()),
                scopes: Some(vec!["mcp:tools".to_owned()]),
                tool_policy: Some(policy.clone()),
                request_timeout_ms: Some(120_000),
                max_response_bytes: Some(2 * 1024 * 1024),
                enabled: Some(true),
                priority: Some(7),
            },
        )
        .await
        .expect("route");

    // Only the routing fields: every security field must be preserved.
    service
        .put_route(
            &actor,
            RouteSpec {
                id: route.clone(),
                path_prefix: format!("/{route}"),
                methods: vec!["POST".to_owned()],
                upstream_id: upstream.clone(),
                rewrite_prefix: None,
                tenant_id: None,
                scopes: None,
                tool_policy: None,
                request_timeout_ms: None,
                max_response_bytes: None,
                enabled: None,
                priority: None,
            },
        )
        .await
        .expect("partial route update");

    let saved = service
        .list_routes(PageRequest::new(None, None).expect("page"))
        .await
        .expect("list routes")
        .items
        .into_iter()
        .find(|saved| saved.id == route)
        .expect("route");

    assert_eq!(saved.tenant_id.as_deref(), Some(tenant.as_str()));
    assert_eq!(saved.scopes, vec!["mcp:tools"]);
    assert_eq!(saved.tool_policy, policy);
    assert_eq!(saved.request_timeout_ms, Some(120_000));
    assert_eq!(saved.max_response_bytes, Some(2 * 1024 * 1024));
    assert!(saved.enabled);
    assert_eq!(saved.priority, 7);

    service
        .delete_route(&actor, &route)
        .await
        .ok();
    service
        .delete_upstream(&actor, &upstream)
        .await
        .ok();
    service
        .delete_tenant(&actor, &tenant)
        .await
        .ok();
}

#[tokio::test]
async fn deleting_a_tenant_with_routes_is_a_conflict() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let tenant = unique("restrict-tenant");
    let upstream = unique("restrict-upstream");
    let route = unique("restrict-route");

    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("tenant");
    service
        .put_upstream(&actor, &upstream, "https://mcp.internal", 5_000, None, None)
        .await
        .expect("upstream");
    service
        .put_route(
            &actor,
            RouteSpec {
                id: route.clone(),
                path_prefix: format!("/{route}"),
                methods: vec!["POST".to_owned()],
                upstream_id: upstream.clone(),
                rewrite_prefix: None,
                tenant_id: Some(tenant.clone()),
                scopes: None,
                tool_policy: None,
                request_timeout_ms: None,
                max_response_bytes: None,
                enabled: None,
                priority: None,
            },
        )
        .await
        .expect("route");

    let error = service
        .delete_tenant(&actor, &tenant)
        .await
        .expect_err("routes still reference the tenant");
    assert!(matches!(error, AdminError::Conflict { .. }));

    service
        .delete_route(&actor, &route)
        .await
        .ok();
    service
        .delete_upstream(&actor, &upstream)
        .await
        .ok();
    service
        .delete_tenant(&actor, &tenant)
        .await
        .ok();
}

#[tokio::test]
async fn an_upstream_literal_must_pass_the_egress_policy() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let mut routing = crate::routing::test_routing();
    routing.egress = crate::net::Egress::DenyLinkLocal;

    let store: Arc<dyn ApiKeyStore> = Arc::new(crate::auth::store::InMemoryApiKeyStore::default());
    let service = AdminService::new(
        pool,
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        routing,
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let error = service
        .put_upstream(
            &actor,
            &unique("literal-upstream"),
            "http://127.0.0.1:9090",
            5_000,
            None,
            None,
        )
        .await
        .expect_err("loopback literal must be refused at write time");

    assert!(
        error
            .to_string()
            .contains("UPSTREAM_EGRESS"),
        "expected an egress refusal, got {error:?}"
    );
}

#[tokio::test]
async fn an_upstream_audience_requires_token_exchange() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(crate::auth::store::InMemoryApiKeyStore::default());
    let service = AdminService::new(
        pool,
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let error = service
        .put_upstream(
            &actor,
            &unique("audience-upstream"),
            "https://mcp.internal",
            5_000,
            Some("https://mcp.internal"),
            None,
        )
        .await
        .expect_err("audience without exchange");

    assert!(
        error
            .to_string()
            .contains("OAUTH_TOKEN_ENDPOINT")
    );
}

#[test]
fn empty_id_cursor_survives_page_request() {
    let next_cursor = encode_cursor(CursorKind::Routes, &[""]);
    assert_eq!(
        next_cursor, "routes.",
        "the encoding must be nonempty and named"
    );

    let page = PageRequest::new(Some(1), Some(next_cursor)).expect("page");
    let cursor = page
        .cursor()
        .expect("cursor after the empty id");

    assert_eq!(
        decode_cursor(CursorKind::Routes, cursor, 1).expect("decode"),
        vec![String::new()]
    );
    assert!(decode_cursor(CursorKind::Routes, cursor, 2).is_err());
}

/// Ids address rows in URLs and name them in the audit log, so a blank one is
/// not addressable and must never be created. Validation runs before any
/// database work, which the lazy pool proves.
#[tokio::test]
async fn blank_entity_ids_are_refused_before_any_write() {
    let service = AdminService::new(
        crate::testing::lazy_pool(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        Arc::new(auth::store::InMemoryApiKeyStore::default()),
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");

    assert_blank_id(
        service
            .put_route(
                &actor,
                RouteSpec {
                    id: "  ".to_owned(),
                    path_prefix: "/blank".to_owned(),
                    methods: vec!["GET".to_owned()],
                    upstream_id: "unused".to_owned(),
                    rewrite_prefix: None,
                    tenant_id: None,
                    scopes: None,
                    tool_policy: None,
                    request_timeout_ms: None,
                    max_response_bytes: None,
                    enabled: None,
                    priority: None,
                },
            )
            .await,
        "route",
    );
    assert_blank_id(
        service
            .put_upstream(&actor, "", "https://mcp.internal", 5_000, None, None)
            .await,
        "upstream",
    );
    assert_blank_id(service.create_tenant(&actor, "").await, "tenant");
    assert_blank_id(
        service
            .create_client(&actor, "", "tenant")
            .await,
        "client",
    );
    assert_blank_id(
        service
            .create_client(&actor, "client", " ")
            .await,
        "tenant",
    );
}

fn assert_blank_id(result: Result<(), AdminError>, entity: &str) {
    match result {
        Err(AdminError::Invalid(message)) => assert!(
            message.contains(&format!("{entity} id must not be blank")),
            "{message}"
        ),
        other => panic!("expected Invalid for a blank {entity} id, got {other:?}"),
    }
}

#[test]
fn a_blank_cursor_is_rejected_rather_than_reinterpreted() {
    // A broken client that sends `cursor=` must learn that it is broken, not
    // silently restart at the first page.
    assert!(PageRequest::new(None, Some(String::new())).is_err());
    assert!(PageRequest::new(None, Some("   ".to_owned())).is_err());

    // Omitting the parameter still means the first page.
    assert!(
        PageRequest::new(None, None)
            .expect("page")
            .cursor()
            .is_none()
    );
}

#[test]
fn cursors_round_trip_and_reject_garbage() {
    let encoded = encode_cursor(CursorKind::Routes, &["/api", "route-1"]);

    assert_eq!(
        decode_cursor(CursorKind::Routes, &encoded, 2).expect("decode"),
        vec!["/api".to_owned(), "route-1".to_owned()]
    );

    // A part may contain anything, including the character an "encode the
    // joined string" scheme would have used as a separator.
    let awkward = encode_cursor(CursorKind::Routes, &["/api/\u{1f}/x", "id.with.dots"]);
    assert_eq!(
        decode_cursor(CursorKind::Routes, &awkward, 2).expect("decode"),
        vec!["/api/\u{1f}/x".to_owned(), "id.with.dots".to_owned()]
    );

    // Empty parts are legal (rows written before ids were validated), so the
    // codec must round-trip them rather than break pagination on the row after
    // one.
    assert_eq!(
        decode_cursor(
            CursorKind::Routes,
            &encode_cursor(CursorKind::Routes, &["", "id"]),
            2
        )
        .expect("decode"),
        vec![String::new(), "id".to_owned()]
    );

    let at = OffsetDateTime::now_utc();
    let timestamped = encode_timestamp_cursor(CursorKind::Audit, at, "42");
    let (decoded_at, tiebreak) =
        decode_timestamp_cursor(CursorKind::Audit, &timestamped).expect("decode");
    assert_eq!(decoded_at.unix_timestamp_nanos(), at.unix_timestamp_nanos());
    assert_eq!(tiebreak, "42");
    assert!(decode_timestamp_cursor(CursorKind::Audit, "zz").is_err());

    for (candidate, parts) in [
        // not hex
        ("routes.zz", 2),
        // odd-length hex
        ("routes.abc", 2),
        // no tag at all
        ("", 2),
        ("zz", 2),
        // right encoding, wrong arity for this listing
        (encoded.as_str(), 1),
    ] {
        assert!(
            matches!(
                decode_cursor(CursorKind::Routes, candidate, parts),
                Err(AdminError::Invalid(_))
            ),
            "{candidate:?} with {parts} parts must be rejected"
        );
    }
}

/// A cursor names the listing it belongs to. Keys, audit, and data-audit all
/// page over `(timestamp, tiebreak)`, so arity alone cannot tell them apart;
/// without the tag one listing would accept another's cursor and silently page
/// from a boundary it never produced.
#[test]
fn a_cursor_from_another_listing_is_rejected() {
    let at = OffsetDateTime::now_utc();
    let from_audit = encode_timestamp_cursor(CursorKind::Audit, at, "42");

    // Same arity, same shape, wrong listing.
    assert!(matches!(
        decode_timestamp_cursor(CursorKind::Keys, &from_audit),
        Err(AdminError::Invalid(_))
    ));
    assert!(matches!(
        decode_timestamp_cursor(CursorKind::DataAudit, &from_audit),
        Err(AdminError::Invalid(_))
    ));

    let from_routes = encode_cursor(CursorKind::Routes, &["route-1"]);
    assert!(matches!(
        decode_cursor(CursorKind::Upstreams, &from_routes, 1),
        Err(AdminError::Invalid(_))
    ));
}

/// The issued token is a secret; `Debug` is how it would reach a log, a panic
/// message, or a trace without anyone writing `token` on purpose.
#[test]
fn an_issued_token_never_reaches_debug_output() {
    let issued = IssuedKey {
        key_id: "key-1".to_owned(),
        token: "the-secret-token".to_owned(),
        scopes: vec!["read".to_owned()],
        expires_at: None,
    };

    let rendered = format!("{issued:?}");

    assert!(!rendered.contains("the-secret-token"), "{rendered}");
    assert!(rendered.contains("key-1"), "{rendered}");
}

#[tokio::test]
async fn route_listing_pages_and_ends() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("test");
    let upstream = unique("page-upstream");
    let tenant = unique("page-tenant");

    service
        .put_upstream(&actor, &upstream, "https://mcp.internal", 5_000, None, None)
        .await
        .expect("upstream");
    service
        .create_tenant(&actor, &tenant)
        .await
        .expect("tenant");

    let mut route_ids = Vec::new();
    for suffix in ["a", "b", "c"] {
        let id = format!("{}-{suffix}", unique("page-route"));
        service
            .put_route(
                &actor,
                RouteSpec {
                    id: id.clone(),
                    path_prefix: format!("/{id}"),
                    methods: vec!["GET".to_owned()],
                    upstream_id: upstream.clone(),
                    rewrite_prefix: None,
                    tenant_id: None,
                    scopes: None,
                    tool_policy: None,
                    request_timeout_ms: None,
                    max_response_bytes: None,
                    enabled: Some(true),
                    priority: None,
                },
            )
            .await
            .expect("route");
        route_ids.push(id);
    }

    // The listing is global, so walk it to the end rather than assuming these
    // are the only routes in the database. Page size and ordering are asserted
    // on the way, and only this test's rows are removed afterwards.
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut last: Option<String> = None;

    for _ in 0..32 {
        let page = service
            .list_routes(PageRequest::new(Some(2), cursor).expect("page"))
            .await
            .expect("page");

        assert!(page.items.len() <= 2, "a page is never larger than asked");

        for route in &page.items {
            if let Some(previous) = &last {
                assert!(
                    previous < &route.id,
                    "pages must be strictly ordered by id: {previous} then {}",
                    route.id
                );
            }
            last = Some(route.id.clone());
            seen.push(route.id.clone());
        }

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    for id in &route_ids {
        assert_eq!(
            seen.iter()
                .filter(|seen| *seen == id)
                .count(),
            1,
            "route `{id}` must appear exactly once across pages"
        );
    }

    for id in &route_ids {
        service
            .delete_route(&actor, id)
            .await
            .ok();
    }
    service
        .delete_upstream(&actor, &upstream)
        .await
        .ok();
    service
        .delete_tenant(&actor, &tenant)
        .await
        .ok();
}

/// An empty id sorts before every other id, so it is the first row of a
/// listing. Its cursor is `routes.`: the tag keeps it nonempty, so it survives
/// `PageRequest`, and the empty part after the dot names the row. The write
/// path and the schema both refuse new blank ids, so the only remaining source
/// is a row stored before those checks — which is why the codec still knows how
/// to encode and read one.
#[test]
fn a_cursor_past_a_legacy_empty_id_is_nonempty_and_steps_over_it() {
    let page = finish_page(
        vec![
            ((), encode_cursor(CursorKind::Routes, &[""])),
            ((), encode_cursor(CursorKind::Routes, &["next"])),
        ],
        1,
    );

    assert_eq!(page.next_cursor.as_deref(), Some("routes."));

    let request = PageRequest::new(Some(1), page.next_cursor).expect("the cursor is accepted");
    let after =
        decode_cursor(CursorKind::Routes, request.cursor().expect("cursor"), 1).expect("decode");

    // `WHERE id > ''` matches every non-blank id, so the listing advances.
    assert_eq!(after, vec![String::new()]);
}

/// The migration is the second boundary: a writer that bypasses the service
/// cannot recreate the row the cursor above exists to survive. `NOT VALID` is
/// deliberate — rows stored before the check are not rewritten or deleted.
#[tokio::test]
async fn the_schema_carries_the_blank_id_check() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let check: Vec<(String, bool)> = sqlx::query_as(
        "SELECT conname, convalidated FROM pg_constraint
         WHERE conname IN ('clients_id_not_blank', 'routes_id_not_blank',
                           'tenants_id_not_blank', 'upstreams_id_not_blank')
         ORDER BY conname",
    )
    .fetch_all(&pool)
    .await
    .expect("read the blank-id constraints");

    assert_eq!(
        check
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "clients_id_not_blank",
            "routes_id_not_blank",
            "tenants_id_not_blank",
            "upstreams_id_not_blank",
        ]
    );
    assert!(
        check
            .iter()
            .all(|(_, validated)| !validated),
        "legacy rows must not block the migration: {check:?}"
    );
}

#[test]
fn page_requests_are_bounded() {
    assert_eq!(
        PageRequest::new(None, None)
            .expect("default")
            .limit,
        DEFAULT_PAGE_SIZE
    );
    assert!(PageRequest::new(Some(0), None).is_err());
    assert!(PageRequest::new(Some(MAX_PAGE_SIZE + 1), None).is_err());
    assert!(PageRequest::new(Some(MAX_PAGE_SIZE), None).is_ok());
}

#[tokio::test]
async fn audit_listing_pages_newest_first() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("pager");
    let mut subjects = Vec::new();
    for _ in 0..3 {
        let tenant = unique("audit-page");
        service
            .create_tenant(&actor, &tenant)
            .await
            .expect("tenant");
        subjects.push(tenant);
    }

    // The log is shared and append-only, so walk a bounded number of pages and
    // assert the contract on what was returned: newest first, no repeats.
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut last: Option<OffsetDateTime> = None;

    for _ in 0..64 {
        let page = service
            .list_audit(PageRequest::new(Some(2), cursor).expect("page"))
            .await
            .expect("audit page");

        assert!(page.items.len() <= 2, "a page is never larger than asked");

        for entry in &page.items {
            if let Some(previous) = last {
                assert!(
                    entry.occurred_at <= previous,
                    "audit pages must be newest first"
                );
            }
            last = Some(entry.occurred_at);
            seen.push(entry.subject.clone());
        }

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    for subject in &subjects {
        assert_eq!(
            seen.iter()
                .filter(|seen| *seen == subject)
                .count(),
            1,
            "event for `{subject}` must appear exactly once across pages"
        );
        service
            .delete_tenant(&actor, subject)
            .await
            .ok();
    }
}

/// Regression: a route's path prefix can be edited, so it cannot be the sort
/// key. Ordered by prefix, moving the middle route *before* the page boundary
/// made the walk skip it; the id order must not move.
#[tokio::test]
async fn route_pagination_survives_a_prefix_edit_between_pages() {
    let Some(pool) = pg_pool().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let store: Arc<dyn ApiKeyStore> = Arc::new(auth::store::postgres::PostgresApiKeyStore::new(
        pool.clone(),
    ));
    let service = AdminService::new(
        pool.clone(),
        Arc::new(KeyVerifier::new(crate::config::SecretString::new("pepper"))),
        crate::routing::test_routing(),
        store,
        std::time::Duration::from_secs(300),
        false,
    );

    let actor = Actor::local("pager");
    let upstream = unique("edit-upstream");
    service
        .put_upstream(&actor, &upstream, "https://mcp.internal", 5_000, None, None)
        .await
        .expect("upstream");

    let base = unique("page-edit");
    let ids: Vec<String> = ["a", "b", "c"]
        .iter()
        .map(|suffix| format!("{base}-{suffix}"))
        .collect();

    for id in &ids {
        service
            .put_route(
                &actor,
                RouteSpec {
                    id: id.clone(),
                    path_prefix: format!("/{id}"),
                    methods: vec!["GET".to_owned()],
                    upstream_id: upstream.clone(),
                    rewrite_prefix: None,
                    tenant_id: None,
                    scopes: None,
                    tool_policy: None,
                    request_timeout_ms: None,
                    max_response_bytes: None,
                    enabled: Some(true),
                    priority: None,
                },
            )
            .await
            .expect("route");
    }

    // Walk one row at a time until the first of this test's routes is reached.
    let mut cursor = None;
    let mut reached = false;

    for _ in 0..256 {
        let page = service
            .list_routes(PageRequest::new(Some(1), cursor.clone()).expect("page"))
            .await
            .expect("page");

        let Some(route) = page.items.first() else {
            break;
        };

        assert!(
            route.id <= ids[0] || reached,
            "the walk passed the test routes without seeing them"
        );

        if route.id == ids[0] {
            reached = true;
            cursor = page.next_cursor;
            break;
        }

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    assert!(reached, "did not reach the test routes");

    // Move the middle route before the page boundary in prefix order.
    service
        .put_route(
            &actor,
            RouteSpec {
                id: ids[1].clone(),
                path_prefix: format!("/000{}", ids[1]),
                methods: vec!["GET".to_owned()],
                upstream_id: upstream.clone(),
                rewrite_prefix: None,
                tenant_id: None,
                scopes: None,
                tool_policy: None,
                request_timeout_ms: None,
                max_response_bytes: None,
                enabled: Some(true),
                priority: None,
            },
        )
        .await
        .expect("prefix edit");

    let second = service
        .list_routes(PageRequest::new(Some(1), cursor).expect("page"))
        .await
        .expect("page after the edit");
    assert_eq!(
        second
            .items
            .first()
            .map(|route| route.id.as_str()),
        Some(ids[1].as_str()),
        "a prefix edit must not move a route out of the page walk"
    );

    let third = service
        .list_routes(PageRequest::new(Some(1), second.next_cursor.clone()).expect("page"))
        .await
        .expect("page after the edit");
    assert_eq!(
        third
            .items
            .first()
            .map(|route| route.id.as_str()),
        Some(ids[2].as_str())
    );

    for id in &ids {
        service
            .delete_route(&actor, id)
            .await
            .ok();
    }
    service
        .delete_upstream(&actor, &upstream)
        .await
        .ok();
}
