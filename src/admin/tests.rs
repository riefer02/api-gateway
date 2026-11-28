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
fn cursors_round_trip_and_reject_garbage() {
    let encoded = encode_cursor(&["/api", "route-1"]);

    assert_eq!(
        decode_cursor(&encoded, 2).expect("decode"),
        vec!["/api".to_owned(), "route-1".to_owned()]
    );

    // A caller must not be able to fabricate a cursor for another listing, or a
    // truncated one, and silently skip rows.
    let at = OffsetDateTime::now_utc();
    let timestamped = encode_timestamp_cursor(at, "42");
    let (decoded_at, tiebreak) = decode_timestamp_cursor(&timestamped).expect("decode");
    assert_eq!(decoded_at.unix_timestamp_nanos(), at.unix_timestamp_nanos());
    assert_eq!(tiebreak, "42");
    assert!(decode_timestamp_cursor("zz").is_err());

    for (candidate, parts) in [
        // not hex
        ("zz", 2),
        // odd-length hex
        ("abc", 2),
        ("", 2),
        // right encoding, wrong arity for this listing
        (encoded.as_str(), 1),
    ] {
        assert!(
            matches!(decode_cursor(candidate, parts), Err(AdminError::Invalid(_))),
            "{candidate:?} with {parts} parts must be rejected"
        );
    }
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
    let mut last: Option<(String, String)> = None;

    for _ in 0..32 {
        let page = service
            .list_routes(PageRequest::new(Some(2), cursor).expect("page"))
            .await
            .expect("page");

        assert!(page.items.len() <= 2, "a page is never larger than asked");

        for route in &page.items {
            let key = (route.path_prefix.clone(), route.id.clone());
            if let Some(previous) = &last {
                assert!(
                    previous < &key,
                    "pages must be strictly ordered by (prefix, id): {previous:?} then {key:?}"
                );
            }
            last = Some(key);
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
