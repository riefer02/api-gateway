use std::collections::HashSet;

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::auth::{
    AccountStatus, ApiKeyId, ApiKeyRecord, Client, ClientId, Credential, SecretVerifier, Tenant,
    TenantId,
};

use super::{ApiKeyStore, KeyPage, KeySummary, NewApiKey, StoreError};

pub(crate) struct PostgresApiKeyStore {
    pool: PgPool,
}

impl PostgresApiKeyStore {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiKeyStore for PostgresApiKeyStore {
    async fn find_by_key_id(&self, key_id: &ApiKeyId) -> Result<Option<Credential>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT
                k.key_id,
                k.client_id,
                k.verifier,
                k.verifier_version,
                k.expires_at,
                k.revoked_at,
                c.tenant_id,
                c.status AS client_status,
                t.status AS tenant_status,
                COALESCE(
                    array_agg(s.scope) FILTER (WHERE s.scope IS NOT NULL),
                    '{}'
                ) AS scopes
            FROM api_keys k
            JOIN clients c ON c.id = k.client_id
            JOIN tenants t ON t.id = c.tenant_id
            LEFT JOIN api_key_scopes s ON s.key_id = k.key_id
            WHERE k.key_id = $1
            GROUP BY k.key_id, c.id, t.id
            "#,
        )
        .bind(key_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let verifier_bytes: Vec<u8> = row
            .try_get("verifier")
            .map_err(decode)?;
        let verifier: [u8; 32] = verifier_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Unavailable)?;

        let verifier_version: i16 = row
            .try_get("verifier_version")
            .map_err(decode)?;
        let verifier_version =
            u8::try_from(verifier_version).map_err(|_| StoreError::Unavailable)?;

        let client_status: String = row
            .try_get("client_status")
            .map_err(decode)?;
        let tenant_status: String = row
            .try_get("tenant_status")
            .map_err(decode)?;

        let scopes: Vec<String> = row.try_get("scopes").map_err(decode)?;
        let tenant_id = TenantId(
            row.try_get("tenant_id")
                .map_err(decode)?,
        );
        let client_id = ClientId(
            row.try_get("client_id")
                .map_err(decode)?,
        );

        Ok(Some(Credential {
            key: ApiKeyRecord {
                key_id: ApiKeyId(row.try_get("key_id").map_err(decode)?),
                client_id: client_id.clone(),
                verifier: SecretVerifier(verifier),
                verifier_version,
                scopes: scopes
                    .into_iter()
                    .collect::<HashSet<_>>(),
                expires_at: row
                    .try_get("expires_at")
                    .map_err(decode)?,
                revoked_at: row
                    .try_get("revoked_at")
                    .map_err(decode)?,
            },
            client: Client {
                id: client_id,
                tenant_id: tenant_id.clone(),
                status: parse_status(&client_status)?,
            },
            tenant: Tenant {
                id: tenant_id,
                status: parse_status(&tenant_status)?,
            },
        }))
    }

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = now()
             WHERE key_id = $1 AND revoked_at IS NULL",
        )
        .bind(key_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;

        if result.rows_affected() > 0 {
            notify_key_change(&mut transaction, key_id).await?;
        }

        transaction
            .commit()
            .await
            .map_err(unavailable)?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_for_client(
        &self,
        client_id: &ClientId,
        page: KeyPage,
    ) -> Result<Vec<KeySummary>, StoreError> {
        let (after_at, after_id) = match &page.after {
            Some((at, id)) => (Some(*at), Some(id.as_str())),
            None => (None, None),
        };

        let rows = sqlx::query(
            r#"
            SELECT
                k.key_id,
                k.client_id,
                k.created_at,
                k.expires_at,
                k.revoked_at,
                COALESCE(array_agg(s.scope) FILTER (WHERE s.scope IS NOT NULL), '{}') AS scopes
            FROM api_keys k
            LEFT JOIN api_key_scopes s ON s.key_id = k.key_id
            WHERE k.client_id = $1
              AND ($2::timestamptz IS NULL OR (k.created_at, k.key_id) < ($2, $3::text))
            GROUP BY k.key_id
            ORDER BY k.created_at DESC, k.key_id DESC
            LIMIT $4
            "#,
        )
        .bind(client_id.as_str())
        .bind(after_at)
        .bind(after_id)
        .bind(i64::from(page.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;

        rows.into_iter()
            .map(|row| {
                Ok(KeySummary {
                    key_id: row.try_get("key_id").map_err(decode)?,
                    client_id: row
                        .try_get("client_id")
                        .map_err(decode)?,
                    scopes: row.try_get("scopes").map_err(decode)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(decode)?,
                    expires_at: row
                        .try_get("expires_at")
                        .map_err(decode)?,
                    revoked_at: row
                        .try_get("revoked_at")
                        .map_err(decode)?,
                })
            })
            .collect()
    }

    async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

        insert_key_in(&mut transaction, &key).await?;

        transaction
            .commit()
            .await
            .map_err(unavailable)
    }

    async fn rotate_key(&self, old: &ApiKeyId, new: NewApiKey) -> Result<bool, StoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

        // Revoke first: if the old key is gone or already revoked, nothing is
        // inserted and the caller gets `false` instead of an orphan credential.
        let revoked = sqlx::query(
            "UPDATE api_keys SET revoked_at = now()
             WHERE key_id = $1 AND revoked_at IS NULL",
        )
        .bind(old.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;

        if revoked.rows_affected() == 0 {
            transaction
                .rollback()
                .await
                .map_err(unavailable)?;
            return Ok(false);
        }

        insert_key_in(&mut transaction, &new).await?;
        notify_key_change(&mut transaction, old).await?;
        notify_key_change(&mut transaction, &new.key_id).await?;

        transaction
            .commit()
            .await
            .map_err(unavailable)?;

        Ok(true)
    }

    async fn replace_key(&self, new: NewApiKey) -> Result<(), StoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

        sqlx::query("DELETE FROM api_keys WHERE key_id = $1")
            .bind(new.key_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;

        insert_key_in(&mut transaction, &new).await?;
        notify_key_change(&mut transaction, &new.key_id).await?;

        transaction
            .commit()
            .await
            .map_err(unavailable)
    }
}

/// Inserts the key row and its scopes into an open transaction.
async fn insert_key_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &NewApiKey,
) -> Result<(), StoreError> {
    sqlx::query(
        r#"
        INSERT INTO api_keys
            (key_id, client_id, verifier, verifier_version, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(key.key_id.as_str())
    .bind(key.client_id.as_str())
    .bind(key.verifier.0.to_vec())
    .bind(i16::from(key.verifier_version))
    .bind(key.expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(insert_error)?;

    let scopes: Vec<String> = key.scopes.iter().cloned().collect();

    sqlx::query(
        "INSERT INTO api_key_scopes (key_id, scope)
         SELECT $1, unnest($2::text[])",
    )
    .bind(key.key_id.as_str())
    .bind(&scopes)
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;

    Ok(())
}

/// Announces a credential change on the revocation channel.
///
/// Transactional: the notification commits with the write, so no replica can
/// see one without the other.
async fn notify_key_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key_id: &ApiKeyId,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(crate::auth::cache::REVOCATION_CHANNEL)
        .bind(key_id.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;

    Ok(())
}

fn parse_status(value: &str) -> Result<AccountStatus, StoreError> {
    AccountStatus::parse(value).ok_or(StoreError::Unavailable)
}

fn decode(error: sqlx::Error) -> StoreError {
    tracing::error!(%error, "credential row could not be decoded");
    StoreError::Unavailable
}

fn unavailable(error: sqlx::Error) -> StoreError {
    tracing::error!(%error, "credential store query failed");
    StoreError::Unavailable
}

fn insert_error(error: sqlx::Error) -> StoreError {
    if is_unique_violation(&error) {
        return StoreError::DuplicateKey;
    }

    unavailable(error)
}

pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{pg_pool, unique};
    use std::collections::HashSet;

    async fn provision(pool: &PgPool) -> (TenantId, ClientId) {
        let tenant_id = TenantId(unique("tenant"));
        let client_id = ClientId(unique("client"));

        sqlx::query("INSERT INTO tenants (id, status) VALUES ($1, 'active')")
            .bind(tenant_id.as_str())
            .execute(pool)
            .await
            .expect("insert tenant");
        sqlx::query("INSERT INTO clients (id, tenant_id, status) VALUES ($1, $2, 'active')")
            .bind(client_id.as_str())
            .bind(tenant_id.as_str())
            .execute(pool)
            .await
            .expect("insert client");

        (tenant_id, client_id)
    }

    async fn cleanup(pool: &PgPool, tenant_id: &TenantId, client_id: &ClientId) {
        sqlx::query("DELETE FROM api_keys WHERE client_id = $1")
            .bind(client_id.as_str())
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM clients WHERE id = $1")
            .bind(client_id.as_str())
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant_id.as_str())
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn round_trips_a_credential() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let key_id = ApiKeyId(unique("key"));

        let store = PostgresApiKeyStore::new(pool.clone());
        let key = NewApiKey {
            key_id: key_id.clone(),
            client_id: client_id.clone(),
            verifier: SecretVerifier([7_u8; 32]),
            verifier_version: 2,
            scopes: HashSet::from(["read".to_owned()]),
            expires_at: None,
        };

        store
            .insert_key(key.clone())
            .await
            .expect("insert credential");

        let found = store
            .find_by_key_id(&key_id)
            .await
            .expect("lookup")
            .expect("credential exists");

        assert_eq!(found.key.key_id, key_id);
        assert_eq!(found.client.id, client_id);
        assert_eq!(found.tenant.id, tenant_id);
        assert_eq!(found.key.verifier.0, [7_u8; 32]);
        assert_eq!(found.key.scopes, key.scopes);
        assert!(found.key.revoked_at.is_none());

        assert!(matches!(
            store.insert_key(key).await,
            Err(StoreError::DuplicateKey)
        ));

        assert!(
            store
                .revoke_by_key_id(&key_id)
                .await
                .expect("revoke")
        );

        let revoked = store
            .find_by_key_id(&key_id)
            .await
            .expect("lookup")
            .expect("credential exists");
        assert!(revoked.key.revoked_at.is_some());

        cleanup(&pool, &tenant_id, &client_id).await;
    }

    #[tokio::test]
    async fn revocation_notifies_other_replicas() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let key_id = ApiKeyId(unique("key"));
        let store = PostgresApiKeyStore::new(pool.clone());

        store
            .insert_key(NewApiKey {
                key_id: key_id.clone(),
                client_id: client_id.clone(),
                verifier: SecretVerifier([7_u8; 32]),
                verifier_version: 2,
                scopes: HashSet::new(),
                expires_at: None,
            })
            .await
            .expect("insert credential");

        let mut listener = sqlx::postgres::PgListener::connect_with(&pool)
            .await
            .expect("listener");
        listener
            .listen(crate::auth::cache::REVOCATION_CHANNEL)
            .await
            .expect("subscribe");

        assert!(
            store
                .revoke_by_key_id(&key_id)
                .await
                .expect("revoke")
        );

        // Every test shares the Postgres channel, so another test's revoke can
        // arrive first. Wait for this key's notification instead of assuming
        // the first one is ours.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut matched = false;

        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());

            match tokio::time::timeout(remaining, listener.recv()).await {
                Ok(Ok(notification)) if notification.payload() == key_id.as_str() => {
                    matched = true;
                    break;
                }
                Ok(Ok(_)) => continue,
                Ok(Err(error)) => panic!("listener failed: {error}"),
                Err(_) => break,
            }
        }

        assert!(
            matched,
            "revocation notification for {key_id} was not observed"
        );

        cleanup(&pool, &tenant_id, &client_id).await;
    }

    #[tokio::test]
    async fn missing_key_returns_none() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let store = PostgresApiKeyStore::new(pool);

        assert!(
            store
                .find_by_key_id(&ApiKeyId(unique("absent")))
                .await
                .expect("lookup")
                .is_none()
        );
    }

    fn verifier() -> crate::auth::KeyVerifier {
        crate::auth::KeyVerifier::new(crate::config::SecretString::new("test-pepper"))
    }

    fn token_for(client: &ClientId, verifier: &crate::auth::KeyVerifier) -> NewApiKey {
        crate::auth::key::generate(
            verifier,
            client.clone(),
            HashSet::from(["read".to_owned()]),
            None,
        )
        .expect("generate key")
        .0
    }

    #[tokio::test]
    async fn rotation_issues_the_replacement_and_revokes_the_old_key() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let store = PostgresApiKeyStore::new(pool.clone());
        let verifier = verifier();

        let old = token_for(&client_id, &verifier);
        let old_id = old.key_id.clone();
        store
            .insert_key(old)
            .await
            .expect("insert");

        let new = token_for(&client_id, &verifier);
        let new_id = new.key_id.clone();
        assert!(
            store
                .rotate_key(&old_id, new)
                .await
                .expect("rotate")
        );

        let old_row = store
            .find_by_key_id(&old_id)
            .await
            .expect("read old")
            .expect("old row");
        assert!(
            old_row.key.revoked_at.is_some(),
            "the old key must be revoked in the same transaction"
        );

        let new_row = store
            .find_by_key_id(&new_id)
            .await
            .expect("read new")
            .expect("new row");
        assert!(
            new_row.key.revoked_at.is_none(),
            "the replacement must be active"
        );

        cleanup(&pool, &tenant_id, &client_id).await;
    }

    #[tokio::test]
    async fn rotation_of_a_revoked_key_inserts_nothing() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let store = PostgresApiKeyStore::new(pool.clone());
        let verifier = verifier();

        let old = token_for(&client_id, &verifier);
        let old_id = old.key_id.clone();
        store
            .insert_key(old)
            .await
            .expect("insert");
        assert!(
            store
                .revoke_by_key_id(&old_id)
                .await
                .expect("revoke")
        );

        let new = token_for(&client_id, &verifier);
        let new_id = new.key_id.clone();

        assert!(
            !store
                .rotate_key(&old_id, new)
                .await
                .expect("rotate"),
            "an inactive key cannot be rotated"
        );
        assert!(
            store
                .find_by_key_id(&new_id)
                .await
                .expect("read")
                .is_none(),
            "no credential may be left behind when the rotation is refused"
        );

        cleanup(&pool, &tenant_id, &client_id).await;
    }

    #[tokio::test]
    async fn lists_only_the_clients_keys() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let (other_tenant, other_client) = provision(&pool).await;
        let store = PostgresApiKeyStore::new(pool.clone());
        let verifier = verifier();

        let mut ids = Vec::new();
        for _ in 0..2 {
            let key = token_for(&client_id, &verifier);
            ids.push(key.key_id.0.clone());
            store
                .insert_key(key)
                .await
                .expect("insert");
        }
        store
            .insert_key(token_for(&other_client, &verifier))
            .await
            .expect("insert other");

        let summaries = store
            .list_for_client(
                &client_id,
                KeyPage {
                    after: None,
                    limit: 10,
                },
            )
            .await
            .expect("list");

        assert_eq!(summaries.len(), 2);
        assert!(
            summaries
                .iter()
                .all(|summary| summary.client_id == client_id.as_str())
        );
        assert!(
            summaries
                .iter()
                .all(|summary| summary.scopes == vec!["read".to_owned()])
        );
        assert!(ids.iter().all(|id| {
            summaries
                .iter()
                .any(|summary| &summary.key_id == id)
        }));

        cleanup(&pool, &tenant_id, &client_id).await;
        cleanup(&pool, &other_tenant, &other_client).await;
    }

    #[tokio::test]
    async fn key_listing_pages_without_gaps_or_repeats() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let store = PostgresApiKeyStore::new(pool.clone());
        let verifier = verifier();

        let mut key_ids = Vec::new();
        for _ in 0..3 {
            let key = token_for(&client_id, &verifier);
            key_ids.push(key.key_id.0.clone());
            store
                .insert_key(key)
                .await
                .expect("insert");
        }

        let first = store
            .list_for_client(
                &client_id,
                KeyPage {
                    after: None,
                    limit: 2,
                },
            )
            .await
            .expect("first page");
        assert_eq!(first.len(), 2);

        let last = first.last().expect("row");
        let second = store
            .list_for_client(
                &client_id,
                KeyPage {
                    after: Some((last.created_at, last.key_id.clone())),
                    limit: 2,
                },
            )
            .await
            .expect("second page");
        assert_eq!(second.len(), 1);

        let mut seen: Vec<String> = first
            .iter()
            .chain(second.iter())
            .map(|summary| summary.key_id.clone())
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 3, "every key appears exactly once");

        key_ids.sort_unstable();
        assert_eq!(seen, key_ids);

        cleanup(&pool, &tenant_id, &client_id).await;
    }

    #[tokio::test]
    async fn replacing_a_key_swaps_the_verifier() {
        let Some(pool) = pg_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let (tenant_id, client_id) = provision(&pool).await;
        let store = PostgresApiKeyStore::new(pool.clone());
        let verifier = verifier();

        let first = token_for(&client_id, &verifier);
        let key_id = first.key_id.clone();
        store
            .insert_key(first)
            .await
            .expect("insert");

        let mut second = token_for(&client_id, &verifier);
        second.key_id = key_id.clone();
        let expected = second.verifier.0;
        store
            .replace_key(second)
            .await
            .expect("replace");

        let row = store
            .find_by_key_id(&key_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(row.key.verifier.0, expected);
        assert!(row.key.revoked_at.is_none());

        cleanup(&pool, &tenant_id, &client_id).await;
    }
}
