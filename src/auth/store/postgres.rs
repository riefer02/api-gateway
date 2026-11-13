use std::collections::HashSet;

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::auth::{
    AccountStatus, ApiKeyId, ApiKeyRecord, Client, ClientId, Credential, SecretVerifier, Tenant,
    TenantId,
};

use super::{ApiKeyStore, NewApiKey, StoreError};

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
            // Transactional: the notification commits with the revoke, so no
            // replica can see one without the other.
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(crate::auth::cache::REVOCATION_CHANNEL)
                .bind(key_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(unavailable)?;
        }

        transaction
            .commit()
            .await
            .map_err(unavailable)?;

        Ok(result.rows_affected() > 0)
    }

    async fn insert_key(&self, key: NewApiKey) -> Result<(), StoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

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
        .execute(&mut *transaction)
        .await
        .map_err(insert_error)?;

        let scopes: Vec<String> = key.scopes.into_iter().collect();

        sqlx::query(
            "INSERT INTO api_key_scopes (key_id, scope)
             SELECT $1, unnest($2::text[])",
        )
        .bind(key.key_id.as_str())
        .bind(&scopes)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;

        transaction
            .commit()
            .await
            .map_err(unavailable)
    }
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

        let notification = tokio::time::timeout(std::time::Duration::from_secs(2), listener.recv())
            .await
            .expect("notification within 2s")
            .expect("notification");

        assert_eq!(notification.payload(), key_id.as_str());

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
}
