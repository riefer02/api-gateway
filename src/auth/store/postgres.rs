use std::collections::HashSet;

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::auth::{
    AccountStatus, ApiKeyId, ApiKeyRecord, Client, ClientId, CredentialContext, SecretVerifier,
    Tenant, TenantId,
};

use super::{ApiKeyStore, StoreError};

pub(crate) struct PostgresApiKeyStore {
    pool: PgPool,
}

impl PostgresApiKeyStore {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Development seeding: creates the tenant and client rows that a
    /// credential insert depends on, and clears the previous dev key so the
    /// secret in `.env` always wins. Never called in production.
    pub(crate) async fn prepare_development_seed(&self) -> Result<(), StoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

        sqlx::query("INSERT INTO tenants (id, status) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
            .bind(crate::auth::DEV_TENANT_ID)
            .bind(AccountStatus::Active.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;

        sqlx::query(
            "INSERT INTO clients (id, tenant_id, status) VALUES ($1, $2, $3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(crate::auth::DEV_CLIENT_ID)
        .bind(crate::auth::DEV_TENANT_ID)
        .bind(AccountStatus::Active.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;

        sqlx::query("DELETE FROM api_keys WHERE key_id = $1")
            .bind(crate::auth::DEV_KEY_ID)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;

        transaction
            .commit()
            .await
            .map_err(unavailable)
    }
}

#[async_trait]
impl ApiKeyStore for PostgresApiKeyStore {
    async fn find_by_key_id(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<CredentialContext>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT
                k.key_id,
                k.client_id,
                k.verifier,
                k.verifier_version,
                k.created_at,
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
        .bind(&key_id.0)
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

        Ok(Some(CredentialContext {
            key: ApiKeyRecord {
                key_id: ApiKeyId(row.try_get("key_id").map_err(decode)?),
                client_id: ClientId(
                    row.try_get("client_id")
                        .map_err(decode)?,
                ),
                verifier: SecretVerifier(verifier),
                verifier_version,
                scopes: scopes
                    .into_iter()
                    .collect::<HashSet<_>>(),
                created_at: row
                    .try_get("created_at")
                    .map_err(decode)?,
                expires_at: row
                    .try_get("expires_at")
                    .map_err(decode)?,
                revoked_at: row
                    .try_get("revoked_at")
                    .map_err(decode)?,
            },
            client: Client {
                id: ClientId(
                    row.try_get("client_id")
                        .map_err(decode)?,
                ),
                tenant_id: TenantId(
                    row.try_get("tenant_id")
                        .map_err(decode)?,
                ),
                status: parse_status(&client_status)?,
            },
            tenant: Tenant {
                id: TenantId(
                    row.try_get("tenant_id")
                        .map_err(decode)?,
                ),
                status: parse_status(&tenant_status)?,
            },
        }))
    }

    async fn revoke_by_key_id(&self, key_id: &ApiKeyId) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now()) WHERE key_id = $1",
        )
        .bind(&key_id.0)
        .execute(&self.pool)
        .await
        .map_err(unavailable)?;

        Ok(result.rows_affected() > 0)
    }

    async fn insert_credential(&self, credential: CredentialContext) -> Result<(), StoreError> {
        let key = &credential.key;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(unavailable)?;

        sqlx::query(
            r#"
            INSERT INTO api_keys
                (key_id, client_id, verifier, verifier_version, created_at, expires_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&key.key_id.0)
        .bind(&key.client_id.0)
        .bind(key.verifier.0.to_vec())
        .bind(i16::from(key.verifier_version))
        .bind(key.created_at)
        .bind(key.expires_at)
        .bind(key.revoked_at)
        .execute(&mut *transaction)
        .await
        .map_err(insert_error)?;

        let scopes: Vec<String> = key.scopes.iter().cloned().collect();

        sqlx::query(
            "INSERT INTO api_key_scopes (key_id, scope)
             SELECT $1, unnest($2::text[])",
        )
        .bind(&key.key_id.0)
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
    if let sqlx::Error::Database(database) = &error
        && database.code().as_deref() == Some("23505")
    {
        return StoreError::DuplicateKey;
    }

    unavailable(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::collections::HashSet;

    /// Runs against a real Postgres. Skipped when DATABASE_URL is unset so the
    /// default `cargo test` stays hermetic.
    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to DATABASE_URL");

        crate::db::migrate(&pool)
            .await
            .expect("apply migrations");

        Some(pool)
    }

    fn unique(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();

        format!("{prefix}-{}-{nanos}", std::process::id())
    }

    fn credential(
        tenant_id: &TenantId,
        client_id: &ClientId,
        key_id: &ApiKeyId,
    ) -> CredentialContext {
        CredentialContext {
            key: ApiKeyRecord {
                key_id: key_id.clone(),
                client_id: client_id.clone(),
                verifier: SecretVerifier([7_u8; 32]),
                verifier_version: 1,
                scopes: HashSet::from(["people:read".to_owned()]),
                created_at: time::OffsetDateTime::now_utc(),
                expires_at: None,
                revoked_at: None,
            },
            client: Client {
                id: client_id.clone(),
                tenant_id: tenant_id.clone(),
                status: AccountStatus::Active,
            },
            tenant: Tenant {
                id: tenant_id.clone(),
                status: AccountStatus::Active,
            },
        }
    }

    async fn cleanup(pool: &PgPool, tenant_id: &TenantId, client_id: &ClientId) {
        sqlx::query("DELETE FROM api_keys WHERE client_id = $1")
            .bind(&client_id.0)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM clients WHERE id = $1")
            .bind(&client_id.0)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant_id.0)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn round_trips_a_credential() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL is not set");
            return;
        };

        let tenant_id = TenantId(unique("tenant"));
        let client_id = ClientId(unique("client"));
        let key_id = ApiKeyId(unique("key"));

        sqlx::query("INSERT INTO tenants (id, status) VALUES ($1, 'active')")
            .bind(&tenant_id.0)
            .execute(&pool)
            .await
            .expect("insert tenant");
        sqlx::query("INSERT INTO clients (id, tenant_id, status) VALUES ($1, $2, 'active')")
            .bind(&client_id.0)
            .bind(&tenant_id.0)
            .execute(&pool)
            .await
            .expect("insert client");

        let store = PostgresApiKeyStore::new(pool.clone());
        let credential = credential(&tenant_id, &client_id, &key_id);

        store
            .insert_credential(credential.clone())
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
        assert_eq!(found.key.scopes, credential.key.scopes);
        assert!(found.key.revoked_at.is_none());

        assert!(matches!(
            store
                .insert_credential(credential)
                .await,
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
    async fn missing_key_returns_none() {
        let Some(pool) = test_pool().await else {
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
