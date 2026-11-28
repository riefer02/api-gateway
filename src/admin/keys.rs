use super::*;

impl AdminService {
    pub(crate) async fn issue_key(
        &self,
        actor: &Actor,
        client_id: &str,
        scopes: &[String],
        expires_at: Option<OffsetDateTime>,
    ) -> Result<IssuedKey, AdminError> {
        validate_expiry(expires_at)?;
        let scopes = normalize_scopes(scopes)?;
        self.ensure_client_exists(client_id)
            .await?;

        // A key id collision is astronomically unlikely; regenerate rather than
        // retrying the same id, which could never succeed.
        for _ in 0..3 {
            let (key, secret) = key::generate(
                &self.verifier,
                ClientId(client_id.to_owned()),
                scopes.iter().cloned().collect(),
                expires_at,
            )
            .map_err(|error| AdminError::Invalid(format!("could not generate key: {error}")))?;

            let key_id = key.key_id.0.clone();
            let token = key::token(&key.key_id, &secret);

            match self.store.insert_key(key).await {
                Ok(()) => {
                    self.audit_best_effort(
                        actor,
                        "key.create",
                        &key_id,
                        serde_json::json!({ "client_id": client_id, "scopes": scopes }),
                    )
                    .await;

                    return Ok(IssuedKey {
                        key_id,
                        token,
                        scopes,
                        expires_at,
                    });
                }
                Err(StoreError::DuplicateKey) => continue,
                Err(StoreError::Unavailable) => return Err(AdminError::Unavailable),
            }
        }

        Err(AdminError::Conflict {
            message: "could not allocate a unique key id".to_owned(),
        })
    }

    /// Issues a replacement for `key_id` with the same client, scopes, and
    /// remaining lifetime, then revokes the old key. The old key stays valid
    /// Issues a replacement for `key_id` with the same client, scopes, and
    /// remaining lifetime, then revokes the old key — in one transaction, so
    /// there is no window where both are active and no compensating revoke.
    pub(crate) async fn rotate_key(
        &self,
        actor: &Actor,
        key_id: &str,
    ) -> Result<IssuedKey, AdminError> {
        let old = auth::ApiKeyId(key_id.to_owned());
        let credential = self
            .store
            .find_by_key_id(&old)
            .await
            .map_err(store_error)?
            .ok_or_else(|| AdminError::NotFound {
                entity: "key",
                id: key_id.to_owned(),
            })?;

        if credential.key.revoked_at.is_some() {
            return Err(AdminError::Conflict {
                message: format!("key `{key_id}` is already revoked"),
            });
        }

        if credential
            .key
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        {
            return Err(AdminError::Conflict {
                message: format!(
                    "key `{key_id}` has expired; issue a new key instead of rotating it"
                ),
            });
        }

        let expires_at = credential.key.expires_at;
        let scopes: Vec<String> = {
            let mut scopes: Vec<String> = credential
                .key
                .scopes
                .iter()
                .cloned()
                .collect();
            scopes.sort();
            scopes
        };

        let (key, secret) = key::generate(
            &self.verifier,
            credential.key.client_id.clone(),
            credential.key.scopes.clone(),
            expires_at,
        )
        .map_err(|error| AdminError::Invalid(format!("could not generate key: {error}")))?;

        let replacement = key.key_id.0.clone();
        let token = key::token(&key.key_id, &secret);

        if !self
            .store
            .rotate_key(&old, key)
            .await
            .map_err(store_error)?
        {
            return Err(AdminError::NotFound {
                entity: "active key",
                id: key_id.to_owned(),
            });
        }

        // Same two events as before: the issued credential and the rotation.
        self.audit_best_effort(
            actor,
            "key.create",
            &replacement,
            serde_json::json!({
                "client_id": credential.key.client_id.as_str(),
                "scopes": scopes,
            }),
        )
        .await;

        self.audit_best_effort(
            actor,
            "key.rotate",
            key_id,
            serde_json::json!({ "replacement": replacement }),
        )
        .await;

        Ok(IssuedKey {
            key_id: replacement,
            token,
            scopes,
            expires_at,
        })
    }

    pub(crate) async fn revoke_key(&self, actor: &Actor, key_id: &str) -> Result<(), AdminError> {
        let revoked = self
            .store
            .revoke_by_key_id(&auth::ApiKeyId(key_id.to_owned()))
            .await
            .map_err(store_error)?;

        if !revoked {
            return Err(AdminError::NotFound {
                entity: "active key",
                id: key_id.to_owned(),
            });
        }

        self.audit_best_effort(actor, "key.revoke", key_id, serde_json::json!({}))
            .await;

        Ok(())
    }

    pub(crate) async fn list_keys(&self, client_id: &str) -> Result<Vec<KeySummary>, AdminError> {
        self.store
            .list_for_client(&ClientId(client_id.to_owned()))
            .await
            .map_err(store_error)
    }

    /// Development convenience: provisions the local tenant/client and seeds
    /// the key from `DEV_API_KEY_SECRET`, replacing any previous one.
    ///
    /// The tenant and client rows are this module's own; the credential is the
    /// store's. Two transactions are acceptable here because the next boot
    /// re-runs both inserts idempotently.
    pub(crate) async fn seed_development_key(
        &self,
        secret: &str,
        scopes: &[String],
    ) -> Result<(), AdminError> {
        let scopes = normalize_scopes(scopes)?;

        sqlx::query(
            "INSERT INTO tenants (id, status) VALUES ('tenant-local', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        sqlx::query(
            "INSERT INTO clients (id, tenant_id, status)
             VALUES ('client-local', 'tenant-local', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&self.pool)
        .await
        .map_err(AdminError::Store)?;

        self.store
            .replace_key(NewApiKey {
                key_id: auth::ApiKeyId("dev-local".to_owned()),
                client_id: ClientId("client-local".to_owned()),
                verifier: self.verifier.verifier_for(secret),
                verifier_version: auth::verifier::VERIFIER_VERSION,
                scopes: scopes.iter().cloned().collect(),
                expires_at: None,
            })
            .await
            .map_err(store_error)?;

        self.audit_best_effort(
            &Actor::local("system"),
            "key.seed",
            "dev-local",
            serde_json::json!({ "scopes": scopes }),
        )
        .await;

        Ok(())
    }

    async fn ensure_client_exists(&self, client_id: &str) -> Result<(), AdminError> {
        let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM clients WHERE id = $1")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(AdminError::Store)?;

        if exists.is_some() {
            Ok(())
        } else {
            Err(AdminError::NotFound {
                entity: "client",
                id: client_id.to_owned(),
            })
        }
    }
}

fn validate_expiry(expires_at: Option<OffsetDateTime>) -> Result<(), AdminError> {
    if expires_at.is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc()) {
        return Err(AdminError::Invalid(
            "expiry must be in the future".to_owned(),
        ));
    }

    Ok(())
}

fn store_error(error: StoreError) -> AdminError {
    match error {
        StoreError::DuplicateKey => AdminError::Invalid("key id collision".to_owned()),
        StoreError::Unavailable => AdminError::Unavailable,
    }
}
