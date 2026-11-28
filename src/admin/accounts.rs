use super::*;

impl AdminService {
    pub(crate) async fn create_tenant(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        validate_id("tenant", id)?;

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query("INSERT INTO tenants (id, status) VALUES ($1, 'active')")
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| conflict_or_store(error, "tenant", id))?;

        audit::insert(
            &mut transaction,
            actor,
            "tenant.create",
            id,
            &serde_json::json!({}),
        )
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    pub(crate) async fn create_client(
        &self,
        actor: &Actor,
        id: &str,
        tenant_id: &str,
    ) -> Result<(), AdminError> {
        validate_id("client", id)?;
        validate_id("tenant", tenant_id)?;

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(AdminError::Store)?;

        sqlx::query("INSERT INTO clients (id, tenant_id, status) VALUES ($1, $2, 'active')")
            .bind(id)
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                if is_reference_violation(&error) {
                    AdminError::NotFound {
                        entity: "tenant",
                        id: tenant_id.to_owned(),
                    }
                } else {
                    conflict_or_store(error, "client", id)
                }
            })?;

        audit::insert(
            &mut transaction,
            actor,
            "client.create",
            id,
            &serde_json::json!({ "tenant_id": tenant_id }),
        )
        .await
        .map_err(AdminError::Store)?;

        transaction
            .commit()
            .await
            .map_err(AdminError::Store)
    }

    pub(crate) async fn delete_tenant(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        self.delete_row(
            actor,
            "tenant",
            "tenant.delete",
            id,
            "DELETE FROM tenants WHERE id = $1",
        )
        .await
    }

    pub(crate) async fn delete_client(&self, actor: &Actor, id: &str) -> Result<(), AdminError> {
        self.delete_row(
            actor,
            "client",
            "client.delete",
            id,
            "DELETE FROM clients WHERE id = $1",
        )
        .await
    }
}

fn conflict_or_store(error: sqlx::Error, entity: &'static str, id: &str) -> AdminError {
    if is_unique_violation(&error) {
        AdminError::Conflict {
            message: format!("{entity} `{id}` already exists"),
        }
    } else {
        AdminError::Store(error)
    }
}
