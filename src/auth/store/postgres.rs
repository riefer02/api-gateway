use sqlx::PgPool;

pub(crate) struct PostgresApiKeyStore {
    pool: PgPool,
}

impl PostgresApiKeyStore {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
