use crate::configuration::DatabaseConfiguration;
use sqlx::{PgPool, postgres::PgPoolOptions};

pub async fn create_pool(configuration: &DatabaseConfiguration) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(configuration.max_connections)
        .min_connections(configuration.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(
            configuration.acquire_timeout_seconds,
        ))
        .idle_timeout(std::time::Duration::from_secs(
            configuration.idle_timeout_seconds,
        ))
        .max_lifetime(std::time::Duration::from_secs(
            configuration.max_lifetime_seconds,
        ))
        .connect(configuration.connection_url().as_str())
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
