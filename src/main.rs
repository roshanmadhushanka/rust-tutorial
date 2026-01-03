use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use rust_tutorial::{configuration::Configuration, db};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize tracing subscriber
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_tutorial=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    tracing::info!("Loading configuration...");
    let settings = Configuration::new().expect("Failed to load configuration");
    let server_address = settings.server_address();

    // Creating database connection pool
    tracing::info!("Connecting to  databasee...");
    let pool = db::create_pool(&settings.database).await?;

    // Run database migrations
    tracing::info!("Running database migrations...");
    db::run_migrations(&pool).await?;
    tracing::info!("Database migrations completed");

    Ok(())
}
