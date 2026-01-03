use config::{Config, ConfigError, File};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct DatabaseConfiguration {
    pub username: String,
    pub password: SecretString,
    pub host: String,
    pub port: u16,
    pub database_name: String,
    pub schema: String,
    pub pool_size: u32,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

impl DatabaseConfiguration {
    pub fn connection_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}?options=-c search_path={}",
            self.username,
            self.password.expose_secret(),
            self.host,
            self.port,
            self.database_name,
            self.schema
        )
    }
}

#[derive(Deserialize, Clone)]
pub struct ApplicationConfiguration {
    pub host: String,
    pub port: u16,
    pub jwt_secret: SecretString,
    pub jwt_expiration_hours: u16,
}

#[derive(Deserialize, Clone)]
pub struct Configuration {
    pub database: DatabaseConfiguration,
    pub application: ApplicationConfiguration,
}

impl Configuration {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        let settings = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))
            .add_source(config::Environment::with_prefix("APP").separator("__"))
            .build()?;
        settings.try_deserialize()
    }

    pub fn server_address(&self) -> String {
        format!("{}:{}", self.application.host, self.application.port)
    }
}
