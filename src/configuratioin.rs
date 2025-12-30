use config::{Config, ConfigError, File};
use serde::Deserialize;
use secrecy::{SecretString, ExposeSecret};

#[derive(Deserialize, Clone)]
pub struct DatabaseConfiguration {
    pub username: String,
    pub password: SecretString,
    pub host: String,
    pub port: u16,
    pub database_name: String,
    pub schema: String,
    pub pool_size: u32,
}

impl DatabaseConfiguration {
    pub fn connection_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username,
            self.password.expose_secret(),
            self.host,
            self.port,
            self.database_name
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
}