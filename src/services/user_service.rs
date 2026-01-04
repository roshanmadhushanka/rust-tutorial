use crate::configuration::Configuration;
use crate::error::{AppError, AppResult};
use crate::models::{AuthResponse, CreateUserRequest, User, UserResponse, UserRole};
use crate::repositories::user_repository::UserRepository;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use secrecy::ExposeSecret;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

pub struct UserService {
    repository: Arc<dyn UserRepository>,
    configuration: Arc<Configuration>,
}

impl UserService {
    pub fn new(repository: Arc<dyn UserRepository>, configuration: Arc<Configuration>) -> Self {
        Self {
            repository,
            configuration,
        }
    }

    pub async fn register(&self, req: CreateUserRequest) -> AppResult<AuthResponse> {
        if self.repository.exist_by_email(&req.email).await? {
            return Err(AppError::Conflict(format!(
                "User with email '{}' already exists",
                req.email
            )));
        }

        let password_hash = self.hash_password(&req.password)?;
        let user = self.repository.create(&req, &password_hash).await?;

        self.create_auth_response(user)
    }

    fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AppError::PasswordHash)?;

        Ok(hash.to_string())
    }

    fn create_auth_response(&self, user: User) -> AppResult<AuthResponse> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.configuration.application.jwt_expiration_hours);

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: String::from(user.role.clone()),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(self.configuration.application.jwt_secret.expose_secret().as_bytes()))?;
        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.configuration.application.jwt_expiration_hours * 3600,
            user: UserResponse::from(user),
        })
    }
}
