use crate::configuration::Configuration;
use crate::error::{AppError, AppResult};
use crate::models::{AuthResponse, CreateUserRequest, PaginatedMeta, PaginatedResponse, PaginationParams, User, UserResponse, UserRole};
use crate::repositories::user_repository::UserRepository;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

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

    pub async fn login(&self, email: &str, password: &str) -> AppResult<AuthResponse> {
        let user = self
            .repository
            .find_by_email(email)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid email or password".to_string()))?;

        if !user.is_active {
            return Err(AppError::Auth("User account is inactive".to_string()));
        }

        self.verify_password(password, &user.password_hash)?;
        self.create_auth_response(user)
    }

    pub async fn get_user(&self, id: Uuid) -> AppResult<UserResponse> {
        let user = self.repository.find_by_id(id).await?
            .ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;
        Ok(UserResponse::from(user))
    }

    pub async fn list_users(&self, params: PaginationParams) -> AppResult<PaginatedResponse<UserResponse>> {
        let offset = params.offset();
        let per_page = params.per_page();

        let users = self.repository.find_all(offset, per_page).await?;
        let total = self.repository.count().await?;

        let total_pages = ((total as f64) / (per_page as f64)) as u32;

        Ok(PaginatedResponse{
            data: users.into_iter().map(UserResponse::from).collect(),
            meta: PaginatedMeta {
                current_page: params.page.unwrap_or(1),
                per_page,
                total_items: total,
                total_pages,
            },
        })
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

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(
                self.configuration
                    .application
                    .jwt_secret
                    .expose_secret()
                    .as_bytes(),
            ),
        )?;
        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.configuration.application.jwt_expiration_hours * 3600,
            user: UserResponse::from(user),
        })
    }

    fn verify_password(&self, password: &str, hash: &str) -> AppResult<()> {
        let password_hash = PasswordHash::new(hash).map_err(|_| AppError::PasswordHash)?;
        Argon2::default().verify_password(password.as_bytes(), &password_hash).map_err(|_| AppError::Auth("Invalid credentials".to_string()))
    }
}
