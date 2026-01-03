use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateUserRequest, UpdateUserRequest, User};

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self,  req: &CreateUserRequest, password_hash: &str) -> AppResult<User>;
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>>;
    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>>;
    async fn find_all(&self, offset: u32, limit: u32) -> AppResult<Vec<User>>;
    async fn count(&self) -> AppResult<i64>;
    async fn update(&self, id: Uuid, req:  &UpdateUserRequest) -> AppResult<User>;
    async fn delete(&self, id: Uuid) -> AppResult<bool>;
    async fn exist_by_email(&self, email: &str) -> AppResult<bool>;
}

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create(&self, req: &CreateUserRequest, password_hash: &str) -> AppResult<User> {
        sqlx::query_as::<_, User>(
            r#"
                INSERT INTO users (email, password_hash, first_name, last_name)
                VALUES ($1, $2, $3, $4)
                RETURNING *
                "#,
        )
        .bind(&req.email.to_lowercase())
        .bind(password_hash)
        .bind(&req.first_name)
        .bind(&req.last_name)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err) if db_err.code() == Some("23505".into()) => {
                AppError::Conflict(format!("User with email '{}' already exists", req.email))
            }
            _ => AppError::Database(e),
        })
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"
                SELECT
                    id, email, password_hash, first_name, last_name, "role", is_active,
                    email_verified_at, created_at, updated_at
                FROM users
                WWHERE id = $1
                "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)
    }

    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"
                SELECT
                    id, email, password_hash, first_name, last_name, "role", is_active,
                    email_verified_at, created_at, updated_at
                FROM users
                WWHERE email = $1
                "#,
        )
            .bind(email.to_lowercase())
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::Database)
    }

    async fn find_all(&self, offset: u32, limit: u32) -> AppResult<Vec<User>> {
        sqlx::query_as::<_, User>(
            r#"
                SELECT
                    id, email, password_hash, first_name, last_name, "role", is_active,
                    email_verified_at, created_at, updated_at
                FROM users
                ORDER BY created_at DESC
                OFFSET $1
                LIMIT $2
                "#,
        )
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)
    }
    async fn count(&self) -> AppResult<i64> {
        let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::Database)?;
        Ok(result.0)
    }

    async fn update(&self, id: Uuid, req:  &UpdateUserRequest) -> AppResult<User> {
        let current = self.find_by_id(id).await?.ok_or_else(|| AppError::NotFound(format!("User with id '{}' not found", id)))?;

        let first_name = req.first_name.as_ref().unwrap_or(&current.first_name);
        let last_name = req.last_name.as_ref().unwrap_or(&current.last_name);
        let is_active = req.is_active.unwrap_or(false);

        sqlx::query_as::<_, User>(
            r#"
                UPDATE users
                SET first_name = $1, last_name = $2, is_active = $3, updated_at = now()
                WHERE id = $4
                RETURNING *
                "#,
        )
        .bind(first_name)
        .bind(last_name)
        .bind(is_active)
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)
    }

    async fn delete(&self, id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            r#"
                DELETE FROM users
                WHERE id = $1
                "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn exist_by_email(&self, email: &str) -> AppResult<bool> {
        let result: (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(email.to_lowercase())
            .fetch_one(&self.pool)
            .await?;
        Ok(result.0)
    }
}

