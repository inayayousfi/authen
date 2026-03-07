//! Postgres-backed user repository implementation for the Authen authentication system.
//!
//! This module provides the [`PgUserRepo`] struct, which implements the user repository
//! trait for storing and retrieving user and credential data in a PostgreSQL database.
//!
//! # Features
//!
//! - Comprehensive schema validation for required tables and constraints
//! - Async operations using `tokio` and `sqlx`
//! - Implements the [`UserRepository`] trait for user CRUD operations
//!
//! # Usage
//!
//! This module is only available when the `postgres` feature is enabled.

use async_trait::async_trait;
use uuid::Uuid;

#[cfg(feature = "postgres")]
use crate::{core::user::User, error::AuthError};

#[cfg(feature = "postgres")]
use tokio::sync::Mutex;

/// A PostgreSQL-backed implementation of the user repository for Authen.
///
/// This struct manages a single mutable PostgreSQL connection for user and credential operations.
/// If you need connection pooling, wrap this repository in a pool-aware struct.
///
/// # Thread Safety
///
/// The underlying connection is protected by a [`tokio::sync::Mutex`] to ensure safe concurrent access.
///
/// # Usage
///
/// This repository is intended for use with the `postgres` feature enabled. It provides all user CRUD operations
/// and schema validation for the required tables and constraints.
#[derive(Debug)]
#[cfg(feature = "postgres")]
pub struct PgUserRepo {
    /// The underlying PostgreSQL connection, protected by a mutex for safe concurrent access.
    conn: Mutex<sqlx::PgConnection>,
}

#[cfg(feature = "postgres")]
impl PgUserRepo {
    /// Checks that the required PostgreSQL schema for Authen exists and is valid.
    ///
    /// This function verifies the existence and structure of the following tables:
    /// - `authen_users`
    /// - `authen_credentials`
    /// - `authen_oauth_accounts`
    ///
    /// It checks for required columns, primary keys, unique constraints, and foreign key relationships.
    ///
    /// # Arguments
    ///
    /// * `conn` - A mutable reference to an established [`sqlx::PgConnection`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::DatabaseError`] if any required table, column, or constraint is missing or invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use authen::postgres::PgUserRepo;
    /// # async fn check(conn: &mut sqlx::PgConnection) {
    /// PgUserRepo::check_schema(conn).await?;
    /// # Ok::<(), authen::error::AuthError>(())
    /// # }
    /// ```
    pub async fn check_schema(
        conn: &mut sqlx::PgConnection,
    ) -> Result<(), crate::error::AuthError> {
        use sqlx::Row;
        // Check if the authen_users table exists
        // Check authen_users table
        // Check if the authen_users table exists using a connection pool
        // Acquire a connection from the pool
        // Check if the authen_users table exists using a connection pool
        let user_cols = sqlx::query(
            r#"SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'authen_users'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_users table missing: {e}")))?;
        let mut has_id = false;
        let mut has_created_at = false;
        let mut has_updated_at = false;
        for col in &user_cols {
            let name: &str = col.get("column_name");
            let dtype: &str = col.get("data_type");
            if name == "id" && dtype == "uuid" {
                has_id = true;
            }
            if name == "created_at" && dtype == "timestamp without time zone" {
                has_created_at = true;
            }
            if name == "updated_at" && dtype == "timestamp without time zone" {
                has_updated_at = true;
            }
        }
        if !has_id {
            return Err(AuthError::DatabaseError(
                "authen_users.id column missing or wrong type".to_string(),
            ));
        }
        if !has_created_at {
            return Err(AuthError::DatabaseError(
                "authen_users.created_at column missing or wrong type".to_string(),
            ));
        }
        if !has_updated_at {
            return Err(AuthError::DatabaseError(
                "authen_users.updated_at column missing or wrong type".to_string(),
            ));
        }

        // Check primary key on authen_users.id
        let pk = sqlx::query(
            r#"SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                WHERE tc.table_name = 'authen_users' AND tc.constraint_type = 'PRIMARY KEY'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_users PK check failed: {e}")))?;
        let mut pk_ok = false;
        for row in &pk {
            let col: &str = row.get("column_name");
            if col == "id" {
                pk_ok = true;
            }
        }
        if !pk_ok {
            return Err(AuthError::DatabaseError(
                "authen_users.id is not primary key".to_string(),
            ));
        }

        // Check authen_credentials table
        let cred_cols = sqlx::query(
            r#"SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'authen_credentials'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_credentials table missing: {e}")))?;
        let mut has_user_id = false;
        let mut has_identifier = false;
        let mut has_password_hash = false;
        for col in &cred_cols {
            let name: &str = col.get("column_name");
            let dtype: &str = col.get("data_type");
            if name == "user_id" && dtype == "uuid" {
                has_user_id = true;
            }
            if name == "identifier" && dtype == "character varying" {
                has_identifier = true;
            }
            if name == "password_hash" && dtype == "character varying" {
                has_password_hash = true;
            }
        }
        if !has_user_id || !has_identifier || !has_password_hash {
            return Err(AuthError::DatabaseError(
                "authen_credentials columns missing or wrong types".to_string(),
            ));
        }

        // Check PK on authen_credentials.user_id
        let cred_pk = sqlx::query(
            r#"SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                WHERE tc.table_name = 'authen_credentials' AND tc.constraint_type = 'PRIMARY KEY'"#
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_credentials PK check failed: {e}")))?;
        let mut cred_pk_ok = false;
        for row in &cred_pk {
            let col: &str = row.get("column_name");
            if col == "user_id" {
                cred_pk_ok = true;
            }
        }
        if !cred_pk_ok {
            return Err(AuthError::DatabaseError(
                "authen_credentials.user_id is not primary key".to_string(),
            ));
        }

        // Check unique constraint on identifier
        let _unique_identifier = sqlx::query(
            r#"SELECT tc.constraint_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.table_name = 'authen_credentials' AND tc.constraint_type = 'UNIQUE' AND ccu.column_name = 'identifier'"#
        )
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| AuthError::DatabaseError("authen_credentials.identifier is not unique".to_string()))?;

        // Check FK from authen_credentials.user_id to authen_users.id
        let fk = sqlx::query(
            r#"SELECT kcu.column_name, ccu.table_name AS foreign_table_name, ccu.column_name AS foreign_column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.table_name = 'authen_credentials' AND tc.constraint_type = 'FOREIGN KEY'"#
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_credentials FK check failed: {e}")))?;
        let mut fk_ok = false;
        for row in &fk {
            let col: &str = row.get("column_name");
            let ftable: &str = row.get("foreign_table_name");
            let fcol: &str = row.get("foreign_column_name");
            if col == "user_id" && ftable == "authen_users" && fcol == "id" {
                fk_ok = true;
            }
        }
        if !fk_ok {
            return Err(AuthError::DatabaseError(
                "authen_credentials.user_id does not reference authen_users.id".to_string(),
            ));
        }

        // Check authen_oauth_accounts table
        let oauth_cols = sqlx::query(
            r#"SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'authen_oauth_accounts'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            AuthError::DatabaseError(format!("authen_oauth_accounts table missing: {e}"))
        })?;

        let mut has_oauth_user_id = false;
        let mut has_provider = false;
        let mut has_provider_user_id = false;
        for col in &oauth_cols {
            let name: &str = col.get("column_name");
            let dtype: &str = col.get("data_type");
            if name == "user_id" && dtype == "uuid" {
                has_oauth_user_id = true;
            }
            if name == "provider" && dtype == "character varying" {
                has_provider = true;
            }
            if name == "provider_user_id" && dtype == "character varying" {
                has_provider_user_id = true;
            }
        }
        if !has_oauth_user_id || !has_provider || !has_provider_user_id {
            return Err(AuthError::DatabaseError(
                "authen_oauth_accounts required columns missing or wrong types".to_string(),
            ));
        }

        // Check composite PK on authen_oauth_accounts (user_id, provider)
        let oauth_pk = sqlx::query(
            r#"SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                WHERE tc.table_name = 'authen_oauth_accounts' AND tc.constraint_type = 'PRIMARY KEY'
                ORDER BY kcu.ordinal_position"#
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_oauth_accounts PK check failed: {e}")))?;

        let mut oauth_pk_cols: Vec<String> =
            oauth_pk.iter().map(|row| row.get("column_name")).collect();
        oauth_pk_cols.sort();
        if oauth_pk_cols != vec!["provider", "user_id"] {
            return Err(AuthError::DatabaseError(
                "authen_oauth_accounts composite primary key (user_id, provider) missing"
                    .to_string(),
            ));
        }

        // Check unique constraint on (provider, provider_user_id)
        let oauth_unique = sqlx::query(
            r#"SELECT ccu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.table_name = 'authen_oauth_accounts' AND tc.constraint_type = 'UNIQUE'
                ORDER BY ccu.column_name"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            AuthError::DatabaseError(format!("authen_oauth_accounts unique check failed: {e}"))
        })?;

        let mut unique_cols: Vec<String> = oauth_unique
            .iter()
            .map(|row| row.get("column_name"))
            .collect();
        unique_cols.sort();
        unique_cols.dedup();
        if !unique_cols.contains(&"provider".to_string())
            || !unique_cols.contains(&"provider_user_id".to_string())
        {
            return Err(AuthError::DatabaseError(
                "authen_oauth_accounts unique constraint on (provider, provider_user_id) missing"
                    .to_string(),
            ));
        }

        // Check FK from authen_oauth_accounts.user_id to authen_users.id
        let oauth_fk = sqlx::query(
            r#"SELECT kcu.column_name, ccu.table_name AS foreign_table_name, ccu.column_name AS foreign_column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.table_name = 'authen_oauth_accounts' AND tc.constraint_type = 'FOREIGN KEY'"#
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("authen_oauth_accounts FK check failed: {e}")))?;

        let mut oauth_fk_ok = false;
        for row in &oauth_fk {
            let col: &str = row.get("column_name");
            let ftable: &str = row.get("foreign_table_name");
            let fcol: &str = row.get("foreign_column_name");
            if col == "user_id" && ftable == "authen_users" && fcol == "id" {
                oauth_fk_ok = true;
            }
        }
        if !oauth_fk_ok {
            return Err(AuthError::DatabaseError(
                "authen_oauth_accounts.user_id does not reference authen_users.id".to_string(),
            ));
        }

        Ok(())
    }

    /// Creates a new [`PgUserRepo`] instance from a PostgreSQL connection.
    ///
    /// # Arguments
    ///
    /// * `conn` - An established [`sqlx::PgConnection`] to the database.
    ///
    /// # Returns
    ///
    /// Returns a new [`PgUserRepo`] instance wrapped in a mutex.
    ///
    /// # Errors
    ///
    /// This function does not perform schema validation. Call [`PgUserRepo::check_schema`] separately if needed.
    pub async fn new(conn: sqlx::PgConnection) -> Result<Self, crate::error::AuthError> {
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl crate::core::user::persistence::traits::UserRepository for PgUserRepo {
    /// Adds a new user and their credentials to the database.
    ///
    /// Inserts a new user record into the `authen_users` table, along with associated credentials
    /// and OAuth accounts if provided.
    ///
    /// # Arguments
    ///
    /// * `user` - The [`User`] struct to insert.
    ///
    /// # Returns
    ///
    /// Returns the inserted [`User`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::DatabaseError`] if insertion fails or IDs are invalid.
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        // Convert String IDs to Uuid
        let user_id =
            Uuid::parse_str(&user.id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut conn = self.conn.lock().await;

        // Insert into authen_users with timestamps
        sqlx::query!(
            "INSERT INTO authen_users (id, created_at, updated_at) VALUES ($1, $2, $3)",
            user_id,
            user.created_at,
            user.updated_at
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Insert credentials if they exist
        if let Some(credentials) = &user.credentials {
            let cred_user_id = Uuid::parse_str(&credentials.user_id)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            sqlx::query!(
                "INSERT INTO authen_credentials (user_id, identifier, password_hash) VALUES ($1, $2, $3)",
                cred_user_id,
                credentials.identifier,
                credentials.password_hash
            )
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }

        // Insert OAuth accounts
        for (provider, oauth_info) in &user.oauth_accounts {
            let provider_str = match provider {
                crate::core::oauth::store::OAuth2Provider::Google => "google",
                crate::core::oauth::store::OAuth2Provider::GitHub => "github",
                crate::core::oauth::store::OAuth2Provider::Discord => "discord",
                crate::core::oauth::store::OAuth2Provider::Microsoft => "microsoft",
            };

            let raw_data_json = oauth_info
                .raw_data
                .as_ref()
                .map(|data| serde_json::to_value(data).unwrap_or(serde_json::Value::Null));

            sqlx::query!(
                r#"INSERT INTO authen_oauth_accounts
                   (user_id, provider, provider_user_id, email, name, avatar_url, verified_email, locale, updated_at, raw_data)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
                user_id,
                provider_str,
                oauth_info.provider_user_id,
                oauth_info.email,
                oauth_info.name,
                oauth_info.avatar_url,
                oauth_info.verified_email,
                oauth_info.locale,
                oauth_info.updated_at,
                raw_data_json
            )
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }

        Ok(user)
    }

    /// Retrieves a user and their credentials by user ID.
    ///
    /// Looks up a user in the `authen_users` table by their UUID, and fetches associated credentials
    /// and OAuth accounts.
    ///
    /// # Arguments
    ///
    /// * `id` - The user ID as a string (UUID format).
    ///
    /// # Returns
    ///
    /// Returns [`Some(User)`] if found, or [`None`] if not found or ID is invalid.
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        let uuid = Uuid::parse_str(id).ok()?;
        let mut conn = self.conn.lock().await;

        // Get user basic info
        let user_rec = sqlx::query!(
            "SELECT id, created_at, updated_at FROM authen_users WHERE id = $1",
            uuid
        )
        .fetch_one(&mut *conn)
        .await
        .ok()?;

        // Get credentials (if any)
        let credentials = sqlx::query!(
            "SELECT user_id, identifier, password_hash FROM authen_credentials WHERE user_id = $1",
            uuid
        )
        .fetch_optional(&mut *conn)
        .await
        .ok()?
        .map(|rec| crate::core::credentials::Credentials {
            user_id: rec.user_id.to_string(),
            identifier: rec.identifier,
            password_hash: rec.password_hash,
        });

        // Get OAuth accounts
        let oauth_records = sqlx::query!(
            r#"SELECT provider, provider_user_id, email, name, avatar_url, verified_email, locale, updated_at, raw_data
               FROM authen_oauth_accounts WHERE user_id = $1"#,
            uuid
        )
        .fetch_all(&mut *conn)
        .await
        .ok()?;

        let mut oauth_accounts = std::collections::HashMap::new();
        for oauth_rec in oauth_records {
            let provider = match oauth_rec.provider.as_str() {
                "google" => crate::core::oauth::store::OAuth2Provider::Google,
                "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
                "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
                "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
                _ => continue, // Skip unknown providers
            };

            let oauth_info = crate::core::oauth::store::OAuth2UserInfo {
                user_id: user_rec.id.to_string(),
                provider,
                provider_user_id: oauth_rec.provider_user_id,
                email: oauth_rec.email,
                name: oauth_rec.name,
                avatar_url: oauth_rec.avatar_url,
                verified_email: oauth_rec.verified_email,
                locale: oauth_rec.locale,
                updated_at: oauth_rec.updated_at,
                raw_data: oauth_rec.raw_data,
            };

            oauth_accounts.insert(provider, oauth_info);
        }

        Some(User {
            id: user_rec.id.to_string(),
            credentials,
            oauth_accounts,
            created_at: user_rec.created_at,
            updated_at: user_rec.updated_at,
        })
    }

    /// Retrieves a user and their credentials by identifier (e.g., username or email).
    ///
    /// Looks up a user by their unique identifier in the `authen_credentials` table, then fetches
    /// the full user record and associated data.
    ///
    /// # Arguments
    ///
    /// * `identifier` - The unique identifier for the user.
    ///
    /// # Returns
    ///
    /// Returns [`Some(User)`] if found, or [`None`] if not found.
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let mut conn = self.conn.lock().await;

        // Get user ID from credentials
        let cred_rec = sqlx::query!(
            "SELECT user_id FROM authen_credentials WHERE identifier = $1",
            identifier
        )
        .fetch_one(&mut *conn)
        .await
        .ok()?;

        // Use get_user_by_id to get the full user with all data
        drop(conn); // Release the lock before calling get_user_by_id
        self.get_user_by_id(&cred_rec.user_id.to_string()).await
    }

    /// Updates a user's credentials and metadata in the database.
    ///
    /// Updates the `updated_at` timestamp in the `authen_users` table, and updates credentials
    /// in the `authen_credentials` table if provided.
    ///
    /// # Arguments
    ///
    /// * `user` - The [`User`] struct with updated credentials.
    ///
    /// # Returns
    ///
    /// Returns [`Ok(())`] on success, or [`AuthError::DatabaseError`] on failure.
    async fn update_user(&self, user: &User) -> Result<(), crate::error::AuthError> {
        // Convert String user_id to Uuid
        let user_id =
            Uuid::parse_str(&user.id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut conn = self.conn.lock().await;

        // Update user's updated_at timestamp
        sqlx::query!(
            "UPDATE authen_users SET updated_at = $1 WHERE id = $2",
            user.updated_at,
            user_id
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Update credentials if they exist
        if let Some(credentials) = &user.credentials {
            let cred_user_id = Uuid::parse_str(&credentials.user_id)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            sqlx::query!(
                "UPDATE authen_credentials SET identifier = $1, password_hash = $2 WHERE user_id = $3",
                credentials.identifier,
                credentials.password_hash,
                cred_user_id
            )
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }

        Ok(())
    }

    /// Deletes a user and their credentials from the database by user ID.
    ///
    /// Removes the user record from the `authen_users` table, along with any associated credentials
    /// and OAuth accounts (if foreign key constraints are set to cascade).
    ///
    /// # Arguments
    ///
    /// * `id` - The user ID as a string (UUID format).
    ///
    /// # Returns
    ///
    /// Returns [`Ok(())`] on success, or [`AuthError::DatabaseError`] on failure.
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        let uuid = Uuid::parse_str(id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let mut conn = self.conn.lock().await;
        sqlx::query!("DELETE FROM authen_users WHERE id = $1", uuid)
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Retrieves a user by their OAuth provider and provider user ID.
    ///
    /// Looks up a user in the `authen_oauth_accounts` table by provider and provider user ID,
    /// then fetches the full user record and associated data.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    /// * `provider_user_id` - The user ID from the OAuth provider.
    ///
    /// # Returns
    ///
    /// Returns [`Some(User)`] if found, or [`None`] if not found.
    async fn get_user_by_oauth_id(
        &self,
        provider: crate::core::oauth::store::OAuth2Provider,
        provider_user_id: &str,
    ) -> Option<User> {
        let provider_str = match provider {
            crate::core::oauth::store::OAuth2Provider::Google => "google",
            crate::core::oauth::store::OAuth2Provider::GitHub => "github",
            crate::core::oauth::store::OAuth2Provider::Discord => "discord",
            crate::core::oauth::store::OAuth2Provider::Microsoft => "microsoft",
        };

        let mut conn = self.conn.lock().await;

        // Get user ID from OAuth accounts
        let oauth_rec = sqlx::query!(
            "SELECT user_id FROM authen_oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
            provider_str,
            provider_user_id
        )
        .fetch_one(&mut *conn)
        .await
        .ok()?;

        // Use get_user_by_id to get the full user with all data
        drop(conn); // Release the lock before calling get_user_by_id
        self.get_user_by_id(&oauth_rec.user_id.to_string()).await
    }
}
