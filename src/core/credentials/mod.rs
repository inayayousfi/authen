//! # Credentials Module
//!
//! This module provides data structures and functionality for handling user credentials,
//! including password hashing, verification, and secure management of user authentication data.
//!
//! ## Overview
//!
//! - Defines the [`Credentials`] struct, which encapsulates a user's authentication information.
//! - Provides methods for creating credentials from plaintext passwords or precomputed hashes.
//! - Supports password verification using pluggable password managers.
//!
//! ## Features
//!
//! - Secure password hashing and verification
//! - Extensible password management via the [`SecurePasswordManager`] trait
//! - Designed for use with unique user identifiers (UUID, email, username)
//!
//! ## Modules
//!
//! - [`plain_password`]: Contains the [`PlainPassword`] type for handling plaintext passwords.
//!
//! ## Example
//!
//! ```rust,no_run
//! use authen::core::credentials::{Credentials, PlainPassword};
//! use authen::core::password::SecurePasswordManager;
//! use authen::error::AuthError;
//! # struct DummyManager;
//! # #[async_trait::async_trait]
//! # impl SecurePasswordManager for DummyManager {
//! #     async fn hash_password(&self, password: &str) -> Result<String, AuthError> { Ok(password.to_owned()) }
//! #     async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> { Ok(password == hash) }
//! # }
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let manager = DummyManager;
//! let plain = PlainPassword::new("my_password".to_string());
//! let creds = Credentials::from_plain_password(&manager, "user-1".to_string(), "user@example.com".to_string(), plain).await.unwrap();
//! assert!(creds.verify_password(&manager, &PlainPassword::new("my_password".to_string())).await.unwrap());
//! # });
//! ```

pub mod plain_password;

pub use plain_password::PlainPassword;

/// Represents a user's credentials, including identifiers and hashed password.
///
/// This struct is used to store and manage authentication data for a user.
///
/// # Fields
///
/// - `user_id`: Unique identifier for the user (preferably a UUID).
/// - `identifier`: Unique user identifier (such as email or username).
/// - `password_hash`: Securely hashed password.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// Unique identifier for the user (preferably UUID)
    pub user_id: String,
    /// Unique identifier for the user (preferably email or username)
    pub identifier: String,
    /// Hashed password
    pub password_hash: String,
}

impl Credentials {
    /// Creates a new [`Credentials`] instance from an already hashed password.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user (e.g., UUID).
    /// * `identifier` - User's login identifier (e.g., email or username).
    /// * `password_hash` - Precomputed password hash.
    ///
    /// # Returns
    ///
    /// A new [`Credentials`] object containing the provided data.
    pub fn new(user_id: String, identifier: String, password_hash: String) -> Self {
        Self {
            user_id,
            identifier,
            password_hash,
        }
    }

    /// Creates credentials by hashing a plaintext password using the provided password manager.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to a type implementing [`SecurePasswordManager`] for hashing.
    /// * `user_id` - Unique identifier for the user (e.g., UUID).
    /// * `identifier` - User's login identifier (e.g., email or username).
    /// * `plain_password` - The user's plaintext password.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::HashingError`] if password hashing fails.
    ///
    /// # Returns
    ///
    /// A [`Credentials`] object with the hashed password on success.
    pub async fn from_plain_password(
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        user_id: String,
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let password_hash = manager
            .hash_password(plain_password.as_str())
            .await
            .map_err(|e| crate::error::AuthError::HashingError(format!("Couldn't hash : {e}")))?;

        Ok(Self {
            user_id,
            identifier,
            password_hash,
        })
    }

    /// Verifies a plaintext password against the stored password hash.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to a type implementing [`SecurePasswordManager`] for verification.
    /// * `plain_password` - The plaintext password to verify.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::VerificationError`] if verification fails.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the password matches, `Ok(false)` if it does not, or an error if verification fails.
    pub async fn verify_password(
        &self,
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        plain_password: &PlainPassword,
    ) -> Result<bool, crate::error::AuthError> {
        manager
            .verify_password(plain_password.as_str(), &self.password_hash)
            .await
            .map_err(|e| {
                crate::error::AuthError::VerificationError(format!("Couldn't verify : {e}"))
            })
    }
}
