//! Argon2 password manager implementation.
//!
//! This module provides an implementation of the [`SecurePasswordManager`] trait using the Argon2 password hashing algorithm.
//! It is responsible for securely hashing and verifying passwords using Argon2, a modern and secure password hashing function.
//!
//! # Example
//!
//! ```rust,no_run
//! use authen::core::password::argon2::Argon2PasswordManager;
//! use authen::core::password::manager::SecurePasswordManager;
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let manager = Argon2PasswordManager::default();
//! let password = "mysecret";
//! let hash = manager.hash_password(password).await.unwrap();
//! assert!(manager.verify_password(password, &hash).await.unwrap());
//! # });
//! ```

use crate::core::hash::Argon2Hasher;
use crate::core::password::manager::SecurePasswordManager;
use crate::error::AuthError;

/// A password manager that uses the Argon2 algorithm for hashing and verifying passwords.
///
/// This struct wraps an [`Argon2Hasher`] and implements the [`SecurePasswordManager`] trait,
/// providing asynchronous methods for password hashing and verification.
#[derive(Default)]
pub struct Argon2PasswordManager {
    /// The Argon2 hasher instance used for password operations.
    hasher: Argon2Hasher,
}

#[async_trait::async_trait]
impl SecurePasswordManager for Argon2PasswordManager {
    /// Hashes a password using the Argon2 algorithm.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to hash.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` containing the hashed password if successful.
    /// * `Err(AuthError)` if the password is empty or hashing fails.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidPassword`] if the password is empty, or [`AuthError::HashingError`] if hashing fails.
    async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        if password.is_empty() {
            return Err(AuthError::InvalidPassword(
                "Password cannot be empty".to_string(),
            ));
        }
        let hash = self
            .hasher
            .hash(password.as_bytes(), None)
            .map_err(|e| AuthError::HashingError(format!("Hashing error: {e}")))?;
        Ok(hash)
    }

    /// Verifies a plaintext password against a hashed password using Argon2.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to verify.
    /// * `hashed_password` - The hashed password to compare against.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the password matches the hash.
    /// * `Ok(false)` if the password or hash is empty, or if verification fails.
    /// * `Err(AuthError)` if verification encounters an error.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::VerificationError`] if verification fails due to an internal error.
    async fn verify_password(
        &self,
        password: &str,
        hashed_password: &str,
    ) -> Result<bool, AuthError> {
        if password.is_empty() || hashed_password.is_empty() {
            return Ok(false);
        }
        let valid = self
            .hasher
            .verify(password.as_bytes(), hashed_password)
            .map_err(|e| AuthError::VerificationError(format!("Verification error: {e}")))?;
        Ok(valid)
    }
}
