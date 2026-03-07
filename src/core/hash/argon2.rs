//! Argon2 password hashing and verification utilities.
//!
//! This module provides a wrapper around the [`argon2`] crate for hashing and verifying passwords or arbitrary data.
//! It exposes a simple interface for generating password hashes and verifying them, using secure random salts.
//!
//! # Examples
//!
//! ```rust
//! use authen::core::hash::argon2::Argon2Hasher;
//! use argon2::password_hash::SaltString;
//!
//! let hasher = Argon2Hasher::new();
//! let password = b"mysecret";
//! let salt = SaltString::generate(&mut rand::thread_rng());
//! let hash = hasher.hash(password, Some(&salt)).unwrap();
//! assert!(hasher.verify(password, &hash).unwrap());
//! ```
use argon2::{
    Argon2,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};

/// A wrapper for the Argon2 password hashing algorithm.
///
/// Provides methods to hash and verify passwords or arbitrary data using Argon2.
#[derive(Default)]
pub struct Argon2Hasher {
    /// The underlying Argon2 hasher instance.
    hasher: Argon2<'static>,
}

impl Argon2Hasher {
    /// Creates a new [`Argon2Hasher`] with default parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authen::core::hash::argon2::Argon2Hasher;
    /// let hasher = Argon2Hasher::new();
    /// ```
    pub fn new() -> Self {
        Self {
            hasher: Argon2::default(),
        }
    }

    /// Hashes arbitrary data (such as a password) using Argon2 and a salt.
    ///
    /// If a salt is not provided, a secure random salt will be generated.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash (e.g., a password as bytes).
    /// * `salt` - An optional [`SaltString`]. If `None`, a secure salt is generated.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the hash string on success, or a [`PasswordHashError`] on failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authen::core::hash::argon2::Argon2Hasher;
    /// let hasher = Argon2Hasher::new();
    /// let hash = hasher.hash(b"password", None).unwrap();
    /// ```
    pub fn hash(
        &self,
        data: &[u8],
        salt: Option<&SaltString>,
    ) -> Result<String, PasswordHashError> {
        let salt = match salt {
            Some(s) => s.clone(),
            None => crate::core::hash::salt::generate_secure_salt()?,
        };
        let hash = self.hasher.hash_password(data, &salt)?;
        Ok(hash.to_string())
    }

    /// Verifies arbitrary data (such as a password) against a hash string.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to verify (e.g., a password as bytes).
    /// * `hash_str` - The hash string to verify against (as produced by [`Self::hash`]).
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the data matches the hash, `Ok(false)` if it does not, or a [`PasswordHashError`] on error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authen::core::hash::argon2::Argon2Hasher;
    /// let hasher = Argon2Hasher::new();
    /// let hash = hasher.hash(b"password", None).unwrap();
    /// assert!(hasher.verify(b"password", &hash).unwrap());
    /// ```
    pub fn verify(&self, data: &[u8], hash_str: &str) -> Result<bool, PasswordHashError> {
        let parsed_hash = PasswordHash::new(hash_str)?;
        match self.hasher.verify_password(data, &parsed_hash) {
            Ok(()) => Ok(true),
            Err(PasswordHashError::Password) => Ok(false),
            Err(e) => Err(e),
        }
    }
}
