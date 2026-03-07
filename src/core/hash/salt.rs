//! Utilities for generating cryptographically secure salts for password hashing.
//!
//! This module provides a function to generate a random salt suitable for use with Argon2 password hashing.
//! It uses the operating system's cryptographically secure random number generator to ensure high entropy.
//!
//! # Example
//!
//! ```rust
//! use authen::core::hash::salt::generate_secure_salt;
//!
//! let salt = generate_secure_salt().expect("Failed to generate salt");
//! println!("Salt: {}", salt.as_str());
//! ```

use argon2::password_hash::{Error as PasswordHashError, SaltString};
use rand::{TryRngCore, rngs::OsRng};

/// Generates a cryptographically secure random salt for password hashing.
///
/// This function uses the operating system's secure random number generator to fill a 16-byte array,
/// then encodes it as a base64 salt string compatible with Argon2 password hashing.
///
/// # Errors
///
/// Returns a [`PasswordHashError`] if the random number generator fails or if the salt encoding fails.
///
/// # Example
///
/// ```rust
/// use authen::core::hash::salt::generate_secure_salt;
/// let salt = generate_secure_salt().expect("Failed to generate salt");
/// println!("Salt: {}", salt.as_str());
/// ```
pub fn generate_secure_salt() -> Result<SaltString, PasswordHashError> {
    let mut bytes = [0u8; 16];

    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PasswordHashError::Password)?;

    SaltString::encode_b64(&bytes)
}
