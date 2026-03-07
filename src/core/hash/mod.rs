pub use argon2::Argon2Hasher;
pub use salt::generate_secure_salt;

/// Hashing utilities for the `authen` authentication library.
///
/// This module provides secure password hashing and salt generation utilities.
/// It exposes the Argon2 password hasher and a cryptographically secure salt generator.
///
/// # Modules
/// - [`argon2`]: Contains the Argon2 password hashing implementation.
/// - [`salt`]: Contains utilities for generating secure random salts.
///
/// # Re-exports
/// - [`Argon2Hasher`]: Main struct for hashing and verifying passwords using Argon2.
/// - [`generate_secure_salt`]: Function to generate a cryptographically secure random salt.
/// Argon2 password hashing implementation.
pub mod argon2;
/// Salt generation utilities.
pub mod salt;
