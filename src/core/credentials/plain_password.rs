//! This module defines the [`PlainPassword`] structure for secure handling
//! of plaintext passwords with automatic memory clearing.
//!
//! # Overview
//!
//! The [`PlainPassword`] type is a temporary container for plaintext passwords.
//! It ensures that sensitive data is securely zeroed from memory when dropped,
//! using the [`Zeroize`] and [`ZeroizeOnDrop`] traits. This is useful for minimizing
//! the risk of leaking sensitive password data in memory.
//!
//! ## Example
//!
//! ```rust
//! use authen::core::credentials::plain_password::PlainPassword;
//!
//! let password = PlainPassword::new("mysecret".to_string());
//! assert_eq!(password.as_str(), "mysecret");
//! // password will be zeroed from memory when dropped
//! ```
//!
//! # Security
//!
//! Always use this type for handling plaintext passwords in memory, and avoid
//! storing passwords as plain `String` or `&str` types.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A temporary container for plaintext passwords.
///
/// This structure wraps a `String` containing a plaintext password and ensures
/// that the password is securely zeroed from memory when dropped.
///
/// # Security
///
/// Use this type to minimize the risk of leaking sensitive password data in memory.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] for automatic memory clearing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlainPassword(String);

impl PlainPassword {
    /// Creates a new [`PlainPassword`] from a `String`.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to wrap.
    ///
    /// # Returns
    ///
    /// A new [`PlainPassword`] instance containing the provided password.
    pub fn new(password: String) -> Self {
        Self(password)
    }

    /// Returns the password as a string slice.
    ///
    /// # Returns
    ///
    /// A `&str` reference to the plaintext password.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
