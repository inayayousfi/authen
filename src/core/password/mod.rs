//! Password Management Module
//!
//! This module provides secure password hashing and verification functionality for authentication systems.
//! It exposes password management strategies and utilities, including Argon2-based password hashing.
//!
//! # Modules
//!
//! - [`argon2`]: Contains the Argon2 password hashing implementation and configuration.
//! - [`manager`]: Defines the `SecurePasswordManager` trait and related password management logic.
//!
//! # Re-exports
//!
//! - [`Argon2PasswordManager`]: A concrete password manager using Argon2 for hashing and verification.
//! - [`SecurePasswordManager`]: The main trait for password management operations.
//!
//! # Example
//!
//! ```rust
//! use authen::core::password::{Argon2PasswordManager, SecurePasswordManager};
//!
//! let manager = Argon2PasswordManager::default();
//! let password = "mysecret";
//! let hash = manager.hash_password(password)?;
//! assert!(manager.verify_password(password, &hash)?);
//! ```
//!
//! # Security
//!
//! Always use a secure, up-to-date password hashing algorithm such as Argon2. Never store plain-text passwords.
//! This module is designed to make it easy to follow best practices for password security.

pub mod argon2;
pub mod manager;

/// Re-export of the Argon2-based password manager implementation.
pub use argon2::Argon2PasswordManager;

/// Re-export of the main password management trait.
pub use manager::SecurePasswordManager;
