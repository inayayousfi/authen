//! # Authen Authentication Crate
//!
//! `authen` is a robust and secure authentication library for Rust, designed to provide all the essential building blocks for modern authentication systems.
//!
//! ## Features
//! - **User Management**: Create, update, and manage user accounts with flexible persistence options.
//! - **Password Hashing**: Secure password storage using industry-standard algorithms (e.g., Argon2).
//! - **Token Management**: JWT-based access and refresh token generation, validation, and rotation.
//! - **Session Handling**: Tools for managing user sessions securely.
//! - **Policy Enforcement**: Password and authentication policy enforcement.
//! - **Pluggable Backends**: Support for in-memory and PostgreSQL backends (enable with `postgres` feature).
//! - **Web Integration**: Axum-based web server integration (enable with `web` feature).
//!
//! ## Optional Features
//! - `postgres`: Enables PostgreSQL-backed persistence.
//! - `web`: Enables Axum web server integration for HTTP APIs.
//!
//! ## Example
//! ```rust
//! use authen::{AuthService, AuthenUser};
//! // ...
//! ```
//!
//! ## Modules
//! - [`auth_service`]: High-level authentication service API.
//! - [`core`]: Core primitives (users, credentials, hashing, tokens, etc.).
//! - [`error`]: Error types for authentication operations.
//! - [`postgres`]: PostgreSQL backend (requires `postgres` feature).
//! - [`web_axum`]: Axum web integration (requires `web` feature).
//!
//! ## Re-exports
//! - [`AuthService`]: Main authentication service.
//! - [`AuthenUser`]: User type.
//! - [`AuthError`]: Error type.
//! - [`get_authen_axum_router`], [`start_server`]: Web server utilities (with `web` feature).
//!
//! ## License
//! See [LICENCE](../LICENCE) for details.
//!
//! ---
//!
//! _For more details, see the individual module documentation._

/// High-level authentication service API.
pub mod auth_service;
/// Core primitives: users, credentials, hashing, tokens, etc.
pub mod core;
/// Error types for authentication operations.
pub mod error;
/// PostgreSQL backend (requires `postgres` feature).
#[cfg(feature = "postgres")]
pub mod postgres;
/// Axum web integration (requires `axum` feature).
#[cfg(feature = "axum")]
pub mod web_axum;

/// Main authentication service.
pub use auth_service::AuthService;
/// Authentication method enums for unified login and signup.
pub use auth_service::{LoginMethod, SignupMethod};
/// User type.
pub use core::user::User as AuthenUser;
/// Error type for authentication operations.
pub use error::AuthError;
/// Returns an Axum router with authentication endpoints (with `axum` feature).
#[cfg(feature = "axum")]
pub use web_axum::get_authen_axum_router;
/// Starts the Axum web server (with `axum` feature).
#[cfg(feature = "axum")]
pub use web_axum::start_server;
